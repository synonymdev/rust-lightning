//! Voucher-only commitment rounds after an authenticated, durably retained close acknowledgement.
//! The manager owns signed evidence and persistence. This module never treats a peer report as
//! permission to drain, and never releases the ordinary mutation fence before final persistence.

use super::*;
use crate::ln::ffor::journal::FFORCooperativeJournal;
use crate::ln::ffor_recovery::FFORReceiverCloseRecord;

pub(super) struct FFORReceiverDrain {
	acknowledgement_hash: [u8; 32],
	activation_hash: [u8; 32],
	feerate_per_kw: u32,
	settled: Vec<u8>,
	known_preimages: Vec<(u64, PaymentPreimage)>,
	completion_hash: Option<[u8; 32]>,
	closed: bool,
	// Instance-local permission follows a successful manager write. Never restored from disk.
	enabled: bool,
	// Native per-slot outcomes. Legacy drains restored without one never acquire outcomes.
	journal: Option<FFORCooperativeJournal>,
}

impl_writeable_tlv_based!(FFORReceiverDrain, {
	(0, acknowledgement_hash, required),
	(2, settled, required_vec),
	(4, known_preimages, required_vec),
	(6, completion_hash, option),
	(8, closed, required),
	(10, activation_hash, required),
	(12, feerate_per_kw, required),
	(11, enabled, (static_value, false)),
	(14, journal, option),
});

/// Point-in-time proof that both current commitments are empty and all stock rounds completed.
/// Only the channel can construct this value. The manager must retain it and complete its final
/// write before calling `finish_ffor_receiver_closed` under the same channel authority.
#[derive(Clone)]
pub(crate) struct FFORReceiverDrainCompletion {
	epoch_id: [u8; 32],
	activation_hash: [u8; 32],
	acknowledgement_hash: [u8; 32],
	commitments: FFORVoucherCommitments,
	channel_id: ChannelId,
	funding_txo: OutPoint,
	monitor_update_id: u64,
	journal: Option<FFORCooperativeJournal>,
}

impl FFORReceiverDrainCompletion {
	/// The complete native outcome journal, absent only for a legacy drain without one.
	pub(crate) fn journal(&self) -> Option<&FFORCooperativeJournal> {
		self.journal.as_ref()
	}
	pub(crate) fn epoch_id(&self) -> [u8; 32] {
		self.epoch_id
	}
	pub(crate) fn activation_hash(&self) -> [u8; 32] {
		self.activation_hash
	}
	pub(crate) fn acknowledgement_hash(&self) -> [u8; 32] {
		self.acknowledgement_hash
	}
	pub(crate) fn commitments(&self) -> FFORVoucherCommitments {
		self.commitments
	}
	pub(crate) fn monitor_identity(&self) -> (ChannelId, OutPoint, u64) {
		(self.channel_id, self.funding_txo, self.monitor_update_id)
	}
	pub(crate) fn completion_hash(&self) -> [u8; 32] {
		ffor_drain_completion_digest(
			self.epoch_id,
			self.activation_hash,
			self.acknowledgement_hash,
			self.channel_id,
			self.funding_txo,
			self.commitments,
			self.monitor_update_id,
			self.journal.as_ref(),
		)
	}
}

/// Recompute a retained completion digest. This does not construct or authenticate a channel proof.
/// A journal binds every resolved and fulfilled slot under a distinct domain; legacy records
/// without one keep the original domain.
pub(crate) fn ffor_drain_completion_digest(
	epoch_id: [u8; 32], activation_hash: [u8; 32], acknowledgement_hash: [u8; 32],
	channel_id: ChannelId, funding_txo: OutPoint, commitments: FFORVoucherCommitments,
	monitor_update_id: u64, journal: Option<&FFORCooperativeJournal>,
) -> [u8; 32] {
	let mut bytes = if journal.is_some() {
		b"ffor/native-drain-complete/v2".to_vec()
	} else {
		b"ffor/native-drain-complete/v1".to_vec()
	};
	bytes.extend_from_slice(&epoch_id);
	bytes.extend_from_slice(&activation_hash);
	bytes.extend_from_slice(&acknowledgement_hash);
	bytes.extend_from_slice(&channel_id.0);
	bytes.extend_from_slice(&funding_txo.encode());
	bytes.extend_from_slice(&monitor_update_id.to_be_bytes());
	for identity in [commitments.holder, commitments.counterparty] {
		bytes.extend_from_slice(&identity.number.to_be_bytes());
		bytes.extend_from_slice(identity.txid.as_byte_array());
	}
	if let Some(journal) = journal {
		bytes.extend_from_slice(&journal.digest_bytes());
	}
	Sha256::hash(&bytes).to_byte_array()
}

impl FFORReceiverDrain {
	pub(super) fn record_removal(&mut self, slot: usize, fulfilled: bool) {
		if self.closed {
			return;
		}
		if let Some(journal) = &mut self.journal {
			journal.record(slot, fulfilled);
		}
	}
}

impl FFORReceiverBook {
	pub(super) fn is_closed(&self) -> bool {
		self.drain.as_ref().map_or(false, |drain| drain.closed)
	}

	/// Closed with the retained completion hash of the final proof.
	pub(super) fn is_closed_with_completion(&self) -> bool {
		self.drain.as_ref().map_or(false, |drain| drain.closed && drain.completion_hash.is_some())
	}
}

impl<SP: Deref> ChannelContext<SP>
where
	SP::Target: SignerProvider,
{
	pub(in crate::ln::channel) fn ffor_drain_enabled(&self) -> bool {
		self.ffor_receiver_book.as_ref().map_or(false, |book| {
			matches!(book.fence.as_ref().map(|f| f.phase), Some(FFORReceiverFencePhase::Draining))
				&& book.drain.as_ref().map_or(false, |drain| drain.enabled && !drain.closed)
		})
	}

	pub(in crate::ln::channel) fn ffor_blocks_commitment_round(&self) -> bool {
		self.is_ffor_frozen()
			&& (!self.ffor_drain_enabled() || self.validate_ffor_drain_context().is_err())
	}

	pub(in crate::ln::channel) fn check_ffor_commitment_round(&self) -> Result<(), ChannelError> {
		if self.ffor_blocks_commitment_round() {
			Err(ChannelError::WarnAndDisconnect(FFOR_FROZEN_MESSAGE.to_owned()))
		} else {
			Ok(())
		}
	}

	pub(in crate::ln::channel) fn ffor_failure_permitted(&self, id: u64) -> bool {
		if !self.is_ffor_frozen() {
			return true;
		}
		if !self.ffor_drain_enabled() {
			return false;
		}
		let book = self.ffor_receiver_book.as_ref().unwrap();
		let drain = book.drain.as_ref().unwrap();
		book.vouchers.iter().position(|v| v.htlc_id == id).map_or(false, |slot| {
			drain.settled[slot / 8] & (1 << (slot % 8)) == 0
				&& !drain.known_preimages.iter().any(|(known, _)| *known == id)
				&& !self.holding_cell_htlc_updates.iter().any(
					|update| matches!(update, HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } if *htlc_id == id),
				)
		})
	}

	fn validate_ffor_drain_context(&self) -> Result<(), DecodeError> {
		let book = self.ffor_receiver_book.as_ref().ok_or(DecodeError::InvalidValue)?;
		let drain = book.drain.as_ref().ok_or(DecodeError::InvalidValue)?;
		if book.setup.is_none()
			|| book.abort_reason.is_some()
			|| drain.settled.len() != (book.vouchers.len() + 7) / 8
			|| drain.known_preimages.len() > book.vouchers.len()
			|| self.feerate_per_kw != drain.feerate_per_kw
			|| (book.vouchers.len() % 8 != 0
				&& drain
					.settled
					.last()
					.map_or(true, |last| *last >> (book.vouchers.len() % 8) != 0))
			|| !matches!(self.channel_state, ChannelState::ChannelReady(_))
			|| self.channel_state.is_local_shutdown_sent()
			|| self.channel_state.is_remote_shutdown_sent()
			|| self.pending_update_fee.is_some()
			|| self.holding_cell_update_fee.is_some()
			|| self.interactive_tx_signing_session.is_some()
			|| self.signer_pending_closing
			|| self.signer_pending_funding
			|| self.signer_pending_channel_ready
			|| self.monitor_pending_channel_ready
			|| !self.monitor_pending_forwards.is_empty()
			|| !self.monitor_pending_update_adds.is_empty()
			|| !self.monitor_pending_failures.is_empty()
			|| !self.pending_outbound_htlcs.is_empty()
		{
			return Err(DecodeError::InvalidValue);
		}
		let mut ids = alloc::collections::BTreeSet::new();
		for (id, preimage) in &drain.known_preimages {
			if !ids.insert(*id) || !self.ffor_owns_preimage(*id, preimage) {
				return Err(DecodeError::InvalidValue);
			}
		}
		for htlc in &self.pending_inbound_htlcs {
			let slot = book
				.vouchers
				.iter()
				.position(|v| {
					v.htlc_id == htlc.htlc_id
						&& v.payment_hash == htlc.payment_hash
						&& v.amount_msat == htlc.amount_msat
						&& v.cltv_expiry == htlc.cltv_expiry
				})
				.ok_or(DecodeError::InvalidValue)?;
			match &htlc.state {
				InboundHTLCState::Committed => {},
				InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(preimage, _))
					if self.ffor_owns_preimage(htlc.htlc_id, preimage) => {},
				InboundHTLCState::LocalRemoved(_)
					if drain.settled[slot / 8] & (1 << (slot % 8)) == 0 => {},
				_ => return Err(DecodeError::InvalidValue),
			}
		}
		if let Some(journal) = &drain.journal {
			journal.validate(book.vouchers.len())?;
			for (slot, voucher) in book.vouchers.iter().enumerate() {
				let pending =
					self.pending_inbound_htlcs.iter().any(|h| h.htlc_id == voucher.htlc_id);
				if journal.is_resolved(slot) == pending {
					return Err(DecodeError::InvalidValue);
				}
				if journal.is_fulfilled(slot)
					&& !drain.known_preimages.iter().any(|(id, _)| *id == voucher.htlc_id)
				{
					return Err(DecodeError::InvalidValue);
				}
			}
		}
		for update in &self.holding_cell_htlc_updates {
			match update {
				HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, payment_preimage, .. }
					if self.ffor_owns_preimage(*htlc_id, payment_preimage) => {},
				HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. }
				| HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. } => {
					let slot = book
						.vouchers
						.iter()
						.position(|v| v.htlc_id == *htlc_id)
						.ok_or(DecodeError::InvalidValue)?;
					if drain.settled[slot / 8] & (1 << (slot % 8)) != 0
						|| drain.known_preimages.iter().any(|(id, _)| id == htlc_id)
					{
						return Err(DecodeError::InvalidValue);
					}
				},
				_ => return Err(DecodeError::InvalidValue),
			}
		}
		Ok(())
	}
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn install_ffor_receiver_drain(
		&mut self, record: &FFORReceiverCloseRecord,
	) -> Result<(), FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		let fence = book.fence.as_ref().ok_or(FFORCommitmentError::PendingUpdates)?;
		record
			.validate(
				book.setup.as_ref().ok_or(FFORCommitmentError::InvalidVoucherBook)?,
				fence.activation_hash,
			)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let acknowledgement_hash =
			record.acknowledgement_hash().ok_or(FFORCommitmentError::InvalidVoucherBook)?;
		let settled = record.settled().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if let Some(drain) = &book.drain {
			return if drain.acknowledgement_hash == acknowledgement_hash && drain.settled == settled
			{
				Ok(())
			} else {
				Err(FFORCommitmentError::InvalidVoucherBook.into())
			};
		}
		if fence.phase != FFORReceiverFencePhase::Active {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		self.validate_ffor_fence().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let known_preimages = self
			.context
			.holding_cell_htlc_updates
			.iter()
			.filter_map(|update| {
				if let HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, payment_preimage, .. } = update {
					Some((*htlc_id, *payment_preimage))
				} else {
					None
				}
			})
			.collect();
		let book = self.context.ffor_receiver_book.as_mut().unwrap();
		book.drain = Some(FFORReceiverDrain {
			acknowledgement_hash,
			activation_hash: book.fence.as_ref().unwrap().activation_hash,
			feerate_per_kw: self.context.feerate_per_kw,
			settled,
			known_preimages,
			completion_hash: None,
			closed: false,
			enabled: false,
			journal: FFORCooperativeJournal::new(book.vouchers.len()),
		});
		book.fence.as_mut().unwrap().phase = FFORReceiverFencePhase::Draining;
		Ok(())
	}

	/// Call only after the exact close acknowledgement is durably retained in this instance.
	pub(crate) fn enable_ffor_receiver_drain(
		&mut self, epoch: [u8; 32], ack_hash: [u8; 32],
	) -> Result<(), FFORReceiverError> {
		if matches!(
			self.ffor_reconnect_outcome,
			Some(FFORReestablishOutcome::CloseReplayRequired { .. })
		) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		self.validate_ffor_drain().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		if book.epoch_id != epoch {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		if !matches!(book.fence.as_ref().map(|f| f.phase), Some(FFORReceiverFencePhase::Draining)) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let drain = book.drain.as_mut().ok_or(FFORCommitmentError::InvalidVoucherBook)?;
		if drain.acknowledgement_hash != ack_hash {
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		drain.enabled = true;
		Ok(())
	}

	/// Restore messages whose monitor write completed while the manager barrier still blocked drain.
	/// If true, the manager must immediately call the stock `monitor_updating_restored` handler.
	pub(crate) fn prepare_ffor_receiver_drain_monitor_resume(&mut self) -> bool {
		if self.context.ffor_blocks_commitment_round()
			|| !self.context.ffor_drain_enabled()
			|| self.context.channel_state.is_monitor_update_in_progress()
			|| !self.context.blocked_monitor_updates.is_empty()
		{
			return false;
		}
		if self.context.monitor_pending_commitment_signed
			|| self.context.monitor_pending_revoke_and_ack
			|| !self.context.monitor_pending_finalized_fulfills.is_empty()
		{
			self.context.channel_state.set_monitor_update_in_progress();
			true
		} else {
			false
		}
	}

	/// Scheduling observation only. The opaque final proof still checks both views and monitor.
	pub(crate) fn ffor_receiver_drain_pending(&self) -> bool {
		!self.context.pending_inbound_htlcs.is_empty() || self.check_ffor_synchronized().is_err()
	}

	pub(crate) fn ffor_receiver_drain_enabled(&self) -> bool {
		self.context.ffor_drain_enabled()
	}

	pub(crate) fn ffor_receiver_drain_binding(
		&self,
	) -> Option<([u8; 32], Vec<u8>, bool, Option<FFORCooperativeJournal>)> {
		self.context.ffor_receiver_book.as_ref()?.drain.as_ref().map(|drain| {
			(drain.acknowledgement_hash, drain.settled.clone(), drain.closed, drain.journal.clone())
		})
	}

	pub(crate) fn ffor_receiver_drain_activation_hash(&self) -> Option<[u8; 32]> {
		self.context.ffor_receiver_book.as_ref()?.drain.as_ref().map(|drain| drain.activation_hash)
	}

	pub(crate) fn ffor_receiver_closed_completion_hash(&self) -> Option<[u8; 32]> {
		self.context.ffor_receiver_book.as_ref()?.drain.as_ref()?.completion_hash
	}

	/// The native outcome journal of the current drain, if this drain has one.
	pub(crate) fn ffor_receiver_drain_journal(&self) -> Option<&FFORCooperativeJournal> {
		self.context.ffor_receiver_book.as_ref()?.drain.as_ref()?.journal.as_ref()
	}

	pub(crate) fn validate_ffor_drain(&self) -> Result<(), DecodeError> {
		let book = self.context.ffor_receiver_book.as_ref().ok_or(DecodeError::InvalidValue)?;
		if book.is_closed() {
			let drain = book.drain.as_ref().unwrap();
			if let Some(journal) = &drain.journal {
				journal.validate(book.vouchers.len())?;
				if !journal.all_resolved() || !journal.covers_settled(&drain.settled) {
					return Err(DecodeError::InvalidValue);
				}
			}
			return if book.fence.is_none()
				&& book.abort_reason.is_none()
				&& drain.completion_hash.is_some()
			{
				Ok(())
			} else {
				Err(DecodeError::InvalidValue)
			};
		}
		self.context.validate_ffor_drain_context()?;
		if self.pending_splice.is_some() || self.quiescent_action.is_some() {
			return Err(DecodeError::InvalidValue);
		}
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		let drain = book.drain.as_ref().unwrap();
		if book.fence.as_ref().map(|f| f.activation_hash) != Some(drain.activation_hash) {
			return Err(DecodeError::InvalidValue);
		}
		match book.fence.as_ref().map(|f| f.phase) {
			Some(FFORReceiverFencePhase::Draining)
				if !drain.closed && drain.completion_hash.is_none() => {},
			Some(FFORReceiverFencePhase::ClosedPendingPersistence)
				if !drain.closed && drain.completion_hash.is_some() => {},
			None if drain.closed && drain.completion_hash.is_some() => return Ok(()),
			_ => return Err(DecodeError::InvalidValue),
		}
		Ok(())
	}

	/// Queue failures only after retained claims have priority. Signed settled slots are never failed.
	pub(crate) fn ffor_queue_draining_vouchers<L: Deref>(&mut self, logger: &L)
	where
		L::Target: Logger,
	{
		if self.context.ffor_blocks_commitment_round() || !self.context.ffor_drain_enabled() {
			return;
		}
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		let failures: Vec<_> =
			book.received
				.iter()
				.filter_map(|received| {
					let id = received.voucher.htlc_id;
					if self.context.ffor_failure_permitted(id)
						&& self.context.pending_inbound_htlcs.iter().any(|h| {
							h.htlc_id == id && matches!(h.state, InboundHTLCState::Committed)
						}) {
						received.failure.clone().map(|failure| (id, failure))
					} else {
						None
					}
				})
				.collect();
		for (id, failure) in failures {
			match failure {
				FFORVoucherFailure::Relay { packet } => {
					let _ = self.queue_fail_htlc(
						id,
						msgs::OnionErrorPacket { data: packet, attribution_data: None },
						logger,
					);
				},
				FFORVoucherFailure::Malformed { sha256_of_onion, failure_code } => {
					let _ =
						self.queue_fail_malformed_htlc(id, failure_code, sha256_of_onion, logger);
				},
			}
		}
	}

	/// Remember owned knowledge and replace only failures which have not entered a commitment.
	/// A late preimage for an already signed failure still reaches the monitor, never rewrites it.
	pub(in crate::ln::channel) fn ffor_prepare_drain_claim(
		&mut self, id: u64, preimage: PaymentPreimage, payment_info: Option<PaymentClaimDetails>,
	) -> Option<UpdateFulfillFetch> {
		if !self.context.ffor_owns_preimage(id, &preimage)
			|| self.context.ffor_receiver_book.as_ref().and_then(|b| b.drain.as_ref()).is_none()
		{
			return None;
		}
		let state =
			self.context.pending_inbound_htlcs.iter().find(|h| h.htlc_id == id).map(|h| &h.state);
		let late = !matches!(
			state,
			Some(InboundHTLCState::Committed)
				| Some(InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(_, _)))
		);
		let value = self
			.context
			.ffor_receiver_book
			.as_ref()
			.unwrap()
			.vouchers
			.iter()
			.find(|v| v.htlc_id == id)
			.unwrap()
			.amount_msat;
		let drain = self.context.ffor_receiver_book.as_mut().unwrap().drain.as_mut().unwrap();
		let known = drain.known_preimages.iter().any(|(known, _)| *known == id);
		if !known {
			drain.known_preimages.push((id, preimage));
		}
		self.context.holding_cell_htlc_updates.retain(|update| !matches!(update,
			HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } | HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. } if *htlc_id == id));
		if !late {
			return None;
		}
		if known {
			return Some(UpdateFulfillFetch::DuplicateClaim {});
		}
		self.context.latest_monitor_update_id += 1;
		Some(UpdateFulfillFetch::NewClaim {
			monitor_update: ChannelMonitorUpdate {
				update_id: self.context.latest_monitor_update_id,
				updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
					payment_preimage: preimage,
					payment_info,
				}],
				channel_id: Some(self.context.channel_id()),
			},
			htlc_value_msat: value,
			update_blocked: true,
		})
	}

	pub(crate) fn ffor_receiver_drain_completion<L: Deref>(
		&self, monitor: &FFORMonitorSnapshot, logger: &L,
	) -> Result<FFORReceiverDrainCompletion, FFORReceiverError>
	where
		L::Target: Logger,
	{
		self.validate_ffor_drain().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		self.check_ffor_synchronized()?;
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		let drain = book.drain.as_ref().unwrap();
		let fence = book.fence.as_ref().ok_or(FFORCommitmentError::PendingUpdates)?;
		if !matches!(
			fence.phase,
			FFORReceiverFencePhase::Draining | FFORReceiverFencePhase::ClosedPendingPersistence
		) || !self.context.pending_inbound_htlcs.is_empty()
			|| !self.holder_commitment_point.can_advance()
			|| !self.context.monitor_pending_finalized_fulfills.is_empty()
			|| monitor.channel_id != self.context.channel_id()
			|| Some(monitor.funding_txo) != self.funding.get_funding_txo()
			|| monitor.update_id != self.context.latest_monitor_update_id
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let holder_point = self
			.holder_commitment_point
			.current_point()
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let remote_point = self
			.context
			.counterparty_current_commitment_point
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let holder = self
			.context
			.build_commitment_transaction(
				&self.funding,
				self.holder_commitment_point.current_transaction_number(),
				&holder_point,
				true,
				false,
				logger,
			)
			.tx;
		let counterparty = self
			.context
			.build_commitment_transaction(
				&self.funding,
				self.context.counterparty_next_commitment_transaction_number + 1,
				&remote_point,
				false,
				true,
				logger,
			)
			.tx;
		if !holder.nondust_htlcs().is_empty()
			|| !counterparty.nondust_htlcs().is_empty()
			|| !monitor.holder.nondust_htlcs().is_empty()
			|| !monitor.counterparty_htlcs.is_empty()
			|| monitor.holder_number != holder.commitment_number()
			|| monitor.holder.commitment_number() != holder.commitment_number()
			|| monitor.holder.trust().built_transaction().transaction
				!= holder.trust().built_transaction().transaction
			|| monitor.counterparty_number != counterparty.commitment_number()
			|| monitor.counterparty_txid != counterparty.trust().txid()
			|| monitor.revoked_through != counterparty.commitment_number() + 1
			|| self.context.commitment_secrets.get_min_seen_secret() != monitor.revoked_through
		{
			return Err(FFORCommitmentError::MonitorMismatch.into());
		}
		verification::verify_claim_signatures(
			&holder,
			&monitor.holder,
			&self.funding.channel_transaction_parameters,
		)?;
		if let Some(journal) = &drain.journal {
			if !journal.all_resolved() {
				return Err(FFORCommitmentError::PendingUpdates.into());
			}
			if !journal.covers_settled(&drain.settled) {
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			}
		}
		Ok(FFORReceiverDrainCompletion {
			epoch_id: book.epoch_id,
			activation_hash: fence.activation_hash,
			acknowledgement_hash: drain.acknowledgement_hash,
			channel_id: monitor.channel_id,
			funding_txo: monitor.funding_txo,
			monitor_update_id: monitor.update_id,
			commitments: FFORVoucherCommitments {
				holder: verification::commitment_identity(&holder),
				counterparty: verification::commitment_identity(&counterparty),
			},
			journal: drain.journal.clone(),
		})
	}

	pub(crate) fn prepare_ffor_receiver_closed(
		&mut self, completion: &FFORReceiverDrainCompletion,
	) -> Result<(), FFORReceiverError> {
		self.check_ffor_synchronized()?;
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		let fence = book.fence.as_mut().ok_or(FFORCommitmentError::PendingUpdates)?;
		let drain = book.drain.as_mut().ok_or(FFORCommitmentError::PendingUpdates)?;
		if book.epoch_id != completion.epoch_id
			|| fence.activation_hash != completion.activation_hash
			|| drain.acknowledgement_hash != completion.acknowledgement_hash
			|| drain.journal != completion.journal
			|| self.context.latest_monitor_update_id != completion.monitor_update_id
			|| !self.context.pending_inbound_htlcs.is_empty()
			|| !matches!(
				fence.phase,
				FFORReceiverFencePhase::Draining | FFORReceiverFencePhase::ClosedPendingPersistence
			) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		fence.phase = FFORReceiverFencePhase::ClosedPendingPersistence;
		drain.enabled = false;
		drain.completion_hash = Some(completion.completion_hash());
		Ok(())
	}

	pub(crate) fn finish_ffor_receiver_closed(
		&mut self, epoch: [u8; 32], completion_hash: [u8; 32],
	) -> Result<(), FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		let drain = book.drain.as_mut().ok_or(FFORCommitmentError::PendingUpdates)?;
		if book.epoch_id != epoch
			|| drain.completion_hash != Some(completion_hash)
			|| !matches!(
				book.fence.as_ref().map(|f| f.phase),
				Some(FFORReceiverFencePhase::ClosedPendingPersistence)
			) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		drain.closed = true;
		book.fence = None;
		// The same completed Closed proof releases pre-init interception, if this epoch used it.
		// No separate gate flag may authorize ordinary traffic before the final barrier.
		if book.request.is_some() {
			book.request_gate_released = Some(true);
		}
		Ok(())
	}
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	/// Drain reconnect uses unchanged BOLT counters and resend rules, after this report check.
	pub(in crate::ln::channel) fn ffor_check_drain_reestablish<L: Deref>(
		&mut self, msg: &msgs::ChannelReestablish, logger: &L,
	) -> Result<Option<ReestablishResponses>, ChannelError>
	where
		L::Target: Logger,
	{
		use lightning_ffor::reestablish::ReportedState;
		self.context.check_ffor_commitment_round()?;
		self.validate_ffor_drain()
			.map_err(|_| ChannelError::WarnAndDisconnect(FFOR_FROZEN_MESSAGE.to_owned()))?;
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		let hash = book.drain.as_ref().unwrap().activation_hash;
		let peer_report = msg.ffor_reestablish.as_ref().map(|wire| wire.report());
		if let Some(report) = peer_report.filter(|report| {
			report.epoch_id == book.epoch_id
				&& report.activation_hash == hash
				&& report.state == ReportedState::Active
		}) {
			self.validate_reestablish_prefix(msg, logger)?;
			let next_counterparty = INITIAL_COMMITMENT_NUMBER
				- self.context.counterparty_next_commitment_transaction_number;
			if msg.next_local_commitment_number + 1 < next_counterparty
				|| msg.next_local_commitment_number > next_counterparty
				|| msg.next_funding.is_some()
				|| msg
					.my_current_funding_locked
					.as_ref()
					.map_or(false, |funding| self.funding.get_funding_txid() != Some(funding.txid))
			{
				return Err(ChannelError::WarnAndDisconnect(FFOR_FROZEN_MESSAGE.to_owned()));
			}
			self.context.ffor_receiver_book.as_mut().unwrap().drain.as_mut().unwrap().enabled =
				false;
			self.ffor_reconnect_outcome =
				Some(FFORReestablishOutcome::CloseReplayRequired { peer_report: report });
			self.context.channel_state.clear_peer_disconnected();
			self.mark_response_received();
			return Ok(Some(ReestablishResponses {
				channel_ready: None,
				channel_ready_order: ChannelReadyOrder::ChannelReadyFirst,
				raa: None,
				commitment_update: None,
				commitment_order: self.context.resend_order.clone(),
				announcement_sigs: None,
				shutdown_msg: None,
				tx_signatures: None,
				tx_abort: None,
				inferred_splice_locked: None,
			}));
		}
		if peer_report.map_or(false, |report| {
			report.epoch_id == book.epoch_id
				&& report.activation_hash == hash
				&& matches!(report.state, ReportedState::Draining | ReportedState::Closed)
		}) && msg.next_funding.is_none()
			&& msg
				.my_current_funding_locked
				.as_ref()
				.map_or(true, |funding| self.funding.get_funding_txid() == Some(funding.txid))
		{
			return Ok(None);
		}
		self.ffor_reconnect_outcome =
			Some(FFORReestablishOutcome::ResolutionRequired { peer_report });
		Err(ChannelError::WarnAndDisconnect(
			"FFOR drain reconnect requires the same retained epoch and close acknowledgement"
				.to_owned(),
		))
	}

	pub(in crate::ln::channel) fn ffor_drain_reestablish_report(
		&self,
	) -> Option<msgs::FFORChannelReestablish> {
		use lightning_ffor::reestablish::{Reestablish, ReportedState};
		let book = self.context.ffor_receiver_book.as_ref()?;
		let drain = book.drain.as_ref()?;
		Some(msgs::FFORChannelReestablish::new(Reestablish {
			epoch_id: book.epoch_id,
			activation_hash: drain.activation_hash,
			state: if drain.closed { ReportedState::Closed } else { ReportedState::Draining },
		}))
	}
}

#[cfg(test)]
mod tests;
