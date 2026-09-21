use super::*;

mod activation;
mod fence;
mod quiescence;
mod reestablish;
mod setup;
use crate::ln::ffor::{
	self as verification, FFORCommitmentError, FFORMonitorSnapshot, FFORReceiverAbortReason,
	FFORReceiverError, FFORReceiverStatus, FFORSettlementParty, FFORVoucher,
	FFORVoucherCommitments, FFORVoucherFailure,
};
use fence::FFORReceiverFence;
pub(crate) use fence::{FFORReceiverFencePhase, FFOR_FROZEN_MESSAGE};
pub(crate) use quiescence::FFORReceiverQuiescence;
pub(crate) use reestablish::FFORReestablishOutcome;
#[cfg(test)]
pub(crate) use setup::ffor_setup_test_messages;
pub(crate) use setup::FFORReceiverSetup;

/// Channel-owned identity survives the stock inbound HTLC's transition to `Committed`.
pub(super) struct FFORReceiverBook {
	epoch_id: [u8; 32],
	vouchers: Vec<FFORVoucher>,
	received: Vec<FFORReceivedVoucher>,
	abort_reason: Option<FFORReceiverAbortReason>,
	setup: Option<FFORReceiverSetup>,
	fence: Option<FFORReceiverFence>,
}

struct FFORReceivedVoucher {
	voucher: FFORVoucher,
	failure: Option<FFORVoucherFailure>,
}

impl_writeable_tlv_based!(FFORReceivedVoucher, {
	(0, voucher, required),
	(2, failure, option),
});

impl_writeable_tlv_based!(FFORReceiverBook, {
	(0, epoch_id, required),
	(2, vouchers, required_vec),
	(4, received, required_vec),
	(6, abort_reason, option),
	// Readers predating authenticated setup must refuse this record.
	(8, setup, option),
	// A reader without the mutation fence must refuse this channel.
	(10, fence, option),
});

impl FFORReceiverBook {
	pub(super) fn abort(&mut self, reason: FFORReceiverAbortReason) {
		if self.fence.is_none() {
			self.abort_reason.get_or_insert(reason);
		}
	}

	pub(super) fn restored(
		&mut self, inbound_htlcs: &[InboundHTLCOutput],
	) -> Result<(), DecodeError> {
		verification::validate_vouchers(&self.vouchers).map_err(|_| DecodeError::InvalidValue)?;
		let mut ids = alloc::collections::BTreeSet::new();
		if self.received.len() > 483
			|| self.received.iter().any(|received| !ids.insert(received.voucher.htlc_id))
		{
			return Err(DecodeError::InvalidValue);
		}
		for received in &self.received {
			let valid_failure = match received.failure.as_ref() {
				None => true,
				// The fixed temporary_node_failure packet has 256 payload/padding bytes,
				// two length fields, and a 32-byte HMAC.
				Some(FFORVoucherFailure::Relay { packet }) => packet.len() == 292,
				Some(FFORVoucherFailure::Malformed { sha256_of_onion, failure_code }) => {
					*failure_code == LocalHTLCFailureReason::InvalidOnionKey.failure_code()
						|| *failure_code
							== LocalHTLCFailureReason::InvalidOnionVersion.failure_code()
						|| (*failure_code
							== LocalHTLCFailureReason::InvalidOnionBlinding.failure_code()
							&& *sha256_of_onion == [0; 32])
				},
			};
			if !valid_failure {
				return Err(DecodeError::InvalidValue);
			}
		}
		for htlc in inbound_htlcs {
			let received =
				self.received.iter().find(|received| received.voucher.htlc_id == htlc.htlc_id);
			if let Some(received) = received {
				let voucher = &received.voucher;
				if voucher.payment_hash != htlc.payment_hash
					|| voucher.amount_msat != htlc.amount_msat
					|| voucher.cltv_expiry != htlc.cltv_expiry
				{
					return Err(DecodeError::InvalidValue);
				}
			} else if self.abort_reason.is_none()
				|| self.vouchers.iter().any(|voucher| voucher.payment_hash == htlc.payment_hash)
			{
				// Never restore a live voucher whose channel-owned interception record was lost.
				return Err(DecodeError::InvalidValue);
			}
		}
		if let Some(setup) = self.setup.as_ref() {
			setup.validate_book(self).map_err(|_| DecodeError::InvalidValue)?;
		}
		Ok(())
	}

	fn owns(&self, htlc_id: u64) -> bool {
		self.received.iter().any(|received| received.voucher.htlc_id == htlc_id)
	}
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn register_ffor_receiver_book(
		&mut self, epoch_id: [u8; 32], vouchers: &[FFORVoucher],
	) -> Result<(), FFORReceiverError> {
		if self.context.ffor_receiver_book.is_some() {
			return Err(FFORReceiverError::AlreadyRegistered);
		}
		self.check_ffor_synchronized()?;
		if !self.context.is_connected() {
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		verification::validate_vouchers(vouchers)?;
		if !self.context.pending_inbound_htlcs.is_empty()
			|| !self.context.pending_outbound_htlcs.is_empty()
			|| vouchers[0].htlc_id != self.context.next_counterparty_htlc_id
		{
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		self.context.ffor_receiver_book = Some(FFORReceiverBook {
			epoch_id,
			vouchers: vouchers.to_vec(),
			received: Vec::new(),
			abort_reason: None,
			setup: None,
			fence: None,
		});
		Ok(())
	}

	pub(crate) fn ffor_receiver_book_status<L: Deref>(
		&self, monitor: &FFORMonitorSnapshot, logger: &L,
	) -> Result<FFORReceiverStatus, FFORReceiverError>
	where
		L::Target: Logger,
	{
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		if let Some(reason) = book.abort_reason {
			let pending =
				self.context.pending_inbound_htlcs.iter().any(|htlc| book.owns(htlc.htlc_id));
			return Ok(
				if pending
					|| !self.context.is_connected()
					|| self.check_ffor_synchronized().is_err()
				{
					FFORReceiverStatus::Aborting { reason }
				} else {
					FFORReceiverStatus::Aborted { reason }
				},
			);
		}
		let parked = book.received.iter().filter(|received| received.failure.is_some()).count();
		if parked != book.vouchers.len() {
			return Ok(FFORReceiverStatus::Registered {
				parked_vouchers: parked as u16,
				total_vouchers: book.vouchers.len() as u16,
			});
		}
		if self.ffor_revealed_secret_matches()? {
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		let commitments = self.ffor_voucher_commitments(
			FFORSettlementParty::Counterparty,
			&book.vouchers,
			monitor,
			logger,
		)?;
		Ok(FFORReceiverStatus::Parked { commitments })
	}

	pub(crate) fn abort_ffor_receiver_book(
		&mut self, epoch_id: [u8; 32],
	) -> Result<(), FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		if book.epoch_id != epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		if book.fence.is_some() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		book.abort(FFORReceiverAbortReason::Requested);
		Ok(())
	}

	/// Called only after normal channel validation has accepted an incoming add.
	pub(super) fn ffor_record_update_add(&mut self, msg: &msgs::UpdateAddHTLC) {
		let owned_pending = self
			.context
			.ffor_receiver_book
			.as_ref()
			.map(|book| {
				self.context.pending_inbound_htlcs.iter().any(|htlc| book.owns(htlc.htlc_id))
			})
			.unwrap_or(false);
		let book = match self.context.ffor_receiver_book.as_mut() {
			Some(book) => book,
			None => return,
		};
		// Bound retained received records to the live HTLC set. The expected book itself is the
		// permanent tombstone, including hashes that must never reenter ordinary payment handling.
		book.received.retain(|received| {
			self.context
				.pending_inbound_htlcs
				.iter()
				.any(|htlc| htlc.htlc_id == received.voucher.htlc_id)
		});
		let reserved_hash =
			book.vouchers.iter().any(|voucher| voucher.payment_hash == msg.payment_hash);
		if book.abort_reason.is_some() && !reserved_hash && !owned_pending {
			return;
		}
		let voucher = FFORVoucher {
			htlc_id: msg.htlc_id,
			payment_hash: msg.payment_hash,
			amount_msat: msg.amount_msat,
			cltv_expiry: msg.cltv_expiry,
		};
		if !book.vouchers.contains(&voucher)
			|| msg.blinding_point.is_some()
			|| msg.hold_htlc.is_some()
			|| msg.skimmed_fee_msat.is_some()
			|| msg.onion_routing_packet.version != 0
			|| msg.onion_routing_packet.public_key.is_err()
		{
			book.abort(FFORReceiverAbortReason::VoucherMismatch);
		}
		if let Some(received) =
			book.received.iter_mut().find(|received| received.voucher.htlc_id == msg.htlc_id)
		{
			// An uncommitted add can be dropped on disconnect and this ID then reused. The aborted
			// registration retains ownership, but its old encrypted failure must not be reused.
			received.voucher = voucher;
			received.failure = None;
		} else {
			book.received.push(FFORReceivedVoucher { voucher, failure: None });
		}
	}

	pub(crate) fn ffor_owns_received_htlc(&self, htlc_id: u64) -> bool {
		self.context.ffor_receiver_book.as_ref().map(|book| book.owns(htlc_id)).unwrap_or(false)
	}

	/// A committed voucher needs either its failure packet or the stock deferred add from which
	/// one can still be derived. Validate this after the manager's deferred queue has been read.
	pub(crate) fn ffor_validate_unwind_material(
		&self, deferred_adds: &[msgs::UpdateAddHTLC],
	) -> Result<(), DecodeError> {
		self.ffor_validate_receiver_setup()?;
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) => book,
			None => return Ok(()),
		};
		for received in &book.received {
			if received.failure.is_some() {
				continue;
			}
			let voucher = &received.voucher;
			let committed = self.context.pending_inbound_htlcs.iter().any(|htlc| {
				htlc.htlc_id == voucher.htlc_id && matches!(htlc.state, InboundHTLCState::Committed)
			});
			let has_deferred_add = deferred_adds
				.iter()
				.chain(self.context.monitor_pending_update_adds.iter())
				.any(|add| {
					add.channel_id == self.context.channel_id()
						&& add.htlc_id == voucher.htlc_id
						&& add.payment_hash == voucher.payment_hash
						&& add.amount_msat == voucher.amount_msat
						&& add.cltv_expiry == voucher.cltv_expiry
				});
			if committed && !has_deferred_add {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(())
	}

	pub(crate) fn ffor_park_received_htlc(&mut self, htlc_id: u64, failure: FFORVoucherFailure) {
		self.ffor_abort_revealed_secret_reuse();
		if let Some(book) = self.context.ffor_receiver_book.as_mut() {
			if let Some(received) =
				book.received.iter_mut().find(|received| received.voucher.htlc_id == htlc_id)
			{
				received.failure = Some(failure);
			}
		}
	}

	/// Queue only irrevocably committed vouchers; partial rounds keep their stock deferred add.
	pub(crate) fn ffor_queue_aborted_vouchers<L: Deref>(&mut self, logger: &L)
	where
		L::Target: Logger,
	{
		self.ffor_abort_revealed_secret_reuse();
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) if book.abort_reason.is_some() && book.fence.is_none() => book,
			_ => return,
		};
		let failures: Vec<_> = book
			.received
			.iter()
			.filter_map(|received| {
				let claimed = self.context.holding_cell_htlc_updates.iter().any(|update| {
					matches!(update, HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. }
						if *htlc_id == received.voucher.htlc_id)
				});
				let committed = self.context.pending_inbound_htlcs.iter().any(|htlc| {
					htlc.htlc_id == received.voucher.htlc_id
						&& matches!(htlc.state, InboundHTLCState::Committed)
				});
				if committed && !claimed {
					received.failure.clone().map(|failure| (received.voucher.htlc_id, failure))
				} else {
					None
				}
			})
			.collect();
		for (htlc_id, failure) in failures {
			match failure {
				FFORVoucherFailure::Relay { packet } => {
					let packet = msgs::OnionErrorPacket { data: packet, attribution_data: None };
					let _ = self.queue_fail_htlc(htlc_id, packet, logger);
				},
				FFORVoucherFailure::Malformed { sha256_of_onion, failure_code } => {
					let _ = self.queue_fail_malformed_htlc(
						htlc_id,
						failure_code,
						sha256_of_onion,
						logger,
					);
				},
			}
		}
	}

	pub(crate) fn ffor_voucher_commitments<L: Deref>(
		&self, settlement_party: FFORSettlementParty, vouchers: &[FFORVoucher],
		monitor: &FFORMonitorSnapshot, logger: &L,
	) -> Result<FFORVoucherCommitments, FFORCommitmentError>
	where
		L::Target: Logger,
	{
		self.check_ffor_synchronized()?;
		verification::validate_vouchers(vouchers)?;
		self.check_ffor_htlc_ids(settlement_party, vouchers)?;
		let context = &self.context;
		if monitor.channel_id != context.channel_id()
			|| Some(monitor.funding_txo) != self.funding.get_funding_txo()
			|| monitor.update_id != context.latest_monitor_update_id
		{
			return Err(FFORCommitmentError::MonitorMismatch);
		}

		let holder_point = self
			.holder_commitment_point
			.current_point()
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let counterparty_point = context
			.counterparty_current_commitment_point
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let holder = context
			.build_commitment_transaction(
				&self.funding,
				self.holder_commitment_point.current_transaction_number(),
				&holder_point,
				true,
				false,
				logger,
			)
			.tx;
		let counterparty = context
			.build_commitment_transaction(
				&self.funding,
				context.counterparty_next_commitment_transaction_number + 1,
				&counterparty_point,
				false,
				true,
				logger,
			)
			.tx;
		let holder_offered = settlement_party == FFORSettlementParty::Holder;
		verification::verify_outputs(&holder, holder_offered, vouchers)?;
		verification::verify_outputs(&counterparty, !holder_offered, vouchers)?;
		if monitor.holder_number != holder.commitment_number()
			|| monitor.holder.commitment_number() != holder.commitment_number()
			|| monitor.holder.trust().built_transaction().transaction
				!= holder.trust().built_transaction().transaction
			|| monitor.holder.trust().txid() != holder.trust().txid()
			|| monitor.holder.nondust_htlcs() != holder.nondust_htlcs()
			|| monitor.counterparty_number != counterparty.commitment_number()
			|| monitor.counterparty_txid != counterparty.trust().txid()
			|| &monitor.counterparty_htlcs != counterparty.nondust_htlcs()
			|| monitor.revoked_through != counterparty.commitment_number() + 1
			|| context.commitment_secrets.get_min_seen_secret() != monitor.revoked_through
		{
			return Err(FFORCommitmentError::MonitorMismatch);
		}
		verification::verify_claim_signatures(
			&holder,
			&monitor.holder,
			&self.funding.channel_transaction_parameters,
		)?;
		Ok(FFORVoucherCommitments {
			holder: verification::commitment_identity(&holder),
			counterparty: verification::commitment_identity(&counterparty),
		})
	}

	fn check_ffor_synchronized(&self) -> Result<(), FFORCommitmentError> {
		let context = &self.context;
		let channel_type = self.funding.get_channel_type();
		if !channel_type.supports_static_remote_key()
			|| !channel_type.supports_anchors_zero_fee_htlc_tx()
			|| channel_type.supports_taproot()
			|| channel_type.supports_anchor_zero_fee_commitments()
		{
			return Err(FFORCommitmentError::UnsupportedChannelType);
		}
		if !context.is_usable() {
			return Err(FFORCommitmentError::ChannelUnavailable);
		}
		if context.is_waiting_on_peer_pending_channel_update()
			|| context.is_monitor_or_signer_pending_channel_update()
			|| !context.holding_cell_htlc_updates.is_empty()
			|| context.holding_cell_update_fee.is_some()
			|| !context.blocked_monitor_updates.is_empty()
			|| context.monitor_pending_revoke_and_ack
			|| context.monitor_pending_commitment_signed
			|| context.interactive_tx_signing_session.is_some()
			|| self.pending_splice.is_some()
			|| matches!(self.quiescent_action, Some(QuiescentAction::Splice(_)))
		{
			return Err(FFORCommitmentError::PendingUpdates);
		}
		Ok(())
	}

	fn check_ffor_htlc_ids(
		&self, settlement_party: FFORSettlementParty, vouchers: &[FFORVoucher],
	) -> Result<(), FFORCommitmentError> {
		let context = &self.context;
		let actual: Vec<FFORVoucher> = match settlement_party {
			FFORSettlementParty::Holder if context.pending_inbound_htlcs.is_empty() => context
				.pending_outbound_htlcs
				.iter()
				.map(|h| FFORVoucher {
					htlc_id: h.htlc_id,
					payment_hash: h.payment_hash,
					amount_msat: h.amount_msat,
					cltv_expiry: h.cltv_expiry,
				})
				.collect(),
			FFORSettlementParty::Counterparty if context.pending_outbound_htlcs.is_empty() => {
				context
					.pending_inbound_htlcs
					.iter()
					.map(|h| FFORVoucher {
						htlc_id: h.htlc_id,
						payment_hash: h.payment_hash,
						amount_msat: h.amount_msat,
						cltv_expiry: h.cltv_expiry,
					})
					.collect()
			},
			_ => return Err(FFORCommitmentError::InvalidVoucherBook),
		};
		if actual.len() != vouchers.len() || actual.iter().any(|htlc| !vouchers.contains(htlc)) {
			return Err(FFORCommitmentError::InvalidVoucherBook);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ln::ffor_tests::{
		anchor_config, deliver_parked_voucher, offer_voucher, register_book,
	};
	use crate::ln::functional_test_utils::*;

	#[test]
	fn ffor_parking_rejects_inconsistent_stored_ownership_and_unwind_material() {
		for mutation in 0..7 {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let config = anchor_config();
			let node_chanmgrs =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
			let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
			let sender_id = nodes[0].node.get_our_node_id();
			let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
			register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
			deliver_parked_voucher(&nodes[0], &nodes[1], update);
			let encoded = {
				let peers = nodes[1].node.per_peer_state.read().unwrap();
				let mut peer = peers.get(&sender_id).unwrap().lock().unwrap();
				let channel =
					peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
				let book = channel.context.ffor_receiver_book.as_mut().unwrap();
				let original_book = book.encode();
				match mutation {
					0 => book.received.clear(),
					1 => book.received[0].voucher.payment_hash.0[0] ^= 1,
					2 => book.received[0].voucher.amount_msat += 1,
					3 => book.received[0].voucher.cltv_expiry += 1,
					4 => {
						book.received[0].failure = Some(FFORVoucherFailure::Malformed {
							sha256_of_onion: [0; 32],
							failure_code: 0,
						})
					},
					5 => book.received[0].failure = None,
					_ => {
						book.received[0].failure =
							Some(FFORVoucherFailure::Relay { packet: Vec::new() })
					},
				}
				let damaged = channel.encode();
				channel.context.ffor_receiver_book =
					Some(FFORReceiverBook::read(&mut &original_book[..]).unwrap());
				damaged
			};
			let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
			let restored = FundedChannel::read(
				&mut &encoded[..],
				(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
			);
			if mutation == 5 {
				// The manager checks this once its deferred adds have also been read. A parked
				// voucher whose packet and original add were both lost cannot be unwound.
				let restored = restored.unwrap();
				assert_eq!(
					restored.ffor_validate_unwind_material(&[]),
					Err(DecodeError::InvalidValue)
				);
			} else {
				assert!(
					matches!(restored, Err(DecodeError::InvalidValue)),
					"mutation {}",
					mutation
				);
			}
		}
	}
}
