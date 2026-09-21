//! A private durable mutation fence, independent of connection-scoped STFU flags.
//!
//! The private manager activation owner archives exact signed evidence and installs the fence
//! under the same channel/manager persistence boundary. No public activation or reconciliation
//! entry point is exposed. This module does not authenticate activation transcripts.

use super::*;

pub(crate) const FFOR_FROZEN_MESSAGE: &str =
	"FFOR channel requires authenticated reconciliation before ordinary updates";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FFORReceiverFencePhase {
	Activating,
	Active,
	Aborting,
}

impl_writeable_tlv_based_enum!(FFORReceiverFencePhase,
	(0, Activating) => {},
	(2, Active) => {},
	(4, Aborting) => {},
);

pub(super) struct FFORReceiverFence {
	pub(super) phase: FFORReceiverFencePhase,
	pub(super) activation_hash: [u8; 32],
}

impl_writeable_tlv_based!(FFORReceiverFence, {
	(0, phase, required),
	(2, activation_hash, required),
});

impl<SP: Deref> ChannelContext<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn is_ffor_frozen(&self) -> bool {
		self.ffor_receiver_book.as_ref().map_or(false, |book| book.fence.is_some())
	}

	pub(in crate::ln::channel) fn check_ffor_mutation(&self) -> Result<(), ChannelError> {
		if self.is_ffor_frozen() {
			Err(ChannelError::WarnAndDisconnect(FFOR_FROZEN_MESSAGE.to_owned()))
		} else {
			Ok(())
		}
	}

	pub(in crate::ln::channel) fn check_ffor_local_mutation(&self) -> Result<(), APIError> {
		if self.is_ffor_frozen() {
			Err(APIError::ChannelUnavailable { err: FFOR_FROZEN_MESSAGE.to_owned() })
		} else {
			Ok(())
		}
	}

	pub(in crate::ln::channel) fn ffor_monitor_update_allowed(
		&self, update: &ChannelMonitorUpdate,
	) -> bool {
		if !self.is_ffor_frozen() {
			return true;
		}
		update.updates.iter().all(|step| match step {
			ChannelMonitorUpdateStep::PaymentPreimage { payment_preimage, .. } => {
				let hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
				self.ffor_receiver_book
					.as_ref()
					.unwrap()
					.vouchers
					.iter()
					.any(|voucher| voucher.payment_hash == hash)
			},
			_ => false,
		})
	}

	pub(in crate::ln::channel) fn ffor_owns_preimage(
		&self, id: u64, preimage: &PaymentPreimage,
	) -> bool {
		let hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		self.ffor_receiver_book.as_ref().map_or(false, |book| {
			book.vouchers
				.iter()
				.any(|voucher| voucher.htlc_id == id && voucher.payment_hash == hash)
		})
	}
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn ffor_receiver_fence(&self) -> Option<(FFORReceiverFencePhase, [u8; 32])> {
		self.context
			.ffor_receiver_book
			.as_ref()
			.and_then(|book| book.fence.as_ref())
			.map(|fence| (fence.phase, fence.activation_hash))
	}

	pub(in crate::ln::channel) fn validate_ffor_fence(&self) -> Result<(), DecodeError> {
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) if book.fence.is_some() => book,
			_ => return Ok(()),
		};
		let context = &self.context;
		let abort_matches_phase = match book.fence.as_ref().unwrap().phase {
			FFORReceiverFencePhase::Aborting => {
				book.abort_reason == Some(FFORReceiverAbortReason::Disconnected)
			},
			_ => book.abort_reason.is_none(),
		};
		if book.setup.is_none()
			|| !abort_matches_phase
			|| !matches!(context.channel_state, ChannelState::ChannelReady(_))
			|| context.channel_state.is_local_shutdown_sent()
			|| context.channel_state.is_remote_shutdown_sent()
			|| context.is_waiting_on_peer_pending_channel_update()
			|| context.pending_update_fee.is_some()
			|| context.holding_cell_update_fee.is_some()
			|| context.interactive_tx_signing_session.is_some()
			|| self.pending_splice.is_some()
			|| matches!(self.quiescent_action, Some(QuiescentAction::Splice(_)))
			|| !self.holder_commitment_point.can_advance()
			|| context.signer_pending_commitment_update
			|| context.signer_pending_revoke_and_ack
			|| context.monitor_pending_commitment_signed
			|| context.monitor_pending_revoke_and_ack
			|| context.signer_pending_closing
			|| context.signer_pending_funding
			|| context.signer_pending_channel_ready
			|| context.monitor_pending_channel_ready
			|| !context.monitor_pending_forwards.is_empty()
			|| !context.monitor_pending_update_adds.is_empty()
			|| !context.monitor_pending_failures.is_empty()
			|| !context.monitor_pending_finalized_fulfills.is_empty()
			|| !context.pending_outbound_htlcs.is_empty()
			|| context.pending_inbound_htlcs.len() != book.vouchers.len()
			|| book.received.len() != book.vouchers.len()
			|| book.received.iter().any(|received| received.failure.is_none())
		{
			return Err(DecodeError::InvalidValue);
		}
		for htlc in &context.pending_inbound_htlcs {
			if !matches!(htlc.state, InboundHTLCState::Committed)
				|| !book.vouchers.iter().any(|voucher| {
					voucher.htlc_id == htlc.htlc_id
						&& voucher.payment_hash == htlc.payment_hash
						&& voucher.amount_msat == htlc.amount_msat
						&& voucher.cltv_expiry == htlc.cltv_expiry
				}) {
				return Err(DecodeError::InvalidValue);
			}
		}
		for update in &context.holding_cell_htlc_updates {
			match update {
				HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, payment_preimage, .. }
					if context.ffor_owns_preimage(*htlc_id, payment_preimage) => {},
				_ => return Err(DecodeError::InvalidValue),
			}
		}
		for pending in &context.blocked_monitor_updates {
			if !context.ffor_monitor_update_allowed(&pending.update) {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(())
	}

	/// Test-only installation exercises gates using actual channel and monitor evidence.
	/// The caller must also install matching authenticated recovery evidence before manager persistence.
	/// This method checks the native channel proof, not the supplied activation hash.
	#[cfg(test)]
	pub(crate) fn install_ffor_fence_for_test<L: Deref>(
		&mut self, phase: FFORReceiverFencePhase, activation_hash: [u8; 32],
		monitor: &FFORMonitorSnapshot, current_height: u32, logger: &L,
	) -> Result<(), FFORReceiverError>
	where
		L::Target: Logger,
	{
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		if book.fence.is_some() || book.setup.is_none() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let epoch_id = book.epoch_id;
		if self.ffor_receiver_quiescence_status(epoch_id, current_height, logger)?
			!= crate::ln::ffor::FFORReceiverQuiescenceStatus::Quiescent
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		if !matches!(
			self.ffor_receiver_book_status(monitor, logger)?,
			FFORReceiverStatus::Parked { .. }
		) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		self.context.ffor_receiver_book.as_mut().unwrap().fence =
			Some(FFORReceiverFence { phase, activation_hash });
		if self.validate_ffor_fence().is_err() {
			self.context.ffor_receiver_book.as_mut().unwrap().fence = None;
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
