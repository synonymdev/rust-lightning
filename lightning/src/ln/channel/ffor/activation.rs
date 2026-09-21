//! Private phase transitions composed by the manager with its archive and persistence barrier.

use super::*;
use crate::ln::ffor::FFORReceiverQuiescenceStatus;
use crate::ln::ffor_recovery::FFORReceiverActivation;

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn ffor_receiver_abort_reason(&self) -> Option<FFORReceiverAbortReason> {
		self.context.ffor_receiver_book.as_ref().and_then(|book| book.abort_reason)
	}

	pub(crate) fn install_ffor_receiver_activation<L: Deref>(
		&mut self, activation: &FFORReceiverActivation, monitor: &FFORMonitorSnapshot,
		current_height: u32, logger: &L,
	) -> Result<(), FFORReceiverError>
	where
		L::Target: Logger,
	{
		let setup = self
			.ffor_receiver_setup_record()
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
			.ok_or(FFORReceiverError::NotRegistered)?;
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if activation.is_active() || activation.is_aborted() || self.ffor_receiver_fence().is_some()
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		if self.ffor_receiver_quiescence_status(
			authenticated.header().epoch_id,
			current_height,
			logger,
		)? != FFORReceiverQuiescenceStatus::Quiescent
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		match self.ffor_receiver_book_status(monitor, logger)? {
			FFORReceiverStatus::Parked { commitments }
				if commitments == activation.commitments() => {},
			_ => return Err(FFORCommitmentError::MonitorMismatch.into()),
		}
		let activation_hash = activation
			.activation_hash(&setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		self.context.ffor_receiver_book.as_mut().unwrap().fence =
			Some(FFORReceiverFence { phase: FFORReceiverFencePhase::Activating, activation_hash });
		if self.validate_ffor_fence().is_err() {
			self.context.ffor_receiver_book.as_mut().unwrap().fence = None;
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(())
	}

	pub(crate) fn accept_ffor_receiver_activation(
		&mut self, activation: &FFORReceiverActivation,
	) -> Result<(), FFORReceiverError> {
		let setup = self
			.ffor_receiver_setup_record()
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
			.ok_or(FFORReceiverError::NotRegistered)?;
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let epoch = authenticated.header().epoch_id;
		let hash = activation
			.activation_hash(&setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if !activation.is_active() || activation.is_aborted() || !self.context.is_connected() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		match self.ffor_receiver_fence() {
			Some((FFORReceiverFencePhase::Active, existing)) if existing == hash => return Ok(()),
			Some((FFORReceiverFencePhase::Activating, existing)) if existing == hash => {},
			_ => return Err(FFORCommitmentError::PendingUpdates.into()),
		}
		let recovered = matches!(self.ffor_receiver_reconnect_outcome(),
			Some(FFORReestablishOutcome::MatchingActive { peer_report })
			if peer_report.epoch_id == epoch && peer_report.activation_hash == hash);
		if !self.has_ffor_receiver_quiescence(epoch) && !recovered {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		self.validate_ffor_fence().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		self.context.ffor_receiver_book.as_mut().unwrap().fence.as_mut().unwrap().phase =
			FFORReceiverFencePhase::Active;
		self.finish_ffor_quiescence();
		Ok(())
	}

	/// Keep the fence while the manager persists the terminal abort observation.
	pub(crate) fn begin_ffor_receiver_reconnect_abort(
		&mut self, activation: &FFORReceiverActivation,
	) -> Result<(), FFORReceiverError> {
		let setup = self
			.ffor_receiver_setup_record()
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
			.ok_or(FFORReceiverError::NotRegistered)?;
		let hash = activation
			.activation_hash(&setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if activation.aborted_reason() != Some(FFORReceiverAbortReason::Disconnected) {
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		match self.ffor_receiver_fence() {
			Some((FFORReceiverFencePhase::Aborting, existing)) if existing == hash => return Ok(()),
			Some((FFORReceiverFencePhase::Activating, existing)) if existing == hash => {},
			_ => return Err(FFORCommitmentError::PendingUpdates.into()),
		}
		if !matches!(
			self.ffor_receiver_reconnect_outcome(),
			Some(FFORReestablishOutcome::AbortRequired { peer_report })
				if activation.matches_abort_report(*peer_report)
		) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		self.validate_ffor_fence().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let book = self.context.ffor_receiver_book.as_mut().unwrap();
		book.fence.as_mut().unwrap().phase = FFORReceiverFencePhase::Aborting;
		book.abort_reason = Some(FFORReceiverAbortReason::Disconnected);
		self.finish_ffor_quiescence();
		Ok(())
	}

	/// Called only after the manager's matching terminal archive write is durable.
	pub(crate) fn release_ffor_receiver_reconnect_abort(
		&mut self, epoch: [u8; 32], hash: [u8; 32],
	) -> Result<(), FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		if book.epoch_id != epoch
			|| book.abort_reason != Some(FFORReceiverAbortReason::Disconnected)
		{
			return Err(FFORReceiverError::UnknownEpoch);
		}
		match book.fence.as_ref() {
			Some(fence)
				if fence.phase == FFORReceiverFencePhase::Aborting
					&& fence.activation_hash == hash => {},
			None => return Ok(()),
			_ => return Err(FFORCommitmentError::PendingUpdates.into()),
		}
		book.fence = None;
		Ok(())
	}

	fn finish_ffor_quiescence(&mut self) {
		self.release_ffor_receiver_quiescence();
		self.context.channel_state.clear_local_stfu_sent();
		self.context.channel_state.clear_remote_stfu_sent();
		self.context.channel_state.clear_quiescent();
		self.mark_response_received();
	}
}
