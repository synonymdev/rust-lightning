//! Connection-scoped STFU ownership for a complete authenticated receiver book.
//!
//! Only the epoch identity is serialized. A restart aborts setup and discards the transient
//! proof rather than resuming quiescence. This state never authorizes offline receiving.

use super::*;
use crate::ln::ffor::FFORReceiverQuiescenceStatus;

pub(crate) struct FFORReceiverQuiescence {
	epoch_id: [u8; 32],
	monitor: Option<FFORMonitorSnapshot>,
	completed: bool,
}

impl_writeable_tlv_based!(FFORReceiverQuiescence, {
	(0, epoch_id, required),
	(_unused, monitor, (static_value, None)),
	(_unused, completed, (static_value, false)),
});

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn request_ffor_receiver_quiescence<L: Deref>(
		&mut self, epoch_id: [u8; 32], monitor: FFORMonitorSnapshot, current_height: u32,
		logger: &L,
	) -> Result<Option<msgs::Stfu>, FFORReceiverError>
	where
		L::Target: Logger,
	{
		self.check_ffor_quiescence_book(epoch_id, &monitor, current_height, logger)?;
		if !self.context.is_connected()
			|| self.quiescent_action.is_some()
			|| self.context.channel_state.is_awaiting_quiescence()
			|| self.context.channel_state.is_local_stfu_sent()
			|| self.context.channel_state.is_remote_stfu_sent()
			|| self.context.channel_state.is_quiescent()
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let action = QuiescentAction::FFORReceiver(FFORReceiverQuiescence {
			epoch_id,
			monitor: Some(monitor),
			completed: false,
		});
		match self.propose_quiescence(logger, action) {
			Ok(Some(message)) => Ok(Some(message)),
			_ => {
				// Admission requires a live, synchronized channel, so postponing the STFU is
				// not supported. Never leave an owned action that can start implicitly later.
				self.release_ffor_receiver_quiescence();
				Err(FFORCommitmentError::PendingUpdates.into())
			},
		}
	}

	fn check_ffor_quiescence_book<L: Deref>(
		&self, epoch_id: [u8; 32], monitor: &FFORMonitorSnapshot, current_height: u32, logger: &L,
	) -> Result<(), FFORReceiverError>
	where
		L::Target: Logger,
	{
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		if book.epoch_id != epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let record = book.setup.as_ref().ok_or(FFORCommitmentError::InvalidVoucherBook)?;
		let setup =
			record.validate_recovery().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if current_height >= setup.terms().settlement_deadline {
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		self.ffor_validate_receiver_setup().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		match self.ffor_receiver_book_status(monitor, logger)? {
			FFORReceiverStatus::Parked { .. } => Ok(()),
			_ => Err(FFORCommitmentError::PendingUpdates.into()),
		}
	}

	pub(crate) fn ffor_receiver_quiescence_status<L: Deref>(
		&self, epoch_id: [u8; 32], current_height: u32, logger: &L,
	) -> Result<FFORReceiverQuiescenceStatus, FFORReceiverError>
	where
		L::Target: Logger,
	{
		let request = match self.quiescent_action.as_ref() {
			Some(QuiescentAction::FFORReceiver(request)) => request,
			_ => return Err(FFORCommitmentError::ChannelUnavailable.into()),
		};
		if request.epoch_id != epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		if !request.completed {
			let book =
				self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
			if book.abort_reason.is_some() {
				return Err(FFORCommitmentError::PendingUpdates.into());
			}
			return Ok(FFORReceiverQuiescenceStatus::Negotiating);
		}
		let monitor = request.monitor.as_ref().ok_or(FFORCommitmentError::MonitorMismatch)?;
		self.check_ffor_quiescence_book(epoch_id, monitor, current_height, logger)?;
		if !self.context.channel_state.is_quiescent() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(FFORReceiverQuiescenceStatus::Quiescent)
	}

	pub(crate) fn complete_ffor_receiver_quiescence<L: Deref>(
		&mut self, is_initiator: bool, current_height: u32, logger: &L,
	) -> Result<(), ChannelError>
	where
		L::Target: Logger,
	{
		let valid = match self.quiescent_action.as_ref() {
			Some(QuiescentAction::FFORReceiver(request))
				if is_initiator && self.context.channel_state.is_quiescent() =>
			{
				request.monitor.as_ref().map_or(false, |monitor| {
					self.check_ffor_quiescence_book(
						request.epoch_id,
						monitor,
						current_height,
						logger,
					)
					.is_ok()
				})
			},
			_ => false,
		};
		if !valid {
			if let Some(book) = self.context.ffor_receiver_book.as_mut() {
				book.abort(FFORReceiverAbortReason::QuiescenceFailed);
			}
			self.release_ffor_receiver_quiescence();
			return Err(ChannelError::WarnAndDisconnect(
				"FFOR quiescence no longer matches its authenticated voucher book".to_owned(),
			));
		}
		if let Some(QuiescentAction::FFORReceiver(request)) = self.quiescent_action.as_mut() {
			request.completed = true;
		}
		Ok(())
	}

	/// Drop only FFOR ownership. Stock STFU flags must survive until a disconnect has also
	/// ended the peer's quiescence; otherwise queued failures would be sent into that session.
	pub(crate) fn release_ffor_receiver_quiescence(&mut self) -> bool {
		if !matches!(self.quiescent_action, Some(QuiescentAction::FFORReceiver(_))) {
			return false;
		}
		self.quiescent_action = None;
		self.context.channel_state.clear_awaiting_quiescence();
		self.context.channel_state.is_local_stfu_sent()
			|| self.context.channel_state.is_remote_stfu_sent()
			|| self.context.channel_state.is_quiescent()
	}

	pub(in crate::ln::channel) fn restore_ffor_receiver_quiescence(
		&mut self,
	) -> Result<(), DecodeError> {
		if let Some(QuiescentAction::FFORReceiver(request)) = self.quiescent_action.as_ref() {
			let book = self.context.ffor_receiver_book.as_ref().ok_or(DecodeError::InvalidValue)?;
			if book.epoch_id != request.epoch_id || book.setup.is_none() {
				return Err(DecodeError::InvalidValue);
			}
			self.release_ffor_receiver_quiescence();
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ser::MaybeReadable;

	#[test]
	fn ffor_quiescence_action_requires_new_reader() {
		enum PreviousAction {
			Splice(SpliceInstructions),
		}
		impl_writeable_tlv_based_enum_upgradable!(PreviousAction,, {1, Splice} => (),);
		let action = QuiescentAction::FFORReceiver(FFORReceiverQuiescence {
			epoch_id: [81; 32],
			monitor: None,
			completed: false,
		});
		let encoded = action.encode();
		assert!(matches!(
			PreviousAction::read(&mut &encoded[..]),
			Err(DecodeError::UnknownRequiredFeature)
		));
	}
}
