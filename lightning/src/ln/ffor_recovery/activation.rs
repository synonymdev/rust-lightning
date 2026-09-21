//! Exact receiver activation evidence retained independently of a live channel.
//!
//! These records authenticate a historical transcript, not current channel authority. The
//! manager must install the matching channel fence and registry upgrade atomically, then await
//! persistence before releasing wire. No production activation entry point exists yet.

mod close;
pub(crate) use close::FFORReceiverCloseRecord;

use alloc::vec::Vec;
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Txid};
use lightning_ffor::reestablish::{Reestablish, ReportedState};
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Message, Payload, MAX_MESSAGE_LEN};

use crate::ln::channel::{FFORReceiverSetup, INITIAL_COMMITMENT_NUMBER};
use crate::ln::ffor::{
	FFORCommitment, FFORMonitorRecoveryIdentity, FFORMonitorSnapshot, FFORReceiverAbortReason,
	FFORVoucherCommitments,
};
use crate::ln::msgs::DecodeError;
use crate::util::ser::Writeable;

/// This copy binds the activation transcript to the monitor's identity and recovery destination.
/// The complete persisted ChannelMonitor remains required for signatures and on-chain claims.
#[derive(Clone)]
pub(crate) struct FFORReceiverActivation {
	activate_wire: Vec<u8>,
	ack_wire: Option<Vec<u8>>,
	abort: Option<AbortedActivation>,
	close: Option<FFORReceiverCloseRecord>,
	receiver_number: u64,
	receiver_txid: Txid,
	settlement_number: u64,
	settlement_txid: Txid,
	monitor_update_id: u64,
	preparation_height: u32,
	destination_script: ScriptBuf,
}

impl_writeable_tlv_based!(FFORReceiverActivation, {
	(0, activate_wire, required_vec),
	(2, ack_wire, option),
	(4, receiver_number, required),
	(6, receiver_txid, required),
	(8, settlement_number, required),
	(10, settlement_txid, required),
	(12, monitor_update_id, required),
	(14, preparation_height, required),
	(16, destination_script, required),
	(18, abort, option),
	(20, close, option),
});

/// A manager-observed reconnect outcome, not a signed statement from the peer. The transition
/// owner must authenticate the connection before constructing this terminal consistency record.
#[derive(Clone)]
struct AbortedActivation {
	reason: FFORReceiverAbortReason,
	peer_report: Option<Vec<u8>>,
}

impl_writeable_tlv_based!(AbortedActivation, {
	(0, reason, required),
	(2, peer_report, option),
});

impl AbortedActivation {
	fn validate(&self) -> Result<(), DecodeError> {
		if self.reason != FFORReceiverAbortReason::Disconnected {
			return Err(DecodeError::InvalidValue);
		}
		if let Some(bytes) = self.peer_report.as_ref() {
			let report = Reestablish::decode(bytes).map_err(|_| DecodeError::InvalidValue)?;
			if matches!(
				report.state,
				ReportedState::Active | ReportedState::Draining | ReportedState::Closed
			) {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(())
	}
}

impl FFORReceiverActivation {
	/// Called only after the channel rechecks both commitment views under owned quiescence.
	/// The opaque monitor supplies its original destination; callers cannot substitute a script.
	/// This does not prove that the manager write or monitor persistence has completed.
	pub(crate) fn prepare(
		setup: &FFORReceiverSetup, activate_wire: &[u8], commitments: FFORVoucherCommitments,
		monitor: &FFORMonitorSnapshot, current_height: u32,
	) -> Result<Self, DecodeError> {
		let authenticated = setup.validate_recovery()?;
		if monitor.channel_id.0 != authenticated.header().channel_id
			|| monitor.funding_txo != setup.funding_txo()
			|| INITIAL_COMMITMENT_NUMBER.checked_sub(monitor.holder_number)
				!= Some(commitments.holder.number)
			|| INITIAL_COMMITMENT_NUMBER.checked_sub(monitor.counterparty_number)
				!= Some(commitments.counterparty.number)
			|| monitor.holder.trust().txid() != commitments.holder.txid
			|| monitor.counterparty_txid != commitments.counterparty.txid
			|| activate_wire.len() > MAX_MESSAGE_LEN
		{
			return Err(DecodeError::InvalidValue);
		}
		let record = Self {
			activate_wire: activate_wire.to_vec(),
			ack_wire: None,
			abort: None,
			close: None,
			receiver_number: commitments.holder.number,
			receiver_txid: commitments.holder.txid,
			settlement_number: commitments.counterparty.number,
			settlement_txid: commitments.counterparty.txid,
			monitor_update_id: monitor.update_id,
			preparation_height: current_height,
			destination_script: monitor.destination_script.clone(),
		};
		record.validate(&authenticated)?;
		Ok(record)
	}

	/// Reauthenticate historical bytes against the archived setup. Live height checks belong to
	/// the current transition; replaying persisted evidence must not expire its recovery record.
	pub(super) fn validate(&self, setup: &AuthenticatedSetup) -> Result<[u8; 32], DecodeError> {
		let starting_settlement_number = match &setup.accept().payload {
			Payload::Accept(accept) => accept.s_commitment_number,
			_ => return Err(DecodeError::InvalidValue),
		};
		if self.activate_wire.len() > MAX_MESSAGE_LEN
			|| self.ack_wire.as_ref().map_or(false, |wire| wire.len() > MAX_MESSAGE_LEN)
			|| self.receiver_number == 0
			|| self.receiver_number > INITIAL_COMMITMENT_NUMBER
			|| self.settlement_number <= starting_settlement_number
			|| self.settlement_number > INITIAL_COMMITMENT_NUMBER
			|| self.monitor_update_id == 0
			|| self.monitor_update_id == u64::MAX
			|| self.destination_script.is_empty()
			|| self.destination_script.len() > 10_000
		{
			return Err(DecodeError::InvalidValue);
		}
		let activate =
			Message::decode(&self.activate_wire).map_err(|_| DecodeError::InvalidValue)?;
		if !matches!(&activate.payload, Payload::Activate(message)
			if message.epoch_start_height == self.preparation_height)
		{
			return Err(DecodeError::InvalidValue);
		}
		let hash = setup
			.validate_activation(&activate, self.commitment_hash(), self.preparation_height)
			.map_err(|_| DecodeError::InvalidValue)?;
		if self.close.is_some() && (self.ack_wire.is_none() || self.abort.is_some()) {
			return Err(DecodeError::InvalidValue);
		}
		if let Some(abort) = self.abort.as_ref() {
			if self.ack_wire.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			abort.validate()?;
		}
		if let Some(wire) = self.ack_wire.as_ref() {
			let ack = Message::decode(wire).map_err(|_| DecodeError::InvalidValue)?;
			setup.validate_activation_ack(&ack, hash).map_err(|_| DecodeError::InvalidValue)?;
		}
		if let Some(close) = &self.close {
			close.validate_authenticated(setup, hash)?;
			close.validate_closed_after(
				self.receiver_number,
				self.settlement_number,
				self.monitor_update_id,
			)?;
		}
		Ok(hash)
	}

	pub(crate) fn commitment_hash(&self) -> [u8; 32] {
		transcript::commitment_hash(
			self.receiver_number,
			&self.receiver_txid.to_byte_array(),
			self.settlement_number,
			&self.settlement_txid.to_byte_array(),
		)
	}

	/// Preserve the exact activation and accept only the first authentic acknowledgement.
	/// Exact replay is idempotent; a different signed encoding cannot replace retained evidence.
	pub(crate) fn with_ack(
		&self, setup: &FFORReceiverSetup, ack_wire: &[u8],
	) -> Result<Self, DecodeError> {
		if self.abort.is_some()
			|| ack_wire.len() > MAX_MESSAGE_LEN
			|| self.ack_wire.as_ref().map_or(false, |existing| existing != ack_wire)
		{
			return Err(DecodeError::InvalidValue);
		}
		let mut record = self.clone();
		record.ack_wire = Some(ack_wire.to_vec());
		record.validate(&setup.validate_recovery()?)?;
		Ok(record)
	}

	pub(crate) fn is_active(&self) -> bool {
		self.ack_wire.is_some()
	}

	/// Permanently retain a pre-active abort observed on an authenticated reconnect. Absence of
	/// an epoch or a pre-active/aborted peer report permits this outcome; an active or later report
	/// leaves the obligation unresolved even if its epoch or hash differs. The report itself is
	/// unsigned and cannot establish that the caller actually observed that connection.
	pub(crate) fn abort_after_reestablish(
		&self, setup: &FFORReceiverSetup, peer_report: Option<Reestablish>,
	) -> Result<Self, DecodeError> {
		if self.ack_wire.is_some() {
			return Err(DecodeError::InvalidValue);
		}
		let abort = AbortedActivation {
			reason: FFORReceiverAbortReason::Disconnected,
			peer_report: peer_report.map(|report| report.encode().to_vec()),
		};
		abort.validate()?;
		if self.abort.as_ref().map_or(false, |previous| previous.encode() != abort.encode()) {
			return Err(DecodeError::InvalidValue);
		}
		let mut record = self.clone();
		record.abort = Some(abort);
		record.validate(&setup.validate_recovery()?)?;
		Ok(record)
	}

	pub(crate) fn aborted_reason(&self) -> Option<FFORReceiverAbortReason> {
		self.abort.as_ref().map(|abort| abort.reason)
	}

	pub(crate) fn is_aborted(&self) -> bool {
		self.abort.is_some()
	}

	pub(crate) fn matches_abort_report(&self, peer_report: Option<Reestablish>) -> bool {
		self.abort.as_ref().map_or(false, |abort| {
			abort.peer_report == peer_report.map(|report| report.encode().to_vec())
		})
	}

	pub(crate) fn activation_hash(
		&self, setup: &FFORReceiverSetup,
	) -> Result<[u8; 32], DecodeError> {
		self.validate(&setup.validate_recovery()?)
	}

	pub(crate) fn activate_wire(&self) -> &[u8] {
		&self.activate_wire
	}

	pub(crate) fn ack_wire(&self) -> Option<&[u8]> {
		self.ack_wire.as_deref()
	}

	pub(crate) fn commitments(&self) -> FFORVoucherCommitments {
		FFORVoucherCommitments {
			holder: FFORCommitment { number: self.receiver_number, txid: self.receiver_txid },
			counterparty: FFORCommitment {
				number: self.settlement_number,
				txid: self.settlement_txid,
			},
		}
	}

	pub(super) fn validate_monitor(
		&self, setup: &FFORReceiverSetup, monitor: &FFORMonitorRecoveryIdentity,
	) -> Result<(), DecodeError> {
		if self.is_draining() && !self.is_closed() {
			if monitor.channel_id.0 != setup.validate_recovery()?.header().channel_id
				|| monitor.funding_txo != setup.funding_txo()
				|| monitor.update_id < self.monitor_update_id
				|| monitor.destination_script != self.destination_script
				|| monitor.counterparty_txid.is_none()
				|| INITIAL_COMMITMENT_NUMBER
					.checked_sub(monitor.holder_number)
					.map_or(true, |number| number < self.receiver_number)
				|| INITIAL_COMMITMENT_NUMBER
					.checked_sub(monitor.counterparty_number)
					.map_or(true, |number| number < self.settlement_number)
			{
				return Err(DecodeError::InvalidValue);
			}
			return Ok(());
		}
		if self.abort.is_some()
			|| self.is_closed()
			|| monitor.channel_id.0 != setup.validate_recovery()?.header().channel_id
			|| monitor.funding_txo != setup.funding_txo()
			|| monitor.update_id < self.monitor_update_id
			|| INITIAL_COMMITMENT_NUMBER.checked_sub(monitor.holder_number)
				!= Some(self.receiver_number)
			|| INITIAL_COMMITMENT_NUMBER.checked_sub(monitor.counterparty_number)
				!= Some(self.settlement_number)
			|| monitor.holder_txid != self.receiver_txid
			|| monitor.counterparty_txid != Some(self.settlement_txid)
			|| monitor.destination_script != self.destination_script
		{
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}

	/// Every retained transcript byte is immutable. Only the next lifecycle evidence may be added.
	pub(super) fn can_replace(&self, next: &Self) -> bool {
		if self.encode() == next.encode() {
			return true;
		}
		if self.abort.is_some() {
			return false;
		}
		if self.ack_wire.is_none() && next.close.is_some() {
			return false;
		}
		if self.close.is_none() && next.is_draining() {
			return false;
		}
		if self.ack_wire.as_ref().map_or(false, |old| next.ack_wire.as_ref() != Some(old)) {
			return false;
		}
		if let Some(close) = &self.close {
			if !next.close.as_ref().map_or(false, |new| close.can_replace(new)) {
				return false;
			}
		}
		let mut before = self.clone();
		let mut after = next.clone();
		before.ack_wire = None;
		before.abort = None;
		before.close = None;
		after.ack_wire = None;
		after.abort = None;
		after.close = None;
		before.encode() == after.encode()
	}
}

#[cfg(test)]
mod tests;
