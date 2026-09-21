//! Exact receiver activation evidence retained independently of a live channel.
//!
//! These records authenticate a historical transcript, not current channel authority. The
//! manager must install the matching channel fence and registry upgrade atomically, then await
//! persistence before releasing wire. No production activation entry point exists yet.

use alloc::vec::Vec;
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Txid};
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Message, Payload, MAX_MESSAGE_LEN};

use crate::ln::channel::{FFORReceiverSetup, INITIAL_COMMITMENT_NUMBER};
use crate::ln::ffor::{FFORMonitorRecoveryIdentity, FFORMonitorSnapshot, FFORVoucherCommitments};
use crate::ln::msgs::DecodeError;
use crate::util::ser::Writeable;

/// This copy binds the activation transcript to the monitor's identity and recovery destination.
/// The complete persisted ChannelMonitor remains required for signatures and on-chain claims.
#[derive(Clone)]
pub(crate) struct FFORReceiverActivation {
	activate_wire: Vec<u8>,
	ack_wire: Option<Vec<u8>>,
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
});

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
		if let Some(wire) = self.ack_wire.as_ref() {
			let ack = Message::decode(wire).map_err(|_| DecodeError::InvalidValue)?;
			setup.validate_activation_ack(&ack, hash).map_err(|_| DecodeError::InvalidValue)?;
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
		if ack_wire.len() > MAX_MESSAGE_LEN
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

	pub(super) fn validate_monitor(
		&self, setup: &FFORReceiverSetup, monitor: &FFORMonitorRecoveryIdentity,
	) -> Result<(), DecodeError> {
		if monitor.channel_id.0 != setup.validate_recovery()?.header().channel_id
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

	/// The only upgrade preserves every byte except adding the first acknowledgement.
	pub(super) fn can_replace(&self, next: &Self) -> bool {
		if self.encode() == next.encode() {
			return true;
		}
		if self.ack_wire.is_some() || next.ack_wire.is_none() {
			return false;
		}
		let mut without_ack = next.clone();
		without_ack.ack_wire = None;
		self.encode() == without_ack.encode()
	}
}

#[cfg(test)]
mod tests;
