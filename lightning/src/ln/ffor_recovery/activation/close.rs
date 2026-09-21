//! Exact cooperative close evidence. Channel authority and durability remain with the manager.

use super::*;
use crate::chain::transaction::OutPoint;
use crate::ln::channel::{ffor_drain_completion_digest, FFORReceiverDrainCompletion};
use crate::ln::types::ChannelId;
use crate::types::payment::PaymentPreimage;
use bitcoin::hashes::sha256;

/// Immutable signed close intent and its first exact authenticated settlement response.
/// A record alone never permits a voucher removal or establishes that a monitor is durable.
#[derive(Clone)]
pub(crate) struct FFORReceiverCloseRecord {
	close_wire: Vec<u8>,
	ack_wire: Option<Vec<u8>>,
	closed: Option<ClosedDrain>,
}

impl_writeable_tlv_based!(FFORReceiverCloseRecord, {
	(0, close_wire, required_vec),
	(2, ack_wire, option),
	(4, closed, option),
});

/// Retained historical result of the engine's opaque, fully synchronized drain proof.
#[derive(Clone)]
struct ClosedDrain {
	completion_hash: [u8; 32],
	receiver_number: u64,
	receiver_txid: Txid,
	settlement_number: u64,
	settlement_txid: Txid,
	monitor_update_id: u64,
	funding_txo: OutPoint,
}

impl_writeable_tlv_based!(ClosedDrain, {
	(0, completion_hash, required),
	(2, receiver_number, required),
	(4, receiver_txid, required),
	(6, settlement_number, required),
	(8, settlement_txid, required),
	(10, monitor_update_id, required),
	(12, funding_txo, required),
});

impl FFORReceiverCloseRecord {
	fn new(setup: &FFORReceiverSetup, hash: [u8; 32], wire: &[u8]) -> Result<Self, DecodeError> {
		if wire.len() > MAX_MESSAGE_LEN {
			return Err(DecodeError::InvalidValue);
		}
		let record = Self { close_wire: wire.to_vec(), ack_wire: None, closed: None };
		record.validate(setup, hash)?;
		Ok(record)
	}

	/// Authenticate both retained messages against the actual setup and activation digest.
	pub(crate) fn validate(
		&self, setup: &FFORReceiverSetup, hash: [u8; 32],
	) -> Result<(), DecodeError> {
		if self.close_wire.len() > MAX_MESSAGE_LEN
			|| self.ack_wire.as_ref().map_or(false, |wire| wire.len() > MAX_MESSAGE_LEN)
		{
			return Err(DecodeError::InvalidValue);
		}
		if self.closed.as_ref().map_or(false, |closed| closed.funding_txo != setup.funding_txo()) {
			return Err(DecodeError::InvalidValue);
		}
		self.validate_authenticated(&setup.validate_recovery()?, hash)
	}

	pub(super) fn validate_authenticated(
		&self, setup: &AuthenticatedSetup, hash: [u8; 32],
	) -> Result<(), DecodeError> {
		if self.close_wire.len() > MAX_MESSAGE_LEN
			|| self.ack_wire.as_ref().map_or(false, |wire| wire.len() > MAX_MESSAGE_LEN)
			|| (self.closed.is_some() && self.ack_wire.is_none())
		{
			return Err(DecodeError::InvalidValue);
		}
		let close = Message::decode(&self.close_wire).map_err(|_| DecodeError::InvalidValue)?;
		setup.validate_close(&close, hash).map_err(|_| DecodeError::InvalidValue)?;
		if let Some(bytes) = &self.ack_wire {
			let ack = Message::decode(bytes).map_err(|_| DecodeError::InvalidValue)?;
			setup.validate_close_ack(&ack, hash).map_err(|_| DecodeError::InvalidValue)?;
		}
		if let Some(closed) = &self.closed {
			let header = setup.header();
			let commitments = FFORVoucherCommitments {
				holder: FFORCommitment {
					number: closed.receiver_number,
					txid: closed.receiver_txid,
				},
				counterparty: FFORCommitment {
					number: closed.settlement_number,
					txid: closed.settlement_txid,
				},
			};
			let digest = ffor_drain_completion_digest(
				header.epoch_id,
				hash,
				self.acknowledgement_hash().ok_or(DecodeError::InvalidValue)?,
				ChannelId(header.channel_id),
				closed.funding_txo,
				commitments,
				closed.monitor_update_id,
			);
			if digest != closed.completion_hash {
				return Err(DecodeError::InvalidValue);
			}
			if closed.receiver_number == 0
				|| closed.receiver_number > INITIAL_COMMITMENT_NUMBER
				|| closed.settlement_number == 0
				|| closed.settlement_number > INITIAL_COMMITMENT_NUMBER
				|| closed.monitor_update_id == 0
				|| closed.monitor_update_id == u64::MAX
			{
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(())
	}

	fn with_ack(
		&self, setup: &FFORReceiverSetup, hash: [u8; 32], wire: &[u8],
	) -> Result<Self, DecodeError> {
		if wire.len() > MAX_MESSAGE_LEN || self.ack_wire.as_ref().map_or(false, |old| old != wire) {
			return Err(DecodeError::InvalidValue);
		}
		let mut next = self.clone();
		next.ack_wire = Some(wire.to_vec());
		next.validate(setup, hash)?;
		Ok(next)
	}

	pub(crate) fn close_wire(&self) -> &[u8] {
		&self.close_wire
	}

	pub(crate) fn acknowledgement_wire(&self) -> Option<&[u8]> {
		self.ack_wire.as_deref()
	}

	pub(crate) fn acknowledgement_hash(&self) -> Option<[u8; 32]> {
		self.ack_wire.as_ref().map(|wire| sha256::Hash::hash(wire).to_byte_array())
	}

	pub(crate) fn is_closed(&self) -> bool {
		self.closed.is_some()
	}

	pub(crate) fn completion_hash(&self) -> Option<[u8; 32]> {
		self.closed.as_ref().map(|closed| closed.completion_hash)
	}

	/// Returns the signed bitmap only after the caller has authenticated this immutable record.
	pub(crate) fn settled(&self) -> Result<Vec<u8>, DecodeError> {
		match self.ack_payload()? {
			Payload::CloseAck(ack) => Ok(ack.settled),
			_ => Err(DecodeError::InvalidValue),
		}
	}

	/// Every returned preimage still requires stock monitor persistence before claim wire.
	pub(crate) fn preimages(&self) -> Result<Vec<(u16, PaymentPreimage)>, DecodeError> {
		match self.ack_payload()? {
			Payload::CloseAck(ack) => {
				Ok(ack.preimages.into_iter().map(|p| (p.slot, PaymentPreimage(p.value))).collect())
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}

	fn ack_payload(&self) -> Result<Payload, DecodeError> {
		let wire = self.ack_wire.as_ref().ok_or(DecodeError::InvalidValue)?;
		Ok(Message::decode(wire).map_err(|_| DecodeError::InvalidValue)?.payload)
	}

	pub(super) fn validate_closed_after(
		&self, receiver: u64, settlement: u64, update: u64,
	) -> Result<(), DecodeError> {
		if self.closed.as_ref().map_or(false, |closed| {
			closed.receiver_number <= receiver
				|| closed.settlement_number <= settlement
				|| closed.monitor_update_id <= update
		}) {
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}

	pub(super) fn can_replace(&self, next: &Self) -> bool {
		self.close_wire == next.close_wire
			&& self.ack_wire.as_ref().map_or(true, |old| next.ack_wire.as_ref() == Some(old))
			&& !(self.ack_wire.is_none() && next.closed.is_some())
			&& self.closed.as_ref().map_or(true, |old| {
				next.closed.as_ref().map(|new| new.encode()) == Some(old.encode())
			})
	}
}

impl FFORReceiverActivation {
	/// Retain close intent only after signed activation. An exact retry never replaces bytes.
	pub(crate) fn with_close(
		&self, setup: &FFORReceiverSetup, wire: &[u8],
	) -> Result<Self, DecodeError> {
		if !self.is_active() || self.is_aborted() {
			return Err(DecodeError::InvalidValue);
		}
		let hash = self.activation_hash(setup)?;
		if let Some(existing) = &self.close {
			return if existing.close_wire == wire {
				Ok(self.clone())
			} else {
				Err(DecodeError::InvalidValue)
			};
		}
		let mut next = self.clone();
		next.close = Some(FFORReceiverCloseRecord::new(setup, hash, wire)?);
		Ok(next)
	}

	pub(crate) fn with_close_ack(
		&self, setup: &FFORReceiverSetup, wire: &[u8],
	) -> Result<Self, DecodeError> {
		let close = self.close.as_ref().ok_or(DecodeError::InvalidValue)?;
		let hash = self.activation_hash(setup)?;
		let mut next = self.clone();
		next.close = Some(close.with_ack(setup, hash, wire)?);
		Ok(next)
	}

	pub(crate) fn close_record(&self) -> Option<&FFORReceiverCloseRecord> {
		self.close.as_ref()
	}

	pub(crate) fn is_draining(&self) -> bool {
		self.close.as_ref().map_or(false, |close| close.ack_wire.is_some())
	}

	pub(crate) fn is_closed(&self) -> bool {
		self.close.as_ref().map_or(false, |close| close.is_closed())
	}

	/// Only the channel can construct completion proof, after comparing its empty commitment
	/// pair with a fresh persisted monitor snapshot. The manager must retain both mutations.
	pub(crate) fn with_closed(
		&self, setup: &FFORReceiverSetup, completion: &FFORReceiverDrainCompletion,
	) -> Result<Self, DecodeError> {
		let hash = self.activation_hash(setup)?;
		let close = self.close.as_ref().ok_or(DecodeError::InvalidValue)?;
		let (channel_id, funding_txo, monitor_update_id) = completion.monitor_identity();
		let commitments = completion.commitments();
		let header = setup.validate_recovery()?.header();
		if completion.epoch_id() != header.epoch_id
			|| completion.activation_hash() != hash
			|| Some(completion.acknowledgement_hash()) != close.acknowledgement_hash()
			|| channel_id.0 != header.channel_id
			|| funding_txo != setup.funding_txo()
			|| commitments.holder.number <= self.receiver_number
			|| commitments.counterparty.number <= self.settlement_number
			|| monitor_update_id <= self.monitor_update_id
		{
			return Err(DecodeError::InvalidValue);
		}
		let mut next = self.clone();
		let closed = ClosedDrain {
			completion_hash: completion.completion_hash(),
			receiver_number: commitments.holder.number,
			receiver_txid: commitments.holder.txid,
			settlement_number: commitments.counterparty.number,
			settlement_txid: commitments.counterparty.txid,
			monitor_update_id,
			funding_txo,
		};
		if close.closed.as_ref().map_or(false, |old| old.encode() != closed.encode()) {
			return Err(DecodeError::InvalidValue);
		}
		next.close.as_mut().unwrap().closed = Some(closed);
		next.validate(&setup.validate_recovery()?)?;
		Ok(next)
	}
}
