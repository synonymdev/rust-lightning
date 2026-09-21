//! Bounded retained setup evidence, independent of the lifetime of a live channel.
//!
//! This registry proves neither activation nor readiness. The manager must retain it in required
//! TLV 22, under the same consistency lock as channel admission and persistence. Admission uses
//! a borrowed insertion permit so capacity failure cannot leave a channel without its evidence.

mod activation;
pub(crate) use activation::FFORReceiverActivation;

use alloc::vec::Vec;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;

use crate::io;
use crate::ln::channel::{FFORReceiverFencePhase, FFORReceiverSetup};
use crate::ln::ffor::FFORMonitorRecoveryIdentity;
use crate::ln::msgs::DecodeError;
use crate::ln::types::ChannelId;
use crate::util::ser::{FixedLengthReader, Readable, Writeable, Writer};

const SETUP_ONLY_VERSION: u8 = 0;
// Setup-only readers must never silently discard a possibly active epoch's evidence.
const ACTIVATION_VERSION: u8 = 1;
const MAX_RECORDS: usize = 64;
const MAX_ENCODED_BYTES: usize = 8 * 1024 * 1024;
// Two maximum wire messages, a 483-slot canonical book, and fixed admission fields fit here.
const MAX_SETUP_RECORD_BYTES: usize = 192 * 1024;
// Four maximum signed messages, the book, destination script and admission context fit here.
const MAX_RECORD_BYTES: usize = 384 * 1024;
const HEADER_BYTES: usize = 3;
const RECORD_LENGTH_BYTES: usize = 4;
// Includes the maximum acknowledgement plus its vector/TLV framing and growth of the enclosing
// activation and record length prefixes. The fixed outer record prefix does not grow.
const ACK_RESERVATION_BYTES: usize = lightning_ffor::wire::MAX_MESSAGE_LEN + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FFORRecoveryKey {
	pub(crate) channel_id: ChannelId,
	pub(crate) epoch_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FFORRecoveryError {
	InvalidRecord,
	ConflictingRecord,
	CapacityExceeded,
}

struct StoredSetup {
	setup: FFORReceiverSetup,
	canonical_book: Vec<u8>,
	activation: Option<FFORReceiverActivation>,
}

impl_writeable_tlv_based!(StoredSetup, {
	(0, setup, required),
	(2, canonical_book, required_vec),
	(4, activation, option),
});

struct Entry {
	key: FFORRecoveryKey,
	record: StoredSetup,
	encoded_bytes: usize,
}

impl Entry {
	fn new(record: StoredSetup) -> Result<Self, FFORRecoveryError> {
		let authenticated =
			record.setup.validate_recovery().map_err(|_| FFORRecoveryError::InvalidRecord)?;
		if record.canonical_book != authenticated.canonical_book() {
			return Err(FFORRecoveryError::InvalidRecord);
		}
		if let Some(activation) = record.activation.as_ref() {
			activation.validate(&authenticated).map_err(|_| FFORRecoveryError::InvalidRecord)?;
		}
		let header = authenticated.header();
		let encoded_bytes = record.serialized_length();
		let reserved_ack_bytes = Self::ack_reservation(&record);
		if encoded_bytes.saturating_add(reserved_ack_bytes) > MAX_RECORD_BYTES
			|| (record.activation.is_none() && encoded_bytes > MAX_SETUP_RECORD_BYTES)
		{
			return Err(FFORRecoveryError::CapacityExceeded);
		}
		Ok(Self {
			key: FFORRecoveryKey {
				channel_id: ChannelId(header.channel_id),
				epoch_id: header.epoch_id,
			},
			record,
			encoded_bytes,
		})
	}

	fn has_same_identity(&self, other: &Self) -> bool {
		self.key.channel_id == other.key.channel_id
			|| (self.record.setup.chain_hash() == other.record.setup.chain_hash()
				&& self.record.setup.funding_txo() == other.record.setup.funding_txo())
	}

	fn ack_reservation(record: &StoredSetup) -> usize {
		if record.activation.as_ref().map_or(false, |activation| !activation.is_active()) {
			ACK_RESERVATION_BYTES
		} else {
			0
		}
	}

	fn reserved_ack_bytes(&self) -> usize {
		Self::ack_reservation(&self.record)
	}
}

pub(crate) struct FFORRecoveryRegistry {
	entries: Vec<Entry>,
	encoded_bytes: usize,
	// Derived from authenticated phases, never serialized or supplied by a caller.
	reserved_ack_bytes: usize,
}

/// Exclusive capacity reservation. Dropping it changes nothing; commit cannot fail.
pub(crate) struct FFORRecoveryInsertion<'a> {
	registry: &'a mut FFORRecoveryRegistry,
	entry: Option<Entry>,
}

impl FFORRecoveryInsertion<'_> {
	pub(crate) fn commit(self) {
		if let Some(entry) = self.entry {
			self.registry.encoded_bytes += RECORD_LENGTH_BYTES + entry.encoded_bytes;
			self.registry.reserved_ack_bytes += entry.reserved_ack_bytes();
			self.registry.entries.push(entry);
		}
	}
}

/// An exact monotonic replacement with byte capacity reserved before channel mutation.
pub(crate) struct FFORRecoveryUpgrade<'a> {
	registry: &'a mut FFORRecoveryRegistry,
	index: usize,
	entry: Entry,
	total_bytes: usize,
	reserved_ack_bytes: usize,
}

impl FFORRecoveryUpgrade<'_> {
	pub(crate) fn commit(self) {
		self.registry.entries[self.index] = self.entry;
		self.registry.encoded_bytes = self.total_bytes;
		self.registry.reserved_ack_bytes = self.reserved_ack_bytes;
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn new() -> Self {
		Self { entries: Vec::new(), encoded_bytes: HEADER_BYTES, reserved_ack_bytes: 0 }
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	pub(crate) fn get(&self, key: &FFORRecoveryKey) -> Option<&FFORReceiverSetup> {
		self.entries.iter().find(|entry| entry.key == *key).map(|entry| &entry.record.setup)
	}

	pub(crate) fn get_activation(&self, key: &FFORRecoveryKey) -> Option<&FFORReceiverActivation> {
		self.entries
			.iter()
			.find(|entry| entry.key == *key)
			.and_then(|entry| entry.record.activation.as_ref())
	}

	pub(crate) fn contains_exact(&self, record: &FFORReceiverSetup) -> bool {
		let authenticated = match record.validate_recovery() {
			Ok(authenticated) => authenticated,
			Err(_) => return false,
		};
		let header = authenticated.header();
		let key =
			FFORRecoveryKey { channel_id: ChannelId(header.channel_id), epoch_id: header.epoch_id };
		self.get(&key).map_or(false, |stored| stored.encode() == record.encode())
	}

	/// Check every serialized live channel before it can be removed as stale during restore.
	/// Neither a missing fence nor a missing acknowledgement may downgrade archived evidence.
	pub(crate) fn validate_channel_fence(
		&self, setup: &FFORReceiverSetup, fence: Option<(FFORReceiverFencePhase, [u8; 32])>,
	) -> Result<(), DecodeError> {
		if !self.contains_exact(setup) {
			return Err(DecodeError::InvalidValue);
		}
		let authenticated = setup.validate_recovery()?;
		let header = authenticated.header();
		let key =
			FFORRecoveryKey { channel_id: ChannelId(header.channel_id), epoch_id: header.epoch_id };
		match (self.get_activation(&key), fence) {
			(None, None) => Ok(()),
			(Some(record), Some((phase, hash)))
				if record.validate(&authenticated)? == hash
					&& record.is_active() == (phase == FFORReceiverFencePhase::Active) =>
			{
				Ok(())
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}

	/// A possibly active epoch requires its original persisted monitor even without a live channel.
	pub(crate) fn activation_channels(&self) -> Vec<ChannelId> {
		self.entries
			.iter()
			.filter(|entry| entry.record.activation.is_some())
			.map(|entry| entry.key.channel_id)
			.collect()
	}

	pub(crate) fn validate_activation_monitor(
		&self, channel_id: ChannelId, monitor: &FFORMonitorRecoveryIdentity,
	) -> Result<(), DecodeError> {
		let entry = self
			.entries
			.iter()
			.find(|entry| entry.key.channel_id == channel_id)
			.ok_or(DecodeError::InvalidValue)?;
		let activation = entry.record.activation.as_ref().ok_or(DecodeError::InvalidValue)?;
		activation.validate_monitor(&entry.record.setup, monitor)
	}

	/// Must be checked against the actual restoring manager, including archive-only snapshots.
	pub(crate) fn validate_identity(
		&self, receiver: PublicKey, chain_hash: ChainHash,
	) -> Result<(), DecodeError> {
		if self.entries.iter().any(|entry| {
			entry.record.setup.receiver() != receiver
				|| entry.record.setup.chain_hash() != chain_hash
		}) {
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}

	/// Reauthenticate and reserve storage before changing the channel. Retain this permit while
	/// installing the identical prepared setup under the peer lock, then commit it on success.
	/// Exact retries are idempotent; the current format permits only one setup per channel/funding.
	pub(crate) fn prepare_insert(
		&mut self, setup: &FFORReceiverSetup,
	) -> Result<FFORRecoveryInsertion<'_>, FFORRecoveryError> {
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORRecoveryError::InvalidRecord)?;
		let entry = Entry::new(StoredSetup {
			setup: setup.clone(),
			canonical_book: authenticated.canonical_book().to_vec(),
			activation: None,
		})?;
		if let Some(existing) =
			self.entries.iter().find(|existing| existing.has_same_identity(&entry))
		{
			if existing.key != entry.key || existing.record.encode() != entry.record.encode() {
				return Err(FFORRecoveryError::ConflictingRecord);
			}
			return Ok(FFORRecoveryInsertion { registry: self, entry: None });
		}
		self.check_capacity(entry.encoded_bytes, entry.reserved_ack_bytes())?;
		Ok(FFORRecoveryInsertion { registry: self, entry: Some(entry) })
	}

	/// Upgrade an existing identical setup to ACTIVATING, then add only its exact signed ack.
	/// The caller must install the corresponding native fence while retaining this permit.
	/// ACTIVATING reserves capacity for a maximum acknowledgement until its exact bytes arrive.
	pub(crate) fn prepare_activation(
		&mut self, setup: &FFORReceiverSetup, activation: &FFORReceiverActivation,
	) -> Result<FFORRecoveryUpgrade<'_>, FFORRecoveryError> {
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORRecoveryError::InvalidRecord)?;
		let entry = Entry::new(StoredSetup {
			setup: setup.clone(),
			canonical_book: authenticated.canonical_book().to_vec(),
			activation: Some(activation.clone()),
		})?;
		let index = self
			.entries
			.iter()
			.position(|stored| stored.key == entry.key)
			.ok_or(FFORRecoveryError::ConflictingRecord)?;
		let existing = &self.entries[index];
		if existing.record.setup.encode() != setup.encode()
			|| match existing.record.activation.as_ref() {
				Some(previous) => !previous.can_replace(activation),
				None => activation.is_active(),
			} {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		let total_bytes = self
			.encoded_bytes
			.checked_sub(existing.encoded_bytes)
			.and_then(|bytes| bytes.checked_add(entry.encoded_bytes))
			.ok_or(FFORRecoveryError::CapacityExceeded)?;
		let reserved_ack_bytes = self
			.reserved_ack_bytes
			.checked_sub(existing.reserved_ack_bytes())
			.and_then(|bytes| bytes.checked_add(entry.reserved_ack_bytes()))
			.ok_or(FFORRecoveryError::CapacityExceeded)?;
		if total_bytes
			.checked_add(reserved_ack_bytes)
			.map_or(true, |bytes| bytes > MAX_ENCODED_BYTES)
		{
			return Err(FFORRecoveryError::CapacityExceeded);
		}
		Ok(FFORRecoveryUpgrade { registry: self, index, entry, total_bytes, reserved_ack_bytes })
	}

	fn version(&self) -> u8 {
		if self.entries.iter().any(|entry| entry.record.activation.is_some()) {
			ACTIVATION_VERSION
		} else {
			SETUP_ONLY_VERSION
		}
	}

	fn check_capacity(
		&self, record_bytes: usize, reserved_ack_bytes: usize,
	) -> Result<(), FFORRecoveryError> {
		let total = self
			.encoded_bytes
			.checked_add(RECORD_LENGTH_BYTES)
			.and_then(|total| total.checked_add(record_bytes))
			.and_then(|total| total.checked_add(self.reserved_ack_bytes))
			.and_then(|total| total.checked_add(reserved_ack_bytes));
		if self.entries.len() >= MAX_RECORDS
			|| record_bytes > MAX_RECORD_BYTES
			|| total.map_or(true, |total| total > MAX_ENCODED_BYTES)
		{
			return Err(FFORRecoveryError::CapacityExceeded);
		}
		Ok(())
	}
}

impl Writeable for FFORRecoveryRegistry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.version().write(writer)?;
		(self.entries.len() as u16).write(writer)?;
		for entry in &self.entries {
			(entry.encoded_bytes as u32).write(writer)?;
			entry.record.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for FFORRecoveryRegistry {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let version = u8::read(reader)?;
		if version != SETUP_ONLY_VERSION && version != ACTIVATION_VERSION {
			return Err(DecodeError::UnknownRequiredFeature);
		}
		let count = u16::read(reader)? as usize;
		if count > MAX_RECORDS {
			return Err(DecodeError::InvalidValue);
		}
		let mut registry = Self::new();
		for _ in 0..count {
			let length = u32::read(reader)? as usize;
			if version == SETUP_ONLY_VERSION && length > MAX_SETUP_RECORD_BYTES {
				return Err(DecodeError::InvalidValue);
			}
			registry.check_capacity(length, 0).map_err(|_| DecodeError::InvalidValue)?;
			let mut bounded = FixedLengthReader::new(reader, length as u64);
			let record = StoredSetup::read(&mut bounded)?;
			if bounded.bytes_remain() {
				return Err(DecodeError::InvalidValue);
			}
			let entry = Entry::new(record).map_err(|_| DecodeError::InvalidValue)?;
			// Reject ignored storage extensions and alternate framing as well as duplicate keys.
			// Exact signed optional wire extensions remain inside the retained message bytes.
			if entry.encoded_bytes != length
				|| registry.entries.iter().any(|existing| existing.has_same_identity(&entry))
			{
				return Err(DecodeError::InvalidValue);
			}
			registry
				.check_capacity(length, entry.reserved_ack_bytes())
				.map_err(|_| DecodeError::InvalidValue)?;
			registry.encoded_bytes += RECORD_LENGTH_BYTES + length;
			registry.reserved_ack_bytes += entry.reserved_ack_bytes();
			registry.entries.push(entry);
		}
		if registry.version() != version {
			return Err(DecodeError::InvalidValue);
		}
		Ok(registry)
	}
}

#[cfg(test)]
pub(crate) mod tests;
