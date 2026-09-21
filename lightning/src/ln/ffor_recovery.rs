//! Bounded retained setup evidence, independent of the lifetime of a live channel.
//!
//! This registry proves neither activation nor readiness. The manager must retain it in required
//! TLV 22, under the same consistency lock as channel admission and persistence. Admission uses
//! a borrowed insertion permit so capacity failure cannot leave a channel without its evidence.

use alloc::vec::Vec;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;

use crate::io;
use crate::ln::channel::FFORReceiverSetup;
use crate::ln::msgs::DecodeError;
use crate::ln::types::ChannelId;
use crate::util::ser::{FixedLengthReader, Readable, Writeable, Writer};

// A later format containing activation evidence must use a different required version. A
// setup-only reader must never silently discard evidence for a channel that may be active.
const SETUP_ONLY_VERSION: u8 = 0;
const MAX_RECORDS: usize = 64;
const MAX_ENCODED_BYTES: usize = 8 * 1024 * 1024;
// Two maximum wire messages, a 483-slot canonical book, and fixed admission fields fit here.
const MAX_RECORD_BYTES: usize = 192 * 1024;
const HEADER_BYTES: usize = 3;
const RECORD_LENGTH_BYTES: usize = 4;

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
}

impl_writeable_tlv_based!(StoredSetup, {
	(0, setup, required),
	(2, canonical_book, required_vec),
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
		let header = authenticated.header();
		let encoded_bytes = record.serialized_length();
		if encoded_bytes > MAX_RECORD_BYTES {
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
}

pub(crate) struct FFORRecoveryRegistry {
	entries: Vec<Entry>,
	encoded_bytes: usize,
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
			self.registry.entries.push(entry);
		}
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn new() -> Self {
		Self { entries: Vec::new(), encoded_bytes: HEADER_BYTES }
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	pub(crate) fn get(&self, key: &FFORRecoveryKey) -> Option<&FFORReceiverSetup> {
		self.entries.iter().find(|entry| entry.key == *key).map(|entry| &entry.record.setup)
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
		})?;
		if let Some(existing) =
			self.entries.iter().find(|existing| existing.has_same_identity(&entry))
		{
			if existing.key != entry.key || existing.record.encode() != entry.record.encode() {
				return Err(FFORRecoveryError::ConflictingRecord);
			}
			return Ok(FFORRecoveryInsertion { registry: self, entry: None });
		}
		self.check_capacity(entry.encoded_bytes)?;
		Ok(FFORRecoveryInsertion { registry: self, entry: Some(entry) })
	}

	fn check_capacity(&self, record_bytes: usize) -> Result<(), FFORRecoveryError> {
		let total = self
			.encoded_bytes
			.checked_add(RECORD_LENGTH_BYTES)
			.and_then(|total| total.checked_add(record_bytes));
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
		SETUP_ONLY_VERSION.write(writer)?;
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
		if u8::read(reader)? != SETUP_ONLY_VERSION {
			return Err(DecodeError::UnknownRequiredFeature);
		}
		let count = u16::read(reader)? as usize;
		if count > MAX_RECORDS {
			return Err(DecodeError::InvalidValue);
		}
		let mut registry = Self::new();
		for _ in 0..count {
			let length = u32::read(reader)? as usize;
			registry.check_capacity(length).map_err(|_| DecodeError::InvalidValue)?;
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
			registry.encoded_bytes += RECORD_LENGTH_BYTES + length;
			registry.entries.push(entry);
		}
		Ok(registry)
	}
}

#[cfg(test)]
pub(crate) mod tests;
