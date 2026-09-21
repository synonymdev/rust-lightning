//! Per-voucher cooperative drain outcomes recorded at the stock irrevocable removal point.
//!
//! The journal is native accounting, never a peer statement. It is never derived from the signed
//! settled bitmap or from known preimages. A slot becomes resolved exactly once, when the stock
//! revoke-and-ack removal drops its owned inbound HTLC, and is fulfilled only when that removal
//! carried the preimage. Fulfilled is always a subset of resolved.

use crate::ln::msgs::DecodeError;
use crate::prelude::*;
use crate::util::ser::Writeable;

/// The historical result of one owned voucher slot in a fully completed cooperative drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORVoucherOutcome {
	/// The owned voucher was irrevocably removed with its preimage under stock accounting.
	Fulfilled,
	/// The owned voucher was irrevocably removed as a failure under stock accounting.
	Failed,
}

/// Resolved and fulfilled bitmaps for one drain, bounded by the native book of at most 483 slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FFORCooperativeJournal {
	slots: u16,
	resolved: Vec<u8>,
	fulfilled: Vec<u8>,
}

impl_writeable_tlv_based!(FFORCooperativeJournal, {
	(0, slots, required),
	(2, resolved, required_vec),
	(4, fulfilled, required_vec),
});

/// Encoded upper bound: two 61-byte bitmaps, the slot count and TLV framing.
pub(crate) const MAX_JOURNAL_BYTES: usize = 140;

impl FFORCooperativeJournal {
	/// A fresh journal with every slot unresolved. Only valid book sizes are accepted.
	pub(crate) fn new(slots: usize) -> Option<Self> {
		if slots == 0 || slots > lightning_ffor::book::MAX_VOUCHERS {
			return None;
		}
		let bytes = (slots + 7) / 8;
		Some(Self { slots: slots as u16, resolved: vec![0; bytes], fulfilled: vec![0; bytes] })
	}

	pub(crate) fn slots(&self) -> u16 {
		self.slots
	}

	/// Test-only raw constructor for malformed journals; production code only uses `new`.
	#[cfg(test)]
	pub(crate) fn from_parts(slots: u16, resolved: Vec<u8>, fulfilled: Vec<u8>) -> Self {
		Self { slots, resolved, fulfilled }
	}

	/// Structural validity against the actual book size: exact bitmap lengths, zero padding and
	/// fulfilled being a subset of resolved.
	pub(crate) fn validate(&self, slots: usize) -> Result<(), DecodeError> {
		let count = usize::from(self.slots);
		if count != slots || count == 0 || count > lightning_ffor::book::MAX_VOUCHERS {
			return Err(DecodeError::InvalidValue);
		}
		let bytes = (count + 7) / 8;
		if self.resolved.len() != bytes || self.fulfilled.len() != bytes {
			return Err(DecodeError::InvalidValue);
		}
		let used = count % 8;
		if used != 0 {
			let mask = 0xffu8 << used;
			if self.resolved[bytes - 1] & mask != 0 || self.fulfilled[bytes - 1] & mask != 0 {
				return Err(DecodeError::InvalidValue);
			}
		}
		if self.resolved.iter().zip(&self.fulfilled).any(|(r, f)| f & !r != 0) {
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}

	fn bit(bytes: &[u8], slot: usize) -> bool {
		bytes.get(slot / 8).map_or(false, |byte| byte & (1 << (slot % 8)) != 0)
	}

	pub(crate) fn is_resolved(&self, slot: usize) -> bool {
		slot < usize::from(self.slots) && Self::bit(&self.resolved, slot)
	}

	pub(crate) fn is_fulfilled(&self, slot: usize) -> bool {
		slot < usize::from(self.slots) && Self::bit(&self.fulfilled, slot)
	}

	/// Record one irrevocable removal. Returns false, changing nothing, for an out-of-range or
	/// already resolved slot; restore validation guarantees neither happens after preflight.
	pub(crate) fn record(&mut self, slot: usize, fulfilled: bool) -> bool {
		if slot >= usize::from(self.slots) || Self::bit(&self.resolved, slot) {
			return false;
		}
		self.resolved[slot / 8] |= 1 << (slot % 8);
		if fulfilled {
			self.fulfilled[slot / 8] |= 1 << (slot % 8);
		}
		true
	}

	pub(crate) fn all_resolved(&self) -> bool {
		(0..usize::from(self.slots)).all(|slot| Self::bit(&self.resolved, slot))
	}

	/// Every signed settled slot must have been fulfilled under stock accounting. Additional
	/// locally proven fulfillments are allowed.
	pub(crate) fn covers_settled(&self, settled: &[u8]) -> bool {
		settled.len() == self.fulfilled.len()
			&& settled.iter().zip(&self.fulfilled).all(|(s, f)| s & !f == 0)
	}

	/// Canonical bytes bound into the completion digest.
	pub(crate) fn digest_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(2 + self.resolved.len() + self.fulfilled.len());
		bytes.extend_from_slice(&self.slots.to_be_bytes());
		bytes.extend_from_slice(&self.resolved);
		bytes.extend_from_slice(&self.fulfilled);
		bytes
	}

	/// Zero-based slot outcome. None for unresolved or out-of-range slots.
	pub(crate) fn outcome(&self, slot: usize) -> Option<FFORVoucherOutcome> {
		if !self.is_resolved(slot) {
			return None;
		}
		Some(if self.is_fulfilled(slot) {
			FFORVoucherOutcome::Fulfilled
		} else {
			FFORVoucherOutcome::Failed
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ser::Readable;

	#[test]
	fn ffor_journal_bounds_padding_subset_and_encoding() {
		assert!(FFORCooperativeJournal::new(0).is_none());
		assert!(FFORCooperativeJournal::new(484).is_none());
		let mut journal = FFORCooperativeJournal::new(483).unwrap();
		assert_eq!(journal.resolved.len(), 61);
		journal.validate(483).unwrap();
		assert!(journal.validate(482).is_err());
		assert!(!journal.record(483, true));
		assert!(journal.record(482, true));
		assert!(!journal.record(482, false));
		assert!(journal.is_resolved(482) && journal.is_fulfilled(482));
		assert!(!journal.all_resolved());
		for slot in 0..482 {
			assert!(journal.record(slot, slot % 3 == 0));
		}
		assert!(journal.all_resolved());
		assert_eq!(journal.outcome(1), Some(FFORVoucherOutcome::Failed));
		assert_eq!(journal.outcome(3), Some(FFORVoucherOutcome::Fulfilled));
		assert_eq!(journal.outcome(483), None);
		let encoded = journal.encode();
		assert_eq!(journal.serialized_length(), encoded.len());
		assert!(encoded.len() <= MAX_JOURNAL_BYTES, "{}", encoded.len());
		let restored = FFORCooperativeJournal::read(&mut &encoded[..]).unwrap();
		assert_eq!(restored, journal);
		let mut settled = vec![0u8; 61];
		settled[0] = 0b1001;
		assert!(journal.covers_settled(&settled));
		settled[0] = 0b1011;
		assert!(!journal.covers_settled(&settled));
		assert!(!journal.covers_settled(&settled[..60]));

		let mut short = FFORCooperativeJournal::new(9).unwrap();
		short.validate(9).unwrap();
		assert_eq!(short.resolved.len(), 2);
		short.resolved[1] = 0b10;
		assert!(short.validate(9).is_err(), "padding bit");
		short.resolved[1] = 0;
		short.fulfilled[0] = 1;
		assert!(short.validate(9).is_err(), "fulfilled outside resolved");
		short.resolved[0] = 1;
		short.validate(9).unwrap();
		assert_eq!(short.outcome(0), Some(FFORVoucherOutcome::Fulfilled));
		assert_eq!(short.outcome(8), None);
		let mut wrong = short.clone();
		wrong.resolved.push(0);
		assert!(wrong.validate(9).is_err());
	}
}
