use core::fmt;

use bitcoin::hashes::{sha256, Hash};

use super::{AuthenticatedEncryptedRecord, Reader, SignedManifest, WitnessError};

/// Appendix F.2 version 1 plaintext body length, without encryption framing.
pub const RECORD_BODY_LEN: usize = 142;

/// Witness-reported bookkeeping context with no protocol authority.
///
/// These fields are preserved exactly, without interpreting them as proof of payment, fees,
/// current height, or current time. Body verification does not authenticate their origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordBodyContext {
	amount_in_msat: u64,
	amount_out_msat: u64,
	outgoing_cltv: u32,
	observed_unix_time: u64,
}

impl RecordBodyContext {
	/// Informational inbound amount reported by the witness.
	pub fn amount_in_msat(&self) -> u64 {
		self.amount_in_msat
	}

	/// Informational outbound amount reported by the witness.
	pub fn amount_out_msat(&self) -> u64 {
		self.amount_out_msat
	}

	/// Informational outgoing CLTV reported by the witness.
	pub fn outgoing_cltv(&self) -> u32 {
		self.outgoing_cltv
	}

	/// Informational observation timestamp reported by the witness.
	pub fn observed_unix_time(&self) -> u64 {
		self.observed_unix_time
	}
}

/// Exact plaintext terms and preimage checked against a signed manifest and record header.
///
/// This value proves body consistency only. It does not establish that the bytes came from
/// the encrypted record, passed AEAD authentication, or were observed by the witness. Only a
/// separate authenticated decryption boundary can establish that provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRecordBody {
	epoch_id: [u8; 32],
	slot: u16,
	preimage: [u8; 32],
	payment_hash: [u8; 32],
	amount_msat: u64,
	voucher_expiry: u32,
	settlement_deadline: u32,
	context: RecordBodyContext,
}

impl VerifiedRecordBody {
	/// Epoch identity from the signed canonical book.
	pub fn epoch_id(&self) -> [u8; 32] {
		self.epoch_id
	}

	/// One-based slot matching the signed record and canonical entry.
	pub fn slot(&self) -> u16 {
		self.slot
	}

	/// Preimage whose SHA256 equals the canonical payment hash.
	/// This alone does not prove authenticated decryption or witness observation.
	pub fn preimage(&self) -> [u8; 32] {
		self.preimage
	}

	/// Payment hash from the signed canonical entry.
	pub fn payment_hash(&self) -> [u8; 32] {
		self.payment_hash
	}

	/// Voucher amount from the signed canonical entry.
	pub fn amount_msat(&self) -> u64 {
		self.amount_msat
	}

	/// Voucher expiry height from the signed canonical entry.
	pub fn voucher_expiry(&self) -> u32 {
		self.voucher_expiry
	}

	/// Settlement admission deadline from the signed canonical entry.
	pub fn settlement_deadline(&self) -> u32 {
		self.settlement_deadline
	}

	/// Uninterpreted context, distinct from the verified payment terms.
	pub fn context(&self) -> &RecordBodyContext {
		&self.context
	}

	fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
		let mut reader = Reader(bytes);
		let body = Self {
			epoch_id: reader.array()?,
			slot: reader.u16()?,
			preimage: reader.array()?,
			payment_hash: reader.array()?,
			amount_msat: u64::from_be_bytes(reader.array()?),
			voucher_expiry: reader.u32()?,
			settlement_deadline: reader.u32()?,
			context: RecordBodyContext {
				amount_in_msat: u64::from_be_bytes(reader.array()?),
				amount_out_msat: u64::from_be_bytes(reader.array()?),
				outgoing_cltv: reader.u32()?,
				observed_unix_time: u64::from_be_bytes(reader.array()?),
			},
		};
		reader.finish()?;
		Ok(body)
	}

	fn verify_entry(&self, entry: &[u8]) -> Result<(), WitnessError> {
		let mut reader = Reader(entry);
		if self.slot != reader.u16()?
			|| self.payment_hash != reader.array::<32>()?
			|| self.amount_msat != u64::from_be_bytes(reader.array()?)
			|| self.voucher_expiry != reader.u32()?
			|| self.settlement_deadline != reader.u32()?
		{
			return Err(WitnessError::Terms);
		}
		if sha256::Hash::hash(&self.preimage).to_byte_array() != self.payment_hash {
			return Err(WitnessError::Preimage);
		}
		Ok(())
	}
}

impl fmt::Debug for VerifiedRecordBody {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VerifiedRecordBody")
			.field("epoch_id", &self.epoch_id)
			.field("slot", &self.slot)
			.field("preimage", &"[redacted]")
			.field("payment_hash", &self.payment_hash)
			.field("amount_msat", &self.amount_msat)
			.field("voucher_expiry", &self.voucher_expiry)
			.field("settlement_deadline", &self.settlement_deadline)
			.field("context", &self.context)
			.finish()
	}
}

impl AuthenticatedEncryptedRecord {
	/// Verify exactly 142 supplied plaintext bytes against this record and a retained manifest.
	///
	/// Rechecks the record's mailbox, encryption key, H_act and full canonical entry terms hash,
	/// then verifies the body epoch, slot, payment terms and SHA256(preimage). Informational
	/// context is preserved without semantic restrictions. No decryption or AEAD check occurs:
	/// callers must authenticate the encrypted body before interpreting this as witness evidence.
	pub fn verify_body(
		&self, manifest: &SignedManifest, bytes: &[u8],
	) -> Result<VerifiedRecordBody, WitnessError> {
		let entry = self.record().checked_entry(manifest)?;
		let body = VerifiedRecordBody::decode(bytes)?;
		if manifest.unsigned().canonical_book().get(..32) != Some(body.epoch_id.as_slice()) {
			return Err(WitnessError::Transcript);
		}
		body.verify_entry(entry)?;
		Ok(body)
	}
}
