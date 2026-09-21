use alloc::vec::Vec;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

use super::{Reader, SignedManifest, WitnessError, MAX_MESSAGE_LEN, RECORD_BODY_LEN};
use crate::transcript;

/// Appendix F.2 fixed version 1 record header length.
pub const RECORD_HEADER_LEN: usize = 235;
/// Compressed ephemeral key, 142-byte version 1 body, and 16-byte Poly1305 tag.
pub const CIPHERTEXT_LEN: usize = 33 + RECORD_BODY_LEN + 16;
const MAX_RECORD_LEN: usize = MAX_MESSAGE_LEN - 2 - 16 - 1 - 2 - 2;

/// Public signed record metadata. These claims do not prove that its body decrypts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
	/// Receiver-selected mailbox from the signed manifest.
	pub mailbox_id: [u8; 32],
	/// Witness-selected random record identity.
	pub record_id: [u8; 32],
	/// One-based canonical voucher slot.
	pub slot: u16,
	/// H_act of the recorded epoch.
	pub activation_hash: [u8; 32],
	/// SHA256 of `ffor/terms` and the exact 58-byte canonical book entry.
	pub terms_hash: [u8; 32],
	/// Claimed signing witness, requiring comparison with the provisioned identity.
	pub witness: PublicKey,
	/// Receiver's epoch encryption public key.
	pub encryption_public_key: PublicKey,
	/// Witness-reported observation height, not an authenticated chain observation.
	pub recorded_height: u32,
	/// True when the witness reports propagating without completing its storage barrier.
	pub unbarriered: bool,
	/// SHA256 of the entire ciphertext, including ephemeral key and authentication tag.
	pub ciphertext_hash: [u8; 32],
}

impl RecordHeader {
	/// Canonical version 1/profile 1 signed header.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(RECORD_HEADER_LEN);
		bytes.extend_from_slice(&[1, 1]);
		bytes.extend_from_slice(&self.mailbox_id);
		bytes.extend_from_slice(&self.record_id);
		bytes.extend_from_slice(&self.slot.to_be_bytes());
		bytes.extend_from_slice(&self.activation_hash);
		bytes.extend_from_slice(&self.terms_hash);
		bytes.extend_from_slice(&self.witness.serialize());
		bytes.extend_from_slice(&self.encryption_public_key.serialize());
		bytes.extend_from_slice(&self.recorded_height.to_be_bytes());
		bytes.push(u8::from(self.unbarriered));
		bytes.extend_from_slice(&self.ciphertext_hash);
		bytes
	}

	/// The F.3 AEAD associated data, with only ciphertext_hash replaced by zero bytes.
	/// Providing AAD does not decrypt or authenticate an encrypted body.
	pub fn associated_data(&self) -> Vec<u8> {
		let mut bytes = self.encode();
		bytes[RECORD_HEADER_LEN - 32..].fill(0);
		bytes
	}

	/// Single SHA256 record domain over the exact canonical header.
	pub fn signing_digest(&self) -> [u8; 32] {
		transcript::hash_parts(b"ffor/witness/record", &[&self.encode()])
	}

	fn read(reader: &mut Reader<'_>) -> Result<Self, WitnessError> {
		if reader.byte()? != 1 {
			return Err(WitnessError::Version);
		}
		if reader.byte()? != 1 {
			return Err(WitnessError::Profile);
		}
		let mailbox_id = reader.array()?;
		let record_id = reader.array()?;
		let slot = reader.u16()?;
		if slot == 0 || usize::from(slot) > crate::book::MAX_VOUCHERS {
			return Err(WitnessError::Terms);
		}
		let activation_hash = reader.array()?;
		let terms_hash = reader.array()?;
		let witness = reader.public_key()?;
		let encryption_public_key = reader.public_key()?;
		let recorded_height = reader.u32()?;
		let unbarriered = match reader.byte()? {
			0 => false,
			1 => true,
			_ => return Err(WitnessError::NonCanonical),
		};
		let ciphertext_hash = reader.array()?;
		Ok(Self {
			mailbox_id,
			record_id,
			slot,
			activation_hash,
			terms_hash,
			witness,
			encryption_public_key,
			recorded_height,
			unbarriered,
			ciphertext_hash,
		})
	}
}

/// Canonical encrypted record with a valid signature under its claimed witness key.
///
/// This does not authenticate the claimed witness against a provision. Call `authenticate`
/// before use. No method decrypts, verifies a Poly1305 tag, or establishes a payment preimage.
/// Guardian receipt bytes are unsigned opaque attachments, not proof of storage or payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
	header: RecordHeader,
	signature: [u8; 64],
	ciphertext: Vec<u8>,
	receipts: Vec<Vec<u8>>,
}

impl EncryptedRecord {
	/// Parse bounded framing, strict version/profile/flags, compressed points, low-S signature
	/// and ciphertext hash. No trailing fields are defined by version 1.
	pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_RECORD_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		let header = RecordHeader::read(&mut reader)?;
		let signature = reader.array()?;
		let length = usize::from(reader.u16()?);
		if length != CIPHERTEXT_LEN {
			return Err(WitnessError::Ciphertext);
		}
		let ciphertext = reader.take(length)?;
		PublicKey::from_slice(&ciphertext[..33]).map_err(|_| WitnessError::PublicKey)?;
		if sha256::Hash::hash(ciphertext).to_byte_array() != header.ciphertext_hash {
			return Err(WitnessError::Ciphertext);
		}
		let count = usize::from(reader.byte()?);
		let mut receipts = Vec::new();
		for _ in 0..count {
			let length = usize::from(reader.u16()?);
			receipts.push(reader.take(length)?.to_vec());
		}
		reader.finish()?;
		transcript::verify_digest_signature(header.signing_digest(), &signature, &header.witness)?;
		Ok(Self { header, signature, ciphertext: ciphertext.to_vec(), receipts })
	}

	/// Preserve the exact signed record and opaque receipt framing.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = self.header.encode();
		bytes.extend_from_slice(&self.signature);
		bytes.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
		bytes.extend_from_slice(&self.ciphertext);
		bytes.push(self.receipts.len() as u8);
		for receipt in &self.receipts {
			bytes.extend_from_slice(&(receipt.len() as u16).to_be_bytes());
			bytes.extend_from_slice(receipt);
		}
		bytes
	}

	/// The signed public claims. They remain insufficient for plaintext verification.
	pub fn header(&self) -> &RecordHeader {
		&self.header
	}
	/// Exact compressed ephemeral key followed by encrypted body and its AEAD tag.
	pub fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
	}
	/// Unsigned guardian attachments. Their count does not establish a storage promise.
	pub fn receipts(&self) -> &[Vec<u8>] {
		&self.receipts
	}

	/// Bind the signed metadata to the retained manifest and provisioned witness identity.
	/// Records can be fetched after voucher expiry; this method has no live-height admission rule.
	pub fn authenticate(
		self, manifest: &SignedManifest, expected_witness: PublicKey,
	) -> Result<AuthenticatedEncryptedRecord, WitnessError> {
		if self.header.witness != expected_witness {
			return Err(WitnessError::Witness);
		}
		self.checked_entry(manifest)?;
		Ok(AuthenticatedEncryptedRecord { record: self })
	}

	pub(super) fn checked_entry<'a>(
		&self, manifest: &'a SignedManifest,
	) -> Result<&'a [u8], WitnessError> {
		let m = manifest.unsigned();
		let p = m.parameters();
		if self.header.mailbox_id != p.mailbox_id
			|| self.header.encryption_public_key != p.encryption_public_key
		{
			return Err(WitnessError::Mailbox);
		}
		if self.header.activation_hash != m.activation_hash() {
			return Err(WitnessError::Transcript);
		}
		let start = 36 + 58 * (usize::from(self.header.slot) - 1);
		let entry = m.canonical_book().get(start..start + 58).ok_or(WitnessError::Terms)?;
		if transcript::hash_parts(b"ffor/terms", &[entry]) != self.header.terms_hash {
			return Err(WitnessError::Terms);
		}
		Ok(entry)
	}
}

/// Authenticated opaque ciphertext bound to one provisioned witness, manifest and book entry.
///
/// This is deliberately not a receipt or preimage authority. A decryption boundary must verify
/// AEAD before passing the resulting plaintext to [`Self::verify_body`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedEncryptedRecord {
	record: EncryptedRecord,
}

impl AuthenticatedEncryptedRecord {
	/// The exact checked encrypted record, still requiring authenticated decryption.
	pub fn record(&self) -> &EncryptedRecord {
		&self.record
	}
}
