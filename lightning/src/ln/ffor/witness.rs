//! Authenticated witness decryption using the native channel library's existing crypto.

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use core::fmt;
use lightning_ffor::witness::{
	AuthenticatedEncryptedRecord, RecordHeader, SignedManifest, VerifiedRecordBody, WitnessError,
	CIPHERTEXT_LEN, RECORD_BODY_LEN as BODY_LEN,
};

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

/// A witness record whose signature, manifest, AEAD tag and plaintext terms were checked.
///
/// This proves knowledge of a voucher preimage. It does not prove that the witness stored it
/// durably or that the channel has claimed it. The owner must retain the evidence and pass the
/// preimage through the normal channel monitor before reporting payment or releasing claims.
/// Debug output redacts the preimage, including through the body accessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORWitnessReceipt {
	header: RecordHeader,
	body: VerifiedRecordBody,
}

impl FFORWitnessReceipt {
	/// Exact authenticated public metadata, including the witness's storage-barrier claim.
	pub fn header(&self) -> &RecordHeader {
		&self.header
	}

	/// Verified voucher terms and preimage. Observation amounts and times are informational.
	pub fn body(&self) -> &VerifiedRecordBody {
		&self.body
	}
}

/// Why an authenticated encrypted record could not be opened for this retained epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORWitnessDecryptionError {
	/// The supplied epoch encryption key does not match the signed record.
	EncryptionKey,
	/// The ciphertext or Poly1305 authentication tag is invalid.
	Ciphertext,
	/// The decrypted body or supplied manifest differs from the authenticated record.
	Record(WitnessError),
}

impl fmt::Display for FFORWitnessDecryptionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::EncryptionKey => f.write_str("FFOR witness encryption key mismatch"),
			Self::Ciphertext => f.write_str("FFOR witness ciphertext authentication failed"),
			Self::Record(error) => error.fmt(f),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for FFORWitnessDecryptionError {}

/// Decrypt an Appendix F.3 record using a borrowed, caller-owned epoch encryption key.
///
/// The record must first be authenticated against its provisioned witness. This function checks
/// that the key matches the record, authenticates the complete header as associated data, and
/// verifies the decrypted epoch, slot, terms and preimage against the supplied signed manifest.
/// The preimage is available only after all checks succeed. No channel state or storage changes.
///
/// The caller owns protected key storage and must use a fresh encryption key for each epoch.
/// Fetching and decrypting historical evidence remains valid after the voucher deadline.
pub fn decrypt_ffor_witness_record(
	record: &AuthenticatedEncryptedRecord, manifest: &SignedManifest, encryption_key: &SecretKey,
) -> Result<FFORWitnessReceipt, FFORWitnessDecryptionError> {
	let header = record.record().header();
	let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), encryption_key);
	if public_key != header.encryption_public_key {
		return Err(FFORWitnessDecryptionError::EncryptionKey);
	}
	let mut plaintext = decrypt_body(record, encryption_key)?;
	let result = record.verify_body(manifest, &plaintext);
	plaintext.fill(0);
	let body = result.map_err(FFORWitnessDecryptionError::Record)?;
	Ok(FFORWitnessReceipt { header: header.clone(), body })
}

fn decrypt_body(
	record: &AuthenticatedEncryptedRecord, encryption_key: &SecretKey,
) -> Result<[u8; BODY_LEN], FFORWitnessDecryptionError> {
	let bytes = record.record().ciphertext();
	if bytes.len() != CIPHERTEXT_LEN {
		return Err(FFORWitnessDecryptionError::Ciphertext);
	}
	let ephemeral =
		PublicKey::from_slice(&bytes[..33]).map_err(|_| FFORWitnessDecryptionError::Ciphertext)?;
	// libsecp256k1 already hashes the compressed ECDH point. Do not hash it a second time.
	let shared = SharedSecret::new(&ephemeral, encryption_key);
	let key = body_key(&shared.secret_bytes());
	let aad = record.record().header().associated_data();
	let mut cipher = ChaCha20Poly1305RFC::new(&key, &[0; 12], &aad);
	let mut plaintext = [0; BODY_LEN];
	cipher
		.variable_time_decrypt(&bytes[33..33 + BODY_LEN], &mut plaintext, &bytes[33 + BODY_LEN..])
		.map_err(|_| FFORWitnessDecryptionError::Ciphertext)?;
	Ok(plaintext)
}

fn body_key(shared: &[u8; 32]) -> [u8; 32] {
	let mut extract = HmacEngine::<sha256::Hash>::new(&[]);
	extract.input(shared);
	let prk = Hmac::from_engine(extract).to_byte_array();
	let mut expand = HmacEngine::<sha256::Hash>::new(&prk);
	expand.input(b"ffor/witness/body");
	expand.input(&[1]);
	Hmac::from_engine(expand).to_byte_array()
}

#[cfg(test)]
mod tests;
