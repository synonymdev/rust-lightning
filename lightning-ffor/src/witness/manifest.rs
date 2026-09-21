use alloc::vec::Vec;

use bitcoin::locktime::absolute::LOCK_TIME_THRESHOLD;
use bitcoin::secp256k1::PublicKey;

use crate::setup::AuthenticatedSetup;
use crate::transcript::{self, Digest};

use super::{Reader, WitnessError, MAX_MESSAGE_LEN, RETENTION_MARGIN_BLOCKS};

// The manifest must also fit inside type + request_id + manifest.
const MAX_MANIFEST_LEN: usize = MAX_MESSAGE_LEN - 2 - 16;

/// Public receiver-selected provisioning fields, with no secret key material.
///
/// The engine supplies the already-validated commitment digest and activation height. The
/// caller generates fresh mailbox/fetch identities per witness and epoch, and an encryption
/// key for the epoch. This type cannot establish freshness, actual activation or persistence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestParameters {
	/// Random, unlinkable 32-byte mailbox identity for this witness and epoch.
	pub mailbox_id: [u8; 32],
	/// H_commit from the engine's verified, fully signed voucher commitments.
	pub commitment_hash: Digest,
	/// Height bound into the epoch's signed activation.
	pub epoch_start_height: u32,
	/// Per-witness/per-epoch key authorizing the manifest, fetch and close requests.
	pub fetch_public_key: PublicKey,
	/// Public key to which the witness encrypts records; its private half stays local.
	pub encryption_public_key: PublicKey,
	/// Block height through which the witness must retain every record.
	pub retention_until: u32,
	/// Requested guardian receipt count; zero requests local witness durability only.
	pub minimum_receipts: u8,
}

/// Canonical manifest bytes awaiting an externally produced fetch-key signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedManifest {
	parameters: ManifestParameters,
	setup_hash: Digest,
	activation_hash: Digest,
	book: Vec<u8>,
}

impl UnsignedManifest {
	/// Build a version 1/D-R manifest from an existing authenticated canonical setup.
	///
	/// The caller must separately match the commitment digest and height to its persisted ACTIVE
	/// epoch. Recomputing H_act here does not establish channel-state or storage authority.
	pub fn new(
		setup: &AuthenticatedSetup, parameters: ManifestParameters,
	) -> Result<Self, WitnessError> {
		let terms = setup.terms();
		if terms.voucher_expiry >= LOCK_TIME_THRESHOLD {
			return Err(WitnessError::Height);
		}
		let minimum_retention = terms
			.voucher_expiry
			.checked_add(RETENTION_MARGIN_BLOCKS)
			.ok_or(WitnessError::Retention)?;
		if parameters.retention_until < minimum_retention {
			return Err(WitnessError::Retention);
		}
		if parameters.epoch_start_height >= terms.settlement_deadline {
			return Err(WitnessError::Height);
		}
		let setup_hash = setup.setup_hash();
		let activation_hash = transcript::activation_hash(
			&setup_hash,
			&setup.book_hash(),
			&parameters.commitment_hash,
			parameters.epoch_start_height,
		);
		Ok(Self { parameters, setup_hash, activation_hash, book: setup.canonical_book().to_vec() })
	}

	/// Public provisioning fields that will be bound by the fetch-key signature.
	pub fn parameters(&self) -> &ManifestParameters {
		&self.parameters
	}

	/// T_setup already authenticated by the channel's receiver and settlement keys.
	pub fn setup_hash(&self) -> Digest {
		self.setup_hash
	}

	/// H_act recomputed from this setup, book, commitment digest and activation height.
	pub fn activation_hash(&self) -> Digest {
		self.activation_hash
	}

	/// Exact shared section 7.5.3 book, with no independently reconstructed entries.
	pub fn canonical_book(&self) -> &[u8] {
		&self.book
	}

	/// Exact section 9.6.4 manifest bytes, excluding only its final signature.
	pub fn unsigned_bytes(&self) -> Vec<u8> {
		let p = &self.parameters;
		let mut bytes = Vec::with_capacity(207 + self.book.len());
		bytes.extend_from_slice(&[1, 1]);
		bytes.extend_from_slice(&p.mailbox_id);
		bytes.extend_from_slice(&self.setup_hash);
		bytes.extend_from_slice(&p.commitment_hash);
		bytes.extend_from_slice(&p.epoch_start_height.to_be_bytes());
		bytes.extend_from_slice(&self.activation_hash);
		bytes.extend_from_slice(&p.fetch_public_key.serialize());
		bytes.extend_from_slice(&p.encryption_public_key.serialize());
		bytes.extend_from_slice(&p.retention_until.to_be_bytes());
		bytes.push(p.minimum_receipts);
		// AuthenticatedSetup restricts books to 483 fixed-size entries, well below u16::MAX.
		bytes.extend_from_slice(&(self.book.len() as u16).to_be_bytes());
		bytes.extend_from_slice(&self.book);
		bytes
	}

	/// Single SHA256 over `ffor/witness/manifest` and the exact unsigned manifest.
	///
	/// This is a fetch-key domain, not the `ffor/msg` node-key domain. No wire message type or
	/// request identifier is included. An external signer retains the private key.
	pub fn signing_digest(&self) -> Digest {
		transcript::hash_parts(b"ffor/witness/manifest", &[&self.unsigned_bytes()])
	}

	/// Authenticate an external compact low-S signature without signing or exporting keys.
	pub fn authenticate(self, signature: [u8; 64]) -> Result<SignedManifest, WitnessError> {
		transcript::verify_digest_signature(
			self.signing_digest(),
			&signature,
			&self.parameters.fetch_public_key,
		)?;
		Ok(SignedManifest { manifest: self, signature })
	}
}

/// Immutable canonical manifest whose signature and setup binding were checked.
///
/// This authenticates fetch-key control only. A witness does not learn the receiver's node key
/// from the manifest, and this object cannot prove real commitment state or durable activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedManifest {
	manifest: UnsignedManifest,
	signature: [u8; 64],
}

impl SignedManifest {
	/// Decode against the receiver's authenticated setup and verify every signed byte.
	///
	/// No trailing fields are defined for version 1. The entire canonical book must equal the
	/// supplied setup's book; this decoder never trusts a separately supplied list of vouchers.
	pub fn decode(bytes: &[u8], setup: &AuthenticatedSetup) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_MANIFEST_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		if reader.byte()? != 1 {
			return Err(WitnessError::Version);
		}
		if reader.byte()? != 1 {
			return Err(WitnessError::Profile);
		}
		let mailbox_id = reader.array()?;
		let setup_hash = reader.array()?;
		let commitment_hash = reader.array()?;
		let epoch_start_height = reader.u32()?;
		let activation_hash = reader.array()?;
		let fetch_public_key = reader.public_key()?;
		let encryption_public_key = reader.public_key()?;
		let retention_until = reader.u32()?;
		let minimum_receipts = reader.byte()?;
		let length = reader.u16()? as usize;
		if reader.take(length)? != setup.canonical_book() {
			return Err(WitnessError::Book);
		}
		let signature = reader.array()?;
		reader.finish()?;
		let manifest = UnsignedManifest::new(
			setup,
			ManifestParameters {
				mailbox_id,
				commitment_hash,
				epoch_start_height,
				fetch_public_key,
				encryption_public_key,
				retention_until,
				minimum_receipts,
			},
		)?;
		if manifest.setup_hash != setup_hash || manifest.activation_hash != activation_hash {
			return Err(WitnessError::Transcript);
		}
		manifest.authenticate(signature)
	}

	/// The immutable validated fields and exact canonical unsigned encoding.
	pub fn unsigned(&self) -> &UnsignedManifest {
		&self.manifest
	}

	/// Original compact low-S fetch-key signature, in fixed 64-byte form.
	pub fn signature(&self) -> &[u8; 64] {
		&self.signature
	}

	/// Exact canonical manifest including the original signature, suitable for durable retries.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = self.manifest.unsigned_bytes();
		bytes.extend_from_slice(&self.signature);
		bytes
	}
}
