//! Immutable public witness registration metadata. These observations contain no secrets or readiness.

use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;

/// Retained native selection of witnesses for one authenticated receiver epoch.
///
/// This survives channel removal and later lifecycle changes. It lets protected application
/// storage detect missing or substituted keys and manifests. It proves neither current Active
/// authority, witness acknowledgement, nor permission to expose an invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORReceiverWitnessRegistration {
	pub(crate) context_digest: [u8; 32],
	pub(crate) witnesses: Vec<FFORRegisteredWitness>,
}

impl FFORReceiverWitnessRegistration {
	/// Stable digest of the native historical context to which every manifest is bound.
	pub fn context_digest(&self) -> [u8; 32] {
		self.context_digest
	}

	/// The complete immutable selection, in authenticated compressed-public-key order.
	pub fn witnesses(&self) -> &[FFORRegisteredWitness] {
		&self.witnesses
	}
}

/// Public metadata for one exact signed manifest, without the repeated canonical voucher book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORRegisteredWitness {
	pub(crate) witness: PublicKey,
	pub(crate) manifest_digest: [u8; 32],
	pub(crate) mailbox_id: [u8; 32],
	pub(crate) fetch_public_key: PublicKey,
	pub(crate) encryption_public_key: PublicKey,
	pub(crate) retention_until: u32,
	pub(crate) minimum_receipts: u8,
	pub(crate) signature: [u8; 64],
}

impl FFORRegisteredWitness {
	/// Selected witness identity, checked against the signed setup restriction when present.
	pub fn witness_node_id(&self) -> PublicKey {
		self.witness
	}
	/// SHA256 of the entire exact signed manifest, including its signature.
	pub fn manifest_digest(&self) -> [u8; 32] {
		self.manifest_digest
	}
	/// Per-witness mailbox retained in the exact signed manifest.
	pub fn mailbox_id(&self) -> [u8; 32] {
		self.mailbox_id
	}
	/// Public fetch identity. Its private key belongs in protected application storage.
	pub fn fetch_public_key(&self) -> PublicKey {
		self.fetch_public_key
	}
	/// Shared public encryption identity for this epoch.
	pub fn encryption_public_key(&self) -> PublicKey {
		self.encryption_public_key
	}
	/// Minimum record retention requested by this immutable manifest.
	pub fn retention_until(&self) -> u32 {
		self.retention_until
	}
	/// Requested guardian receipt count, without asserting any witness acknowledgement.
	pub fn minimum_receipts(&self) -> u8 {
		self.minimum_receipts
	}
}
