//! Observations of native witness promises and opaque connection-scoped provisioning attempts.

use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;

use super::FFORPeerConnection;
use crate::ln::ffor_recovery::FFORRecoveryKey;
use crate::sync::Arc;

/// One native-correlated provisioning attempt. This is not an acknowledgement or readiness token.
///
/// Only native staging constructs it, using the actual authenticated witness generation. Cloning
/// preserves the attempt. Disconnect, replacement and manager restore invalidate it. No request,
/// manifest or phase can be substituted by the application when releasing this attempt.
#[derive(Clone, Debug)]
pub struct FFORWitnessProvisionAttempt {
	pub(crate) identity: Arc<()>,
	pub(crate) key: FFORRecoveryKey,
	pub(crate) context_digest: [u8; 32],
	pub(crate) connection: FFORPeerConnection,
	pub(crate) request_id: [u8; 16],
	pub(crate) manifest_digest: [u8; 32],
}

/// Retained unsigned witness promises, observed on authenticated native connections.
///
/// An empty list means that native ACK tracking is reserved but no witness promise was retained.
/// This historical observation survives channel removal. It does not assert current durability,
/// an Active channel, invoice readiness or that a witness will honor its storage promise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORReceiverWitnessAcknowledgements {
	pub(crate) context_digest: [u8; 32],
	pub(crate) acknowledgements: Vec<FFORWitnessAcknowledgement>,
}

impl FFORReceiverWitnessAcknowledgements {
	/// Immutable native context to which these promises belong.
	pub fn context_digest(&self) -> [u8; 32] {
		self.context_digest
	}
	/// First retained promise for each witness, in compressed-public-key order.
	pub fn acknowledgements(&self) -> &[FFORWitnessAcknowledgement] {
		&self.acknowledgements
	}
}

/// Compact evidence of one accepted ACK and its exact native manifest correlation.
///
/// The wire ACK is unsigned. These fields describe an observation made by the authenticated
/// native handler, not a portable witness signature or permission to expose an invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORWitnessAcknowledgement {
	pub(crate) witness: PublicKey,
	pub(crate) manifest_digest: [u8; 32],
	pub(crate) request_id: [u8; 16],
	pub(crate) retention_until: u32,
}

impl FFORWitnessAcknowledgement {
	/// Witness authenticated on the original native connection.
	pub fn witness_node_id(&self) -> PublicKey {
		self.witness
	}
	/// SHA256 of the exact registered signed manifest acknowledged on that connection.
	pub fn manifest_digest(&self) -> [u8; 32] {
		self.manifest_digest
	}
	/// Exact Provision request ID to which the original ACK replied.
	pub fn request_id(&self) -> [u8; 16] {
		self.request_id
	}
	/// Original accepted retention promise, at least the immutable manifest requirement.
	pub fn retention_until(&self) -> u32 {
		self.retention_until
	}
}
