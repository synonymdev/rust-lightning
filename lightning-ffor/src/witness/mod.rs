//! Receiver-side D-R manifest and provisioning primitives from section 9.6 and Appendix F.1.
//!
//! A manifest proves fetch-key control and agreement with a supplied authenticated setup. A
//! checked acknowledgement only correlates a response with one immutable provisioning request.
//! Neither value proves live commitment state, durable storage, ACTIVE, or invoice readiness.
//! The caller owns authenticated transport, signing, protected key storage and persistence.
//!
//! Version 1/profile 1 manifests and the two provisioning messages define no extension stream.
//! Decoders reject every trailing byte, unknown version/profile, and noncanonical success flag.
//! Refusal text is bounded opaque bytes and need not be UTF-8.
//!
//! ```
//! use lightning_ffor::witness::{Acknowledgement, AcknowledgementResult};
//! let refusal = Acknowledgement::new(
//!     [1; 16], AcknowledgementResult::Refused(b"capacity unavailable".to_vec()),
//! ).unwrap();
//! assert_eq!(Acknowledgement::decode(&refusal.encode()).unwrap(), refusal);
//! ```

use core::fmt;

use bitcoin::secp256k1::PublicKey;

use crate::transcript::SignatureError;

mod correlation;
mod manifest;
mod messages;

pub use correlation::{CheckedAcknowledgement, PendingProvision, WitnessConnection};
pub use manifest::{ManifestParameters, SignedManifest, UnsignedManifest};
pub use messages::{Acknowledgement, AcknowledgementResult, Provision};

/// Appendix F.1 receiver-to-witness provisioning message, including its two-byte type.
pub const PROVISION_MESSAGE_TYPE: u16 = 55055;
/// Appendix F.1 witness-to-receiver provisioning acknowledgement.
pub const ACK_MESSAGE_TYPE: u16 = 55057;
/// Minimum promised record retention beyond voucher expiry, in blocks.
pub const RETENTION_MARGIN_BLOCKS: u32 = 144;
/// BOLT 8's plaintext limit, including the two-byte message type.
pub const MAX_MESSAGE_LEN: usize = crate::wire::MAX_MESSAGE_LEN;

/// A malformed manifest/message or a response that cannot acknowledge this pending request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
	/// The input ends before a declared field is complete.
	Truncated,
	/// A message exceeds the bounded BOLT 8 envelope.
	SizeLimit,
	/// The wire type is outside the two supported provisioning messages.
	MessageType,
	/// Only manifest version 1 is supported.
	Version,
	/// Only the D-R profile, value 1, is supported.
	Profile,
	/// An unsupported trailing field or noncanonical flag was encountered.
	NonCanonical,
	/// A compressed secp256k1 public key is invalid.
	PublicKey,
	/// The supplied fetch-key signature does not authenticate the exact manifest.
	Signature(SignatureError),
	/// The manifest differs from the authenticated setup's canonical book.
	Book,
	/// The setup or recomputed activation digest differs.
	Transcript,
	/// Activation is not before admission closes, or voucher expiry is timestamp-style.
	Height,
	/// Retention is too short or its required lower bound overflows.
	Retention,
	/// This response echoes a different pending request identifier.
	Request,
	/// This response arrived on a different authenticated transport connection.
	Connection,
	/// The actual response peer or acknowledgement names another witness.
	Witness,
	/// The witness explicitly refused the provisioning request.
	Refused,
}

impl fmt::Display for WitnessError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "invalid FFOR witness provisioning: {self:?}")
	}
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessError {}

impl From<SignatureError> for WitnessError {
	fn from(error: SignatureError) -> Self {
		Self::Signature(error)
	}
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
	fn take(&mut self, length: usize) -> Result<&'a [u8], WitnessError> {
		let value = self.0.get(..length).ok_or(WitnessError::Truncated)?;
		self.0 = &self.0[length..];
		Ok(value)
	}

	fn array<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
		self.take(N)?.try_into().map_err(|_| WitnessError::Truncated)
	}

	fn byte(&mut self) -> Result<u8, WitnessError> {
		Ok(self.array::<1>()?[0])
	}

	fn u16(&mut self) -> Result<u16, WitnessError> {
		Ok(u16::from_be_bytes(self.array()?))
	}

	fn u32(&mut self) -> Result<u32, WitnessError> {
		Ok(u32::from_be_bytes(self.array()?))
	}

	fn public_key(&mut self) -> Result<PublicKey, WitnessError> {
		PublicKey::from_slice(self.take(33)?).map_err(|_| WitnessError::PublicKey)
	}

	fn finish(self) -> Result<(), WitnessError> {
		if self.0.is_empty() {
			Ok(())
		} else {
			Err(WitnessError::NonCanonical)
		}
	}
}
