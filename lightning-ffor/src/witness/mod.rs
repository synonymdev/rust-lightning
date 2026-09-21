//! Receiver-side D-R provisioning, fetch and opaque record primitives from section 9.6/Appendix F.
//!
//! A manifest proves fetch-key control and agreement with a supplied authenticated setup. A
//! checked acknowledgement only correlates a response with one immutable provisioning request.
//! Neither value proves live commitment state, durable storage, ACTIVE, or invoice readiness.
//! The caller owns authenticated transport, signing, protected key storage and persistence.
//!
//! Version 1/profile 1 manifests and the two provisioning messages define no extension stream.
//! Decoders reject every trailing byte, unknown version/profile, and noncanonical success flag.
//! Refusal text is bounded opaque bytes and need not be UTF-8.
//! Fetch messages preserve canonical unknown odd TLVs and reject unknown even fields. Records
//! define no extension stream and reject reserved flags. Authenticated encrypted records prove
//! their witness signature and manifest binding only: no AEAD or plaintext verification exists.
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
mod fetch;
mod fetch_correlation;
mod manifest;
mod messages;
mod record;

pub use correlation::{CheckedAcknowledgement, PendingProvision, WitnessConnection};
pub use fetch::{FetchParameters, FetchResponse, FetchResult, SignedFetch, UnsignedFetch};
pub use fetch_correlation::{CheckedFetchPage, PendingFetch};
pub use manifest::{ManifestParameters, SignedManifest, UnsignedManifest};
pub use messages::{Acknowledgement, AcknowledgementResult, Provision};
pub use record::{
	AuthenticatedEncryptedRecord, EncryptedRecord, RecordHeader, CIPHERTEXT_LEN, RECORD_HEADER_LEN,
};

/// Appendix F.1 receiver-to-witness provisioning message, including its two-byte type.
pub const PROVISION_MESSAGE_TYPE: u16 = 55055;
/// Appendix F.1 witness-to-receiver provisioning acknowledgement.
pub const ACK_MESSAGE_TYPE: u16 = 55057;
/// Appendix F.1 signed mailbox fetch request.
pub const FETCH_MESSAGE_TYPE: u16 = 55059;
/// Appendix F.1 paginated encrypted-record response.
pub const FETCH_RESPONSE_MESSAGE_TYPE: u16 = 55061;
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
	/// The wire type is outside the supported witness request/response codecs.
	MessageType,
	/// Only manifest version 1 is supported.
	Version,
	/// Only the D-R profile, value 1, is supported.
	Profile,
	/// An unsupported trailing field or noncanonical flag was encountered.
	NonCanonical,
	/// A compressed secp256k1 public key is invalid.
	PublicKey,
	/// A compact low-S fetch-key or witness signature is invalid for the exact signed bytes.
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
	/// The witness explicitly refused the pending request.
	Refused,
	/// A canonical trailing TLV stream is invalid.
	Tlv(crate::wire::WireError),
	/// The encrypted record's declared ciphertext hash does not match its bytes.
	Ciphertext,
	/// A signed record names another mailbox or encryption key.
	Mailbox,
	/// The slot or canonical book entry differs from this manifest.
	Terms,
	/// A response is unordered, repeats a slot, or has an invalid pagination cursor.
	Pagination,
	/// A request identifier or nonce was already used in this bounded fetch traversal.
	Replay,
}

impl fmt::Display for WitnessError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "invalid FFOR witness data: {self:?}")
	}
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessError {}

impl From<SignatureError> for WitnessError {
	fn from(error: SignatureError) -> Self {
		Self::Signature(error)
	}
}

impl From<crate::wire::WireError> for WitnessError {
	fn from(error: crate::wire::WireError) -> Self {
		Self::Tlv(error)
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
