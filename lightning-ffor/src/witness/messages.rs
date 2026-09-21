use alloc::vec::Vec;

use bitcoin::secp256k1::PublicKey;

use crate::setup::AuthenticatedSetup;

use super::{
	Reader, SignedManifest, WitnessError, ACK_MESSAGE_TYPE, MAX_MESSAGE_LEN, PROVISION_MESSAGE_TYPE,
};

const MAX_REFUSAL_BYTES: usize = MAX_MESSAGE_LEN - 2 - 16 - 1 - 2;

/// Immutable `ff_witness_provision`: one request identity and its exact signed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provision {
	request_id: [u8; 16],
	manifest: SignedManifest,
}

impl Provision {
	/// Associate a freshly allocated request ID with an already authenticated manifest.
	///
	/// Keep this exact value through uncertain send results. The caller must persist its manifest
	/// and protected recovery keys before transport. Constructing a request performs no I/O.
	pub fn new(request_id: [u8; 16], manifest: SignedManifest) -> Self {
		Self { request_id, manifest }
	}

	/// Decode the complete BOLT 8 plaintext, including type, against the receiver's own setup.
	pub fn decode(bytes: &[u8], setup: &AuthenticatedSetup) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_MESSAGE_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		if reader.u16()? != PROVISION_MESSAGE_TYPE {
			return Err(WitnessError::MessageType);
		}
		let request_id = reader.array()?;
		let manifest = SignedManifest::decode(reader.0, setup)?;
		Ok(Self { request_id, manifest })
	}

	/// Canonical type, request identity and exact signed manifest bytes.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&PROVISION_MESSAGE_TYPE.to_be_bytes());
		bytes.extend_from_slice(&self.request_id);
		bytes.extend_from_slice(&self.manifest.encode());
		bytes
	}

	/// Request identity that an acknowledgement must echo exactly.
	pub fn request_id(&self) -> [u8; 16] {
		self.request_id
	}

	/// Immutable manifest whose acknowledgement is being requested.
	pub fn manifest(&self) -> &SignedManifest {
		&self.manifest
	}
}

/// The witness's unsigned response, requiring authenticated transport correlation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcknowledgementResult {
	/// Claimed witness identity and record retention promise.
	Accepted {
		/// Must equal both the requested witness and the actual authenticated response peer.
		witness: PublicKey,
		/// Must be at least the pending manifest's retention promise.
		retention_until: u32,
	},
	/// Bounded opaque diagnostic bytes.
	Refused(Vec<u8>),
}

/// Canonical `ff_witness_ack`, which alone proves neither identity nor storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acknowledgement {
	request_id: [u8; 16],
	result: AcknowledgementResult,
}

impl Acknowledgement {
	/// Construct a bounded response; success identity is still an unauthenticated claim here.
	pub fn new(request_id: [u8; 16], result: AcknowledgementResult) -> Result<Self, WitnessError> {
		if matches!(&result, AcknowledgementResult::Refused(error) if error.len() > MAX_REFUSAL_BYTES)
		{
			return Err(WitnessError::SizeLimit);
		}
		Ok(Self { request_id, result })
	}

	/// Decode complete plaintext with a strict 0/1 result and no trailing extension fields.
	pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_MESSAGE_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		if reader.u16()? != ACK_MESSAGE_TYPE {
			return Err(WitnessError::MessageType);
		}
		let request_id = reader.array()?;
		let result = match reader.byte()? {
			1 => AcknowledgementResult::Accepted {
				witness: reader.public_key()?,
				retention_until: reader.u32()?,
			},
			0 => {
				let length = reader.u16()? as usize;
				AcknowledgementResult::Refused(reader.take(length)?.to_vec())
			},
			_ => return Err(WitnessError::NonCanonical),
		};
		reader.finish()?;
		Self::new(request_id, result)
	}

	/// Canonical acknowledgement, including its two-byte type.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&ACK_MESSAGE_TYPE.to_be_bytes());
		bytes.extend_from_slice(&self.request_id);
		match &self.result {
			AcknowledgementResult::Accepted { witness, retention_until } => {
				bytes.push(1);
				bytes.extend_from_slice(&witness.serialize());
				bytes.extend_from_slice(&retention_until.to_be_bytes());
			},
			AcknowledgementResult::Refused(error) => {
				bytes.push(0);
				bytes.extend_from_slice(&(error.len() as u16).to_be_bytes());
				bytes.extend_from_slice(error);
			},
		}
		bytes
	}

	/// The response correlation identifier, not part of a signature.
	pub fn request_id(&self) -> [u8; 16] {
		self.request_id
	}

	/// The untrusted success claim or bounded refusal.
	pub fn result(&self) -> &AcknowledgementResult {
		&self.result
	}
}
