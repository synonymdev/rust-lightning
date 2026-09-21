use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;

use super::{
	EncryptedRecord, Reader, WitnessError, FETCH_MESSAGE_TYPE, FETCH_RESPONSE_MESSAGE_TYPE,
	MAX_MESSAGE_LEN,
};
use crate::transcript;
use crate::wire::{tlv, Tlv};

/// Public fetch fields. Fresh nonces authorize each page independently; request IDs only correlate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchParameters {
	/// Transport correlation identity, intentionally outside the fetch signature domain.
	pub request_id: [u8; 16],
	/// Mailbox selected in the retained signed manifest.
	pub mailbox_id: [u8; 32],
	/// Fresh nonce that the witness must never accept twice for this mailbox.
	pub nonce: [u8; 32],
	/// Exclusive lower slot bound. Absence means zero and has a distinct signed encoding.
	pub after_slot: Option<u16>,
	/// Canonical unknown odd TLVs, retained exactly and covered by the request signature.
	pub extensions: Vec<Tlv>,
}

/// Canonical fetch request awaiting an external fetch-key signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedFetch {
	parameters: FetchParameters,
	tlvs: Vec<u8>,
}

impl UnsignedFetch {
	/// Validate all TLVs and the completed signed message size without accessing a key.
	pub fn new(parameters: FetchParameters) -> Result<Self, WitnessError> {
		let tlvs = encode_paging(parameters.after_slot, &parameters.extensions)?;
		if 2 + 16 + 32 + 32 + 64 + tlvs.len() > MAX_MESSAGE_LEN {
			return Err(WitnessError::SizeLimit);
		}
		Ok(Self { parameters, tlvs })
	}

	/// Exact immutable fields whose mailbox, nonce and TLVs will be signed.
	pub fn parameters(&self) -> &FetchParameters {
		&self.parameters
	}

	/// Single SHA256 of `ffor/witness/fetch || mailbox_id || nonce || trailing_tlvs`.
	/// Neither the two-byte wire type nor request_id is included by Appendix F.1.
	pub fn signing_digest(&self) -> [u8; 32] {
		transcript::hash_parts(
			b"ffor/witness/fetch",
			&[&self.parameters.mailbox_id, &self.parameters.nonce, &self.tlvs],
		)
	}

	/// Validate an external compact low-S signature using the mailbox's expected fetch key.
	pub fn authenticate(
		self, signature: [u8; 64], expected_fetch_key: PublicKey,
	) -> Result<SignedFetch, WitnessError> {
		transcript::verify_digest_signature(
			self.signing_digest(),
			&signature,
			&expected_fetch_key,
		)?;
		Ok(SignedFetch { request: self, signature, fetch_key: expected_fetch_key })
	}
}

/// Canonical fetch authorized by a supplied fetch key, not by the request's Noise peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFetch {
	request: UnsignedFetch,
	signature: [u8; 64],
	fetch_key: PublicKey,
}

impl SignedFetch {
	/// Decode the complete wire message and authenticate against a trusted mailbox fetch key.
	pub fn decode(bytes: &[u8], expected_fetch_key: PublicKey) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_MESSAGE_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		if reader.u16()? != FETCH_MESSAGE_TYPE {
			return Err(WitnessError::MessageType);
		}
		let request_id = reader.array()?;
		let mailbox_id = reader.array()?;
		let nonce = reader.array()?;
		let signature = reader.array()?;
		let (after_slot, extensions) = decode_paging(reader.0)?;
		UnsignedFetch::new(FetchParameters {
			request_id,
			mailbox_id,
			nonce,
			after_slot,
			extensions,
		})?
		.authenticate(signature, expected_fetch_key)
	}

	/// Exact original canonical request, including its correlation ID and compact signature.
	pub fn encode(&self) -> Vec<u8> {
		let p = self.request.parameters();
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&FETCH_MESSAGE_TYPE.to_be_bytes());
		bytes.extend_from_slice(&p.request_id);
		bytes.extend_from_slice(&p.mailbox_id);
		bytes.extend_from_slice(&p.nonce);
		bytes.extend_from_slice(&self.signature);
		bytes.extend_from_slice(&self.request.tlvs);
		bytes
	}

	/// Immutable canonical request fields and signing domain.
	pub fn unsigned(&self) -> &UnsignedFetch {
		&self.request
	}
	/// The trusted public key under which this request was checked.
	pub fn fetch_key(&self) -> PublicKey {
		self.fetch_key
	}
}

/// Unsigned response fields. Every returned record still needs expected-manifest correlation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchResult {
	/// One ascending page, with a cursor only when records remain above the last returned slot.
	Page {
		/// Bounded individually signed encrypted records.
		records: Vec<EncryptedRecord>,
		/// The last returned slot if another page is available.
		next_after_slot: Option<u16>,
		/// Canonical unknown odd response TLVs, preserved without granting semantics.
		extensions: Vec<Tlv>,
	},
	/// Bounded opaque diagnostic bytes, with no trailing TLV stream.
	Refused(Vec<u8>),
}

/// Canonical `ff_witness_fetch_resp`. Noise connection and request correlation remain mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchResponse {
	request_id: [u8; 16],
	result: FetchResult,
}

impl FetchResponse {
	/// Construct a response bounded by one complete BOLT 8 plaintext frame.
	pub fn new(request_id: [u8; 16], result: FetchResult) -> Result<Self, WitnessError> {
		let response = Self { request_id, result };
		response.encode_checked()?;
		Ok(response)
	}

	/// Parse strict 0/1 status, record counts, record framing and canonical pagination TLVs.
	pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
		if bytes.len() > MAX_MESSAGE_LEN {
			return Err(WitnessError::SizeLimit);
		}
		let mut reader = Reader(bytes);
		if reader.u16()? != FETCH_RESPONSE_MESSAGE_TYPE {
			return Err(WitnessError::MessageType);
		}
		let request_id = reader.array()?;
		let result = match reader.byte()? {
			0 => {
				let length = usize::from(reader.u16()?);
				let error = reader.take(length)?.to_vec();
				reader.finish()?;
				FetchResult::Refused(error)
			},
			1 => {
				let count = usize::from(reader.u16()?);
				if count > crate::book::MAX_VOUCHERS {
					return Err(WitnessError::SizeLimit);
				}
				let mut records = Vec::new();
				for _ in 0..count {
					let length = usize::from(reader.u16()?);
					records.push(EncryptedRecord::decode(reader.take(length)?)?);
				}
				let (next_after_slot, extensions) = decode_paging(reader.0)?;
				FetchResult::Page { records, next_after_slot, extensions }
			},
			_ => return Err(WitnessError::NonCanonical),
		};
		Self::new(request_id, result)
	}

	/// Exact canonical response bytes. Construction already bounded every field.
	pub fn encode(&self) -> Vec<u8> {
		self.encode_checked().expect("invariant: immutable response was bounded on construction")
	}
	/// Echo of the pending request's unsigned correlation identity.
	pub fn request_id(&self) -> [u8; 16] {
		self.request_id
	}
	/// Uncorrelated response contents; no plaintext or payment is established.
	pub fn result(&self) -> &FetchResult {
		&self.result
	}

	fn encode_checked(&self) -> Result<Vec<u8>, WitnessError> {
		let mut writer = tlv::Writer::new();
		writer.u16(FETCH_RESPONSE_MESSAGE_TYPE)?;
		writer.put(&self.request_id)?;
		match &self.result {
			FetchResult::Refused(error) => {
				if error.len() > MAX_MESSAGE_LEN - 21 {
					return Err(WitnessError::SizeLimit);
				}
				writer.put(&[0])?;
				writer.u16(error.len() as u16)?;
				writer.put(error)?;
			},
			FetchResult::Page { records, next_after_slot, extensions } => {
				if records.len() > crate::book::MAX_VOUCHERS {
					return Err(WitnessError::SizeLimit);
				}
				writer.put(&[1])?;
				writer.u16(records.len() as u16)?;
				for record in records {
					let bytes = record.encode();
					writer.u16(bytes.len() as u16)?;
					writer.put(&bytes)?;
				}
				writer.put(&encode_paging(*next_after_slot, extensions)?)?;
			},
		}
		Ok(writer.0)
	}
}

fn encode_paging(slot: Option<u16>, extensions: &[Tlv]) -> Result<Vec<u8>, WitnessError> {
	let known =
		slot.map(|slot| Tlv { kind: 1, value: slot.to_be_bytes().to_vec() }).into_iter().collect();
	let mut writer = tlv::Writer::new();
	// TLV 1 is reserved even when omitted, never an unknown extension.
	if extensions.iter().any(|entry| entry.kind == 1) {
		return Err(WitnessError::NonCanonical);
	}
	tlv::write_tlvs(&mut writer, known, extensions)?;
	Ok(writer.0)
}

fn decode_paging(bytes: &[u8]) -> Result<(Option<u16>, Vec<Tlv>), WitnessError> {
	let mut entries = tlv::read_tlvs(&mut tlv::Reader::new(bytes))?;
	let slot = tlv::optional(&mut entries, 1)
		.map(|value| tlv::fixed::<2>(value, 1).map(u16::from_be_bytes))
		.transpose()?;
	tlv::check_extensions(&entries)?;
	Ok((slot, entries))
}
