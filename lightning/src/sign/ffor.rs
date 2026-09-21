//! Domain-bound signing requests for the experimental FFOR Variant D protocol.
//!
//! This module constructs no protocol messages and owns no channel transitions. The protocol
//! adapter must validate canonical fields and lifecycle authority before using the node signer.

use bitcoin::hashes::{sha256, Hash, HashEngine};

/// A bounded FFOR signing request containing the wire type and complete unsigned body.
///
/// Construction checks only the allowed message type and envelope bounds. It does not parse
/// protocol fields, authenticate a peer, or authorize a channel transition. Bytes are borrowed
/// immutably so they cannot change between signer inspection and digest construction.
///
/// Use [`crate::sign::NodeSigner::sign_ffor_message`] to keep private key material in the signer.
pub struct FFORSigningRequest<'a> {
	unsigned_wire: &'a [u8],
}

impl<'a> FFORSigningRequest<'a> {
	/// Check the unsigned envelope's type and bounds before sending it to a signer.
	///
	/// `unsigned_wire` contains the two-byte message type, the channel and epoch IDs, and all
	/// canonical fields/TLVs, excluding the final 64-byte signature. Only the seven signed Variant
	/// D setup and lifecycle message types are accepted. The completed message must fit BOLT 8's
	/// 65,535-byte plaintext limit. Callers must separately validate the full protocol structure.
	pub fn new(unsigned_wire: &'a [u8]) -> Result<Self, ()> {
		if unsigned_wire.len() < 2 + 32 + 32 || unsigned_wire.len() > 65_535 - 64 {
			return Err(());
		}
		let message_type = u16::from_be_bytes([unsigned_wire[0], unsigned_wire[1]]);
		if !matches!(message_type, 55001 | 55003 | 55045 | 55047 | 55049 | 55051 | 55053) {
			return Err(());
		}
		Ok(Self { unsigned_wire })
	}

	/// The exact type and body that a signer may inspect against its own policy.
	pub fn unsigned_wire(&self) -> &'a [u8] {
		self.unsigned_wire
	}

	/// The single SHA256 digest specified by FFOR section 7: `SHA256("ffor/msg" || wire)`.
	///
	/// The wire already includes its two-byte type. No Lightning signed-message prefix, double
	/// hash, tagged-hash construction or signature bytes are included.
	pub fn digest(&self) -> [u8; 32] {
		let mut engine = sha256::Hash::engine();
		engine.input(b"ffor/msg");
		engine.input(self.unsigned_wire);
		sha256::Hash::from_engine(engine).to_byte_array()
	}
}

#[cfg(test)]
mod tests {
	use super::FFORSigningRequest;
	use crate::prelude::*;
	use crate::sign::{KeysManager, NodeSigner, PhantomKeysManager, Recipient};
	use crate::util::test_utils::TestNodeSigner;
	use bitcoin::hashes::{sha256, sha256d, Hash};
	use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

	// Public Appendix D.1 ff_activate, FFOR d719161f42d1eeb6bd6c3856d564222f03c2205e.
	// The published signature is verified here; this fixture contains no signing key.
	const ACTIVATE: &str = "d705bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15ba34be8afe89e4457543a6e7279f86054f1d6e9038234b786b740e9c905c001f8ae276dd460c7b2030287a608677bc51eb9cdef5b7cfc1f73d005e463076510a723024696ad20b4758b228284620d18fd30750b7051cc64efca23a1417cf1321000c0df003aa4c0c160338dfb3783120761fb4a6053836307e196fe3597032f28715b9a021074ec06ceb9c5f06af9854f8b21ff1b6b74ff3ae326a049de8270f2c8dc559";

	fn hex(value: &str) -> Vec<u8> {
		(0..value.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
			.collect()
	}

	#[test]
	fn published_activation_uses_the_exact_single_hash_domain() {
		let wire = hex(ACTIVATE);
		let unsigned = &wire[..wire.len() - 64];
		let request = FFORSigningRequest::new(unsigned).unwrap();
		assert_eq!(request.unsigned_wire(), unsigned);
		assert_eq!(
			request.digest().as_slice(),
			hex("678df08e2efce5c2ac54c389dbf8df5e3846ccbd6ca78301e2bf6ac925716ebc")
		);
		let signature = Signature::from_compact(&wire[wire.len() - 64..]).unwrap();
		let receiver = PublicKey::from_slice(&hex(
			"039fca7f8157aa768708894ffd92550fe970edd18526a5f936583ea3b54dab3228",
		))
		.unwrap();
		let secp = Secp256k1::verification_only();
		secp.verify_ecdsa(&Message::from_digest(request.digest()), &signature, &receiver).unwrap();
		let mut changed = unsigned.to_vec();
		changed[1] ^= 2;
		let wrong_type = FFORSigningRequest::new(&changed).unwrap();
		assert!(secp
			.verify_ecdsa(&Message::from_digest(wrong_type.digest()), &signature, &receiver)
			.is_err());
		let mut wrong_domain = b"Lightning Signed Message:".to_vec();
		wrong_domain.extend_from_slice(unsigned);
		assert!(secp
			.verify_ecdsa(
				&Message::from_digest(sha256::Hash::hash(&wrong_domain).to_byte_array()),
				&signature,
				&receiver
			)
			.is_err());
		let mut double_hash = b"ffor/msg".to_vec();
		double_hash.extend_from_slice(unsigned);
		assert!(secp
			.verify_ecdsa(
				&Message::from_digest(sha256d::Hash::hash(&double_hash).to_byte_array()),
				&signature,
				&receiver
			)
			.is_err());
	}

	#[test]
	fn signer_uses_local_identity_and_low_s_with_no_key_export() {
		let wire = hex(ACTIVATE);
		let request = FFORSigningRequest::new(&wire[..wire.len() - 64]).unwrap();
		let keys = KeysManager::new(&[7; 32], 0, 0, true);
		let phantom = PhantomKeysManager::new(&[7; 32], 0, 0, &[9; 32], true);
		let secp = Secp256k1::verification_only();
		let digest = Message::from_digest(request.digest());
		for signer in [&keys as &dyn NodeSigner, &phantom as &dyn NodeSigner] {
			let signature = signer.sign_ffor_message(&request).unwrap();
			let mut normalized = signature;
			normalized.normalize_s();
			assert_eq!(signature, normalized);
			let identity = signer.get_node_id(Recipient::Node).unwrap();
			secp.verify_ecdsa(&digest, &signature, &identity).unwrap();
			assert!(secp
				.verify_ecdsa(
					&digest,
					&signature,
					&phantom.get_node_id(Recipient::PhantomNode).unwrap()
				)
				.is_err());
		}
	}

	#[test]
	fn unsupported_signers_and_invalid_envelopes_fail_without_signing() {
		let wire = hex(ACTIVATE);
		let unsigned = &wire[..wire.len() - 64];
		let request = FFORSigningRequest::new(unsigned).unwrap();
		let external = TestNodeSigner::new(SecretKey::from_slice(&[1; 32]).unwrap());
		assert!(external.sign_ffor_message(&request).is_err());
		for length in 0..66 {
			assert!(FFORSigningRequest::new(&unsigned[..length]).is_err());
		}
		let mut bytes = vec![0; 65_535 - 64 + 1];
		bytes[..2].copy_from_slice(&55001_u16.to_be_bytes());
		assert!(FFORSigningRequest::new(&bytes).is_err());
		bytes.pop();
		assert!(FFORSigningRequest::new(&bytes).is_ok());
		for message_type in 0_u16..=u16::MAX {
			bytes[..2].copy_from_slice(&message_type.to_be_bytes());
			assert_eq!(
				FFORSigningRequest::new(&bytes).is_ok(),
				matches!(message_type, 55001 | 55003 | 55045 | 55047 | 55049 | 55051 | 55053)
			);
		}
	}
}
