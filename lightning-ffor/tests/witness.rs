use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message as SecpMessage, PublicKey, Secp256k1, SecretKey};
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Accept, Header, Init, Message, Payload};
use lightning_ffor::witness::{
	Acknowledgement, AcknowledgementResult, PendingProvision, Provision, SignedManifest,
	UnsignedManifest, WitnessConnection, WitnessError, MAX_MESSAGE_LEN, RETENTION_MARGIN_BLOCKS,
};
use proptest::prelude::*;
use serde::Deserialize;

#[path = "witness/fetch.rs"]
mod fetch;

fn hex(value: &str) -> Vec<u8> {
	(0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

fn key(value: u8) -> PublicKey {
	PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[value; 32]).unwrap())
}

fn signature(digest: [u8; 32], signer: u8) -> [u8; 64] {
	Secp256k1::new()
		.sign_ecdsa(
			&SecpMessage::from_digest(digest),
			&SecretKey::from_slice(&[signer; 32]).unwrap(),
		)
		.serialize_compact()
}

#[derive(Deserialize)]
struct Appendix {
	init_wire: String,
	accept_wire: String,
}

fn public_setup(index: usize) -> AuthenticatedSetup {
	let fixtures: Vec<Appendix> =
		serde_json::from_str(include_str!("data/appendix-d.json")).unwrap();
	let input = &fixtures[index];
	AuthenticatedSetup::new(
		&Message::decode(&hex(&input.init_wire)).unwrap(),
		&Message::decode(&hex(&input.accept_wire)).unwrap(),
		PublicKey::from_slice(&hex(
			"039fca7f8157aa768708894ffd92550fe970edd18526a5f936583ea3b54dab3228",
		))
		.unwrap(),
		PublicKey::from_slice(&hex(
			"02087b7d1b4789170f6e374f0a0e58a1b7a899e34929795314ab6964e69609e9c0",
		))
		.unwrap(),
	)
	.unwrap()
}

#[derive(Deserialize)]
struct Reference {
	source_revision: String,
	specification_revision: String,
	source_file: String,
	appendix_d_sha256: String,
	fetch_public_key: String,
	encryption_public_key: String,
	witness_public_key: String,
	fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
	scenario: String,
	unsigned: String,
	digest: String,
	manifest: String,
	provision: String,
	acknowledgement: String,
	refusal: String,
}

fn reference() -> Reference {
	serde_json::from_str(include_str!("data/beignet-witness.json")).unwrap()
}

fn manifest() -> SignedManifest {
	SignedManifest::decode(&hex(&reference().fixtures[0].manifest), &public_setup(0)).unwrap()
}

fn synthetic_setup(slots: usize, expiry: u32) -> AuthenticatedSetup {
	let mut init = Message {
		header: Header { channel_id: [1; 32], epoch_id: [2; 32] },
		payload: Payload::Init(Init {
			budget_msat: 1_000_000 * slots as u64,
			min_payment_msat: 1_000_000,
			settlement_deadline: 100,
			voucher_expiry: expiry,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			amounts_msat: vec![1_000_000; slots],
			witness_peers: None,
			hash_chain: false,
		}),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	init.signature = signature(init.signature_digest().unwrap(), 42);
	let mut accept = Message {
		header: init.header,
		payload: Payload::Accept(Accept {
			s_commitment_number: 3,
			payment_hashes: (0..slots)
				.map(|index| sha256::Hash::hash(&(index as u64).to_be_bytes()).to_byte_array())
				.collect(),
			s_htlc_id_base: 0,
			amounts_msat: vec![1_000_000; slots],
			init_hash: transcript::init_hash(&init.encode().unwrap()),
		}),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	accept.signature = signature(accept.signature_digest().unwrap(), 43);
	AuthenticatedSetup::new(&init, &accept, key(42), key(43)).unwrap()
}

#[test]
fn beignet_manifests_provisions_and_acknowledgements_preserve_exact_bytes() {
	let reference = reference();
	assert_eq!(reference.source_revision, "8aee31d18e596fe49a0d195b325a6e757d7a009b");
	assert_eq!(reference.specification_revision, "d719161f42d1eeb6bd6c3856d564222f03c2205e");
	assert_eq!(reference.source_file, "src/lightning/ffor/witness-messages.ts");
	assert_eq!(
		hex(&reference.appendix_d_sha256),
		sha256::Hash::hash(include_bytes!("data/appendix-d.json")).to_byte_array()
	);
	assert_eq!(hex(&reference.fetch_public_key), key(42).serialize());
	assert_eq!(hex(&reference.encryption_public_key), key(44).serialize());
	assert_eq!(hex(&reference.witness_public_key), key(43).serialize());
	assert_eq!(reference.fixtures.len(), 6);
	for (index, fixture) in reference.fixtures.iter().enumerate() {
		let setup = public_setup(index);
		let manifest = SignedManifest::decode(&hex(&fixture.manifest), &setup).unwrap();
		assert_eq!(manifest.encode(), hex(&fixture.manifest), "{}", fixture.scenario);
		assert_eq!(manifest.unsigned().unsigned_bytes(), hex(&fixture.unsigned));
		assert_eq!(manifest.unsigned().signing_digest().as_slice(), hex(&fixture.digest));
		assert_eq!(manifest.unsigned().canonical_book(), setup.canonical_book());
		assert_eq!(manifest.unsigned().setup_hash(), setup.setup_hash());
		let provision = Provision::decode(&hex(&fixture.provision), &setup).unwrap();
		assert_eq!(provision.encode(), hex(&fixture.provision));
		assert_eq!(provision.manifest(), &manifest);
		for wire in [&fixture.acknowledgement, &fixture.refusal] {
			assert_eq!(Acknowledgement::decode(&hex(wire)).unwrap().encode(), hex(wire));
		}
	}
}

#[test]
fn manifest_rejects_every_truncated_prefix_unknown_fields_and_bad_points() {
	let fixture = &reference().fixtures[0];
	let setup = public_setup(0);
	let wire = hex(&fixture.manifest);
	for length in 0..wire.len() {
		assert!(SignedManifest::decode(&wire[..length], &setup).is_err(), "prefix {length}");
	}
	for (offset, value, expected) in [
		(0, 2, WitnessError::Version),
		(1, 4, WitnessError::Profile),
		(134, 0, WitnessError::PublicKey),
		(167, 0, WitnessError::PublicKey),
	] {
		let mut damaged = wire.clone();
		damaged[offset] = value;
		assert_eq!(SignedManifest::decode(&damaged, &setup), Err(expected));
	}
	let mut trailing = wire.clone();
	trailing.push(1);
	assert_eq!(SignedManifest::decode(&trailing, &setup), Err(WitnessError::NonCanonical));
	let mut declared = wire.clone();
	declared[205..207].copy_from_slice(&u16::MAX.to_be_bytes());
	assert_eq!(SignedManifest::decode(&declared, &setup), Err(WitnessError::Truncated));
	assert_eq!(
		SignedManifest::decode(&vec![0; MAX_MESSAGE_LEN], &setup),
		Err(WitnessError::SizeLimit)
	);
	let provision = hex(&fixture.provision);
	for length in 0..provision.len() {
		assert!(Provision::decode(&provision[..length], &setup).is_err());
	}
	let mut wrong_type = provision;
	wrong_type[1] ^= 1;
	assert_eq!(Provision::decode(&wrong_type, &setup), Err(WitnessError::MessageType));
	assert_eq!(
		Provision::decode(&vec![0; MAX_MESSAGE_LEN + 1], &setup),
		Err(WitnessError::SizeLimit)
	);
}

#[test]
fn manifest_binds_setup_book_activation_and_fetch_signature_domain() {
	let setup = public_setup(0);
	let valid = manifest();
	for (offset, expected) in [
		(34, WitnessError::Transcript),
		(66, WitnessError::Transcript),
		(102, WitnessError::Transcript),
		(207, WitnessError::Book),
		(243, WitnessError::Book),
	] {
		let mut damaged = valid.encode();
		damaged[offset] ^= 1;
		assert_eq!(SignedManifest::decode(&damaged, &setup), Err(expected));
	}
	assert_eq!(SignedManifest::decode(&valid.encode(), &public_setup(1)), Err(WitnessError::Book));
	let unsigned = valid.unsigned().clone();
	assert!(unsigned.clone().authenticate(signature(unsigned.signing_digest(), 43)).is_err());
	let wrong_domain = transcript::message_digest(55055, &unsigned.unsigned_bytes());
	assert!(unsigned.clone().authenticate(signature(wrong_domain, 42)).is_err());
	let zero = [0; 64];
	assert!(unsigned.clone().authenticate(zero).is_err());
	let mut zero_r = *valid.signature();
	zero_r[..32].fill(0);
	assert!(unsigned.clone().authenticate(zero_r).is_err());
	let mut zero_s = *valid.signature();
	zero_s[32..].fill(0);
	assert!(unsigned.clone().authenticate(zero_s).is_err());
	let mut invalid = *valid.signature();
	invalid[..32].fill(255);
	assert!(unsigned.clone().authenticate(invalid).is_err());
	let mut high = *valid.signature();
	let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
	let mut borrow = 0_i16;
	for index in (0..32).rev() {
		let difference = order[index] as i16 - high[32 + index] as i16 - borrow;
		high[32 + index] = difference as u8;
		borrow = i16::from(difference < 0);
	}
	assert_eq!(
		unsigned.authenticate(high),
		Err(WitnessError::Signature(transcript::SignatureError::HighS))
	);
}

#[test]
fn retention_and_activation_height_boundaries_use_checked_arithmetic() {
	let setup = public_setup(0);
	let valid = manifest();
	let mut parameters = *valid.unsigned().parameters();
	assert_eq!(parameters.retention_until, setup.terms().voucher_expiry + RETENTION_MARGIN_BLOCKS);
	parameters.retention_until -= 1;
	assert_eq!(UnsignedManifest::new(&setup, parameters), Err(WitnessError::Retention));
	parameters.retention_until = u32::MAX;
	assert!(UnsignedManifest::new(&setup, parameters).is_ok());
	parameters.epoch_start_height = setup.terms().settlement_deadline;
	assert_eq!(UnsignedManifest::new(&setup, parameters), Err(WitnessError::Height));
	parameters.epoch_start_height -= 1;
	assert!(UnsignedManifest::new(&setup, parameters).is_ok());
	parameters.epoch_start_height = 50;
	assert_eq!(
		UnsignedManifest::new(&synthetic_setup(1, u32::MAX), parameters),
		Err(WitnessError::Height)
	);
	let height_setup = synthetic_setup(1, 499_999_999);
	let height_manifest = UnsignedManifest::new(&height_setup, parameters).unwrap();
	for expiry in [500_000_000, u32::MAX] {
		let timestamp_setup = synthetic_setup(1, expiry);
		assert_eq!(UnsignedManifest::new(&timestamp_setup, parameters), Err(WitnessError::Height));
		// A previously signed manifest with matching timestamp-style setup must also fail restore.
		let mut encoded = height_manifest.unsigned_bytes();
		encoded[34..66].copy_from_slice(&timestamp_setup.setup_hash());
		encoded[102..134].copy_from_slice(&transcript::activation_hash(
			&timestamp_setup.setup_hash(),
			&timestamp_setup.book_hash(),
			&parameters.commitment_hash,
			parameters.epoch_start_height,
		));
		encoded[207..].copy_from_slice(timestamp_setup.canonical_book());
		let mut digest_input = b"ffor/witness/manifest".to_vec();
		digest_input.extend_from_slice(&encoded);
		encoded
			.extend_from_slice(&signature(sha256::Hash::hash(&digest_input).to_byte_array(), 42));
		assert_eq!(SignedManifest::decode(&encoded, &timestamp_setup), Err(WitnessError::Height));
	}
	let mut bytes = valid.encode();
	bytes[200..204].copy_from_slice(&(setup.terms().voucher_expiry + 143).to_be_bytes());
	assert_eq!(SignedManifest::decode(&bytes, &setup), Err(WitnessError::Retention));
}

#[test]
fn maximum_book_and_receipt_count_remain_bounded_and_roundtrip() {
	let setup = synthetic_setup(483, 1108);
	let mut parameters = *manifest().unsigned().parameters();
	parameters.epoch_start_height = 50;
	parameters.retention_until = 1252;
	parameters.minimum_receipts = 255;
	let unsigned = UnsignedManifest::new(&setup, parameters).unwrap();
	let signed = unsigned.clone().authenticate(signature(unsigned.signing_digest(), 42)).unwrap();
	let provision = Provision::new([5; 16], signed);
	assert!(provision.encode().len() < MAX_MESSAGE_LEN);
	assert_eq!(Provision::decode(&provision.encode(), &setup).unwrap(), provision);
}

#[test]
fn acknowledgement_codec_rejects_invalid_flags_points_lengths_and_extensions() {
	for encoded in [&reference().fixtures[0].acknowledgement, &reference().fixtures[0].refusal] {
		let bytes = hex(encoded);
		for length in 0..bytes.len() {
			assert!(Acknowledgement::decode(&bytes[..length]).is_err());
		}
		let mut trailing = bytes.clone();
		trailing.push(0);
		assert_eq!(Acknowledgement::decode(&trailing), Err(WitnessError::NonCanonical));
		let mut flag = bytes.clone();
		flag[18] = 2;
		assert_eq!(Acknowledgement::decode(&flag), Err(WitnessError::NonCanonical));
		let mut kind = bytes;
		kind[0] = 0;
		assert_eq!(Acknowledgement::decode(&kind), Err(WitnessError::MessageType));
	}
	let mut bad_key = hex(&reference().fixtures[0].acknowledgement);
	bad_key[19] = 0;
	assert_eq!(Acknowledgement::decode(&bad_key), Err(WitnessError::PublicKey));
	let limit = MAX_MESSAGE_LEN - 21;
	let max =
		Acknowledgement::new([0; 16], AcknowledgementResult::Refused(vec![255; limit])).unwrap();
	assert_eq!(max.encode().len(), MAX_MESSAGE_LEN);
	assert_eq!(Acknowledgement::decode(&max.encode()).unwrap(), max);
	assert_eq!(
		Acknowledgement::new([0; 16], AcknowledgementResult::Refused(vec![0; limit + 1])),
		Err(WitnessError::SizeLimit)
	);
	assert_eq!(
		Acknowledgement::decode(&vec![0; MAX_MESSAGE_LEN + 1]),
		Err(WitnessError::SizeLimit)
	);
}

#[test]
fn checked_acknowledgement_requires_exact_request_witness_connection_and_promise() {
	let fixture = &reference().fixtures[0];
	let provision = Provision::decode(&hex(&fixture.provision), &public_setup(0)).unwrap();
	let source = WitnessConnection { node_id: key(43), identity: 7_u64 };
	let pending = PendingProvision::new(provision.clone(), source.clone());
	let ack = Acknowledgement::decode(&hex(&fixture.acknowledgement)).unwrap();
	let checked = pending.check_acknowledgement(&ack, &source).unwrap();
	assert_eq!(checked.provision(), &provision);
	assert_eq!(checked.connection(), pending.connection());
	assert_eq!(
		checked.retention_until(),
		provision.manifest().unsigned().parameters().retention_until
	);
	let wrong_id = Acknowledgement::new([99; 16], ack.result().clone()).unwrap();
	assert_eq!(pending.check_acknowledgement(&wrong_id, &source), Err(WitnessError::Request));
	let mut reconnect = source.clone();
	reconnect.identity += 1;
	assert_eq!(pending.check_acknowledgement(&ack, &reconnect), Err(WitnessError::Connection));
	let mut other_peer = source.clone();
	other_peer.node_id = key(44);
	assert_eq!(pending.check_acknowledgement(&ack, &other_peer), Err(WitnessError::Witness));
	for (witness, retention_until, expected) in [
		(key(44), checked.retention_until(), WitnessError::Witness),
		(key(43), checked.retention_until() - 1, WitnessError::Retention),
	] {
		let changed = Acknowledgement::new(
			ack.request_id(),
			AcknowledgementResult::Accepted { witness, retention_until },
		)
		.unwrap();
		assert_eq!(pending.check_acknowledgement(&changed, &source), Err(expected));
	}
	let refused = Acknowledgement::decode(&hex(&fixture.refusal)).unwrap();
	assert_eq!(pending.check_acknowledgement(&refused, &source), Err(WitnessError::Refused));
	// All failures leave the exact pending request available for an authenticated retry.
	assert_eq!(pending.check_acknowledgement(&ack, &source).unwrap(), checked);
	let another =
		Provision::decode(&hex(&reference().fixtures[1].provision), &public_setup(1)).unwrap();
	assert_ne!(checked.provision().manifest(), another.manifest());
	// Sufficient retention means the exact requested promise, including any extra local margin.
	let mut parameters = *provision.manifest().unsigned().parameters();
	parameters.retention_until += 100;
	parameters.mailbox_id[0] ^= 1;
	let unsigned = UnsignedManifest::new(&public_setup(0), parameters).unwrap();
	let signed = unsigned.clone().authenticate(signature(unsigned.signing_digest(), 42)).unwrap();
	let another_request = Provision::new([88; 16], signed);
	let stronger = PendingProvision::new(another_request.clone(), source.clone());
	let too_short =
		Acknowledgement::new(another_request.request_id(), ack.result().clone()).unwrap();
	assert_eq!(stronger.check_acknowledgement(&too_short, &source), Err(WitnessError::Retention));
	let sufficient = Acknowledgement::new(
		another_request.request_id(),
		AcknowledgementResult::Accepted {
			witness: source.node_id,
			retention_until: parameters.retention_until,
		},
	)
	.unwrap();
	let second_checked = stronger.check_acknowledgement(&sufficient, &source).unwrap();
	assert_eq!(second_checked.provision(), &another_request);
	assert_ne!(second_checked.provision().manifest(), checked.provision().manifest());
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(64))]
	#[test]
	fn arbitrary_bounded_inputs_decode_canonically(bytes in prop::collection::vec(any::<u8>(), 0..=MAX_MESSAGE_LEN + 1)) {
		let setup = public_setup(0);
		if let Ok(value) = SignedManifest::decode(&bytes, &setup) { prop_assert_eq!(&value.encode(), &bytes); }
		if let Ok(value) = Provision::decode(&bytes, &setup) { prop_assert_eq!(&value.encode(), &bytes); }
		if let Ok(value) = Acknowledgement::decode(&bytes) { prop_assert_eq!(&value.encode(), &bytes); }
	}
	#[test]
	fn arbitrary_refusal_bytes_roundtrip(bytes in prop::collection::vec(any::<u8>(), 0..2048), request_id in any::<[u8; 16]>()) {
		let ack = Acknowledgement::new(request_id, AcknowledgementResult::Refused(bytes)).unwrap();
		prop_assert_eq!(Acknowledgement::decode(&ack.encode()).unwrap(), ack);
	}
}
