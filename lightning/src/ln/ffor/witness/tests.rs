use super::*;
use crate::prelude::*;
use bitcoin::secp256k1::Message;
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::wire::Message as WireMessage;
use lightning_ffor::witness::{EncryptedRecord, RECORD_HEADER_LEN};

// Public deterministic Beignet vectors exported by generate_native_witness_fixtures.py.
// The shared tests cover all six scenarios; these pin native ECDH, HKDF and AEAD together.
struct Fixture<'a>(&'a str);

impl Fixture<'_> {
	fn value(&self, name: &str) -> &str {
		self.0
			.lines()
			.find_map(|line| {
				let (key, value) = line.split_once('=')?;
				if key == name {
					Some(value)
				} else {
					None
				}
			})
			.unwrap()
	}
	fn bytes(&self, name: &str) -> Vec<u8> {
		hex(self.value(name))
	}
	fn manifest(&self) -> SignedManifest {
		let receiver = PublicKey::from_slice(&hex(
			"039fca7f8157aa768708894ffd92550fe970edd18526a5f936583ea3b54dab3228",
		))
		.unwrap();
		let settlement = PublicKey::from_slice(&hex(
			"02087b7d1b4789170f6e374f0a0e58a1b7a899e34929795314ab6964e69609e9c0",
		))
		.unwrap();
		let setup = AuthenticatedSetup::new(
			&WireMessage::decode(&self.bytes("init")).unwrap(),
			&WireMessage::decode(&self.bytes("accept")).unwrap(),
			receiver,
			settlement,
		)
		.unwrap();
		SignedManifest::decode(&self.bytes("manifest"), &setup).unwrap()
	}
	fn record(&self) -> AuthenticatedEncryptedRecord {
		authenticate(&self.bytes("record"), &self.manifest())
	}
}

fn fixtures() -> impl Iterator<Item = Fixture<'static>> {
	include_str!("fixtures.txt").trim().split("\n\n").map(Fixture)
}

fn hex(value: &str) -> Vec<u8> {
	(0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

fn secret(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}
fn public(byte: u8) -> PublicKey {
	PublicKey::from_secret_key(&Secp256k1::new(), &secret(byte))
}

fn authenticate(bytes: &[u8], manifest: &SignedManifest) -> AuthenticatedEncryptedRecord {
	EncryptedRecord::decode(bytes).unwrap().authenticate(manifest, public(43)).unwrap()
}

fn sign_record(bytes: &mut [u8]) {
	let digest = sha256::Hash::hash(&[b"ffor/witness/record".as_slice(), &bytes[..235]].concat());
	let signature =
		Secp256k1::new().sign_ecdsa(&Message::from_digest(digest.to_byte_array()), &secret(43));
	bytes[235..299].copy_from_slice(&signature.serialize_compact());
}

fn ciphertext_hash(bytes: &mut [u8]) {
	let hash = sha256::Hash::hash(&bytes[301..301 + CIPHERTEXT_LEN]);
	bytes[203..235].copy_from_slice(hash.as_byte_array());
}

#[test]
fn ffor_witness_decryption_matches_beignet_ecdh_hkdf_aead_and_body() {
	for fixture in fixtures() {
		let manifest = fixture.manifest();
		let record = fixture.record();
		let ephemeral = PublicKey::from_slice(&record.record().ciphertext()[..33]).unwrap();
		let shared = SharedSecret::new(&ephemeral, &secret(44));
		assert_eq!(shared.secret_bytes().as_slice(), fixture.bytes("shared_hash"));
		assert_eq!(body_key(&shared.secret_bytes()).as_slice(), fixture.bytes("body_key"));
		assert_eq!(decrypt_body(&record, &secret(44)).unwrap().as_slice(), fixture.bytes("body"));
		let receipt = decrypt_ffor_witness_record(&record, &manifest, &secret(44)).unwrap();
		assert_eq!(receipt.header(), record.record().header());
		assert_eq!(receipt.body().preimage().as_slice(), &fixture.bytes("body")[34..66]);
		let debug = format!("{:?}", receipt);
		assert!(!debug.contains(&format!("{:?}", &fixture.bytes("body")[34..66])));
		assert_eq!(
			decrypt_ffor_witness_record(&record, &manifest, &secret(45)),
			Err(FFORWitnessDecryptionError::EncryptionKey)
		);
	}
}

#[test]
fn ffor_witness_decryption_rejects_signed_ciphertext_and_aad_substitution() {
	let fixture = fixtures().next().unwrap();
	let manifest = fixture.manifest();
	for offset in [301 + 33, 301 + CIPHERTEXT_LEN - 1, 34, 198, 202] {
		let mut wire = fixture.bytes("record");
		wire[offset] ^= 1;
		ciphertext_hash(&mut wire);
		sign_record(&mut wire);
		let record = authenticate(&wire, &manifest);
		assert_eq!(
			decrypt_ffor_witness_record(&record, &manifest, &secret(44)),
			Err(FFORWitnessDecryptionError::Ciphertext),
			"offset {offset}"
		);
	}
	let mut wire = fixture.bytes("record");
	wire[301..334].copy_from_slice(&public(46).serialize());
	ciphertext_hash(&mut wire);
	sign_record(&mut wire);
	assert_eq!(
		decrypt_ffor_witness_record(&authenticate(&wire, &manifest), &manifest, &secret(44)),
		Err(FFORWitnessDecryptionError::Ciphertext)
	);
}

#[test]
fn ffor_witness_decryption_rejects_a_different_retained_manifest() {
	let fixture = fixtures().next().unwrap();
	let other = fixtures().nth(1).unwrap();
	assert_eq!(
		decrypt_ffor_witness_record(&fixture.record(), &other.manifest(), &secret(44)),
		Err(FFORWitnessDecryptionError::Record(WitnessError::Mailbox))
	);
}

fn reseal(fixture: &Fixture, plaintext: &[u8]) -> AuthenticatedEncryptedRecord {
	let record = fixture.record();
	let mut header = record.record().header().clone();
	let key =
		body_key(&SharedSecret::new(&header.encryption_public_key, &secret(47)).secret_bytes());
	let mut cipher = ChaCha20Poly1305RFC::new(&key, &[0; 12], &header.associated_data());
	let mut encrypted = [0; BODY_LEN];
	let mut tag = [0; 16];
	cipher.encrypt(plaintext, &mut encrypted, &mut tag);
	let bytes = [&public(47).serialize()[..], &encrypted, &tag].concat();
	header.ciphertext_hash = sha256::Hash::hash(&bytes).to_byte_array();
	let mut wire = header.encode();
	wire.resize(RECORD_HEADER_LEN + 64, 0);
	wire.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
	wire.extend_from_slice(&bytes);
	wire.push(0);
	sign_record(&mut wire);
	authenticate(&wire, &fixture.manifest())
}

#[test]
fn ffor_witness_decryption_rejects_authenticated_bodies_with_wrong_voucher_terms() {
	let fixture = fixtures().next().unwrap();
	let manifest = fixture.manifest();
	for offset in [0, 33, 34, 66, 105, 109, 113] {
		let mut plaintext = fixture.bytes("body");
		plaintext[offset] ^= 1;
		let record = reseal(&fixture, &plaintext);
		assert!(
			matches!(
				decrypt_ffor_witness_record(&record, &manifest, &secret(44)),
				Err(FFORWitnessDecryptionError::Record(_))
			),
			"offset {offset}"
		);
	}
	// Observation context is authenticated but does not change a voucher's payment amount.
	let mut plaintext = fixture.bytes("body");
	plaintext[114..].fill(255);
	let record = reseal(&fixture, &plaintext);
	let receipt = decrypt_ffor_witness_record(&record, &manifest, &secret(44)).unwrap();
	assert_eq!(receipt.body().preimage().as_slice(), &plaintext[34..66]);
}
