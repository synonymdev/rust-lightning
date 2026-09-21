use super::*;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message as SecpMessage, Secp256k1, SecretKey};
use bitcoin::{Network, Txid};
use lightning_ffor::transcript;
use lightning_ffor::wire::{Accept, Header, Init, Message, Payload, Tlv, MAX_MESSAGE_LEN};

use crate::chain::transaction::OutPoint;

pub(super) struct Fixture {
	init_wire: Vec<u8>,
	accept_wire: Vec<u8>,
	receiver: PublicKey,
	settlement: PublicKey,
	chain_hash: ChainHash,
	funding_txo: OutPoint,
	channel_value_sat: u64,
	receiver_balance_msat: u64,
	feerate_sat_per_kw: u32,
	settlement_is_funder: bool,
	admission_height: u32,
	claim_margin_blocks: u32,
}

impl_writeable_tlv_based!(Fixture, {
	(0, init_wire, required_vec),
	(2, accept_wire, required_vec),
	(4, receiver, required),
	(6, settlement, required),
	(8, chain_hash, required),
	(10, funding_txo, required),
	(12, channel_value_sat, required),
	(14, receiver_balance_msat, required),
	(16, feerate_sat_per_kw, required),
	(18, settlement_is_funder, required),
	(20, admission_height, required),
	(22, claim_margin_blocks, required),
});

impl Fixture {
	pub(super) fn record(&self) -> FFORReceiverSetup {
		FFORReceiverSetup::read(&mut &self.encode()[..]).unwrap()
	}
}

fn key(value: u8) -> PublicKey {
	PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[value; 32]).unwrap())
}

pub(super) fn sign(message: &mut Message, value: u8) {
	message.signature = Secp256k1::new()
		.sign_ecdsa(
			&SecpMessage::from_digest(message.signature_digest().unwrap()),
			&SecretKey::from_slice(&[value; 32]).unwrap(),
		)
		.serialize_compact();
}

fn message(header: Header, payload: Payload, signer: u8, maximum_size: bool) -> Message {
	let mut message = Message { header, payload, extensions: Vec::new(), signature: [0; 64] };
	sign(&mut message, signer);
	if maximum_size {
		let padding = MAX_MESSAGE_LEN - message.encode().unwrap().len() - 4;
		message.extensions.push(Tlv { kind: 101, value: vec![11; padding] });
		sign(&mut message, signer);
		assert_eq!(message.encode().unwrap().len(), MAX_MESSAGE_LEN);
	}
	message
}

pub(super) fn fixture(identity: u8, maximum_size: bool) -> Fixture {
	let header = Header { channel_id: [identity; 32], epoch_id: [identity.wrapping_add(1); 32] };
	let count = if maximum_size { 483 } else { 2 };
	let init = message(
		header,
		Payload::Init(Init {
			budget_msat: 1_000_000 * count as u64,
			min_payment_msat: 1_000_000,
			settlement_deadline: 1000,
			voucher_expiry: 2000,
			fee_base_msat: 10,
			fee_proportional_millionths: 10,
			amounts_msat: vec![1_000_000; count],
			witness_peers: None,
			hash_chain: false,
		}),
		41,
		maximum_size,
	);
	let hashes = (0..count)
		.map(|index| {
			let mut hash = [identity; 32];
			hash[..2].copy_from_slice(&(index as u16).to_be_bytes());
			hash
		})
		.collect();
	let accept = message(
		header,
		Payload::Accept(Accept {
			s_commitment_number: 3,
			payment_hashes: hashes,
			s_htlc_id_base: 8,
			amounts_msat: vec![1_000_000; count],
			init_hash: transcript::init_hash(&init.encode().unwrap()),
		}),
		42,
		maximum_size,
	);
	Fixture {
		init_wire: init.encode().unwrap(),
		accept_wire: accept.encode().unwrap(),
		receiver: key(41),
		settlement: key(42),
		chain_hash: ChainHash::using_genesis_block(Network::Regtest),
		funding_txo: OutPoint { txid: Txid::from_byte_array([identity; 32]), index: 0 },
		channel_value_sat: 1_000_000,
		receiver_balance_msat: 5_000_000,
		feerate_sat_per_kw: 253,
		settlement_is_funder: true,
		admission_height: 500,
		claim_margin_blocks: 12,
	}
}

fn stored(record: FFORReceiverSetup) -> StoredSetup {
	let book = record.validate_recovery().unwrap().canonical_book().to_vec();
	StoredSetup { setup: record, canonical_book: book, activation: None, request: None }
}

fn frame(records: &[Vec<u8>]) -> Vec<u8> {
	let mut bytes = Vec::new();
	SETUP_ONLY_VERSION.write(&mut bytes).unwrap();
	(records.len() as u16).write(&mut bytes).unwrap();
	for record in records {
		(record.len() as u32).write(&mut bytes).unwrap();
		bytes.extend_from_slice(record);
	}
	bytes
}

fn decode(bytes: &[u8]) -> Result<FFORRecoveryRegistry, DecodeError> {
	FFORRecoveryRegistry::read(&mut &bytes[..])
}

pub(crate) fn full_registry() -> FFORRecoveryRegistry {
	let mut registry = FFORRecoveryRegistry::new();
	for identity in 1..=MAX_RECORDS {
		registry.prepare_insert(&fixture(identity as u8, false).record()).unwrap().commit();
	}
	registry
}

fn without_book(setup: FFORReceiverSetup) -> Result<Vec<u8>, io::Error> {
	let mut bytes = Vec::new();
	write_tlv_fields!(&mut bytes, { (0, setup, required) });
	Ok(bytes)
}

#[test]
fn ffor_recovery_roundtrip_retains_exact_signed_setup_and_native_identity() {
	let record = fixture(1, true).record();
	let mut registry = FFORRecoveryRegistry::new();
	registry.prepare_insert(&record).unwrap().commit();
	let encoded = registry.encode();
	let restored = decode(&encoded).unwrap();
	assert_eq!(restored.encode(), encoded);
	assert!(restored.contains_exact(&record));
	assert_eq!(restored.encoded_bytes, encoded.len());
	assert_eq!(restored.reserved_transition_bytes, 0);
	assert!(restored.validate_identity(record.receiver(), record.chain_hash()).is_ok());
	assert_eq!(
		restored.validate_identity(key(43), record.chain_hash()),
		Err(DecodeError::InvalidValue)
	);
	assert_eq!(
		restored
			.validate_identity(record.receiver(), ChainHash::using_genesis_block(Network::Bitcoin)),
		Err(DecodeError::InvalidValue)
	);
}

#[test]
fn ffor_recovery_cancelled_admission_and_duplicate_retry_do_not_mutate_registry() {
	let record = fixture(2, false).record();
	let mut registry = FFORRecoveryRegistry::new();
	drop(registry.prepare_insert(&record).unwrap());
	assert!(registry.is_empty());
	registry.prepare_insert(&record).unwrap().commit();
	let encoded = registry.encode();
	registry.prepare_insert(&record).unwrap().commit();
	assert_eq!(registry.encode(), encoded);
}

#[test]
fn ffor_recovery_conflicting_channel_or_funding_cannot_replace_evidence() {
	let original = fixture(3, false);
	let mut registry = FFORRecoveryRegistry::new();
	registry.prepare_insert(&original.record()).unwrap().commit();
	let encoded = registry.encode();
	let mut changed = fixture(3, false);
	changed.feerate_sat_per_kw += 1;
	assert!(matches!(
		registry.prepare_insert(&changed.record()),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	assert!(!registry.contains_exact(&changed.record()));
	let mut changed = fixture(4, false);
	changed.funding_txo = original.funding_txo;
	assert!(matches!(
		registry.prepare_insert(&changed.record()),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	assert_eq!(registry.encode(), encoded);
}

#[test]
fn ffor_recovery_capacity_refuses_new_records_without_eviction() {
	let mut registry = FFORRecoveryRegistry::new();
	let first = fixture(1, false).record();
	for identity in 1..=MAX_RECORDS {
		registry.prepare_insert(&fixture(identity as u8, false).record()).unwrap().commit();
	}
	let before = registry.encode();
	assert!(matches!(
		registry.prepare_insert(&fixture(90, false).record()),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	registry.prepare_insert(&first).unwrap().commit();
	assert_eq!(registry.encode(), before);
	assert!(registry.contains_exact(&first));
}

#[test]
fn ffor_recovery_total_byte_limit_applies_before_record_count_limit() {
	let mut registry = FFORRecoveryRegistry::new();
	let mut hit_limit = false;
	for identity in 1..=MAX_RECORDS {
		let record = fixture(identity as u8, true).record();
		let before = registry.encoded_bytes;
		match registry.prepare_insert(&record) {
			Ok(permit) => permit.commit(),
			Err(FFORRecoveryError::CapacityExceeded) => {
				hit_limit = true;
			},
			Err(other) => panic!("unexpected insertion error: {:?}", other),
		}
		if hit_limit {
			assert_eq!(registry.encoded_bytes, before);
			assert!(registry.entries.len() < MAX_RECORDS);
			break;
		}
	}
	assert!(hit_limit);
	assert!(registry.encoded_bytes <= MAX_ENCODED_BYTES);
	assert!(decode(&registry.encode()).is_ok());
}

#[test]
fn ffor_recovery_reader_rejects_duplicate_and_conflicting_identity_keys() {
	let record = stored(fixture(5, false).record()).encode();
	assert!(decode(&frame(&[record.clone(), record.clone()])).is_err());
	let mut changed = fixture(5, false);
	changed.feerate_sat_per_kw += 1;
	assert!(decode(&frame(&[record.clone(), stored(changed.record()).encode()])).is_err());
	let mut changed = fixture(6, false);
	changed.funding_txo = fixture(5, false).funding_txo;
	assert!(decode(&frame(&[record, stored(changed.record()).encode()])).is_err());
}

#[test]
fn ffor_recovery_reader_reauthenticates_signatures_and_canonical_book() {
	let mut record = stored(fixture(7, false).record());
	record.canonical_book[40] ^= 1;
	assert!(decode(&frame(&[record.encode()])).is_err());
	let mut broken = fixture(7, false);
	let last = broken.accept_wire.len() - 1;
	broken.accept_wire[last] ^= 1;
	let invalid = broken.record();
	assert!(matches!(
		FFORRecoveryRegistry::new().prepare_insert(&invalid),
		Err(FFORRecoveryError::InvalidRecord)
	));
	let mut record = stored(fixture(7, false).record());
	record.setup = invalid;
	assert!(decode(&frame(&[record.encode()])).is_err());
}

#[test]
fn ffor_recovery_reader_refuses_future_schema_missing_fields_and_truncation() {
	let record = stored(fixture(8, false).record()).encode();
	let framed = frame(&[record]);
	for length in 0..framed.len() {
		assert!(decode(&framed[..length]).is_err(), "accepted prefix {}", length);
	}
	let mut future = framed.clone();
	future[0] = REQUEST_VERSION + 1;
	assert!(matches!(decode(&future), Err(DecodeError::UnknownRequiredFeature)));
	// Empty TLV records omit both mandatory fields.
	assert!(decode(&frame(&[vec![0]])).is_err());
	// No canonical book, although the setup itself is valid.
	let missing = without_book(fixture(8, false).record()).unwrap();
	assert!(decode(&frame(&[missing])).is_err());
}

#[test]
fn ffor_recovery_reader_bounds_declared_counts_and_lengths_before_reading_records() {
	assert!(decode(&[SETUP_ONLY_VERSION, 0, MAX_RECORDS as u8 + 1]).is_err());
	for length in [MAX_RECORD_BYTES + 1, u32::MAX as usize] {
		let mut bytes = vec![SETUP_ONLY_VERSION, 0, 1];
		bytes.extend_from_slice(&(length as u32).to_be_bytes());
		assert!(matches!(decode(&bytes), Err(DecodeError::InvalidValue)));
	}
	let mut registry = FFORRecoveryRegistry::new();
	registry.encoded_bytes = MAX_ENCODED_BYTES;
	assert_eq!(registry.check_capacity(0, 0), Err(FFORRecoveryError::CapacityExceeded));
	assert_eq!(registry.check_capacity(usize::MAX, 0), Err(FFORRecoveryError::CapacityExceeded));
	assert_eq!(registry.check_capacity(0, usize::MAX), Err(FFORRecoveryError::CapacityExceeded));
}
