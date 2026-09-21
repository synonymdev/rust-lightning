use super::*;
use lightning_ffor::witness::{AuthenticatedEncryptedRecord, RECORD_BODY_LEN};

fn authenticated(index: usize, record: usize) -> AuthenticatedEncryptedRecord {
	EncryptedRecord::decode(&hex(&fixtures().fixtures[index].records[record].record))
		.unwrap()
		.authenticate(&retained(index), key(43))
		.unwrap()
}

#[test]
fn witness_body_matches_all_pinned_beignet_scenarios() {
	let inputs = fixtures();
	assert_eq!(inputs.fixtures.len(), 6);
	for (index, fixture) in inputs.fixtures.iter().enumerate() {
		let setup = public_setup(index);
		let manifest = retained(index);
		for (record_index, record) in fixture.records.iter().enumerate() {
			let body = authenticated(index, record_index)
				.verify_body(&manifest, &hex(&record.body))
				.unwrap();
			let slot = body.slot();
			let voucher = &setup.vouchers()[usize::from(slot) - 1];
			let expected_preimage = sha256::Hash::hash(
				&[
					format!("ffor/vector/{}/preimage", fixture.scenario).as_bytes(),
					&slot.to_be_bytes(),
				]
				.concat(),
			)
			.to_byte_array();
			assert_eq!(hex(&record.body).len(), RECORD_BODY_LEN);
			assert_eq!(body.epoch_id(), setup.header().epoch_id);
			assert_eq!(body.preimage(), expected_preimage);
			assert_eq!(body.payment_hash(), voucher.payment_hash);
			assert_eq!(body.amount_msat(), voucher.amount_msat);
			assert_eq!(body.voucher_expiry(), voucher.expiry);
			assert_eq!(body.settlement_deadline(), voucher.deadline);
			assert_eq!(body.context().amount_in_msat(), voucher.amount_msat + 6000);
			assert_eq!(body.context().amount_out_msat(), voucher.amount_msat);
			assert_eq!(body.context().outgoing_cltv(), 791_000);
			assert_eq!(body.context().observed_unix_time(), 1_700_000_000);
			assert_eq!(body.clone(), body);
		}
	}
}

#[test]
fn witness_body_rejects_truncated_trailing_and_mismatched_terms() {
	let record = authenticated(0, 0);
	let manifest = retained(0);
	let bytes = hex(&fixtures().fixtures[0].records[0].body);
	for length in 0..RECORD_BODY_LEN {
		assert_eq!(record.verify_body(&manifest, &bytes[..length]), Err(WitnessError::Truncated));
	}
	for extra in [1, 2, 142, MAX_MESSAGE_LEN] {
		let mut trailing = bytes.clone();
		trailing.resize(RECORD_BODY_LEN + extra, 0);
		assert_eq!(record.verify_body(&manifest, &trailing), Err(WitnessError::NonCanonical));
	}
	for (offset, error) in [
		(0, WitnessError::Transcript),
		(32, WitnessError::Terms),
		(34, WitnessError::Preimage),
		(66, WitnessError::Terms),
		(98, WitnessError::Terms),
		(106, WitnessError::Terms),
		(110, WitnessError::Terms),
	] {
		let mut wrong = bytes.clone();
		wrong[offset] ^= 1;
		assert_eq!(record.verify_body(&manifest, &wrong), Err(error));
	}
	for slot in [0u16, 2, 483, 484, u16::MAX] {
		let mut wrong = bytes.clone();
		wrong[32..34].copy_from_slice(&slot.to_be_bytes());
		assert_eq!(record.verify_body(&manifest, &wrong), Err(WitnessError::Terms));
	}
	// A valid plaintext for another slot is still not the body named by this signed header.
	assert_eq!(
		authenticated(1, 0)
			.verify_body(&retained(1), &hex(&fixtures().fixtures[1].records[1].body)),
		Err(WitnessError::Terms)
	);
}

#[test]
fn witness_body_rechecks_supplied_manifest_record_binding() {
	let record = authenticated(0, 0);
	let manifest = retained(0);
	let bytes = hex(&fixtures().fixtures[0].records[0].body);
	for (change, expected) in [
		(0, WitnessError::Mailbox),
		(1, WitnessError::Mailbox),
		(2, WitnessError::Transcript),
		(3, WitnessError::Transcript),
	] {
		let mut params = *manifest.unsigned().parameters();
		match change {
			0 => params.mailbox_id[0] ^= 1,
			1 => params.encryption_public_key = key(45),
			2 => params.commitment_hash[0] ^= 1,
			3 => params.epoch_start_height -= 1,
			_ => unreachable!(),
		}
		let unsigned = UnsignedManifest::new(&public_setup(0), params).unwrap();
		let signed =
			unsigned.clone().authenticate(signature(unsigned.signing_digest(), 42)).unwrap();
		assert_eq!(record.verify_body(&signed, &bytes), Err(expected));
	}
	assert!(record.verify_body(&retained(1), &bytes).is_err());
	assert!(record.verify_body(&manifest, &bytes).is_ok());
}

#[test]
fn witness_body_context_is_informational_and_preimage_debug_is_redacted() {
	let record = authenticated(0, 0);
	let manifest = retained(0);
	let mut bytes = hex(&fixtures().fixtures[0].records[0].body);
	for value in [0, 255] {
		bytes[114..].fill(value);
		let body = record.verify_body(&manifest, &bytes).unwrap();
		let expected_u64 = if value == 0 { 0 } else { u64::MAX };
		let expected_u32 = if value == 0 { 0 } else { u32::MAX };
		assert_eq!(body.context().amount_in_msat(), expected_u64);
		assert_eq!(body.context().amount_out_msat(), expected_u64);
		assert_eq!(body.context().outgoing_cltv(), expected_u32);
		assert_eq!(body.context().observed_unix_time(), expected_u64);
		for debug in [format!("{body:?}"), format!("{body:#?}")] {
			assert!(debug.contains("[redacted]"));
			assert!(!debug.contains(&format!("{:?}", body.preimage())));
			assert!(!debug.contains(&format!("{:#?}", body.preimage())));
			assert!(!debug.contains(&fixtures().fixtures[0].records[0].body[68..132]));
		}
	}
}

#[test]
fn witness_body_consistency_does_not_claim_authenticated_decryption() {
	let fixture = &fixtures().fixtures[0].records[0];
	let mut wire = hex(&fixture.record);
	wire[334] ^= 1;
	let hash = sha256::Hash::hash(&wire[301..492]).to_byte_array();
	wire[203..235].copy_from_slice(&hash);
	let record = EncryptedRecord::decode(&resign_record(wire, 43))
		.unwrap()
		.authenticate(&retained(0), key(43))
		.unwrap();
	// Supplied valid plaintext remains consistent even though this signed ciphertext cannot
	// decrypt to it. A native authenticated receipt must additionally verify the AEAD tag.
	assert!(record.verify_body(&retained(0), &hex(&fixture.body)).is_ok());
}

proptest! {
	#[test]
	fn witness_body_any_changed_authoritative_byte_fails(offset in 0usize..114, bit in 0u8..8) {
		let mut bytes = hex(&fixtures().fixtures[0].records[0].body);
		bytes[offset] ^= 1 << bit;
		prop_assert!(authenticated(0, 0).verify_body(&retained(0), &bytes).is_err());
	}

	#[test]
	fn witness_body_arbitrary_informational_context_is_preserved(context in any::<[u8; 28]>()) {
		let mut bytes = hex(&fixtures().fixtures[0].records[0].body);
		bytes[114..].copy_from_slice(&context);
		let body = authenticated(0, 0).verify_body(&retained(0), &bytes).unwrap();
		prop_assert_eq!(body.context().amount_in_msat(), u64::from_be_bytes(context[..8].try_into().unwrap()));
		prop_assert_eq!(body.context().amount_out_msat(), u64::from_be_bytes(context[8..16].try_into().unwrap()));
		prop_assert_eq!(body.context().outgoing_cltv(), u32::from_be_bytes(context[16..20].try_into().unwrap()));
		prop_assert_eq!(body.context().observed_unix_time(), u64::from_be_bytes(context[20..].try_into().unwrap()));
	}
}
