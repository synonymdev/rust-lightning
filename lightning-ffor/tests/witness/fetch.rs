use super::*;
use lightning_ffor::wire::{Tlv, WireError};
use lightning_ffor::witness::{
	EncryptedRecord, FetchParameters, FetchResponse, FetchResult, PendingFetch, SignedFetch,
	UnsignedFetch, CIPHERTEXT_LEN, RECORD_HEADER_LEN,
};

#[path = "body.rs"]
mod body;

#[derive(Deserialize)]
struct FetchReference {
	source_revision: String,
	specification_revision: String,
	appendix_d_sha256: String,
	source_files: Vec<String>,
	fixtures: Vec<FetchFixture>,
}
#[derive(Deserialize)]
struct FetchFixture {
	scenario: String,
	records: Vec<RecordFixture>,
	first_request: String,
	first_digest: String,
	continuation_request: String,
	continuation_digest: String,
	odd_request: String,
	first_response: String,
	continuation_response: String,
	empty_response: String,
	refusal: String,
}
#[derive(Deserialize)]
struct RecordFixture {
	record: String,
	header: String,
	aad: String,
	digest: String,
	ciphertext: String,
	body: String,
	shared_hash: String,
	body_key: String,
}

fn fixtures() -> FetchReference {
	serde_json::from_str(include_str!("../data/beignet-witness-fetch.json")).unwrap()
}
fn retained(index: usize) -> SignedManifest {
	SignedManifest::decode(&hex(&reference().fixtures[index].manifest), &public_setup(index))
		.unwrap()
}
fn connection() -> WitnessConnection<u64> {
	WitnessConnection { node_id: key(43), identity: 7 }
}
fn first(index: usize) -> PendingFetch<u64> {
	let request =
		SignedFetch::decode(&hex(&fixtures().fixtures[index].first_request), key(42)).unwrap();
	PendingFetch::first(request, retained(index), connection()).unwrap()
}
fn resign_record(mut bytes: Vec<u8>, signer: u8) -> Vec<u8> {
	let digest = sha256::Hash::hash(&[b"ffor/witness/record".as_slice(), &bytes[..235]].concat())
		.to_byte_array();
	bytes[235..299].copy_from_slice(&signature(digest, signer));
	bytes
}
fn resign_fetch(mut bytes: Vec<u8>) -> Vec<u8> {
	let digest = sha256::Hash::hash(
		&[b"ffor/witness/fetch".as_slice(), &bytes[18..82], &bytes[146..]].concat(),
	)
	.to_byte_array();
	bytes[82..146].copy_from_slice(&signature(digest, 42));
	bytes
}
fn page(request: [u8; 16], records: Vec<EncryptedRecord>, next: Option<u16>) -> FetchResponse {
	FetchResponse::new(
		request,
		FetchResult::Page { records, next_after_slot: next, extensions: Vec::new() },
	)
	.unwrap()
}

#[test]
fn witness_fetch_pinned_reference_roundtrips_and_domains_match() {
	let inputs = fixtures();
	assert_eq!(inputs.source_revision, "8aee31d18e596fe49a0d195b325a6e757d7a009b");
	assert_eq!(inputs.specification_revision, "d719161f42d1eeb6bd6c3856d564222f03c2205e");
	assert_eq!(inputs.source_files.len(), 3);
	assert_eq!(
		hex(&inputs.appendix_d_sha256),
		sha256::Hash::hash(include_bytes!("../data/appendix-d.json")).to_byte_array()
	);
	for (index, fixture) in inputs.fixtures.iter().enumerate() {
		assert_eq!(fixture.scenario, reference().fixtures[index].scenario);
		for (wire, digest) in [
			(&fixture.first_request, &fixture.first_digest),
			(&fixture.continuation_request, &fixture.continuation_digest),
		] {
			let request = SignedFetch::decode(&hex(wire), key(42)).unwrap();
			assert_eq!(request.encode(), hex(wire));
			assert_eq!(request.unsigned().signing_digest().to_vec(), hex(digest));
		}
		let odd = SignedFetch::decode(&hex(&fixture.odd_request), key(42)).unwrap();
		assert_eq!(odd.encode(), hex(&fixture.odd_request));
		assert_eq!(odd.unsigned().parameters().extensions, vec![Tlv { kind: 3, value: vec![7] }]);
		for wire in [
			&fixture.first_response,
			&fixture.continuation_response,
			&fixture.empty_response,
			&fixture.refusal,
		] {
			assert_eq!(FetchResponse::decode(&hex(wire)).unwrap().encode(), hex(wire));
		}
		for record in &fixture.records {
			let parsed = EncryptedRecord::decode(&hex(&record.record)).unwrap();
			assert_eq!(parsed.encode(), hex(&record.record));
			assert_eq!(parsed.header().encode(), hex(&record.header));
			assert_eq!(parsed.header().associated_data(), hex(&record.aad));
			assert_eq!(parsed.header().signing_digest().to_vec(), hex(&record.digest));
			assert_eq!(parsed.ciphertext(), hex(&record.ciphertext));
			assert_eq!(parsed.ciphertext().len(), CIPHERTEXT_LEN);
			assert_eq!(hex(&record.body).len(), 142);
			assert_eq!(hex(&record.body_key).len(), 32);
			let ephemeral = sha256::Hash::hash(
				&[
					format!("ffor/witness-fetch-fixture/{}/ephemeral", fixture.scenario).as_bytes(),
					&parsed.header().slot.to_be_bytes(),
				]
				.concat(),
			)
			.to_byte_array();
			let shared = bitcoin::secp256k1::ecdh::SharedSecret::new(
				&key(44),
				&SecretKey::from_slice(&ephemeral).unwrap(),
			);
			assert_eq!(shared.secret_bytes().to_vec(), hex(&record.shared_hash));
			assert!(parsed.authenticate(&retained(index), key(43)).is_ok());
		}
	}
}

#[test]
fn witness_fetch_authentication_excludes_request_id_but_binds_mailbox_nonce_and_tlvs() {
	let wire = hex(&fixtures().fixtures[1].continuation_request);
	let mut renamed = wire.clone();
	renamed[2] ^= 1;
	assert!(SignedFetch::decode(&renamed, key(42)).is_ok());
	for offset in [18, 50, 149] {
		let mut damaged = wire.clone();
		damaged[offset] ^= 1;
		assert!(SignedFetch::decode(&damaged, key(42)).is_err());
	}
	assert!(SignedFetch::decode(&wire, key(43)).is_err());
	let parsed = SignedFetch::decode(&wire, key(42)).unwrap();
	assert!(parsed
		.unsigned()
		.clone()
		.authenticate(signature(transcript::message_digest(55059, &wire[2..82]), 42), key(42))
		.is_err());
	let p = parsed.unsigned().parameters().clone();
	let mut collision = p.clone();
	collision.extensions.push(Tlv { kind: 1, value: vec![0, 1] });
	assert_eq!(UnsignedFetch::new(collision), Err(WitnessError::NonCanonical));
	let mut even = p.clone();
	even.extensions.push(Tlv { kind: 2, value: vec![] });
	assert_eq!(UnsignedFetch::new(even), Err(WitnessError::Tlv(WireError::UnknownEvenTlv(2))));
	let mut oversized = p;
	oversized.extensions.push(Tlv { kind: 3, value: vec![0; MAX_MESSAGE_LEN] });
	assert!(UnsignedFetch::new(oversized).is_err());
}

#[test]
fn witness_fetch_rejects_noncanonical_tlvs_status_lengths_and_counts() {
	let fixture = &fixtures().fixtures[0];
	let request = hex(&fixture.first_request);
	for suffix in [
		vec![1, 1, 0],
		vec![1, 2, 0, 1, 1, 2, 0, 2],
		vec![3, 0, 1, 2, 0, 1],
		vec![253, 0, 1, 2, 0, 1],
		vec![2, 0],
		vec![3, 253, 0, 1, 7],
	] {
		let mut damaged = request.clone();
		damaged.extend_from_slice(&suffix);
		assert!(SignedFetch::decode(&resign_fetch(damaged), key(42)).is_err());
	}
	for length in 0..request.len() {
		assert!(SignedFetch::decode(&request[..length], key(42)).is_err());
	}
	let response = hex(&fixture.first_response);
	for length in 0..response.len() {
		assert!(FetchResponse::decode(&response[..length]).is_err());
	}
	for (offset, value) in [(0, 0), (18, 2), (19, 255), (21, 255)] {
		let mut damaged = response.clone();
		damaged[offset] = value;
		assert!(FetchResponse::decode(&damaged).is_err());
	}
	let mut refusal = hex(&fixture.refusal);
	refusal.push(0);
	assert_eq!(FetchResponse::decode(&refusal), Err(WitnessError::NonCanonical));
	assert_eq!(FetchResponse::decode(&vec![0; MAX_MESSAGE_LEN + 1]), Err(WitnessError::SizeLimit));
	assert_eq!(
		SignedFetch::decode(&vec![0; MAX_MESSAGE_LEN + 1], key(42)),
		Err(WitnessError::SizeLimit)
	);
}

#[test]
fn witness_record_rejects_header_points_flags_signature_and_ciphertext_damage() {
	let wire = hex(&fixtures().fixtures[0].records[0].record);
	for length in 0..wire.len() {
		assert!(EncryptedRecord::decode(&wire[..length]).is_err());
	}
	for offset in [0, 1, 66, 132, 165, 202, 203, 235, 299, 301, 334] {
		let mut damaged = wire.clone();
		damaged[offset] ^= 255;
		assert!(EncryptedRecord::decode(&damaged).is_err(), "offset {offset}");
	}
	let mut trailing = wire.clone();
	trailing.push(0);
	assert_eq!(EncryptedRecord::decode(&trailing), Err(WitnessError::NonCanonical));
	let mut wrong_len = wire.clone();
	wrong_len[299..301].copy_from_slice(&190u16.to_be_bytes());
	assert_eq!(EncryptedRecord::decode(&wrong_len), Err(WitnessError::Ciphertext));
	for range in [235..267, 267..299] {
		let mut zero = wire.clone();
		zero[range].fill(0);
		assert!(EncryptedRecord::decode(&zero).is_err());
	}
	let mut high = wire.clone();
	let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
	let mut borrow = 0_i16;
	for i in (0..32).rev() {
		let n = i16::from(order[i]) - i16::from(high[267 + i]) - borrow;
		high[267 + i] = n as u8;
		borrow = i16::from(n < 0);
	}
	assert_eq!(
		EncryptedRecord::decode(&high),
		Err(WitnessError::Signature(transcript::SignatureError::HighS))
	);
	let mut fetch = hex(&fixtures().fixtures[0].first_request);
	fetch[114..146].copy_from_slice(&high[267..299]);
	assert_eq!(
		SignedFetch::decode(&fetch, key(42)),
		Err(WitnessError::Signature(transcript::SignatureError::HighS))
	);
}

#[test]
fn witness_record_binds_expected_witness_manifest_encryption_and_canonical_terms() {
	let wire = hex(&fixtures().fixtures[0].records[0].record);
	let manifest = retained(0);
	for (offset, expected) in
		[(2, WitnessError::Mailbox), (68, WitnessError::Transcript), (100, WitnessError::Terms)]
	{
		let mut wrong = wire.clone();
		wrong[offset] ^= 1;
		assert_eq!(
			EncryptedRecord::decode(&resign_record(wrong, 43))
				.unwrap()
				.authenticate(&manifest, key(43)),
			Err(expected)
		);
	}
	let mut wrong_key = wire.clone();
	wrong_key[165..198].copy_from_slice(&key(45).serialize());
	assert_eq!(
		EncryptedRecord::decode(&resign_record(wrong_key, 43))
			.unwrap()
			.authenticate(&manifest, key(43)),
		Err(WitnessError::Mailbox)
	);
	assert_eq!(
		EncryptedRecord::decode(&wire).unwrap().authenticate(&manifest, key(44)),
		Err(WitnessError::Witness)
	);
	let mut wrong_slot = wire;
	wrong_slot[66..68].copy_from_slice(&2u16.to_be_bytes());
	assert_eq!(
		EncryptedRecord::decode(&resign_record(wrong_slot, 43))
			.unwrap()
			.authenticate(&manifest, key(43)),
		Err(WitnessError::Terms)
	);
}

#[test]
fn witness_record_remains_opaque_even_if_witness_signs_an_invalid_aead_body() {
	let mut wire = hex(&fixtures().fixtures[0].records[0].record);
	wire[334] ^= 1;
	let hash = sha256::Hash::hash(&wire[301..492]).to_byte_array();
	wire[203..235].copy_from_slice(&hash);
	let opaque = EncryptedRecord::decode(&resign_record(wire, 43))
		.unwrap()
		.authenticate(&retained(0), key(43))
		.unwrap();
	assert_eq!(opaque.record().ciphertext().len(), CIPHERTEXT_LEN);
	// Metadata authentication intentionally does not claim that the altered AEAD tag/body opens.
	assert_ne!(opaque.record().ciphertext(), hex(&fixtures().fixtures[0].records[0].ciphertext));
}

#[test]
fn witness_fetch_correlates_connection_request_mailbox_and_preserves_earlier_pages() {
	let pending = first(1);
	let f = &fixtures().fixtures[1];
	let response = FetchResponse::decode(&hex(&f.first_response)).unwrap();
	for (source, expected) in [
		(WitnessConnection { identity: 8, ..connection() }, WitnessError::Connection),
		(WitnessConnection { node_id: key(44), ..connection() }, WitnessError::Witness),
	] {
		assert_eq!(pending.check_response(&response, &source), Err(expected));
	}
	let wrong_id = FetchResponse::new([99; 16], response.result().clone()).unwrap();
	assert_eq!(pending.check_response(&wrong_id, &connection()), Err(WitnessError::Request));
	let checked = pending.check_response(&response, &connection()).unwrap();
	assert_eq!(checked.records().len(), 1);
	let next =
		checked.next(SignedFetch::decode(&hex(&f.continuation_request), key(42)).unwrap()).unwrap();
	let wrong_mailbox =
		SignedFetch::decode(&hex(&fixtures().fixtures[0].first_request), key(42)).unwrap();
	assert_eq!(
		PendingFetch::first(wrong_mailbox, retained(1), connection()),
		Err(WitnessError::Mailbox)
	);
	assert_eq!(next.check_response(&response, &connection()), Err(WitnessError::Request));
	assert_eq!(checked.records().len(), 1);
	let terminal = next
		.check_response(
			&FetchResponse::decode(&hex(&f.continuation_response)).unwrap(),
			&connection(),
		)
		.unwrap();
	assert!(terminal.next_after_slot().is_none());
	assert_eq!(terminal.records().len(), f.records.len() - 1);
	assert!(terminal.next(next.request().clone()).is_err());
}

#[test]
fn witness_fetch_rejects_backward_duplicate_skipped_and_impossible_cursors() {
	let pending = first(1);
	let records: Vec<_> = fixtures().fixtures[1]
		.records
		.iter()
		.map(|r| EncryptedRecord::decode(&hex(&r.record)).unwrap())
		.collect();
	let id = pending.request().unsigned().parameters().request_id;
	for (entries, next) in [
		(vec![], Some(1)),
		(vec![records[0].clone()], Some(0)),
		(vec![records[0].clone()], Some(2)),
		(vec![records[0].clone(), records[0].clone()], None),
		(vec![records[1].clone(), records[0].clone()], None),
	] {
		assert_eq!(
			pending.check_response(&page(id, entries, next), &connection()),
			Err(WitnessError::Pagination)
		);
	}
	let only = first(0);
	let record = EncryptedRecord::decode(&hex(&fixtures().fixtures[0].records[0].record)).unwrap();
	assert_eq!(
		only.check_response(
			&page(only.request().unsigned().parameters().request_id, vec![record], Some(1)),
			&connection()
		),
		Err(WitnessError::Pagination)
	);
	let checked = pending
		.check_response(&page(id, vec![records[0].clone()], Some(1)), &connection())
		.unwrap();
	let mut params = pending.request().unsigned().parameters().clone();
	params.after_slot = Some(1);
	for reuse_nonce in [false, true] {
		let mut p = params.clone();
		if reuse_nonce {
			p.request_id = [89; 16];
		} else {
			p.nonce = [89; 32];
		}
		let unsigned = UnsignedFetch::new(p).unwrap();
		let signed = unsigned
			.clone()
			.authenticate(signature(unsigned.signing_digest(), 42), key(42))
			.unwrap();
		assert_eq!(checked.next(signed), Err(WitnessError::Replay));
	}
}

#[test]
fn witness_record_receipt_and_frame_boundaries_are_bounded_opaque_bytes() {
	let mut wire = hex(&fixtures().fixtures[0].records[0].record);
	assert_eq!(wire.len(), RECORD_HEADER_LEN + 64 + 2 + CIPHERTEXT_LEN + 1);
	wire[492] = 255;
	for _ in 0..255 {
		wire.extend_from_slice(&[0, 0]);
	}
	assert_eq!(EncryptedRecord::decode(&wire).unwrap().receipts().len(), 255);
	let mut maximal = wire[..493].to_vec();
	maximal[492] = 1;
	let remaining = MAX_MESSAGE_LEN - 23 - 493 - 2;
	maximal.extend_from_slice(&(remaining as u16).to_be_bytes());
	maximal.resize(MAX_MESSAGE_LEN - 23, 7);
	let record = EncryptedRecord::decode(&maximal).unwrap();
	let response = page([0; 16], vec![record.clone()], None);
	assert_eq!(response.encode().len(), MAX_MESSAGE_LEN);
	assert!(FetchResponse::new(
		[0; 16],
		FetchResult::Page {
			records: vec![record.clone()],
			next_after_slot: Some(1),
			extensions: Vec::new()
		}
	)
	.is_err());
	assert!(FetchResponse::new(
		[0; 16],
		FetchResult::Page {
			records: vec![record; 484],
			next_after_slot: None,
			extensions: Vec::new()
		}
	)
	.is_err());
	maximal.push(0);
	assert_eq!(EncryptedRecord::decode(&maximal), Err(WitnessError::SizeLimit));
	let refusal =
		FetchResponse::new([0; 16], FetchResult::Refused(vec![255; MAX_MESSAGE_LEN - 21])).unwrap();
	assert_eq!(refusal.encode().len(), MAX_MESSAGE_LEN);
	assert_eq!(FetchResponse::decode(&refusal.encode()).unwrap(), refusal);
}

#[test]
fn witness_fetch_exact_envelope_and_optional_zero_cursor_are_preserved() {
	let mut parameters = FetchParameters {
		request_id: [1; 16],
		mailbox_id: [2; 32],
		nonce: [3; 32],
		after_slot: None,
		extensions: vec![Tlv { kind: 3, value: vec![7; MAX_MESSAGE_LEN - 146 - 4] }],
	};
	let maximum = UnsignedFetch::new(parameters.clone()).unwrap();
	let signature = signature(maximum.signing_digest(), 42);
	let wire = maximum.authenticate(signature, key(42)).unwrap().encode();
	assert_eq!(wire.len(), MAX_MESSAGE_LEN);
	assert_eq!(SignedFetch::decode(&wire, key(42)).unwrap().encode(), wire);
	parameters.extensions[0].value.push(7);
	assert_eq!(UnsignedFetch::new(parameters.clone()), Err(WitnessError::SizeLimit));
	parameters.extensions.clear();
	let absent = UnsignedFetch::new(parameters.clone()).unwrap();
	parameters.after_slot = Some(0);
	let present = UnsignedFetch::new(parameters).unwrap();
	assert_ne!(absent.signing_digest(), present.signing_digest());
	let signed = present
		.clone()
		.authenticate(super::signature(present.signing_digest(), 42), key(42))
		.unwrap();
	assert_eq!(SignedFetch::decode(&signed.encode(), key(42)).unwrap(), signed);
	let response = FetchResponse::new(
		[1; 16],
		FetchResult::Page {
			records: vec![],
			next_after_slot: None,
			extensions: vec![Tlv { kind: 3, value: vec![5] }],
		},
	)
	.unwrap();
	assert_eq!(FetchResponse::decode(&response.encode()).unwrap(), response);
}

proptest! {
	#[test]
	fn witness_fetch_bounded_arbitrary_inputs_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..70_000)) {
		if let Ok(request) = SignedFetch::decode(&bytes, key(42)) { prop_assert_eq!(request.encode(), bytes.clone()); }
		if let Ok(response) = FetchResponse::decode(&bytes) { prop_assert_eq!(response.encode(), bytes.clone()); }
		if let Ok(record) = EncryptedRecord::decode(&bytes) { prop_assert_eq!(record.encode(), bytes); }
	}
}
