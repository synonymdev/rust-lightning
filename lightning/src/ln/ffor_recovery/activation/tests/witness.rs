use super::*;
use crate::ln::ffor::{FFORReceiverRecoveryContext, FFORReceiverWitnessRegistration};
use crate::ln::ffor_recovery::{Entry, StoredSetup, WITNESS_VERSION};
use bitcoin::secp256k1::{Message as SecpMessage, PublicKey, Secp256k1, SecretKey};
use lightning_ffor::witness::{ManifestParameters, SignedManifest, UnsignedManifest};

pub(crate) fn manifests(
	context: &FFORReceiverRecoveryContext, count: u8,
) -> Vec<(PublicKey, SignedManifest)> {
	let secp = Secp256k1::new();
	let key =
		|value| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[value; 32]).unwrap());
	let activation = match Message::decode(context.activation_wire()).unwrap().payload {
		Payload::Activate(value) => value,
		_ => unreachable!(),
	};
	(0..count)
		.map(|index| {
			let secret = SecretKey::from_slice(&[index + 100; 32]).unwrap();
			let unsigned = UnsignedManifest::new(
				context.setup(),
				ManifestParameters {
					mailbox_id: [index + 80; 32],
					commitment_hash: activation.commit_hash,
					epoch_start_height: activation.epoch_start_height,
					fetch_public_key: PublicKey::from_secret_key(&secp, &secret),
					encryption_public_key: key(120),
					retention_until: context.setup().terms().voucher_expiry + 144,
					minimum_receipts: 0,
				},
			)
			.unwrap();
			let signature = secp
				.sign_ecdsa(&SecpMessage::from_digest(unsigned.signing_digest()), &secret)
				.serialize_compact();
			(key(index + 90), unsigned.authenticate(signature).unwrap())
		})
		.collect()
}

#[test]
fn ffor_witness_archive_bounds_maximum_book_and_reserves_terminal_transitions() {
	let (setup, phases) = close::phases(true);
	let context = phases[1].receiver_context(&setup).unwrap();
	assert_eq!(context.setup().vouchers().len(), 483);
	let selected = manifests(&context, 4);
	let metadata = FFORReceiverWitnessRegistration::from_manifests(&context, &selected).unwrap();
	assert!(metadata.serialized_length() < 1_300);
	assert!(selected.iter().map(|(_, manifest)| manifest.encode().len()).sum::<usize>() > 100_000);
	let mut registry = registered(&setup);
	for phase in &phases[..2] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	registry.prepare_witnesses(&key(&setup), metadata.clone()).unwrap().commit();
	let reserved = registry.encoded_bytes + registry.reserved_transition_bytes;
	for phase in phases.iter().skip(2) {
		registry.prepare_activation(&setup, phase).unwrap().commit();
		assert!(registry.encoded_bytes + registry.reserved_transition_bytes <= reserved);
		assert_eq!(registry.get_witnesses(&key(&setup)), Some(&metadata));
		let bytes = registry.encode();
		assert_eq!(bytes[0], WITNESS_VERSION);
		assert_eq!(bytes.len(), registry.encoded_bytes);
		let restored = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
		assert_eq!(restored.get_witnesses(&key(&setup)), Some(&metadata));
		assert_eq!(restored.encode(), bytes);
	}
}

#[test]
fn ffor_witness_archive_reauthenticates_compact_metadata_and_required_fence() {
	let (setup, phases) = close::phases(false);
	let context = phases[1].receiver_context(&setup).unwrap();
	let metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &manifests(&context, 2)).unwrap();
	let record = || StoredSetup {
		setup: setup.clone(),
		canonical_book: context.setup().canonical_book().to_vec(),
		activation: Some(phases[1].clone()),
		request: None,
		witnesses: Some(metadata.clone()),
	};
	for mutation in 0..9 {
		let mut damaged = record();
		let registration = damaged.witnesses.as_mut().unwrap();
		match mutation {
			0 => registration.context_digest[0] ^= 1,
			1 => registration.witnesses[0].manifest_digest[0] ^= 1,
			2 => registration.witnesses[0].signature[0] ^= 1,
			3 => registration.witnesses[0].mailbox_id[0] ^= 1,
			4 => registration.witnesses[0].retention_until += 1,
			5 => registration.witnesses.swap(0, 1),
			6 => registration.witnesses.clear(),
			7 => damaged.activation = Some(phases[0].clone()),
			_ => registration.witnesses.push(registration.witnesses[0].clone()),
		}
		assert!(Entry::new(damaged).is_err(), "accepted compact metadata corruption {mutation}");
	}
	let mut registry = registered(&setup);
	for phase in &phases[..2] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	registry.prepare_witnesses(&key(&setup), metadata.clone()).unwrap().commit();
	let mut old_version = registry.encode();
	old_version[0] = crate::ln::ffor_recovery::REQUEST_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &old_version[..]).is_err());
	let mut missing = record();
	missing.witnesses = None;
	let mut bytes = vec![WITNESS_VERSION];
	1u16.write(&mut bytes).unwrap();
	(missing.serialized_length() as u32).write(&mut bytes).unwrap();
	missing.write(&mut bytes).unwrap();
	0u16.write(&mut bytes).unwrap();
	assert!(FFORRecoveryRegistry::read(&mut &bytes[..]).is_err());
	// The pre-registration record reader has no field 8 and must reject it as required.
	#[derive(Clone)]
	struct PreviousRecord {
		setup: FFORReceiverSetup,
		canonical_book: Vec<u8>,
		activation: Option<FFORReceiverActivation>,
		request: Option<crate::ln::channel::FFORReceiverRequest>,
	}
	impl_writeable_tlv_based!(PreviousRecord, {
		(0, setup, required), (2, canonical_book, required_vec),
		(4, activation, option), (6, request, option),
	});
	assert!(matches!(
		PreviousRecord::read(&mut &record().encode()[..]),
		Err(DecodeError::UnknownRequiredFeature)
	));
}

#[test]
fn ffor_witness_archive_capacity_failure_cannot_install_registration() {
	let (setup, phases) = close::phases(false);
	let context = phases[1].receiver_context(&setup).unwrap();
	let metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &manifests(&context, 4)).unwrap();
	let mut registry = registered(&setup);
	for phase in &phases[..2] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	// Exercise the exact checked quota arithmetic at the limit without allocating an 8 MiB fixture.
	registry.encoded_bytes = MAX_ENCODED_BYTES - registry.reserved_transition_bytes;
	let before = registry.encode();
	assert!(matches!(
		registry.prepare_witnesses(&key(&setup), metadata),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert_eq!(registry.encode(), before);
	assert!(registry.get_witnesses(&key(&setup)).is_none());
}

#[test]
fn ffor_witness_archive_rejects_signed_key_and_mailbox_reuse() {
	let (setup, phases) = close::phases(false);
	let context = phases[1].receiver_context(&setup).unwrap();
	let selected = manifests(&context, 2);
	let sign_manifest = |parameters, key: u8| {
		let unsigned = UnsignedManifest::new(context.setup(), parameters).unwrap();
		let signature = Secp256k1::new()
			.sign_ecdsa(
				&SecpMessage::from_digest(unsigned.signing_digest()),
				&SecretKey::from_slice(&[key; 32]).unwrap(),
			)
			.serialize_compact();
		unsigned.authenticate(signature).unwrap()
	};
	for duplicate_fetch in [false, true] {
		let mut repeated = selected.clone();
		let mut parameters = *selected[1].1.unsigned().parameters();
		let signer = if duplicate_fetch {
			parameters.fetch_public_key = selected[0].1.unsigned().parameters().fetch_public_key;
			100
		} else {
			parameters.mailbox_id = selected[0].1.unsigned().parameters().mailbox_id;
			101
		};
		repeated[1].1 = sign_manifest(parameters, signer);
		assert!(FFORReceiverWitnessRegistration::from_manifests(&context, &repeated).is_err());
	}
	let mut parameters = *selected[0].1.unsigned().parameters();
	parameters.encryption_public_key = parameters.fetch_public_key;
	let signed_reuse = sign_manifest(parameters, 100);
	let mut metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &selected[..1]).unwrap();
	metadata.witnesses[0].encryption_public_key = parameters.encryption_public_key;
	metadata.witnesses[0].signature = *signed_reuse.signature();
	metadata.witnesses[0].manifest_digest =
		bitcoin::hashes::sha256::Hash::hash(&signed_reuse.encode()).to_byte_array();
	let compact = metadata.encode();
	let restored = FFORReceiverWitnessRegistration::read(&mut &compact[..]).unwrap();
	assert!(restored.validate(&context).is_err());
}
