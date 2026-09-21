use super::*;
use crate::ln::ffor::{FFORReceiverWitnessAcknowledgements, FFORWitnessAcknowledgement};
use crate::ln::ffor_recovery::WITNESS_ACK_VERSION;

fn promise(witness: &crate::ln::ffor::FFORRegisteredWitness, id: u8) -> FFORWitnessAcknowledgement {
	FFORWitnessAcknowledgement {
		witness: witness.witness_node_id(),
		manifest_digest: witness.manifest_digest(),
		request_id: [id; 16],
		retention_until: witness.retention_until(),
	}
}

#[test]
fn ffor_witness_ack_archive_fixed_capacity_survives_maximum_book_and_terminal_growth() {
	let (setup, phases) = close::phases(true);
	let context = phases[1].receiver_context(&setup).unwrap();
	let metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &manifests(&context, 4)).unwrap();
	let mut registry = registered(&setup);
	for phase in &phases[..2] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	let key = key(&setup);
	registry.prepare_witnesses(&key, metadata.clone()).unwrap().commit();
	let before = registry.encoded_bytes;
	let reserved = registry.reserved_transition_bytes;
	assert_eq!(registry.get_witness_acks(&key).unwrap().serialized_length(), 373);
	for (index, witness) in metadata.witnesses().iter().enumerate() {
		registry.prepare_witness_ack(&key, promise(witness, index as u8)).unwrap().commit();
		assert_eq!(registry.encoded_bytes, before);
		assert_eq!(registry.reserved_transition_bytes, reserved);
		let bytes = registry.encode();
		assert_eq!(bytes[0], WITNESS_ACK_VERSION);
		registry = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	}
	let promises = registry.get_witness_acks(&key).unwrap().clone();
	for phase in &phases[2..] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
		assert_eq!(registry.get_witness_acks(&key), Some(&promises));
	}
	assert_eq!(registry.reserved_transition_bytes, 0);
	let encoded = registry.encode();
	assert_eq!(FFORRecoveryRegistry::read(&mut &encoded[..]).unwrap().encode(), encoded);
}

#[test]
fn ffor_witness_ack_archive_legacy_upgrade_checks_capacity_before_tracking() {
	let (setup, phases) = close::phases(false);
	let context = phases[1].receiver_context(&setup).unwrap();
	let metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &manifests(&context, 4)).unwrap();
	let legacy = StoredSetup {
		setup: setup.clone(),
		canonical_book: context.setup().canonical_book().to_vec(),
		activation: Some(phases[1].clone()),
		request: None,
		witnesses: Some(metadata.clone()),
		witness_acks: None,
		invoice: None,
	};
	let mut bytes = vec![WITNESS_VERSION];
	1u16.write(&mut bytes).unwrap();
	(legacy.serialized_length() as u32).write(&mut bytes).unwrap();
	legacy.write(&mut bytes).unwrap();
	0u16.write(&mut bytes).unwrap();
	let mut registry = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	let key = key(&setup);
	assert!(registry.get_witness_acks(&key).is_none());
	let actual_bytes = registry.encoded_bytes;
	registry.encoded_bytes = MAX_ENCODED_BYTES - registry.reserved_transition_bytes;
	assert!(matches!(
		registry.prepare_witnesses(&key, metadata.clone()),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert!(registry.get_witness_acks(&key).is_none());
	assert_eq!(registry.encode(), bytes);
	registry.encoded_bytes = actual_bytes;
	registry.prepare_witnesses(&key, metadata.clone()).unwrap().commit();
	assert_eq!(registry.encode()[0], WITNESS_ACK_VERSION);
	// All future ACK bytes are already charged, including all TLV prefix changes.
	registry.encoded_bytes = MAX_ENCODED_BYTES - registry.reserved_transition_bytes;
	for witness in metadata.witnesses() {
		registry.prepare_witness_ack(&key, promise(witness, 1)).unwrap().commit();
		assert_eq!(registry.encoded_bytes + registry.reserved_transition_bytes, MAX_ENCODED_BYTES);
	}
}

#[test]
fn ffor_witness_ack_archive_rejects_corruption_and_old_reader_downgrade() {
	let (setup, phases) = close::phases(false);
	let context = phases[1].receiver_context(&setup).unwrap();
	let metadata =
		FFORReceiverWitnessRegistration::from_manifests(&context, &manifests(&context, 2)).unwrap();
	let acks = FFORReceiverWitnessAcknowledgements {
		context_digest: context.context_digest(),
		acknowledgements: metadata.witnesses().iter().map(|witness| promise(witness, 1)).collect(),
	};
	let record = || StoredSetup {
		setup: setup.clone(),
		canonical_book: context.setup().canonical_book().to_vec(),
		activation: Some(phases[1].clone()),
		request: None,
		witnesses: Some(metadata.clone()),
		witness_acks: Some(acks.clone()),
		invoice: None,
	};
	for mutation in 0..7 {
		let mut damaged = record();
		let promises = damaged.witness_acks.as_mut().unwrap();
		match mutation {
			0 => promises.context_digest[0] ^= 1,
			1 => promises.acknowledgements[0].manifest_digest[0] ^= 1,
			2 => promises.acknowledgements[0].retention_until -= 1,
			3 => promises.acknowledgements.swap(0, 1),
			4 => promises.acknowledgements[1] = promises.acknowledgements[0].clone(),
			5 => damaged.witnesses = None,
			_ => damaged.activation = Some(phases[0].clone()),
		}
		assert!(Entry::new(damaged).is_err(), "accepted ACK corruption {}", mutation);
	}
	let encoded = acks.encode();
	assert_eq!(encoded.len(), 373);
	let mut padding = encoded.clone();
	*padding.last_mut().unwrap() = 1;
	assert!(FFORReceiverWitnessAcknowledgements::read(&mut &padding[..]).is_err());
	let mut oversized = encoded.clone();
	oversized[32] = 5;
	assert!(FFORReceiverWitnessAcknowledgements::read(&mut &oversized[..]).is_err());
	assert!(FFORReceiverWitnessAcknowledgements::read(&mut &encoded[..372]).is_err());
	struct PreviousRecord {
		setup: FFORReceiverSetup,
		canonical_book: Vec<u8>,
		activation: Option<FFORReceiverActivation>,
		request: Option<crate::ln::channel::FFORReceiverRequest>,
		witnesses: Option<FFORReceiverWitnessRegistration>,
	}
	impl_writeable_tlv_based!(PreviousRecord, {
		(0, setup, required), (2, canonical_book, required_vec), (4, activation, option),
		(6, request, option), (8, witnesses, option),
	});
	assert!(matches!(
		PreviousRecord::read(&mut &record().encode()[..]),
		Err(DecodeError::UnknownRequiredFeature)
	));
	let mut framed = vec![WITNESS_VERSION];
	1u16.write(&mut framed).unwrap();
	(record().serialized_length() as u32).write(&mut framed).unwrap();
	record().write(&mut framed).unwrap();
	0u16.write(&mut framed).unwrap();
	assert!(FFORRecoveryRegistry::read(&mut &framed[..]).is_err());
}
