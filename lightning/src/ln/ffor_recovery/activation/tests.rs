use super::*;
use crate::ln::ffor_recovery::tests::{fixture, sign};
use crate::ln::ffor_recovery::{
	FFORRecoveryError, FFORRecoveryKey, FFORRecoveryRegistry, ACK_RESERVATION_BYTES,
	ACTIVATION_VERSION, CLOSE_RESERVATION_BYTES, MAX_ENCODED_BYTES, MAX_RECORDS,
	SETUP_ONLY_VERSION,
};
use crate::ln::types::ChannelId;
use crate::util::ser::Readable;
use lightning_ffor::wire::{Activate, Tlv};

mod aborted;
mod close;

// Synthetic transaction identities exercise archive authentication only. Real monitor and
// channel evidence are exercised by the manager tests; these values never activate a channel.
fn evidence(maximum_size: bool) -> (FFORReceiverSetup, FFORReceiverActivation) {
	evidence_for_identity(71, maximum_size)
}

fn evidence_for_identity(
	identity: u8, maximum_size: bool,
) -> (FFORReceiverSetup, FFORReceiverActivation) {
	let setup = fixture(identity, maximum_size).record();
	let authenticated = setup.validate_recovery().unwrap();
	let receiver_txid = Txid::from_byte_array(core::array::from_fn(|i| i as u8));
	let settlement_txid = Txid::from_byte_array(core::array::from_fn(|i| (i + 32) as u8));
	let mut message = Message {
		header: authenticated.header(),
		payload: Payload::Activate(Activate {
			setup_hash: authenticated.setup_hash(),
			book_hash: authenticated.book_hash(),
			commit_hash: transcript::commitment_hash(
				4,
				&receiver_txid.to_byte_array(),
				4,
				&settlement_txid.to_byte_array(),
			),
			epoch_start_height: 500,
		}),
		extensions: vec![Tlv { kind: 101, value: vec![9, 2, 3] }],
		signature: [0; 64],
	};
	sign(&mut message, 41);
	if maximum_size {
		message.extensions.clear();
		sign(&mut message, 41);
		let padding = MAX_MESSAGE_LEN - message.encode().unwrap().len() - 4;
		message.extensions.push(Tlv { kind: 101, value: vec![7; padding] });
		sign(&mut message, 41);
		assert_eq!(message.encode().unwrap().len(), MAX_MESSAGE_LEN);
	}
	let record = FFORReceiverActivation {
		activate_wire: message.encode().unwrap(),
		ack_wire: None,
		abort: None,
		close: None,
		receiver_number: 4,
		receiver_txid,
		settlement_number: 4,
		settlement_txid,
		monitor_update_id: 5,
		preparation_height: 500,
		destination_script: ScriptBuf::from_bytes(vec![0, 20].into_iter().chain([3; 20]).collect()),
	};
	assert!(record.validate(&authenticated).is_ok());
	(setup, record)
}

fn acknowledgement(
	setup: &FFORReceiverSetup, record: &FFORReceiverActivation, maximum: bool,
) -> Vec<u8> {
	let authenticated = setup.validate_recovery().unwrap();
	let mut message = Message {
		header: authenticated.header(),
		payload: Payload::ActivateAck(record.validate(&authenticated).unwrap()),
		extensions: vec![],
		signature: [0; 64],
	};
	sign(&mut message, 42);
	if maximum {
		let padding = MAX_MESSAGE_LEN - message.encode().unwrap().len() - 4;
		message.extensions.push(Tlv { kind: 101, value: vec![8; padding] });
		sign(&mut message, 42);
		assert_eq!(message.encode().unwrap().len(), MAX_MESSAGE_LEN);
	}
	message.encode().unwrap()
}

fn registered(setup: &FFORReceiverSetup) -> FFORRecoveryRegistry {
	let mut registry = FFORRecoveryRegistry::new();
	registry.prepare_insert(setup).unwrap().commit();
	registry
}

fn key(setup: &FFORReceiverSetup) -> FFORRecoveryKey {
	let header = setup.validate_recovery().unwrap().header();
	FFORRecoveryKey { channel_id: ChannelId(header.channel_id), epoch_id: header.epoch_id }
}

#[test]
fn ffor_activation_archive_roundtrip_preserves_exact_maximum_transcripts() {
	let (setup, activating) = evidence(true);
	let ack = acknowledgement(&setup, &activating, true);
	let active = activating.with_ack(&setup, &ack).unwrap();
	let mut registry = registered(&setup);
	assert_eq!(registry.encode()[0], SETUP_ONLY_VERSION);
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	for expected in [&activating, &active] {
		registry.prepare_activation(&setup, expected).unwrap().commit();
		let bytes = registry.encode();
		assert_eq!(bytes[0], ACTIVATION_VERSION);
		assert_eq!(bytes.len(), registry.encoded_bytes);
		let restored = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
		assert_eq!(restored.encode(), bytes);
		let reservation =
			CLOSE_RESERVATION_BYTES + if expected.is_active() { 0 } else { ACK_RESERVATION_BYTES };
		assert_eq!(registry.reserved_transition_bytes, reservation);
		assert_eq!(restored.reserved_transition_bytes, reservation);
		assert_eq!(restored.get_activation(&key(&setup)).unwrap().encode(), expected.encode());
		assert!(restored.contains_exact(&setup));
	}
}

#[test]
fn ffor_activation_archive_rejects_signature_role_identity_and_commitment_substitution() {
	let (setup, original) = evidence(false);
	let authenticated = setup.validate_recovery().unwrap();
	for change in 0..10 {
		let mut record = original.clone();
		let mut message = Message::decode(&record.activate_wire).unwrap();
		match change {
			0 => message.header.epoch_id[0] ^= 1,
			1 => message.header.channel_id[0] ^= 1,
			2 => {
				if let Payload::Activate(activate) = &mut message.payload {
					activate.setup_hash[0] ^= 1
				}
			},
			3 => {
				if let Payload::Activate(activate) = &mut message.payload {
					activate.book_hash[0] ^= 1
				}
			},
			4 => {
				if let Payload::Activate(activate) = &mut message.payload {
					activate.commit_hash[0] ^= 1
				}
			},
			5 => record.receiver_number += 1,
			6 => record.settlement_number += 1,
			7 => record.receiver_txid = record.settlement_txid,
			8 => {
				let mut displayed = record.receiver_txid.to_byte_array();
				displayed.reverse();
				record.receiver_txid = Txid::from_byte_array(displayed);
			},
			_ => {},
		}
		sign(&mut message, if change == 9 { 42 } else { 41 });
		record.activate_wire = message.encode().unwrap();
		assert!(record.validate(&authenticated).is_err(), "accepted change {}", change);
	}
}

#[test]
fn ffor_activation_archive_requires_historical_height_and_valid_recovery_context() {
	let (setup, original) = evidence(false);
	let authenticated = setup.validate_recovery().unwrap();
	for change in 0..8 {
		let mut record = original.clone();
		match change {
			0 => record.preparation_height += 1,
			1 => record.receiver_number = 0,
			2 => record.settlement_number = 3,
			3 => record.settlement_number = INITIAL_COMMITMENT_NUMBER + 1,
			4 => record.monitor_update_id = 0,
			5 => record.monitor_update_id = u64::MAX,
			6 => record.destination_script = ScriptBuf::new(),
			_ => record.destination_script = ScriptBuf::from_bytes(vec![1; 10_001]),
		}
		assert!(record.validate(&authenticated).is_err(), "accepted context change {}", change);
	}
	let mut expired = original.clone();
	let mut message = Message::decode(&expired.activate_wire).unwrap();
	if let Payload::Activate(activate) = &mut message.payload {
		activate.epoch_start_height = 1000;
	}
	sign(&mut message, 41);
	expired.activate_wire = message.encode().unwrap();
	expired.preparation_height = 1000;
	assert!(expired.validate(&authenticated).is_err());
}

#[test]
fn ffor_activation_archive_acknowledgement_is_exact_authenticated_and_monotonic() {
	let (setup, activating) = evidence(false);
	let ack = acknowledgement(&setup, &activating, false);
	let active = activating.with_ack(&setup, &ack).unwrap();
	assert!(!activating.is_active());
	assert!(active.is_active());
	assert!(activating.can_replace(&active));
	assert!(!active.can_replace(&activating));
	assert_eq!(active.with_ack(&setup, &ack).unwrap().encode(), active.encode());
	for change in 0..4 {
		let mut changed = Message::decode(&ack).unwrap();
		match change {
			0 => changed.header.epoch_id[0] ^= 1,
			1 => {
				if let Payload::ActivateAck(hash) = &mut changed.payload {
					hash[0] ^= 1
				}
			},
			2 => {},
			_ => changed.extensions.push(Tlv { kind: 101, value: vec![1] }),
		}
		sign(&mut changed, if change == 2 { 41 } else { 42 });
		let bytes = changed.encode().unwrap();
		if change < 3 {
			assert!(activating.with_ack(&setup, &bytes).is_err());
		}
		assert!(active.with_ack(&setup, &bytes).is_err());
	}
}

#[test]
fn ffor_activation_archive_upgrade_is_atomic_idempotent_and_capacity_bounded() {
	let (setup, activating) = evidence(false);
	let active = activating.with_ack(&setup, &acknowledgement(&setup, &activating, false)).unwrap();
	let mut registry = registered(&setup);
	let original = registry.encode();
	assert!(matches!(
		registry.prepare_activation(&setup, &active),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	drop(registry.prepare_activation(&setup, &activating).unwrap());
	assert_eq!(registry.encode(), original);
	assert_eq!(registry.reserved_transition_bytes, 0);
	registry.reserved_transition_bytes = MAX_ENCODED_BYTES - registry.encoded_bytes;
	assert!(matches!(
		registry.prepare_activation(&setup, &activating),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert_eq!(registry.encode(), original);
	assert_eq!(registry.reserved_transition_bytes, MAX_ENCODED_BYTES - registry.encoded_bytes);
	registry.reserved_transition_bytes = 0;
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	let pending = registry.encode();
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	assert_eq!(registry.encode(), pending);
	assert_eq!(registry.reserved_transition_bytes, ACK_RESERVATION_BYTES + CLOSE_RESERVATION_BYTES);
	drop(registry.prepare_activation(&setup, &active).unwrap());
	assert_eq!(registry.encode(), pending);
	assert_eq!(registry.reserved_transition_bytes, ACK_RESERVATION_BYTES + CLOSE_RESERVATION_BYTES);
	registry.prepare_activation(&setup, &active).unwrap().commit();
	let completed = registry.encode();
	assert_eq!(registry.reserved_transition_bytes, CLOSE_RESERVATION_BYTES);
	assert!(completed.len() - pending.len() < ACK_RESERVATION_BYTES);
	registry.prepare_activation(&setup, &active).unwrap().commit();
	assert_eq!(registry.encode(), completed);
	assert!(matches!(
		registry.prepare_activation(&setup, &activating),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	assert_eq!(registry.encode(), completed);
	assert_eq!(registry.reserved_transition_bytes, CLOSE_RESERVATION_BYTES);
}

// Fill with real authenticated records until a further activation cannot reserve its ack. Large
// records reach the byte quota well before the count quota; small ones consume the remainder.
fn fill_ack_capacity(registry: &mut FFORRecoveryRegistry) {
	let mut maximum_size = true;
	for identity in 1..MAX_RECORDS as u8 {
		let (setup, activating) = evidence_for_identity(identity, maximum_size);
		let inserted = match registry.prepare_insert(&setup) {
			Ok(permit) => {
				permit.commit();
				true
			},
			Err(FFORRecoveryError::CapacityExceeded) => false,
			Err(other) => panic!("unexpected insertion error: {:?}", other),
		};
		let activated = inserted
			&& match registry.prepare_activation(&setup, &activating) {
				Ok(permit) => {
					permit.commit();
					true
				},
				Err(FFORRecoveryError::CapacityExceeded) => false,
				Err(other) => panic!("unexpected activation error: {:?}", other),
			};
		if !activated {
			if !maximum_size {
				return;
			}
			maximum_size = false;
		}
	}
	panic!("record count exhausted before acknowledgement capacity");
}

#[test]
fn ffor_activation_archive_reserves_maximum_ack_through_competing_admission_and_restart() {
	let (setup, activating) = evidence(false);
	let (competing_setup, competing_activation) = evidence_for_identity(72, false);
	let mut registry = registered(&setup);
	registry.prepare_insert(&competing_setup).unwrap().commit();
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	fill_ack_capacity(&mut registry);
	assert!(registry.entries.len() < MAX_RECORDS);
	let before = registry.encode();
	let reserved = registry.reserved_transition_bytes;
	assert!(matches!(
		registry.prepare_activation(&competing_setup, &competing_activation),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	let competing_record = fixture(90, true).record();
	// Its actual bytes would fit, but they must not consume the admitted acknowledgements.
	assert!(registry.encoded_bytes + competing_record.encode().len() < MAX_ENCODED_BYTES);
	assert!(matches!(
		registry.prepare_insert(&competing_record),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert_eq!(registry.encode(), before);
	assert_eq!(registry.reserved_transition_bytes, reserved);
	let mut restored = FFORRecoveryRegistry::read(&mut &before[..]).unwrap();
	assert_eq!(restored.reserved_transition_bytes, reserved);
	assert_eq!(restored.encoded_bytes, before.len());
	assert_eq!(restored.encode(), before);
	restored.prepare_activation(&setup, &activating).unwrap().commit();
	assert_eq!(restored.reserved_transition_bytes, reserved);
	let maximum_ack = acknowledgement(&setup, &activating, true);
	assert_eq!(maximum_ack.len(), MAX_MESSAGE_LEN);
	let active = activating.with_ack(&setup, &maximum_ack).unwrap();
	drop(restored.prepare_activation(&setup, &active).unwrap());
	assert_eq!(restored.encode(), before);
	assert_eq!(restored.reserved_transition_bytes, reserved);
	restored.prepare_activation(&setup, &active).unwrap().commit();
	assert_eq!(restored.reserved_transition_bytes, reserved - ACK_RESERVATION_BYTES);
	assert!(restored.encoded_bytes - before.len() < ACK_RESERVATION_BYTES);
	assert!(restored.encoded_bytes + restored.reserved_transition_bytes <= MAX_ENCODED_BYTES);
	assert_eq!(
		restored.get_activation(&key(&setup)).unwrap().ack_wire.as_ref(),
		Some(&maximum_ack)
	);
	let completed = restored.encode();
	restored.prepare_activation(&setup, &active).unwrap().commit();
	assert_eq!(restored.encode(), completed);
	let roundtrip = FFORRecoveryRegistry::read(&mut &completed[..]).unwrap();
	assert_eq!(roundtrip.reserved_transition_bytes, restored.reserved_transition_bytes);

	// A snapshot cannot bypass the reservation by declaring only its smaller current wire size.
	let (extra_setup, extra_activation) = evidence_for_identity(91, true);
	let extra = crate::ln::ffor_recovery::Entry::new(crate::ln::ffor_recovery::StoredSetup {
		canonical_book: extra_setup.validate_recovery().unwrap().canonical_book().to_vec(),
		setup: extra_setup,
		activation: Some(extra_activation),
	})
	.unwrap();
	assert!(restored.encoded_bytes + extra.encoded_bytes + 4 < MAX_ENCODED_BYTES);
	assert!(
		restored.encoded_bytes
			+ restored.reserved_transition_bytes
			+ extra.encoded_bytes
			+ extra.reserved_transition_bytes()
			+ 4 > MAX_ENCODED_BYTES
	);
	restored.entries.push(extra);
	let overcommitted = restored.encode();
	assert!(overcommitted.len() < MAX_ENCODED_BYTES);
	assert!(matches!(
		FFORRecoveryRegistry::read(&mut &overcommitted[..]),
		Err(DecodeError::InvalidValue)
	));
}

#[test]
fn ffor_activation_archive_requires_registered_setup_and_refuses_alternate_activation() {
	let (setup, activating) = evidence(false);
	assert!(matches!(
		FFORRecoveryRegistry::new().prepare_activation(&setup, &activating),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	let mut registry = registered(&setup);
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	let original = registry.encode();
	let mut alternative = activating.clone();
	let mut message = Message::decode(&alternative.activate_wire).unwrap();
	message.extensions[0].value[0] ^= 1;
	sign(&mut message, 41);
	alternative.activate_wire = message.encode().unwrap();
	assert!(alternative.validate(&setup.validate_recovery().unwrap()).is_ok());
	assert!(matches!(
		registry.prepare_activation(&setup, &alternative),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	assert_eq!(registry.encode(), original);
}

#[test]
fn ffor_activation_archive_reader_rejects_downgrades_truncation_and_invalid_evidence() {
	let (setup, activating) = evidence(false);
	let mut registry = registered(&setup);
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	let bytes = registry.encode();
	for length in 0..bytes.len() {
		assert!(FFORRecoveryRegistry::read(&mut &bytes[..length]).is_err());
	}
	let mut downgraded = bytes.clone();
	downgraded[0] = SETUP_ONLY_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &downgraded[..]).is_err());
	let mut missing = registered(&setup).encode();
	missing[0] = ACTIVATION_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &missing[..]).is_err());
	// Keep all framing valid while corrupting only the retained signature.
	let record = registry.entries[0].record.activation.as_mut().unwrap();
	let last = record.activate_wire.len() - 1;
	record.activate_wire[last] ^= 1;
	let invalid = registry.encode();
	assert!(FFORRecoveryRegistry::read(&mut &invalid[..]).is_err());
}

#[test]
fn ffor_activation_archive_requires_exact_live_phase_and_activation_hash() {
	let (setup, activating) = evidence(false);
	let authenticated = setup.validate_recovery().unwrap();
	let hash = activating.validate(&authenticated).unwrap();
	let active = activating.with_ack(&setup, &acknowledgement(&setup, &activating, false)).unwrap();
	let mut registry = registered(&setup);
	assert!(registry.validate_channel_fence(&setup, None).is_ok());
	assert!(registry
		.validate_channel_fence(
			&setup,
			Some((crate::ln::channel::FFORReceiverFencePhase::Activating, hash))
		)
		.is_err());
	for record in [&activating, &active] {
		registry.prepare_activation(&setup, record).unwrap().commit();
		let phase = if record.is_active() {
			crate::ln::channel::FFORReceiverFencePhase::Active
		} else {
			crate::ln::channel::FFORReceiverFencePhase::Activating
		};
		let wrong_phase = if record.is_active() {
			crate::ln::channel::FFORReceiverFencePhase::Activating
		} else {
			crate::ln::channel::FFORReceiverFencePhase::Active
		};
		assert!(registry.validate_channel_fence(&setup, Some((phase, hash))).is_ok());
		assert!(registry.validate_channel_fence(&setup, None).is_err());
		assert!(registry.validate_channel_fence(&setup, Some((wrong_phase, hash))).is_err());
		let mut changed = hash;
		changed[0] ^= 1;
		assert!(registry.validate_channel_fence(&setup, Some((phase, changed))).is_err());
	}
	assert_eq!(registry.activation_channels(), vec![ChannelId(authenticated.header().channel_id)]);
}

#[test]
fn ffor_activation_archive_matches_monitor_destination_and_both_commitment_views() {
	let (setup, activating) = evidence(false);
	let identity = FFORMonitorRecoveryIdentity {
		channel_id: key(&setup).channel_id,
		funding_txo: setup.funding_txo(),
		update_id: activating.monitor_update_id,
		holder_number: INITIAL_COMMITMENT_NUMBER - activating.receiver_number,
		holder_txid: activating.receiver_txid,
		counterparty_number: INITIAL_COMMITMENT_NUMBER - activating.settlement_number,
		counterparty_txid: Some(activating.settlement_txid),
		destination_script: activating.destination_script.clone(),
	};
	let mut registry = registered(&setup);
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	let channel_id = identity.channel_id;
	assert!(registry.validate_activation_monitor(channel_id, &identity).is_ok());
	let mut advanced = identity.clone();
	advanced.update_id += 2; // Preimage and force-close writes retain the same commitment pair.
	assert!(registry.validate_activation_monitor(channel_id, &advanced).is_ok());
	for change in 0..9 {
		let mut changed = identity.clone();
		match change {
			0 => changed.channel_id.0[0] ^= 1,
			1 => changed.funding_txo.index += 1,
			2 => changed.update_id -= 1,
			3 => changed.holder_number -= 1,
			4 => changed.counterparty_number -= 1,
			5 => changed.holder_txid = activating.settlement_txid,
			6 => changed.counterparty_txid = Some(activating.receiver_txid),
			7 => changed.counterparty_txid = None,
			_ => changed.destination_script = ScriptBuf::from_bytes(vec![81]),
		}
		assert!(
			registry.validate_activation_monitor(channel_id, &changed).is_err(),
			"accepted monitor change {}",
			change
		);
	}
	// A well-formed but substituted destination in the archive must also be detected by the
	// real monitor reference, even though scripts are not covered by the FFOR transcript hash.
	let mut changed = activating.clone();
	changed.destination_script = ScriptBuf::from_bytes(vec![81]);
	assert!(changed.validate(&setup.validate_recovery().unwrap()).is_ok());
	assert!(changed.validate_monitor(&setup, &identity).is_err());
}
