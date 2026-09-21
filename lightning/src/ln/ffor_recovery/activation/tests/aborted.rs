use super::*;
use crate::ln::channel::FFORReceiverFencePhase;
use crate::ln::ffor_recovery::{ABORTED_ACTIVATION_VERSION, ABORT_RESERVATION_BYTES};

fn report(setup: &FFORReceiverSetup, state: ReportedState) -> Reestablish {
	Reestablish { epoch_id: key(setup).epoch_id, state, activation_hash: [0; 32] }
}

fn abort_registry(
	setup: &FFORReceiverSetup, activating: &FFORReceiverActivation,
	peer_report: Option<Reestablish>,
) -> FFORRecoveryRegistry {
	let mut registry = registered(setup);
	registry.prepare_activation(setup, activating).unwrap().commit();
	let aborted = activating.abort_after_reestablish(setup, peer_report).unwrap();
	registry.prepare_activation(setup, &aborted).unwrap().commit();
	registry
}

#[test]
fn ffor_activation_abort_retains_exact_history_and_unsigned_reconnect_observation() {
	let (setup, activating) = evidence(false);
	let mut reports = vec![None];
	for state in [
		ReportedState::Negotiating,
		ReportedState::VouchersCommitted,
		ReportedState::Activating,
		ReportedState::Aborted,
	] {
		let expected = report(&setup, state);
		reports.push(Some(expected));
		// A pre-active report may name a different epoch or retain Beignet's pre-active hash.
		let mut other = expected;
		other.epoch_id[0] ^= 1;
		other.activation_hash = [7; 32];
		reports.push(Some(other));
	}
	for peer_report in reports {
		let aborted = activating.abort_after_reestablish(&setup, peer_report).unwrap();
		assert!(aborted.is_aborted());
		assert!(!aborted.is_active());
		assert_eq!(aborted.aborted_reason(), Some(FFORReceiverAbortReason::Disconnected));
		assert!(aborted.matches_abort_report(peer_report));
		assert!(!activating.matches_abort_report(peer_report));
		assert_eq!(aborted.activate_wire(), activating.activate_wire());
		assert_eq!(aborted.commitments(), activating.commitments());
		assert_eq!(
			aborted.activation_hash(&setup).unwrap(),
			activating.activation_hash(&setup).unwrap()
		);
		assert!(aborted.ack_wire().is_none());
		assert!(activating.can_replace(&aborted));
		assert!(!aborted.can_replace(&activating));
		assert_eq!(
			aborted.abort_after_reestablish(&setup, peer_report).unwrap().encode(),
			aborted.encode()
		);
		assert!(aborted.with_ack(&setup, &acknowledgement(&setup, &activating, false)).is_err());
		let alternate = Some(report(&setup, ReportedState::Negotiating));
		if alternate != peer_report {
			assert!(!aborted.matches_abort_report(alternate));
			assert!(aborted.abort_after_reestablish(&setup, alternate).is_err());
		}
	}
}

#[test]
fn ffor_activation_abort_never_discards_active_or_later_obligations() {
	let (setup, activating) = evidence(false);
	let ack = acknowledgement(&setup, &activating, false);
	let active = activating.with_ack(&setup, &ack).unwrap();
	assert_eq!(active.ack_wire(), Some(&ack[..]));
	assert!(active.abort_after_reestablish(&setup, None).is_err());
	for state in [ReportedState::Active, ReportedState::Draining, ReportedState::Closed] {
		for changed_identity in [false, true] {
			let mut peer_report = report(&setup, state);
			peer_report.activation_hash = activating.activation_hash(&setup).unwrap();
			if changed_identity {
				peer_report.epoch_id[0] ^= 1;
				peer_report.activation_hash[0] ^= 1;
			}
			assert!(activating.abort_after_reestablish(&setup, Some(peer_report)).is_err());
		}
	}
}

#[test]
fn ffor_activation_abort_is_monotonic_atomic_and_permanent() {
	let (setup, activating) = evidence(false);
	let aborted = activating.abort_after_reestablish(&setup, None).unwrap();
	let active = activating.with_ack(&setup, &acknowledgement(&setup, &activating, false)).unwrap();
	let mut registry = registered(&setup);
	assert!(matches!(
		registry.prepare_activation(&setup, &aborted),
		Err(FFORRecoveryError::ConflictingRecord)
	));
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	let before = registry.encode();
	drop(registry.prepare_activation(&setup, &aborted).unwrap());
	assert_eq!(registry.encode(), before);
	assert_eq!(registry.reserved_ack_bytes, ACK_RESERVATION_BYTES);
	registry.prepare_activation(&setup, &aborted).unwrap().commit();
	let terminal = registry.encode();
	let different = activating
		.abort_after_reestablish(&setup, Some(report(&setup, ReportedState::Aborted)))
		.unwrap();
	for refused in [&activating, &active, &different] {
		assert!(matches!(
			registry.prepare_activation(&setup, refused),
			Err(FFORRecoveryError::ConflictingRecord)
		));
		assert_eq!(registry.encode(), terminal);
	}
	registry.prepare_activation(&setup, &aborted).unwrap().commit();
	assert_eq!(registry.encode(), terminal);
	assert_eq!(registry.reserved_ack_bytes, 0);
	let mut active_registry = registered(&setup);
	active_registry.prepare_activation(&setup, &activating).unwrap().commit();
	active_registry.prepare_activation(&setup, &active).unwrap().commit();
	assert!(matches!(
		active_registry.prepare_activation(&setup, &aborted),
		Err(FFORRecoveryError::ConflictingRecord)
	));
}

#[test]
fn ffor_activation_abort_restore_requires_terminal_schema_and_matching_channel_reason() {
	let (setup, activating) = evidence(false);
	let peer_report = Some(report(&setup, ReportedState::Aborted));
	let registry = abort_registry(&setup, &activating, peer_report);
	let bytes = registry.encode();
	assert_eq!(bytes[0], ABORTED_ACTIVATION_VERSION);
	let restored = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	assert_eq!(restored.encode(), bytes);
	assert_eq!(restored.encoded_bytes, bytes.len());
	assert_eq!(restored.reserved_ack_bytes, 0);
	assert_eq!(restored.activation_keys(), vec![key(&setup)]);
	assert!(restored.activation_channels().is_empty());
	assert!(restored.get_activation(&key(&setup)).unwrap().matches_abort_report(peer_report));
	let hash = activating.activation_hash(&setup).unwrap();
	for fence in [None, Some((FFORReceiverFencePhase::Aborting, hash))] {
		assert!(restored
			.validate_channel_outcome(&setup, fence, Some(FFORReceiverAbortReason::Disconnected))
			.is_ok());
		for reason in [
			None,
			Some(FFORReceiverAbortReason::Requested),
			Some(FFORReceiverAbortReason::Restarted),
		] {
			assert!(restored.validate_channel_outcome(&setup, fence, reason).is_err());
		}
	}
	assert!(restored.validate_channel_fence(&setup, None).is_err());
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		assert!(restored
			.validate_channel_outcome(
				&setup,
				Some((phase, hash)),
				Some(FFORReceiverAbortReason::Disconnected)
			)
			.is_err());
	}
	let mut wrong_hash = hash;
	wrong_hash[0] ^= 1;
	assert!(restored
		.validate_channel_outcome(
			&setup,
			Some((FFORReceiverFencePhase::Aborting, wrong_hash)),
			Some(FFORReceiverAbortReason::Disconnected)
		)
		.is_err());
	for version in [SETUP_ONLY_VERSION, ACTIVATION_VERSION] {
		let mut downgrade = bytes.clone();
		downgrade[0] = version;
		assert!(FFORRecoveryRegistry::read(&mut &downgrade[..]).is_err());
	}
	let mut missing = registered(&setup);
	missing.prepare_activation(&setup, &activating).unwrap().commit();
	let mut missing = missing.encode();
	missing[0] = ABORTED_ACTIVATION_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &missing[..]).is_err());
}

#[test]
fn ffor_activation_abort_rejects_corrupt_reason_report_and_simultaneous_ack() {
	let (setup, activating) = evidence(false);
	let aborted = activating.abort_after_reestablish(&setup, None).unwrap();
	let authenticated = setup.validate_recovery().unwrap();
	let mut corrupt = aborted.clone();
	corrupt.abort.as_mut().unwrap().reason = FFORReceiverAbortReason::Requested;
	assert!(corrupt.validate(&authenticated).is_err());
	let mut corrupt = aborted.clone();
	corrupt.ack_wire = Some(acknowledgement(&setup, &activating, false));
	assert!(corrupt.validate(&authenticated).is_err());
	let valid_report = report(&setup, ReportedState::Aborted).encode();
	let mut malformed = vec![vec![], valid_report[..66].to_vec(), vec![0; 68]];
	let mut bad_state = valid_report.to_vec();
	bad_state[32] = 7;
	malformed.push(bad_state);
	let mut bad_sequence = valid_report.to_vec();
	bad_sequence[34] = 1;
	malformed.push(bad_sequence);
	malformed.push(report(&setup, ReportedState::Active).encode().to_vec());
	for bytes in malformed {
		let mut corrupt = aborted.clone();
		corrupt.abort.as_mut().unwrap().peer_report = Some(bytes);
		assert!(corrupt.validate(&authenticated).is_err());
		let mut registry = abort_registry(&setup, &activating, None);
		registry.entries[0].record.activation = Some(corrupt);
		registry.entries[0].encoded_bytes = registry.entries[0].record.serialized_length();
		assert!(FFORRecoveryRegistry::read(&mut &registry.encode()[..]).is_err());
	}
}

#[test]
fn ffor_activation_abort_has_reserved_capacity_after_restart_and_competing_admissions() {
	let (setup, activating) = evidence(false);
	let mut registry = registered(&setup);
	registry.prepare_activation(&setup, &activating).unwrap().commit();
	fill_ack_capacity(&mut registry);
	let before = registry.encode();
	let mut restored = FFORRecoveryRegistry::read(&mut &before[..]).unwrap();
	let reserved = restored.reserved_ack_bytes;
	let aborted = activating
		.abort_after_reestablish(&setup, Some(report(&setup, ReportedState::Aborted)))
		.unwrap();
	restored.prepare_activation(&setup, &aborted).unwrap().commit();
	assert_eq!(restored.reserved_ack_bytes, reserved - ACK_RESERVATION_BYTES);
	assert!(restored.encoded_bytes - before.len() < ABORT_RESERVATION_BYTES);
	assert!(restored.encoded_bytes + restored.reserved_ack_bytes <= MAX_ENCODED_BYTES);
	let terminal = restored.encode();
	let restored = FFORRecoveryRegistry::read(&mut &terminal[..]).unwrap();
	assert_eq!(restored.reserved_ack_bytes, reserved - ACK_RESERVATION_BYTES);
	assert_eq!(restored.encode(), terminal);
}
