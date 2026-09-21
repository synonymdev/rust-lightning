use super::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};

fn base() -> ChannelReestablish {
	ChannelReestablish {
		channel_id: ChannelId::from_bytes([3; 32]),
		next_local_commitment_number: 2,
		next_remote_commitment_number: 1,
		your_last_per_commitment_secret: [4; 32],
		my_current_per_commitment_point: PublicKey::from_slice(&[2; 33]).unwrap(),
		next_funding: None,
		my_current_funding_locked: None,
		ffor_reestablish: None,
	}
}

#[test]
fn ffor_reestablish_tlv_has_exact_bolt_framing_and_shared_value() {
	let ordinary = base();
	let original = ordinary.encode();
	assert_eq!(original.len(), 113);
	assert_eq!(
		ChannelReestablish::read_from_fixed_length_buffer(&mut &original[..]).unwrap(),
		ordinary
	);
	for state in [
		ReportedState::Negotiating,
		ReportedState::VouchersCommitted,
		ReportedState::Activating,
		ReportedState::Active,
		ReportedState::Draining,
		ReportedState::Closed,
		ReportedState::Aborted,
	] {
		// Preserve an incoming pre-active hash, including the pinned reference's encoding.
		let report = Reestablish { epoch_id: [5; 32], state, activation_hash: [6; 32] };
		let mut message = ordinary.clone();
		message.ffor_reestablish = Some(FFORChannelReestablish::new(report));
		let bytes = message.encode();
		let mut expected = original.clone();
		expected.extend_from_slice(&[0xfd, 0xd6, 0xd9, 67]);
		expected.extend_from_slice(&report.encode());
		assert_eq!(bytes, expected);
		let restored = ChannelReestablish::read_from_fixed_length_buffer(&mut &bytes[..]).unwrap();
		assert_eq!(restored, message);
		assert_eq!(restored.ffor_reestablish.unwrap().report(), report);
	}
}

#[test]
fn ffor_reestablish_tlv_rejects_length_state_sequence_and_duplicate_fields() {
	let prefix = base().encode();
	let report =
		Reestablish { epoch_id: [5; 32], state: ReportedState::Active, activation_hash: [6; 32] };
	for fault in 0..6 {
		let mut value = report.encode().to_vec();
		match fault {
			0 => {
				value.pop();
			},
			1 => value.push(0),
			2 => value[32] = 7,
			3 => value[33] = 1,
			4 => value[34] = 1,
			_ => {},
		}
		let mut bytes = prefix.clone();
		bytes.extend_from_slice(&[0xfd, 0xd6, 0xd9, value.len() as u8]);
		bytes.extend_from_slice(&value);
		if fault == 5 {
			bytes.extend_from_slice(&[0xfd, 0xd6, 0xd9, 67]);
			bytes.extend_from_slice(&report.encode());
		}
		assert!(
			ChannelReestablish::read_from_fixed_length_buffer(&mut &bytes[..]).is_err(),
			"fault {fault}"
		);
	}
	let mut valid = prefix;
	valid.extend_from_slice(&[0xfd, 0xd6, 0xd9, 67]);
	valid.extend_from_slice(&report.encode());
	for length in 114..valid.len() {
		assert!(ChannelReestablish::read_from_fixed_length_buffer(&mut &valid[..length]).is_err());
	}
}
