use super::*;
use crate::chain::transaction::OutPoint;
use crate::io::Read;
use crate::ln::ffor::journal::FFORCooperativeJournal;
use crate::ln::ffor_recovery::{
	CLOSED_RESERVATION_BYTES, CLOSE_RESERVATION_BYTES, CLOSE_VERSION, INVOICE_VERSION,
	JOURNAL_VERSION, MAX_RECORD_BYTES,
};
use crate::util::ser::BigSize;
use bitcoin::hashes::sha256;
use lightning_ffor::wire::{CloseAck, Preimage};

fn signed(mut message: Message, signer: u8, maximum: bool) -> Vec<u8> {
	sign(&mut message, signer);
	if maximum {
		message.extensions.clear();
		let padding = MAX_MESSAGE_LEN - message.encode().unwrap().len() - 4;
		message.extensions.push(Tlv { kind: 101, value: vec![19; padding] });
		sign(&mut message, signer);
		assert_eq!(message.encode().unwrap().len(), MAX_MESSAGE_LEN);
	}
	message.encode().unwrap()
}

fn close_wire(
	setup: &FFORReceiverSetup, record: &FFORReceiverActivation, maximum: bool,
) -> Vec<u8> {
	signed(
		Message {
			header: setup.validate_recovery().unwrap().header(),
			payload: Payload::Close(record.activation_hash(setup).unwrap()),
			extensions: vec![],
			signature: [0; 64],
		},
		41,
		maximum,
	)
}

fn close_ack(
	setup: &FFORReceiverSetup, record: &FFORReceiverActivation, maximum: bool,
	preimages: Vec<Preimage>,
) -> Vec<u8> {
	let authenticated = setup.validate_recovery().unwrap();
	let count = authenticated.vouchers().len();
	let mut settled = vec![0; (count + 7) / 8];
	for preimage in &preimages {
		let bit = usize::from(preimage.slot - 1);
		settled[bit / 8] |= 1 << (bit % 8);
	}
	signed(
		Message {
			header: authenticated.header(),
			payload: Payload::CloseAck(CloseAck {
				activation_hash: record.activation_hash(setup).unwrap(),
				num_slots: count as u16,
				settled,
				preimages,
				preimages_tlv_present: true,
			}),
			extensions: vec![],
			signature: [0; 64],
		},
		42,
		maximum,
	)
}

pub(super) fn phases(maximum: bool) -> (FFORReceiverSetup, Vec<FFORReceiverActivation>) {
	let (setup, activating) = evidence(maximum);
	let active =
		activating.with_ack(&setup, &acknowledgement(&setup, &activating, maximum)).unwrap();
	let closing = active.with_close(&setup, &close_wire(&setup, &active, maximum)).unwrap();
	let draining =
		closing.with_close_ack(&setup, &close_ack(&setup, &closing, maximum, vec![])).unwrap();
	let journal = full_journal(&setup, 3);
	let closed =
		historical_closed(&setup, &draining, &completion_with(&setup, &draining, Some(journal)));
	(setup, vec![activating, active, closing, draining, closed])
}

/// A complete journal for the whole book, fulfilling every `every`-th slot from the first.
fn full_journal(setup: &FFORReceiverSetup, every: usize) -> FFORCooperativeJournal {
	let count = setup.validate_recovery().unwrap().vouchers().len();
	let mut journal = FFORCooperativeJournal::new(count).unwrap();
	for slot in 0..count {
		assert!(journal.record(slot, slot % every == 0));
	}
	journal
}

// This storage fixture exercises historical framing only. It cannot construct the channel's
// opaque completion proof or authorize any runtime transition. Real channel tests cover that.
#[derive(Clone)]
struct HistoricalCompletion {
	completion_hash: [u8; 32],
	receiver_number: u64,
	receiver_txid: Txid,
	settlement_number: u64,
	settlement_txid: Txid,
	monitor_update_id: u64,
	funding_txo: OutPoint,
	journal: Option<FFORCooperativeJournal>,
}
impl_writeable_tlv_based!(HistoricalCompletion, {
	(0, completion_hash, required), (2, receiver_number, required),
	(4, receiver_txid, required), (6, settlement_number, required),
	(8, settlement_txid, required), (10, monitor_update_id, required), (12, funding_txo, required),
	(14, journal, option),
});

/// The completion record layout before the native outcome journal existed.
#[derive(Clone)]
struct PreviousCompletion {
	completion_hash: [u8; 32],
	receiver_number: u64,
	receiver_txid: Txid,
	settlement_number: u64,
	settlement_txid: Txid,
	monitor_update_id: u64,
	funding_txo: OutPoint,
}
impl_writeable_tlv_based!(PreviousCompletion, {
	(0, completion_hash, required), (2, receiver_number, required),
	(4, receiver_txid, required), (6, settlement_number, required),
	(8, settlement_txid, required), (10, monitor_update_id, required), (12, funding_txo, required),
});

struct HistoricalClose {
	close_wire: Vec<u8>,
	ack_wire: Option<Vec<u8>>,
	closed: Option<HistoricalCompletion>,
}
impl_writeable_tlv_based!(HistoricalClose, {
	(0, close_wire, required_vec), (2, ack_wire, option), (4, closed, option),
});

fn completion(
	setup: &FFORReceiverSetup, draining: &FFORReceiverActivation,
) -> HistoricalCompletion {
	completion_with(setup, draining, None)
}

fn completion_with(
	setup: &FFORReceiverSetup, draining: &FFORReceiverActivation,
	journal: Option<FFORCooperativeJournal>,
) -> HistoricalCompletion {
	let mut completed = HistoricalCompletion {
		completion_hash: [0; 32],
		receiver_number: 5,
		receiver_txid: Txid::from_byte_array([7; 32]),
		settlement_number: 5,
		settlement_txid: Txid::from_byte_array([8; 32]),
		monitor_update_id: 6,
		funding_txo: setup.funding_txo(),
		journal,
	};
	let mut bytes = if completed.journal.is_some() {
		b"ffor/native-drain-complete/v2".to_vec()
	} else {
		b"ffor/native-drain-complete/v1".to_vec()
	};
	bytes.extend_from_slice(&key(setup).epoch_id);
	bytes.extend_from_slice(&draining.activation_hash(setup).unwrap());
	bytes.extend_from_slice(&draining.close_record().unwrap().acknowledgement_hash().unwrap());
	bytes.extend_from_slice(&key(setup).channel_id.0);
	bytes.extend_from_slice(&setup.funding_txo().encode());
	bytes.extend_from_slice(&completed.monitor_update_id.to_be_bytes());
	for (number, txid) in [
		(completed.receiver_number, completed.receiver_txid),
		(completed.settlement_number, completed.settlement_txid),
	] {
		bytes.extend_from_slice(&number.to_be_bytes());
		bytes.extend_from_slice(txid.as_byte_array());
	}
	if let Some(journal) = &completed.journal {
		bytes.extend_from_slice(&journal.digest_bytes());
	}
	completed.completion_hash = sha256::Hash::hash(&bytes).to_byte_array();
	completed
}

fn historical_closed(
	_setup: &FFORReceiverSetup, record: &FFORReceiverActivation, completed: &HistoricalCompletion,
) -> FFORReceiverActivation {
	let close = record.close_record().unwrap();
	let stored = HistoricalClose {
		close_wire: close.close_wire().to_vec(),
		ack_wire: close.acknowledgement_wire().map(|bytes| bytes.to_vec()),
		closed: Some(completed.clone()),
	};
	let mut next = record.clone();
	next.close = Some(FFORReceiverCloseRecord::read(&mut &stored.encode()[..]).unwrap());
	next
}

fn roundtrip(registry: &FFORRecoveryRegistry) -> FFORRecoveryRegistry {
	let bytes = registry.encode();
	assert_eq!(bytes.len(), registry.encoded_bytes);
	let restored = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	assert_eq!(restored.encode(), bytes);
	assert_eq!(restored.reserved_transition_bytes, registry.reserved_transition_bytes);
	restored
}

#[test]
fn ffor_activation_close_maximum_transcripts_preserve_history_and_reservations() {
	let (setup, phases) = phases(true);
	let mut registry = registered(&setup);
	let reservations = [
		ACK_RESERVATION_BYTES + CLOSE_RESERVATION_BYTES,
		CLOSE_RESERVATION_BYTES,
		ACK_RESERVATION_BYTES + CLOSED_RESERVATION_BYTES,
		CLOSED_RESERVATION_BYTES,
		0,
	];
	for (index, phase) in phases.iter().enumerate() {
		registry.prepare_activation(&setup, phase).unwrap().commit();
		assert_eq!(registry.reserved_transition_bytes, reservations[index]);
		assert!(registry.entries[0].encoded_bytes + reservations[index] <= MAX_RECORD_BYTES);
		assert!(registry.contains_exact(&setup));
		let retained = registry.get_activation(&key(&setup)).unwrap();
		assert_eq!(retained.activate_wire(), phases[0].activate_wire());
		assert_eq!(retained.commitments(), phases[0].commitments());
		if index >= 1 {
			assert_eq!(retained.ack_wire(), phases[1].ack_wire());
		}
		if index >= 2 {
			assert_eq!(
				registry.encode()[0],
				if index == 4 { JOURNAL_VERSION } else { CLOSE_VERSION }
			);
			let close = retained.close_record().unwrap();
			assert_eq!(close.close_wire().len(), MAX_MESSAGE_LEN);
			assert_eq!(close.close_wire(), phases[2].close_record().unwrap().close_wire());
		}
		if index >= 3 {
			let close = retained.close_record().unwrap();
			assert_eq!(close.acknowledgement_wire().unwrap().len(), MAX_MESSAGE_LEN);
			assert_eq!(close.settled().unwrap(), vec![0; 61]);
			assert!(close.preimages().unwrap().is_empty());
		}
		if index == 4 {
			assert_eq!(registry.encode()[0], JOURNAL_VERSION);
			let close = retained.close_record().unwrap();
			assert_eq!(close.journal(), Some(&full_journal(&setup, 3)));
			assert_eq!(close.journal().unwrap().slots(), 483);
		}
		registry = roundtrip(&registry);
	}
	assert!(registry.get_activation(&key(&setup)).unwrap().is_closed());
	// The maximum journaled Closed record plus its framing growth stays inside the reservation.
	let maximum = completion_with(&setup, &phases[3], Some(full_journal(&setup, 1)));
	assert!(
		maximum.serialized_length() + 64 <= CLOSED_RESERVATION_BYTES,
		"{}",
		maximum.serialized_length()
	);
}

#[test]
fn ffor_activation_close_journal_binds_completion_and_refuses_legacy_readers_and_corruption() {
	let (setup, phases) = phases(false);
	let authenticated = setup.validate_recovery().unwrap();
	let count = authenticated.vouchers().len();
	let draining = &phases[3];
	// A legacy completion without a journal still validates under the original digest domain
	// and reports no outcomes.
	let legacy = historical_closed(&setup, draining, &completion(&setup, draining));
	legacy.validate(&authenticated).unwrap();
	assert!(legacy.close_record().unwrap().journal().is_none());
	let mut registry = registered(&setup);
	for phase in &phases[..4] {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	let before_closed = registry.encode();
	registry.prepare_activation(&setup, &legacy).unwrap().commit();
	assert_eq!(registry.encode()[0], CLOSE_VERSION);
	registry = FFORRecoveryRegistry::read(&mut &before_closed[..]).unwrap();

	let journal = full_journal(&setup, 2);
	let journaled = historical_closed(
		&setup,
		draining,
		&completion_with(&setup, draining, Some(journal.clone())),
	);
	journaled.validate(&authenticated).unwrap();
	registry.prepare_activation(&setup, &journaled).unwrap().commit();
	let bytes = registry.encode();
	assert_eq!(bytes[0], JOURNAL_VERSION);
	let restored = roundtrip(&registry);
	assert_eq!(
		restored.get_activation(&key(&setup)).unwrap().close_record().unwrap().journal(),
		Some(&journal)
	);
	// The journal cannot be replaced or dropped once the Closed proof is retained.
	assert!(registry.prepare_activation(&setup, &legacy).is_err());
	let other = historical_closed(
		&setup,
		draining,
		&completion_with(&setup, draining, Some(full_journal(&setup, 1))),
	);
	assert!(registry.prepare_activation(&setup, &other).is_err());
	// Old readers reject the journal field and the new version byte instead of dropping them.
	let old_reader = PreviousCompletion::read(
		&mut &completion_with(&setup, draining, Some(journal.clone())).encode()[..],
	);
	assert!(matches!(old_reader, Err(DecodeError::UnknownRequiredFeature)));
	let mut downgraded = bytes.clone();
	downgraded[0] = INVOICE_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &downgraded[..]).is_err());
	let mut future = bytes.clone();
	future[0] = JOURNAL_VERSION + 1;
	assert!(matches!(
		FFORRecoveryRegistry::read(&mut &future[..]),
		Err(DecodeError::UnknownRequiredFeature)
	));
	// Malformed journals: wrong domain, incomplete coverage, padding, subset, size and a signed
	// settled slot that stock accounting never fulfilled.
	let bytes_len = (count + 7) / 8;
	let (payable_setup, payable_closing, preimages) = payable(false);
	let payable_authenticated = payable_setup.validate_recovery().unwrap();
	let settled_draining = payable_closing
		.with_close_ack(
			&payable_setup,
			&close_ack(&payable_setup, &payable_closing, false, vec![preimages[0].clone()]),
		)
		.unwrap();
	let unfulfilled = {
		let mut journal = FFORCooperativeJournal::new(2).unwrap();
		assert!(journal.record(0, false));
		assert!(journal.record(1, true));
		journal
	};
	let cases: Vec<(&FFORReceiverSetup, &FFORReceiverActivation, HistoricalCompletion)> = vec![
		(&setup, draining, {
			let mut completed = completion(&setup, draining);
			completed.journal = Some(journal.clone());
			completed
		}),
		(
			&setup,
			draining,
			completion_with(&setup, draining, Some(FFORCooperativeJournal::new(count).unwrap())),
		),
		(&setup, draining, {
			let mut resolved = vec![0xff; bytes_len];
			if count % 8 == 0 {
				resolved.push(0);
			}
			completion_with(
				&setup,
				draining,
				Some(FFORCooperativeJournal::from_parts(
					count as u16,
					resolved,
					vec![0; bytes_len],
				)),
			)
		}),
		(
			&setup,
			draining,
			completion_with(
				&setup,
				draining,
				Some(FFORCooperativeJournal::from_parts(
					count as u16,
					vec![0; bytes_len],
					vec![1; bytes_len],
				)),
			),
		),
		(&setup, draining, completion_with(&setup, draining, Some(full_journal_of(count + 1, 2)))),
		(
			&payable_setup,
			&settled_draining,
			completion_with(&payable_setup, &settled_draining, Some(unfulfilled)),
		),
	];
	for (index, (case_setup, base, completed)) in cases.iter().enumerate() {
		let closed = historical_closed(case_setup, base, completed);
		let authenticated = if index == 5 { &payable_authenticated } else { &authenticated };
		assert!(closed.validate(authenticated).is_err(), "change {index}");
	}
	// The same signed settled slot validates once stock accounting fulfilled it.
	let fulfilled = {
		let mut journal = FFORCooperativeJournal::new(2).unwrap();
		assert!(journal.record(0, true));
		assert!(journal.record(1, false));
		journal
	};
	historical_closed(
		&payable_setup,
		&settled_draining,
		&completion_with(&payable_setup, &settled_draining, Some(fulfilled)),
	)
	.validate(&payable_authenticated)
	.unwrap();
}

fn full_journal_of(count: usize, every: usize) -> FFORCooperativeJournal {
	let mut journal = FFORCooperativeJournal::new(count).unwrap();
	for slot in 0..count {
		assert!(journal.record(slot, slot % every == 0));
	}
	journal
}

#[test]
fn ffor_activation_close_registry_refuses_skipped_steps_reversal_and_mutating_retries() {
	let (setup, phases) = phases(false);
	for current in 0..phases.len() {
		let mut registry = registered(&setup);
		for phase in &phases[..=current] {
			registry.prepare_activation(&setup, phase).unwrap().commit();
		}
		let before = registry.encode();
		let reserved = registry.reserved_transition_bytes;
		for next in 0..phases.len() {
			let result = registry.prepare_activation(&setup, &phases[next]);
			if next == current || next == current + 1 {
				drop(result.unwrap());
			} else {
				assert!(
					matches!(result, Err(FFORRecoveryError::ConflictingRecord)),
					"{} -> {}",
					current,
					next
				);
			}
			assert_eq!(registry.encode(), before);
			assert_eq!(registry.reserved_transition_bytes, reserved);
		}
		registry.prepare_activation(&setup, &phases[current]).unwrap().commit();
		assert_eq!(registry.encode(), before);
	}
	let mut registry = registered(&setup);
	for phase in &phases[1..] {
		assert!(matches!(
			registry.prepare_activation(&setup, phase),
			Err(FFORRecoveryError::ConflictingRecord)
		));
	}
	let close = phases[2].close_record().unwrap().close_wire();
	assert!(phases[0].with_close(&setup, close).is_err());
	let aborted = phases[0].abort_after_reestablish(&setup, None).unwrap();
	assert!(aborted.with_close(&setup, close).is_err());
	assert!(phases[1]
		.with_close_ack(&setup, phases[3].close_record().unwrap().acknowledgement_wire().unwrap())
		.is_err());
	for phase in &phases[2..] {
		assert!(phase.abort_after_reestablish(&setup, None).is_err());
		assert_eq!(phase.with_close(&setup, close).unwrap().encode(), phase.encode());
	}
}

#[test]
fn ffor_activation_close_authenticates_receiver_header_hash_and_exact_bytes() {
	let (setup, phases) = phases(false);
	let original = phases[2].close_record().unwrap().close_wire();
	for change in 0..6 {
		let mut message = Message::decode(original).unwrap();
		match change {
			0 => message.header.channel_id[0] ^= 1,
			1 => message.header.epoch_id[0] ^= 1,
			2 => {
				if let Payload::Close(hash) = &mut message.payload {
					hash[0] ^= 1;
				}
			},
			3 => message.payload = Payload::ActivateAck(phases[1].activation_hash(&setup).unwrap()),
			_ => {},
		}
		let mut bytes = signed(message, if change == 4 { 42 } else { 41 }, false);
		if change == 5 {
			let last = bytes.len() - 1;
			bytes[last] ^= 1;
		}
		assert!(phases[1].with_close(&setup, &bytes).is_err(), "change {}", change);
	}
	let mut alternate = Message::decode(original).unwrap();
	alternate.extensions.push(Tlv { kind: 101, value: vec![3] });
	let alternate = signed(alternate, 41, false);
	assert!(phases[1].with_close(&setup, &alternate).is_ok());
	assert!(phases[2].with_close(&setup, &alternate).is_err());
	assert!(phases[1].with_close(&setup, &vec![0; MAX_MESSAGE_LEN + 1]).is_err());
}

fn replace_setup_wire(
	setup: &FFORReceiverSetup, init: Vec<u8>, accept: Vec<u8>,
) -> FFORReceiverSetup {
	let encoded = setup.encode();
	let mut reader = &encoded[..];
	let length = BigSize::read(&mut reader).unwrap().0 as usize;
	assert_eq!(reader.len(), length);
	let mut body = Vec::new();
	while !reader.is_empty() {
		let kind = BigSize::read(&mut reader).unwrap();
		let len = BigSize::read(&mut reader).unwrap().0 as usize;
		let mut value = vec![0; len];
		reader.read_exact(&mut value).unwrap();
		let replacement = match kind.0 {
			0 => &init,
			2 => &accept,
			_ => &value,
		};
		kind.write(&mut body).unwrap();
		BigSize(replacement.len() as u64).write(&mut body).unwrap();
		body.extend_from_slice(replacement);
	}
	let mut bytes = Vec::new();
	BigSize(body.len() as u64).write(&mut bytes).unwrap();
	bytes.extend_from_slice(&body);
	FFORReceiverSetup::read(&mut &bytes[..]).unwrap()
}

fn payable(chain: bool) -> (FFORReceiverSetup, FFORReceiverActivation, Vec<Preimage>) {
	let (setup, mut record) = evidence(false);
	let authenticated = setup.validate_recovery().unwrap();
	let values = if chain {
		[sha256::Hash::hash(&[18; 32]).to_byte_array(), [18; 32]]
	} else {
		[[17; 32], [18; 32]]
	};
	let mut init = authenticated.init().clone();
	if let Payload::Init(terms) = &mut init.payload {
		terms.hash_chain = chain;
	}
	let init_wire = signed(init, 41, false);
	let mut accept = authenticated.accept().clone();
	if let Payload::Accept(terms) = &mut accept.payload {
		terms.init_hash = transcript::init_hash(&init_wire);
		terms.payment_hashes =
			values.iter().map(|p| sha256::Hash::hash(p).to_byte_array()).collect();
	}
	let setup = replace_setup_wire(&setup, init_wire, signed(accept, 42, false));
	let authenticated = setup.validate_recovery().unwrap();
	let mut activate = Message::decode(record.activate_wire()).unwrap();
	if let Payload::Activate(message) = &mut activate.payload {
		message.setup_hash = authenticated.setup_hash();
		message.book_hash = authenticated.book_hash();
	}
	record.activate_wire = signed(activate, 41, false);
	let active = record.with_ack(&setup, &acknowledgement(&setup, &record, false)).unwrap();
	let closing = active.with_close(&setup, &close_wire(&setup, &active, false)).unwrap();
	(
		setup,
		closing,
		values
			.iter()
			.enumerate()
			.map(|(i, value)| Preimage { slot: i as u16 + 1, value: *value })
			.collect(),
	)
}

#[test]
fn ffor_activation_close_ack_checks_settlement_role_book_preimages_and_chain_prefix() {
	for chain in [false, true] {
		let (setup, closing, preimages) = payable(chain);
		let wire = close_ack(&setup, &closing, false, preimages.clone());
		let draining = closing.with_close_ack(&setup, &wire).unwrap();
		assert_eq!(draining.close_record().unwrap().settled().unwrap(), vec![3]);
		let retained = draining.close_record().unwrap().preimages().unwrap();
		assert_eq!(retained.len(), 2);
		for (index, (slot, preimage)) in retained.iter().enumerate() {
			assert_eq!(*slot, index as u16 + 1);
			assert_eq!(preimage.0, preimages[index].value);
		}
		for change in 0..7 {
			let mut message = Message::decode(&wire).unwrap();
			match change {
				0 => message.header.channel_id[0] ^= 1,
				1 => message.header.epoch_id[0] ^= 1,
				2 => {
					if let Payload::CloseAck(ack) = &mut message.payload {
						ack.activation_hash[0] ^= 1;
					}
				},
				3 => {
					if let Payload::CloseAck(ack) = &mut message.payload {
						ack.num_slots = 3;
					}
				},
				4 => {
					if let Payload::CloseAck(ack) = &mut message.payload {
						ack.preimages[0].value[0] ^= 1;
					}
				},
				5 => message.payload = Payload::Close(closing.activation_hash(&setup).unwrap()),
				_ => {},
			}
			assert!(
				closing
					.with_close_ack(
						&setup,
						&signed(message, if change == 6 { 41 } else { 42 }, false)
					)
					.is_err(),
				"change {}",
				change
			);
		}
		let later_only = close_ack(&setup, &closing, false, vec![preimages[1].clone()]);
		assert_eq!(closing.with_close_ack(&setup, &later_only).is_err(), chain);
		assert!(closing
			.with_close_ack(&setup, &close_ack(&setup, &closing, false, vec![preimages[0].clone()]))
			.is_ok());
		assert_eq!(draining.with_close_ack(&setup, &wire).unwrap().encode(), draining.encode());
		let mut alternate = Message::decode(&wire).unwrap();
		alternate.extensions.push(Tlv { kind: 101, value: vec![8] });
		let alternate = signed(alternate, 42, false);
		assert!(closing.with_close_ack(&setup, &alternate).is_ok());
		assert!(draining.with_close_ack(&setup, &alternate).is_err());
		assert!(closing.with_close_ack(&setup, &vec![0; MAX_MESSAGE_LEN + 1]).is_err());
	}
}

#[test]
fn ffor_activation_close_preserves_distinct_empty_ack_tlv_and_terminal_history() {
	let (setup, phases) = phases(false);
	let wire = phases[3].close_record().unwrap().acknowledgement_wire().unwrap();
	let mut absent = Message::decode(wire).unwrap();
	if let Payload::CloseAck(ack) = &mut absent.payload {
		ack.preimages_tlv_present = false;
	}
	let absent = signed(absent, 42, false);
	assert_ne!(&absent[..], wire);
	let alternate = phases[2].with_close_ack(&setup, &absent).unwrap();
	assert!(alternate.validate(&setup.validate_recovery().unwrap()).is_ok());
	assert!(phases[3].with_close_ack(&setup, &absent).is_err());
	assert!(phases[4].with_close_ack(&setup, &absent).is_err());
	assert_eq!(phases[4].with_close_ack(&setup, wire).unwrap().encode(), phases[4].encode());
	let mut changed = completion(&setup, &phases[3]);
	changed.receiver_txid = Txid::from_byte_array([9; 32]);
	assert!(!phases[4].can_replace(&historical_closed(&setup, &phases[3], &changed)));
}

#[test]
fn ffor_activation_close_restore_rejects_downgrades_missing_steps_and_altered_completion() {
	let (setup, phases) = phases(false);
	let mut registry = registered(&setup);
	for phase in &phases {
		registry.prepare_activation(&setup, phase).unwrap().commit();
	}
	let original = registry.encode();
	for version in 0..CLOSE_VERSION {
		let mut bytes = original.clone();
		bytes[0] = version;
		assert!(FFORRecoveryRegistry::read(&mut &bytes[..]).is_err());
	}
	for change in 0..11 {
		let mut closed = phases[4].clone();
		if change == 0 {
			closed.ack_wire = None;
		} else if change == 1 {
			let stored = HistoricalClose {
				close_wire: vec![],
				ack_wire: None,
				closed: Some(completion(&setup, &phases[3])),
			};
			closed.close = Some(FFORReceiverCloseRecord::read(&mut &stored.encode()[..]).unwrap());
		} else {
			let mut completed = completion(&setup, &phases[3]);
			match change {
				2 => completed.receiver_number = 0,
				3 => completed.receiver_number = 4,
				4 => completed.settlement_number = INITIAL_COMMITMENT_NUMBER + 1,
				5 => completed.monitor_update_id = u64::MAX,
				6 => completed.monitor_update_id = 5,
				7 => completed.receiver_txid = Txid::from_byte_array([23; 32]),
				8 => completed.settlement_txid = Txid::from_byte_array([23; 32]),
				9 => completed.monitor_update_id = 7,
				_ => completed.completion_hash[0] ^= 1,
			}
			closed = historical_closed(&setup, &phases[3], &completed);
		}
		assert!(closed.validate(&setup.validate_recovery().unwrap()).is_err(), "change {}", change);
		registry.entries[0].record.activation = Some(closed);
		registry.entries[0].encoded_bytes = registry.entries[0].record.serialized_length();
		assert!(
			FFORRecoveryRegistry::read(&mut &registry.encode()[..]).is_err(),
			"stored change {}",
			change
		);
	}
}

#[test]
fn ffor_activation_close_reserved_capacity_survives_competing_admission_and_each_restart() {
	let (setup, phases) = phases(true);
	let mut registry = registered(&setup);
	registry.prepare_activation(&setup, &phases[0]).unwrap().commit();
	fill_ack_capacity(&mut registry);
	let original = registry.encode();
	let reserved = registry.reserved_transition_bytes;
	assert!(matches!(
		registry.prepare_insert(&fixture(90, true).record()),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert_eq!(registry.encode(), original);
	assert_eq!(registry.reserved_transition_bytes, reserved);
	let reservations = [
		CLOSE_RESERVATION_BYTES,
		ACK_RESERVATION_BYTES + CLOSED_RESERVATION_BYTES,
		CLOSED_RESERVATION_BYTES,
		0,
	];
	let mut previous_charge = registry.encoded_bytes + registry.reserved_transition_bytes;
	for (index, phase) in phases[1..].iter().enumerate() {
		registry = roundtrip(&registry);
		let before = registry.encode();
		let before_reserved = registry.reserved_transition_bytes;
		drop(registry.prepare_activation(&setup, phase).unwrap());
		assert_eq!(registry.encode(), before);
		assert_eq!(registry.reserved_transition_bytes, before_reserved);
		registry.prepare_activation(&setup, phase).unwrap().commit();
		assert_eq!(registry.entries[0].reserved_transition_bytes(), reservations[index]);
		let charged = registry.encoded_bytes + registry.reserved_transition_bytes;
		assert!(charged <= previous_charge);
		assert!(charged <= MAX_ENCODED_BYTES);
		previous_charge = charged;
	}
	assert!(roundtrip(&registry).get_activation(&key(&setup)).unwrap().is_closed());
}
