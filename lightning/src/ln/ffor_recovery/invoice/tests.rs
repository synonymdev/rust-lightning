use super::*;

// Called by the real-channel integration fixture, so these archive mutations cannot accidentally
// invent invoice admission authority from synthetic commitment identities.
pub(crate) fn check_archive(registry: &FFORRecoveryRegistry, key: FFORRecoveryKey) {
	let bytes = registry.encode();
	assert_eq!(bytes[0], INVOICE_VERSION);
	let restored = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	assert_eq!(restored.encode(), bytes);
	let record = restored.get_invoice(&key).unwrap().clone();
	assert!(record.serialized_length() < MAX_INVOICE_RECORD_BYTES);
	let entry = restored.entries.iter().find(|entry| entry.key == key).unwrap();
	let context =
		entry.record.activation.as_ref().unwrap().receiver_context(&entry.record.setup).unwrap();
	let registration = entry.record.witnesses.as_ref().unwrap();
	let acks = entry.record.witness_acks.as_ref().unwrap();
	for fault in 0..9 {
		let mut bad = record.clone();
		match fault {
			0 => bad.context_digest[0] ^= 1,
			1 => bad.acknowledgement_digest[0] ^= 1,
			2 => bad.intent.description.push('!'),
			3 => bad.intent.expiry_seconds += 1,
			4 => bad.intent.safety_margin_seconds = u32::MAX,
			5 => bad.settlement_scid ^= 1,
			6 => bad.settlement_cltv += 1,
			7 => bad.invoice.push('x'),
			8 => bad.route.update.contents.fee_base_msat += 1,
			_ => unreachable!(),
		}
		assert!(bad.validate(&context, registration, acks).is_err(), "fault {fault}");
	}
	let mut old_reader = bytes.clone();
	old_reader[0] = WITNESS_ACK_VERSION;
	assert!(FFORRecoveryRegistry::read(&mut &old_reader[..]).is_err());
	let mut future = bytes.clone();
	future[0] = INVOICE_VERSION + 1;
	assert!(FFORRecoveryRegistry::read(&mut &future[..]).is_err());
	let encoded = record.encode();
	for end in [0, 31, 63, 87, encoded.len() - 1] {
		assert!(FFORInvoiceRecord::read(&mut &encoded[..end]).is_err());
	}
	let mut oversized_description = encoded.clone();
	oversized_description[86..88].copy_from_slice(&640u16.to_be_bytes());
	assert!(FFORInvoiceRecord::read(&mut &oversized_description[..]).is_err());

	let mut base = FFORRecoveryRegistry::read(&mut &bytes[..]).unwrap();
	let index = base.entries.iter().position(|entry| entry.key == key).unwrap();
	let old = base.entries.remove(index);
	let old_bytes = old.encoded_bytes;
	let old_reservation = old.reserved_transition_bytes();
	let mut before_record = old.record;
	before_record.invoice = None;
	let before = Entry::new(before_record).unwrap();
	base.encoded_bytes = base.encoded_bytes - old_bytes + before.encoded_bytes;
	base.reserved_transition_bytes =
		base.reserved_transition_bytes - old_reservation + before.reserved_transition_bytes();
	base.entries.insert(index, before);
	let before_bytes = base.encode();
	let real_count = base.encoded_bytes;
	base.encoded_bytes = MAX_ENCODED_BYTES - base.reserved_transition_bytes;
	assert!(matches!(
		base.prepare_invoice(&key, record.clone()),
		Err(FFORRecoveryError::CapacityExceeded)
	));
	assert!(base.get_invoice(&key).is_none());
	base.encoded_bytes = real_count;
	assert_eq!(base.encode(), before_bytes);
	{
		let _cancelled = base.prepare_invoice(&key, record.clone()).unwrap();
	}
	assert!(base.get_invoice(&key).is_none());
	base.prepare_invoice(&key, record.clone()).unwrap().commit();
	assert_eq!(base.encode(), bytes);
	assert!(matches!(
		base.prepare_invoice(&key, record),
		Err(FFORRecoveryError::ConflictingRecord)
	));
}
