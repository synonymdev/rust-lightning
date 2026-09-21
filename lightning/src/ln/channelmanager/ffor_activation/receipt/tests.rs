use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::ln::channelmanager::ffor_activation::drain_tests::{drain, park_two, park_two_epoch};
use crate::ln::channelmanager::ffor_recovery_tests::restore;
use crate::ln::ffor::decrypt_ffor_witness_record;
use crate::ln::ffor_recovery::ffor_test_witness_manifests as manifests;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::HashEngine;
use bitcoin::secp256k1::{ecdh::SharedSecret, Message as SecpMessage, Secp256k1, SecretKey};
use lightning_ffor::wire::CloseAck;
use lightning_ffor::witness::{EncryptedRecord, RecordHeader, SignedManifest};

const EPOCH: [u8; 32] = [81; 32];

fn persist(manager: &TestChannelManager) -> Vec<u8> {
	let token = manager.capture_ffor_persistence();
	let bytes = manager.encode();
	manager.ffor_persistence_completed(token).unwrap();
	bytes
}

fn signed(sender: &Node, context: &FFORReceiverRecoveryContext, payload: Payload) -> Vec<u8> {
	let mut message = FFORMessage {
		header: context.setup().header(),
		payload,
		extensions: Vec::new(),
		signature: [0; 64],
	};
	message.signature = sender
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
	message.encode().unwrap()
}

fn activate(sender: &Node, receiver: &Node, id: ChannelId) -> FFORReceiverRecoveryContext {
	let context = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
	let ack = signed(sender, &context, Payload::ActivateAck(context.activation_hash()));
	receiver
		.node
		.accept_ffor_receiver_activation_ack(&id, &sender.node.get_our_node_id(), EPOCH, &ack)
		.unwrap();
	persist(receiver.node);
	let context = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
	receiver.node.register_ffor_receiver_witnesses(&context, &manifests(&context, 1)).unwrap();
	persist(receiver.node);
	context
}

/// Build a genuine signed, encrypted record and pass it through production authentication/AEAD.
fn receipt(
	context: &FFORReceiverRecoveryContext, manifest: &SignedManifest, preimage: PaymentPreimage,
	witness_byte: u8,
) -> FFORWitnessReceipt {
	receipt_slot(context, manifest, preimage, witness_byte, 1)
}

fn receipt_slot(
	context: &FFORReceiverRecoveryContext, manifest: &SignedManifest, preimage: PaymentPreimage,
	witness_byte: u8, slot: u16,
) -> FFORWitnessReceipt {
	let secp = Secp256k1::new();
	let encryption = SecretKey::from_slice(&[120; 32]).unwrap();
	let ephemeral = SecretKey::from_slice(&[121; 32]).unwrap();
	let witness = SecretKey::from_slice(&[witness_byte; 32]).unwrap();
	let voucher = &context.setup().vouchers()[usize::from(slot) - 1];
	let mut body = Vec::new();
	body.extend_from_slice(&context.epoch_id());
	body.extend_from_slice(&slot.to_be_bytes());
	body.extend_from_slice(&preimage.0);
	body.extend_from_slice(&voucher.payment_hash);
	body.extend_from_slice(&voucher.amount_msat.to_be_bytes());
	body.extend_from_slice(&voucher.expiry.to_be_bytes());
	body.extend_from_slice(&context.setup().terms().settlement_deadline.to_be_bytes());
	body.extend_from_slice(&[0; 28]);
	assert_eq!(body.len(), 142);
	let parameters = manifest.unsigned().parameters();
	let start = 36 + (usize::from(slot) - 1) * 58;
	let entry = &context.setup().canonical_book()[start..start + 58];
	let mut header = RecordHeader {
		mailbox_id: parameters.mailbox_id,
		record_id: [9; 32],
		slot,
		activation_hash: context.activation_hash(),
		terms_hash: Sha256::hash(&[b"ffor/terms".as_slice(), entry].concat()).to_byte_array(),
		witness: PublicKey::from_secret_key(&secp, &witness),
		encryption_public_key: parameters.encryption_public_key,
		recorded_height: 0,
		unbarriered: true,
		ciphertext_hash: [0; 32],
	};
	let shared = SharedSecret::new(&parameters.encryption_public_key, &ephemeral);
	let mut extract = HmacEngine::<Sha256>::new(&[]);
	extract.input(&shared.secret_bytes());
	let prk = Hmac::from_engine(extract).to_byte_array();
	let mut expand = HmacEngine::<Sha256>::new(&prk);
	expand.input(b"ffor/witness/body");
	expand.input(&[1]);
	let key = Hmac::from_engine(expand).to_byte_array();
	let mut ciphertext = vec![0; 142];
	let mut tag = [0; 16];
	ChaCha20Poly1305RFC::new(&key, &[0; 12], &header.associated_data()).encrypt(
		&body,
		&mut ciphertext,
		&mut tag,
	);
	let mut encrypted = PublicKey::from_secret_key(&secp, &ephemeral).serialize().to_vec();
	encrypted.extend_from_slice(&ciphertext);
	encrypted.extend_from_slice(&tag);
	header.ciphertext_hash = Sha256::hash(&encrypted).to_byte_array();
	let signature = secp.sign_ecdsa(&SecpMessage::from_digest(header.signing_digest()), &witness);
	let mut wire = header.encode();
	wire.extend_from_slice(&signature.serialize_compact());
	wire.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
	wire.extend_from_slice(&encrypted);
	wire.push(0);
	let record =
		EncryptedRecord::decode(&wire).unwrap().authenticate(manifest, header.witness).unwrap();
	decrypt_ffor_witness_record(&record, manifest, &encryption).unwrap()
}

fn snapshot(
	node: &Node, context: &FFORReceiverRecoveryContext, receipt: &FFORWitnessReceipt,
) -> FFORWitnessMonitorSnapshot {
	get_monitor!(node, context.channel_id()).ffor_witness_receipt_snapshot(receipt).unwrap()
}

fn no_payment_events(manager: &TestChannelManager) {
	for event in manager.get_and_clear_pending_events() {
		assert!(
			!matches!(event, Event::PaymentClaimed { .. } | Event::PaymentClaimable { .. }),
			"unexpected {event:?}"
		);
	}
}

#[test]
fn ffor_receipt_import_fenced_preimage_waits_for_monitor_and_is_idempotent_after_restart() {
	for receiver_funds in [false, true] {
		let configs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &configs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let (vouchers, preimage) = park_two(sender, receiver, id);
		let context = activate(sender, receiver, id);
		let receipt = receipt(&context, &manifests(&context, 1)[0].1, preimage, 90);
		let stale = snapshot(receiver, &context, &receipt);
		configs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		let progress =
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &stale).unwrap();
		let update = match progress {
			FFORWitnessReceiptProgress::PendingMonitor { monitor_update_id } => monitor_update_id,
			_ => panic!(),
		};
		check_added_monitors(receiver, 1);
		assert_eq!(
			get_monitor!(receiver, id).get_stored_preimages()[&vouchers[0].payment_hash].0,
			preimage
		);
		assert!(receiver
			.node
			.import_ffor_receiver_witness_receipt(&context, &receipt, &stale)
			.is_err());
		let fresh = snapshot(receiver, &context, &receipt);
		assert_eq!(
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			progress
		);
		check_added_monitors(receiver, 0);
		no_payment_events(receiver.node);
		assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
		// Serializing an in-memory monitor must not complete the manager's outstanding write.
		let _saved_pending = persist(receiver.node);
		let monitor_pending = get_monitor!(receiver, id).encode();
		assert!(!monitor_pending.is_empty());
		assert_eq!(
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			progress
		);
		configs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		receiver.chain_monitor.chain_monitor.channel_monitor_updated(id, update).unwrap();
		no_payment_events(receiver.node);
		let protected = FFORWitnessReceiptProgress::MonitorPersisted { monitor_update_id: update };
		assert_eq!(
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			protected
		);
		check_added_monitors(receiver, 0);
		let saved = persist(receiver.node);
		let restored = restore(receiver, &saved, &get_monitor!(receiver, id).encode()).unwrap();
		assert_eq!(
			restored.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			protected
		);
		no_payment_events(&restored);
		assert!(restored.get_and_clear_pending_msg_events().is_empty());
	}
}

#[test]
fn ffor_receipt_import_refuses_unregistered_witness_and_changed_monitor_identity() {
	let configs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &configs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let (_, preimage) = park_two(sender, receiver, id);
	let context = activate(sender, receiver, id);
	let selected = manifests(&context, 2);
	let unknown = receipt(&context, &selected[1].1, preimage, 91);
	assert_eq!(
		receiver.node.import_ffor_receiver_witness_receipt(
			&context,
			&unknown,
			&snapshot(receiver, &context, &unknown)
		),
		Err(FFORReceiverError::InvalidWitnessReceipt)
	);
	let receipt = receipt(&context, &selected[0].1, preimage, 90);
	for mutation in 0..5 {
		let mut evidence = snapshot(receiver, &context, &receipt);
		match mutation {
			0 => evidence.funding_txo.index += 1,
			1 => evidence.channel_id.0[0] ^= 1,
			2 => evidence.counterparty = receiver.node.get_our_node_id(),
			3 => evidence.update_id += 1,
			_ => evidence.payment_hash.0[0] ^= 1,
		}
		assert_eq!(
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &evidence),
			Err(FFORCommitmentError::MonitorMismatch.into())
		);
	}
	check_added_monitors(receiver, 0);
	no_payment_events(receiver.node);
}

#[test]
fn ffor_receipt_import_after_deadline_disconnect_and_force_close_preserves_original_monitor() {
	for receiver_funds in [false, true] {
		let configs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &configs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let (vouchers, preimage) = park_two(sender, receiver, id);
		let context = activate(sender, receiver, id);
		let receipt = receipt(&context, &manifests(&context, 1)[0].1, preimage, 90);
		sender.node.peer_disconnected(receiver.node.get_our_node_id());
		receiver.node.peer_disconnected(sender.node.get_our_node_id());
		receiver.node.best_block.write().unwrap().height =
			context.setup().terms().settlement_deadline + 1;
		receiver
			.node
			.force_close_broadcasting_latest_txn(
				&id,
				&sender.node.get_our_node_id(),
				"receipt recovery".to_owned(),
			)
			.unwrap();
		no_payment_events(receiver.node);
		receiver.node.get_and_clear_pending_msg_events();
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		let progress = receiver
			.node
			.import_ffor_receiver_witness_receipt(
				&context,
				&receipt,
				&snapshot(receiver, &context, &receipt),
			)
			.unwrap();
		assert!(matches!(progress, FFORWitnessReceiptProgress::PendingMonitor { .. }));
		check_added_monitors(receiver, 1);
		let fresh = snapshot(receiver, &context, &receipt);
		assert!(matches!(
			receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		let known = get_monitor!(receiver, id).get_stored_preimages();
		assert_eq!(known[&vouchers[0].payment_hash].0, preimage);
		assert!(known[&vouchers[0].payment_hash].1.is_empty());
		let restored =
			restore(receiver, &persist(receiver.node), &get_monitor!(receiver, id).encode())
				.unwrap();
		assert!(matches!(
			restored.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh).unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		no_payment_events(&restored);
		// Archive-only history without native peer or monitor bookkeeping refuses rather than panics.
		let removed = receiver
			.node
			.per_peer_state
			.write()
			.unwrap()
			.remove(&sender.node.get_our_node_id())
			.unwrap();
		assert!(receiver
			.node
			.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh)
			.is_err());
		receiver
			.node
			.per_peer_state
			.write()
			.unwrap()
			.insert(sender.node.get_our_node_id(), removed);
		let latest = receiver
			.node
			.per_peer_state
			.read()
			.unwrap()
			.get(&sender.node.get_our_node_id())
			.unwrap()
			.lock()
			.unwrap()
			.closed_channel_monitor_update_ids
			.remove(&id)
			.unwrap();
		assert!(receiver
			.node
			.import_ffor_receiver_witness_receipt(&context, &receipt, &fresh)
			.is_err());
		receiver
			.node
			.per_peer_state
			.read()
			.unwrap()
			.get(&sender.node.get_our_node_id())
			.unwrap()
			.lock()
			.unwrap()
			.closed_channel_monitor_update_ids
			.insert(id, latest);
		no_payment_events(receiver.node);
		receiver.node.get_and_clear_pending_msg_events();
	}
}

#[test]
fn ffor_receipt_import_late_failed_voucher_only_protects_monitor_and_keeps_stock_drain() {
	for receive_after_drain in [false, true] {
		let configs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &configs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let id =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let (vouchers, preimage) = park_two(sender, receiver, id);
		let context = activate(sender, receiver, id);
		let peer_id = sender.node.get_our_node_id();
		let receipt = receipt(&context, &manifests(&context, 1)[0].1, preimage, 90);
		{
			let peers = sender.node.per_peer_state.read().unwrap();
			let mut peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
			peer.channel_by_id.get_mut(&id).unwrap().as_funded_mut().unwrap().exit_quiescence();
		}
		receiver.node.prepare_ffor_receiver_close(&id, &peer_id, EPOCH).unwrap();
		persist(receiver.node);
		assert!(receiver
			.node
			.release_ffor_receiver_close(&id, &peer_id, EPOCH, |_| Ok(()))
			.unwrap());
		let ack = signed(
			sender,
			&context,
			Payload::CloseAck(CloseAck {
				activation_hash: context.activation_hash(),
				num_slots: 2,
				settled: vec![0],
				preimages: Vec::new(),
				preimages_tlv_present: true,
			}),
		);
		receiver.node.accept_ffor_receiver_close_ack(&id, &peer_id, EPOCH, &ack).unwrap();
		persist(receiver.node);
		assert!(receiver.node.release_ffor_receiver_drain(&id, &peer_id, EPOCH).unwrap());
		if receive_after_drain {
			let (fulfilled, failed) = drain(sender, receiver);
			assert!(fulfilled.is_empty());
			assert_eq!(failed, vouchers.iter().map(|voucher| voucher.htlc_id).collect::<Vec<_>>());
		} else {
			// The failure was admitted to a signed commitment. A late receipt cannot rewind it.
			let flight = receiver.node.get_and_clear_pending_msg_events();
			assert!(flight.iter().any(|event| matches!(event,
				MessageSendEvent::UpdateHTLCs { updates, .. } if !updates.update_fail_htlcs.is_empty())));
			let peers = receiver.node.per_peer_state.read().unwrap();
			let mut peer = peers.get(&peer_id).unwrap().lock().unwrap();
			peer.pending_msg_events.extend(flight);
		}
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		assert!(matches!(
			receiver
				.node
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::PendingMonitor { .. }
		));
		check_added_monitors(receiver, 1);
		let known = get_monitor!(receiver, id).get_stored_preimages();
		assert_eq!(known[&vouchers[0].payment_hash].0, preimage);
		assert!(known[&vouchers[0].payment_hash].1.is_empty());
		if !receive_after_drain {
			let (fulfilled, failed) = drain(sender, receiver);
			assert!(fulfilled.is_empty());
			assert_eq!(failed.len(), 2);
		}
		assert!(matches!(
			receiver
				.node
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		let monitor = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
		receiver.node.prepare_ffor_receiver_closed(&id, &peer_id, EPOCH, &monitor).unwrap();
		persist(receiver.node);
		assert!(receiver.node.release_ffor_receiver_closed(&id, &peer_id, EPOCH).unwrap());
		// The late preimage protected the monitor but the signed failure is the recorded outcome.
		for (index, voucher) in vouchers.iter().enumerate() {
			assert_eq!(
				receiver
					.node
					.ffor_receiver_voucher_outcome(
						&context,
						index as u16 + 1,
						voucher.payment_hash,
						voucher.amount_msat
					)
					.unwrap(),
				Some(crate::ln::ffor::FFORVoucherOutcome::Failed)
			);
		}
		let restored =
			restore(receiver, &persist(receiver.node), &get_monitor!(receiver, id).encode())
				.unwrap();
		assert!(matches!(
			restored
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		no_payment_events(receiver.node);
		no_payment_events(&restored);
		receiver.node.get_and_clear_pending_msg_events();
		sender.node.get_and_clear_pending_events();
		if receive_after_drain {
			let mut old_scope = snapshot(receiver, &context, &receipt);
			let contribution = crate::ln::funding::SpliceContribution::SpliceOut {
				outputs: vec![bitcoin::TxOut {
					value: bitcoin::Amount::from_sat(10_000),
					script_pubkey: bitcoin::ScriptBuf::from_bytes(
						[vec![0, 20], vec![42; 20]].concat(),
					),
				}],
			};
			let tx = crate::ln::splicing_tests::splice_channel(sender, receiver, id, contribution);
			assert!(get_monitor!(receiver, id).ffor_witness_receipt_snapshot(&receipt).is_err());
			assert!(receiver
				.node
				.import_ffor_receiver_witness_receipt(&context, &receipt, &old_scope)
				.is_err());
			mine_transaction(sender, &tx);
			mine_transaction(receiver, &tx);
			crate::ln::splicing_tests::lock_splice_after_blocks(
				sender,
				receiver,
				crate::chain::channelmonitor::ANTI_REORG_DELAY - 1,
			);
			assert_ne!(get_monitor!(receiver, id).get_funding_txo(), context.funding_txo());
			receiver
				.node
				.force_close_broadcasting_latest_txn(
					&id,
					&peer_id,
					"post-splice receipt".to_owned(),
				)
				.unwrap();
			// Even a matching numeric counter cannot bind an old scope to the closed new funding.
			old_scope.update_id = get_monitor!(receiver, id).get_latest_update_id();
			assert_eq!(
				receiver.node.import_ffor_receiver_witness_receipt(&context, &receipt, &old_scope),
				Err(FFORCommitmentError::MonitorMismatch.into())
			);
			let restored =
				restore(receiver, &persist(receiver.node), &get_monitor!(receiver, id).encode())
					.unwrap();
			assert_eq!(
				restored.import_ffor_receiver_witness_receipt(&context, &receipt, &old_scope),
				Err(FFORCommitmentError::MonitorMismatch.into())
			);
			no_payment_events(receiver.node);
			no_payment_events(&restored);
			receiver.node.get_and_clear_pending_msg_events();
			receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		}
	}
}

#[test]
fn ffor_receipt_import_crash_replays_unpersisted_monitor_preimage_without_payment_events() {
	let configs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &configs);
	let config = anchor_config();
	let (persister, chain_monitor, restored);
	let managers =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (vouchers, preimage) = park_two(&nodes[0], &nodes[1], id);
	let context = activate(&nodes[0], &nodes[1], id);
	let receipt = receipt(&context, &manifests(&context, 1)[0].1, preimage, 90);
	let old_monitor = get_monitor!(nodes[1], id).encode();
	configs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let first = nodes[1]
		.node
		.import_ffor_receiver_witness_receipt(
			&context,
			&receipt,
			&snapshot(&nodes[1], &context, &receipt),
		)
		.unwrap();
	assert!(matches!(first, FFORWitnessReceiptProgress::PendingMonitor { .. }));
	check_added_monitors(&nodes[1], 1);
	let saved = persist(nodes[1].node);
	// The failed write did not replace the durable monitor. The saved manager retains its update.
	reload_node!(nodes[1], config, &saved, &[&old_monitor], persister, chain_monitor, restored);
	persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	no_payment_events(nodes[1].node);
	check_added_monitors(&nodes[1], 1);
	let pending = snapshot(&nodes[1], &context, &receipt);
	assert_eq!(
		nodes[1].node.import_ffor_receiver_witness_receipt(&context, &receipt, &pending).unwrap(),
		first
	);
	assert_eq!(
		get_monitor!(nodes[1], id).get_stored_preimages()[&vouchers[0].payment_hash].0,
		preimage
	);
	persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(id, pending.update_id).unwrap();
	no_payment_events(nodes[1].node);
	assert!(matches!(
		nodes[1].node.import_ffor_receiver_witness_receipt(&context, &receipt, &pending).unwrap(),
		FFORWitnessReceiptProgress::MonitorPersisted { .. }
	));
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);
}

#[test]
fn ffor_receipt_import_preimage_wins_over_queued_failure_before_monitor_release() {
	let configs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &configs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let (vouchers, first_preimage) = park_two(sender, receiver, id);
	let context = activate(sender, receiver, id);
	let manifest = &manifests(&context, 1)[0].1;
	let first = receipt(&context, manifest, first_preimage, 90);
	let second_preimage = PaymentPreimage([first_preimage.0[0] + 1; 32]);
	let second = receipt_slot(&context, manifest, second_preimage, 90, 2);
	configs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	receiver
		.node
		.import_ffor_receiver_witness_receipt(
			&context,
			&second,
			&snapshot(receiver, &context, &second),
		)
		.unwrap();
	check_added_monitors(receiver, 1);
	let second_update = get_monitor!(receiver, id).get_latest_update_id();
	{
		let peers = sender.node.per_peer_state.read().unwrap();
		let mut peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
		peer.channel_by_id.get_mut(&id).unwrap().as_funded_mut().unwrap().exit_quiescence();
	}
	let peer_id = sender.node.get_our_node_id();
	receiver.node.prepare_ffor_receiver_close(&id, &peer_id, EPOCH).unwrap();
	persist(receiver.node);
	let ack = signed(
		sender,
		&context,
		Payload::CloseAck(CloseAck {
			activation_hash: context.activation_hash(),
			num_slots: 2,
			settled: vec![0],
			preimages: Vec::new(),
			preimages_tlv_present: true,
		}),
	);
	receiver.node.accept_ffor_receiver_close_ack(&id, &peer_id, EPOCH, &ack).unwrap();
	persist(receiver.node);
	assert!(receiver.node.release_ffor_receiver_drain(&id, &peer_id, EPOCH).unwrap());
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	let progress = receiver
		.node
		.import_ffor_receiver_witness_receipt(
			&context,
			&first,
			&snapshot(receiver, &context, &first),
		)
		.unwrap();
	let update_id = match progress {
		FFORWitnessReceiptProgress::PendingMonitor { monitor_update_id } => monitor_update_id,
		_ => panic!(),
	};
	check_added_monitors(receiver, 1);
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	let pending = snapshot(receiver, &context, &first);
	assert_eq!(
		receiver.node.import_ffor_receiver_witness_receipt(&context, &first, &pending).unwrap(),
		progress
	);
	configs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	receiver.chain_monitor.chain_monitor.channel_monitor_updated(id, second_update).unwrap();
	receiver.chain_monitor.chain_monitor.channel_monitor_updated(id, update_id).unwrap();
	no_payment_events(receiver.node);
	let (fulfilled, failed) = drain(sender, receiver);
	assert!(failed.is_empty());
	assert_eq!(fulfilled.len(), 2);
	for voucher in vouchers {
		assert!(fulfilled.contains(&voucher.htlc_id));
	}
	sender.node.get_and_clear_pending_events();
	sender.chain_monitor.added_monitors.lock().unwrap().clear();
	assert!(matches!(
		receiver
			.node
			.import_ffor_receiver_witness_receipt(
				&context,
				&first,
				&snapshot(receiver, &context, &first)
			)
			.unwrap(),
		FFORWitnessReceiptProgress::MonitorPersisted { .. }
	));
	no_payment_events(receiver.node);
}

#[test]
fn ffor_receipt_import_retains_protection_during_conflicting_reconnect() {
	use lightning_ffor::reestablish::{Reestablish, ReportedState};
	let configs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &configs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let (_, preimage) = park_two(sender, receiver, id);
	let context = activate(sender, receiver, id);
	let selected = manifests(&context, 1);
	let receipt = receipt(&context, &selected[0].1, preimage, 90);
	let peer_id = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	sender.node.peer_disconnected(receiver_id);
	receiver.node.peer_disconnected(peer_id);
	connect_nodes(sender, receiver);
	let local = get_event_msg!(receiver, MessageSendEvent::SendChannelReestablish, peer_id);
	let mut remote = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	let mut conflicting = context.activation_hash();
	conflicting[0] ^= 1;
	remote.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		activation_hash: conflicting,
		state: ReportedState::Active,
	}));
	sender.node.handle_channel_reestablish(receiver_id, &local);
	receiver.node.handle_channel_reestablish(peer_id, &remote);
	assert!(receiver.node.capture_ffor_receiver_active_context(&id, &peer_id, EPOCH).is_err());
	receiver.node.best_block.write().unwrap().height =
		context.setup().terms().settlement_deadline + 1;
	assert!(matches!(
		receiver
			.node
			.import_ffor_receiver_witness_receipt(
				&context,
				&receipt,
				&snapshot(receiver, &context, &receipt)
			)
			.unwrap(),
		FFORWitnessReceiptProgress::PendingMonitor { .. }
	));
	check_added_monitors(receiver, 1);
	assert!(matches!(
		receiver
			.node
			.import_ffor_receiver_witness_receipt(
				&context,
				&receipt,
				&snapshot(receiver, &context, &receipt)
			)
			.unwrap(),
		FFORWitnessReceiptProgress::MonitorPersisted { .. }
	));
	assert!(receiver.node.capture_ffor_receiver_active_context(&id, &peer_id, EPOCH).is_err());
	no_payment_events(receiver.node);
	for event in receiver.node.get_and_clear_pending_msg_events() {
		assert!(!matches!(event, MessageSendEvent::UpdateHTLCs { .. }));
	}
	sender.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_receipt_import_previous_epoch_after_channel_reuse_protects_original_monitor() {
	for receiver_funds in [false, true] {
		let configs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &configs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let peer_id = sender.node.get_our_node_id();
		let (vouchers, preimage) = park_two(sender, receiver, id);
		let context = activate(sender, receiver, id);
		let receipt = receipt(&context, &manifests(&context, 1)[0].1, preimage, 90);
		{
			let peers = sender.node.per_peer_state.read().unwrap();
			let mut peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
			peer.channel_by_id.get_mut(&id).unwrap().as_funded_mut().unwrap().exit_quiescence();
		}
		receiver.node.prepare_ffor_receiver_close(&id, &peer_id, EPOCH).unwrap();
		persist(receiver.node);
		assert!(receiver
			.node
			.release_ffor_receiver_close(&id, &peer_id, EPOCH, |_| Ok(()))
			.unwrap());
		let ack = signed(
			sender,
			&context,
			Payload::CloseAck(CloseAck {
				activation_hash: context.activation_hash(),
				num_slots: 2,
				settled: vec![0],
				preimages: Vec::new(),
				preimages_tlv_present: true,
			}),
		);
		receiver.node.accept_ffor_receiver_close_ack(&id, &peer_id, EPOCH, &ack).unwrap();
		persist(receiver.node);
		assert!(receiver.node.release_ffor_receiver_drain(&id, &peer_id, EPOCH).unwrap());
		let (fulfilled, failed) = drain(sender, receiver);
		assert!(fulfilled.is_empty());
		assert_eq!(failed, vouchers.iter().map(|voucher| voucher.htlc_id).collect::<Vec<_>>());
		sender.node.get_and_clear_pending_events();
		let monitor = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
		receiver.node.prepare_ffor_receiver_closed(&id, &peer_id, EPOCH, &monitor).unwrap();
		persist(receiver.node);
		assert!(receiver.node.release_ffor_receiver_closed(&id, &peer_id, EPOCH).unwrap());
		// A later epoch now owns the channel book. The first epoch's receipt still belongs to
		// the original monitor and never touches the new book or an ordinary payment.
		let (later, _) = park_two_epoch(sender, receiver, id, [82; 32]);
		assert_ne!(later[0].payment_hash, vouchers[0].payment_hash);
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		assert!(matches!(
			receiver
				.node
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::PendingMonitor { .. }
		));
		check_added_monitors(receiver, 1);
		let known = get_monitor!(receiver, id).get_stored_preimages();
		assert_eq!(known[&vouchers[0].payment_hash].0, preimage);
		assert!(!known.contains_key(&later[0].payment_hash));
		assert!(matches!(
			receiver
				.node
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		assert_eq!(
			receiver
				.node
				.ffor_receiver_voucher_outcome(
					&context,
					1,
					vouchers[0].payment_hash,
					vouchers[0].amount_msat
				)
				.unwrap(),
			Some(crate::ln::ffor::FFORVoucherOutcome::Failed)
		);
		let restored =
			restore(receiver, &persist(receiver.node), &get_monitor!(receiver, id).encode())
				.unwrap();
		assert!(matches!(
			restored
				.import_ffor_receiver_witness_receipt(
					&context,
					&receipt,
					&snapshot(receiver, &context, &receipt)
				)
				.unwrap(),
			FFORWitnessReceiptProgress::MonitorPersisted { .. }
		));
		no_payment_events(receiver.node);
		no_payment_events(&restored);
		receiver.node.get_and_clear_pending_msg_events();
	}
}
