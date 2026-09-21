use super::*;
use crate::ln::channel::ffor_setup_test_messages;
use crate::ln::channelmanager::ffor_recovery_tests::restore;
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler};
use crate::sign::{KeysManager, NodeSigner};

macro_rules! fixture {
	($nodes:ident, $sender:ident, $receiver:ident, $id:ident, $receiver_funds:expr) => {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let $nodes = create_network(2, &node_cfgs, &managers);
		let $id =
			create_announced_chan_between_nodes_with_value(&$nodes, 0, 1, 100_000, 40_000_000).2;
		let ($sender, $receiver) =
			if $receiver_funds { (&$nodes[1], &$nodes[0]) } else { (&$nodes[0], &$nodes[1]) };
	};
}

fn parameters(voucher: &FFORVoucher) -> FFORReceiverParameters {
	FFORReceiverParameters {
		local_request_id: [91; 32],
		amounts_msat: vec![voucher.amount_msat],
		minimum_payment_msat: voucher.amount_msat,
		settlement_deadline: voucher.cltv_expiry - 20,
		voucher_expiry: voucher.cltv_expiry,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		claim_margin_blocks: 20,
		witness_peers: None,
		hash_chain: false,
	}
}
fn persist(receiver: &Node) -> Vec<u8> {
	let token = receiver.node.capture_ffor_persistence();
	let bytes = receiver.node.encode();
	receiver.node.ffor_persistence_completed(token).unwrap();
	bytes
}
fn sign(message: &mut FFORMessage, node: &Node) {
	let keys = KeysManager::new(&node.node_seed, 0, 0, true);
	message.signature = keys
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
}
fn accept(
	sender: &Node, receiver: &Node, channel: ChannelId, voucher: FFORVoucher, init_wire: &[u8],
) -> FFORMessage {
	let init = FFORMessage::decode(init_wire).unwrap();
	let (_, mut accept) = ffor_setup_test_messages(sender, receiver, channel, voucher);
	accept.header = init.header;
	if let Payload::Accept(terms) = &mut accept.payload {
		terms.init_hash = transcript::init_hash(init_wire);
	}
	sign(&mut accept, sender);
	accept
}
fn emit(receiver: &Node, id: &FFORReceiverId, connection: &FFORPeerConnection) -> Vec<u8> {
	let mut wire = Vec::new();
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(id, connection, |bytes| {
				wire = bytes.to_vec();
				Ok(())
			})
			.unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	assert!(!wire.is_empty());
	wire
}

#[test]
fn ffor_driver_durable_init_exact_backpressure_and_synchronous_accept() {
	for receiver_funds in [false, true] {
		fixture!(nodes, sender, receiver, channel, receiver_funds);
		let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
		let connection =
			receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
		let id = receiver
			.node
			.prepare_ffor_receiver(&channel, &connection, parameters(&voucher))
			.unwrap();
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("not durable"))
				.unwrap(),
			FFORReceiverProgress::AwaitingPersistence
		);
		// A failed or cancelled store has no completion, even after encoding the same bytes.
		let failed = receiver.node.capture_ffor_persistence();
		let _ = receiver.node.encode();
		drop(failed);
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("failed store"))
				.unwrap(),
			FFORReceiverProgress::AwaitingPersistence
		);
		persist(receiver);
		let mut refused = Vec::new();
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |wire| {
					refused = wire.to_vec();
					Err(())
				})
				.unwrap(),
			FFORReceiverProgress::Backpressured
		);
		let wire = emit(receiver, &id, &connection);
		assert_eq!(wire, refused);
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("duplicate Init"))
				.unwrap(),
			FFORReceiverProgress::AwaitingPeer
		);
		let accepted = accept(sender, receiver, channel, voucher, &wire).encode().unwrap();
		assert_eq!(
			receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap(),
			FFORReceiverProgress::AwaitingPersistence
		);
		assert_eq!(
			receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap(),
			FFORReceiverProgress::AwaitingPersistence
		);
		// The peer is allowed to send these stock frames immediately after Accept.
		deliver_parked_voucher(sender, receiver, update);
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
		persist(receiver);
		assert_eq!(
			receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap(),
			FFORReceiverProgress::AwaitingVoucherCommitments
		);
		let snapshot = get_monitor!(receiver, channel).ffor_commitment_snapshot().unwrap();
		assert!(matches!(
			receiver
				.node
				.ffor_receiver_book_status(&channel, &sender.node.get_our_node_id(), &snapshot)
				.unwrap(),
			FFORReceiverStatus::Parked { .. }
		));
		let bytes = persist(receiver);
		let monitor = get_monitor!(receiver, channel).encode();
		let restored = restore(receiver, &bytes, &monitor).unwrap();
		assert!(restored.get_and_clear_pending_events().is_empty());
	}
}

#[test]
fn ffor_driver_crash_after_monitor_before_accept_manager_cannot_claim_payment() {
	for receiver_funds in [false, true] {
		fixture!(nodes, sender, receiver, channel, receiver_funds);
		let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
		let connection =
			receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
		let id = receiver
			.node
			.prepare_ffor_receiver(&channel, &connection, parameters(&voucher))
			.unwrap();
		let before_accept = persist(receiver);
		let wire = emit(receiver, &id, &connection);
		let accepted = accept(sender, receiver, channel, voucher, &wire).encode().unwrap();
		receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap();
		receiver
			.node
			.handle_update_add_htlc(sender.node.get_our_node_id(), &update.update_add_htlcs[0]);
		receiver
			.node
			.handle_commitment_signed(sender.node.get_our_node_id(), &update.commitment_signed[0]);
		check_added_monitors(receiver, 1);
		let newer_monitor = get_monitor!(receiver, channel).encode();
		let restored = restore(receiver, &before_accept, &newer_monitor).unwrap();
		assert!(restored.list_channels().is_empty());
		let events = restored.get_and_clear_pending_events();
		assert!(events.iter().any(|event| matches!(event, Event::ChannelClosed { .. })));
		assert!(events.iter().all(|event| !matches!(
			event,
			Event::PaymentClaimable { .. } | Event::PaymentForwarded { .. }
		)));
		assert!(restored
			.ffor_recovery
			.lock()
			.unwrap()
			.request_keys()
			.contains(&FFORRecoveryKey { channel_id: channel, epoch_id: id.epoch_id() }));
		receiver.node.get_and_clear_pending_msg_events();
		receiver.node.get_and_clear_pending_events();
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
	}
}

#[test]
fn ffor_driver_preaccept_add_cannot_be_relabelled_and_stale_connection_cannot_mutate() {
	fixture!(nodes, sender, receiver, channel, false);
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	let wire = emit(receiver, &id, &connection);
	receiver
		.node
		.handle_update_add_htlc(sender.node.get_our_node_id(), &update.update_add_htlcs[0]);
	let accepted = accept(sender, receiver, channel, voucher, &wire).encode().unwrap();
	assert!(matches!(
		receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap(),
		FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::VoucherMismatch }
	));
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	assert!(peer.channel_by_id[&channel]
		.as_funded()
		.unwrap()
		.ffor_receiver_setup_record()
		.unwrap()
		.is_none());
	drop(peer);
	drop(peers);
	// Disconnect discards uncommitted adds, but the request tombstone still refuses promotion.
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
	let init = msgs::Init {
		features: sender.node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	receiver.node.peer_connected(sender.node.get_our_node_id(), &init, false).unwrap();
	let replacement = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	assert_ne!(replacement, connection);
	let before = receiver.node.encode();
	assert!(receiver.node.handle_ffor_receiver_message(&connection, &accepted).is_err());
	assert_eq!(before, receiver.node.encode());
	assert!(receiver
		.node
		.advance_ffor_receiver(&id, &connection, |_| panic!("stale queue"))
		.is_err());
	receiver.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_driver_deadline_crossing_prevents_delayed_init_release() {
	for backpressure in [false, true] {
		fixture!(nodes, sender, receiver, channel, false);
		let voucher = FFORVoucher {
			htlc_id: 0,
			payment_hash: PaymentHash([7; 32]),
			amount_msat: 2_000_000,
			cltv_expiry: 200,
		};
		let connection =
			receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
		let id = receiver
			.node
			.prepare_ffor_receiver(&channel, &connection, parameters(&voucher))
			.unwrap();
		if backpressure {
			persist(receiver);
			assert_eq!(
				receiver.node.advance_ffor_receiver(&id, &connection, |_| Err(())).unwrap(),
				FFORReceiverProgress::Backpressured
			);
		}
		receiver.node.best_block.write().unwrap().height = 180;
		persist(receiver);
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("expired Init"))
				.unwrap(),
			FFORReceiverProgress::AwaitingPersistence
		);
		persist(receiver);
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("aborted Init"))
				.unwrap(),
			FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::SetupRejected }
		);
	}
}

#[test]
fn ffor_driver_pending_restore_required_fence_and_malformed_refusal() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([8; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	let pending = persist(receiver);
	let monitor = get_monitor!(receiver, channel).encode();
	let restored = restore(receiver, &pending, &monitor).unwrap();
	assert!(restored.ffor_peer_connection(&sender.node.get_our_node_id()).is_err());
	assert!(restored.handle_ffor_receiver_message(&connection, &[0]).is_err());
	let registry = receiver.node.ffor_recovery.lock().unwrap().encode();
	assert_eq!(registry[0], 4);
	let mut unsupported = registry.clone();
	unsupported[0] = 5;
	assert!(<FFORRecoveryRegistry as Readable>::read(&mut &unsupported[..]).is_err());
	let _ = emit(receiver, &id, &connection);
	assert!(receiver.node.handle_ffor_receiver_message(&connection, &[0]).is_err());
	persist(receiver);
	assert!(matches!(
		receiver
			.node
			.advance_ffor_receiver(&id, &connection, |_| panic!("malformed retry"))
			.unwrap(),
		FFORReceiverProgress::Aborted { .. }
	));
}

#[test]
fn ffor_driver_local_retry_correlation_survives_restore_and_conflicts() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([9; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let params = parameters(&voucher);
	let id = receiver.node.prepare_ffor_receiver(&channel, &connection, params.clone()).unwrap();
	assert_ne!(id.epoch_id(), params.local_request_id);
	let before = receiver.node.encode();
	assert_eq!(
		receiver.node.prepare_ffor_receiver(&channel, &connection, params.clone()).unwrap(),
		id
	);
	assert_eq!(before, receiver.node.encode());
	let mut conflict = params.clone();
	conflict.amounts_msat[0] += 1;
	assert_eq!(
		receiver.node.prepare_ffor_receiver(&channel, &connection, conflict),
		Err(FFORReceiverError::AlreadyRegistered)
	);
	let bytes = persist(receiver);
	let monitor = get_monitor!(receiver, channel).encode();
	let restored = restore(receiver, &bytes, &monitor).unwrap();
	assert_eq!(restored.find_ffor_receiver_request(params.local_request_id).unwrap(), Some(id));
	assert_eq!(restored.find_ffor_receiver_request([0; 32]).unwrap(), None);
	let mut absent = core::mem::replace(
		&mut *receiver.node.ffor_recovery.lock().unwrap(),
		FFORRecoveryRegistry::new(),
	);
	let damaged = receiver.node.encode();
	core::mem::swap(&mut absent, &mut *receiver.node.ffor_recovery.lock().unwrap());
	assert!(restore(receiver, &damaged, &monitor).is_err());
}

#[test]
fn ffor_driver_cancel_requires_durable_fresh_connection_before_ordinary_payment() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([10; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let sender_id = sender.node.get_our_node_id();
	let connection = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	emit(receiver, &id, &connection);
	assert_eq!(
		receiver.node.cancel_ffor_receiver_setup(&id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver);
	assert!(matches!(
		receiver.node.advance_ffor_receiver(&id, &connection, |_| panic!("cancel send")).unwrap(),
		FFORReceiverProgress::Aborted { .. }
	));
	receiver.node.peer_disconnected(sender_id);
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
	let mut reconnect = ReconnectArgs::new(receiver, sender);
	reconnect.send_channel_ready = (true, true);
	reconnect.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect);
	let next = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	assert_ne!(connection, next);
	// Disconnect itself creates a protected abort revision, so an old completed token cannot
	// release this gate on a new connection.
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &next, |_| panic!("reconnected Init")).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver);
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &next, |_| panic!("gate release send")).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver);
	assert!(matches!(
		receiver.node.advance_ffor_receiver(&id, &next, |_| panic!("terminal send")).unwrap(),
		FFORReceiverProgress::Aborted { .. }
	));
	let released = persist(receiver);
	let released_monitor = get_monitor!(receiver, channel).encode();
	assert!(restore(receiver, &released, &released_monitor).is_ok());
	let (update, later, secret) = offer_voucher(sender, receiver, 2_000_000);
	receiver.node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
	commitment_signed_dance!(receiver, sender, update.commitment_signed, false);
	expect_and_process_pending_htlcs(receiver, false);
	expect_payment_claimable!(receiver, later.payment_hash, secret, later.amount_msat);
	assert_eq!(
		receiver.node.prepare_ffor_receiver(&channel, &next, parameters(&voucher)).unwrap(),
		id
	);
}

#[test]
fn ffor_driver_contradictory_accept_retains_interception_and_never_promotes_again() {
	fixture!(nodes, sender, receiver, channel, false);
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	let init = emit(receiver, &id, &connection);
	let accepted = accept(sender, receiver, channel, voucher, &init);
	receiver.node.handle_ffor_receiver_message(&connection, &accepted.encode().unwrap()).unwrap();
	let mut conflicting = accepted.clone();
	if let Payload::Accept(terms) = &mut conflicting.payload {
		terms.payment_hashes[0] = [99; 32];
	}
	sign(&mut conflicting, sender);
	assert!(receiver
		.node
		.handle_ffor_receiver_message(&connection, &conflicting.encode().unwrap())
		.is_err());
	assert!(matches!(
		receiver
			.node
			.handle_ffor_receiver_message(&connection, &accepted.encode().unwrap())
			.unwrap(),
		FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::SetupRejected }
	));
	// No received slot exists yet. Even a different hash cannot pass the rejected connection's
	// gate and reach ordinary onion processing.
	let mut wrong_add = update.update_add_htlcs[0].clone();
	wrong_add.payment_hash = PaymentHash([99; 32]);
	receiver.node.handle_update_add_htlc(sender.node.get_our_node_id(), &wrong_add);
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	assert!(peer.channel_by_id[&channel]
		.as_funded()
		.unwrap()
		.ffor_owns_received_htlc(wrong_add.htlc_id));
	drop(peer);
	drop(peers);
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
}

#[test]
fn ffor_driver_refuses_capacity_and_unsupported_channel_before_registration() {
	{
		fixture!(nodes, sender, receiver, channel, false);
		let voucher = FFORVoucher {
			htlc_id: 0,
			payment_hash: PaymentHash([11; 32]),
			amount_msat: 2_000_000,
			cltv_expiry: 200,
		};
		let connection =
			receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
		let saved = core::mem::replace(
			&mut *receiver.node.ffor_recovery.lock().unwrap(),
			crate::ln::ffor_recovery::tests::full_registry(),
		);
		assert_eq!(
			receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)),
			Err(FFORReceiverError::RecoveryUnavailable)
		);
		*receiver.node.ffor_recovery.lock().unwrap() = saved;
		assert_eq!(receiver.node.find_ffor_receiver_request([91; 32]).unwrap(), None);
		let peers = receiver.node.per_peer_state.read().unwrap();
		let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
		assert!(peer.channel_by_id[&channel]
			.as_funded()
			.unwrap()
			.ffor_receiver_request()
			.is_none());
	}
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let managers = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let channel = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([12; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let connection = nodes[1].node.ffor_peer_connection(&nodes[0].node.get_our_node_id()).unwrap();
	assert_eq!(
		nodes[1].node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)),
		Err(FFORCommitmentError::UnsupportedChannelType.into())
	);
	assert_eq!(nodes[1].node.find_ffor_receiver_request([91; 32]).unwrap(), None);
}

#[test]
fn ffor_driver_witness_policy_and_signed_preaccept_refusal() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([13; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let mut params = parameters(&voucher);
	params.witness_peers = Some(vec![]);
	assert!(params.init().is_err());
	params.witness_peers = Some(vec![sender.node.get_our_node_id(); 2]);
	assert!(params.init().is_err());
	params.witness_peers = Some(vec![sender.node.get_our_node_id()]);
	assert!(params.init().is_ok());
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id = receiver.node.prepare_ffor_receiver(&channel, &connection, params).unwrap();
	persist(receiver);
	let init = emit(receiver, &id, &connection);
	let mut abort = FFORMessage {
		header: FFORMessage::decode(&init).unwrap().header,
		payload: Payload::Abort(lightning_ffor::wire::Abort {
			transcript_hash: transcript::init_hash(&init),
			reason: 1,
			data: vec![],
		}),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	sign(&mut abort, sender);
	assert!(receiver
		.node
		.handle_ffor_receiver_message(&connection, &abort.encode().unwrap())
		.is_err());
	persist(receiver);
	assert!(matches!(
		receiver
			.node
			.advance_ffor_receiver(&id, &connection, |_| panic!("refused setup send"))
			.unwrap(),
		FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::SetupRejected }
	));
}

#[test]
fn ffor_driver_accept_rechecks_current_deadline_before_promotion() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([14; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	let init = emit(receiver, &id, &connection);
	let accepted = accept(sender, receiver, channel, voucher, &init).encode().unwrap();
	receiver.node.best_block.write().unwrap().height = 180;
	assert!(receiver.node.handle_ffor_receiver_message(&connection, &accepted).is_err());
	persist(receiver);
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &connection, |_| panic!("expired Accept send"))
			.unwrap(),
		FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::SetupRejected }
	);
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	assert!(peer.channel_by_id[&channel]
		.as_funded()
		.unwrap()
		.ffor_receiver_setup_record()
		.unwrap()
		.is_none());
}

#[path = "advance_tests.rs"]
mod lifecycle;
