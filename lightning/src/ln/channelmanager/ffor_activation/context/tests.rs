use super::*;
use crate::ln::channelmanager::ffor_activation::drain_tests::park_two;
use crate::ln::channelmanager::ffor_recovery_tests::restore;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};

const EPOCH: [u8; 32] = [81; 32];

fn persist(node: &TestChannelManager) -> Vec<u8> {
	let token = node.capture_ffor_persistence();
	let bytes = node.encode();
	node.ffor_persistence_completed(token).unwrap();
	bytes
}

fn signed_ack(sender: &Node, context: &FFORReceiverRecoveryContext) -> Vec<u8> {
	let mut ack = FFORMessage {
		header: context.setup().header(),
		payload: Payload::ActivateAck(context.activation_hash()),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	ack.signature = sender
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&ack.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
	ack.encode().unwrap()
}

#[test]
fn ffor_context_requires_current_durable_active_and_invalidates_after_restore_or_close() {
	for receiver_funds in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let sender = &nodes[0];
		let receiver = &nodes[1];
		let peer = sender.node.get_our_node_id();
		assert!(receiver.node.list_ffor_receiver_recovery_contexts().unwrap().is_empty());
		park_two(sender, receiver, id);
		let before_ack = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
		assert_eq!(before_ack.receiver_node_id(), receiver.node.get_our_node_id());
		assert_eq!(before_ack.settlement_node_id(), peer);
		assert_eq!(before_ack.channel_id(), id);
		assert_eq!(before_ack.epoch_id(), EPOCH);
		assert_eq!(before_ack.setup().vouchers().len(), 2);
		assert!(before_ack.activation_ack_wire().is_none());
		assert!(receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).is_err());
		assert_eq!(receiver.node.list_ffor_receiver_recovery_contexts().unwrap().len(), 1);
		let ack = signed_ack(sender, &before_ack);
		receiver.node.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack).unwrap();
		assert!(receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).is_err());
		let manager = persist(receiver.node);
		let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
		assert_eq!(active.recovery_context().context_digest(), before_ack.context_digest());
		assert_eq!(active.recovery_context().activation_ack_wire(), Some(ack.as_slice()));
		receiver.node.validate_ffor_receiver_active_context(&active).unwrap();
		assert!(sender.node.validate_ffor_receiver_active_context(&active).is_err());
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &manager, &monitor).unwrap();
		assert!(restored.validate_ffor_receiver_active_context(&active).is_err());
		assert!(restored.capture_ffor_receiver_active_context(&id, &peer, EPOCH).is_err());
		persist(&restored);
		assert!(restored.validate_ffor_receiver_active_context(&active).is_err());
		let fresh = restored.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
		restored.validate_ffor_receiver_active_context(&fresh).unwrap();
		assert_eq!(fresh.recovery_context().context_digest(), before_ack.context_digest());
		assert!(receiver.node.validate_ffor_receiver_active_context(&fresh).is_err());
		// Even a completed older requirement cannot survive a retained close intent.
		receiver.node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap();
		assert!(receiver.node.validate_ffor_receiver_active_context(&active).is_err());
		persist(receiver.node);
		assert!(receiver.node.validate_ffor_receiver_active_context(&active).is_err());
		let historical = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
		assert_eq!(historical.context_digest(), before_ack.context_digest());
		receiver
			.node
			.force_close_broadcasting_latest_txn(&id, &peer, "context recovery test".into())
			.unwrap();
		receiver.node.get_and_clear_pending_msg_events();
		assert!(receiver
			.node
			.get_and_clear_pending_events()
			.iter()
			.any(|event| matches!(event, Event::ChannelClosed { .. })));
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		assert!(receiver.node.validate_ffor_receiver_active_context(&active).is_err());
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &persist(receiver.node), &monitor).unwrap();
		assert!(restored.list_channels().is_empty());
		let contexts = restored.list_ffor_receiver_recovery_contexts().unwrap();
		assert_eq!(contexts.len(), 1);
		assert_eq!(contexts[0].context_digest(), before_ack.context_digest());
		assert_eq!(contexts[0].activation_wire(), before_ack.activation_wire());
		assert_eq!(contexts[0].activation_ack_wire(), Some(ack.as_slice()));
	}
}

#[test]
fn ffor_context_rejects_conflicting_connection_observation() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let sender = &nodes[0];
	let receiver = &nodes[1];
	let peer = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	park_two(sender, receiver, id);
	let context = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
	let ack = signed_ack(sender, &context);
	receiver.node.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack).unwrap();
	persist(receiver.node);
	let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
	// Local retained Active authority remains observable while the peer is offline.
	sender.node.peer_disconnected(receiver_id);
	receiver.node.peer_disconnected(peer);
	receiver.node.validate_ffor_receiver_active_context(&active).unwrap();
	connect_nodes(sender, receiver);
	let local = get_event_msg!(receiver, MessageSendEvent::SendChannelReestablish, peer);
	let mut remote = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	let mut conflict = context.activation_hash();
	conflict[0] ^= 1;
	remote.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		activation_hash: conflict,
		state: ReportedState::Active,
	}));
	sender.node.handle_channel_reestablish(receiver_id, &local);
	receiver.node.handle_channel_reestablish(peer, &remote);
	assert!(receiver.node.validate_ffor_receiver_active_context(&active).is_err());
	assert!(receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).is_err());
	assert_eq!(
		receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap().context_digest(),
		context.context_digest()
	);
	sender.node.get_and_clear_pending_msg_events();
	receiver.node.get_and_clear_pending_msg_events();
}
