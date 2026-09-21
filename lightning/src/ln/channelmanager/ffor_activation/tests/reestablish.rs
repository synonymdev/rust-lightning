use super::*;

fn reconnect<'a, 'b: 'a, 'c: 'b>(
	sender: &Node<'a, 'b, 'c>, receiver: &Node<'a, 'b, 'c>,
) -> msgs::ChannelReestablish {
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	connect_nodes(sender, receiver);
	get_event_msg!(
		sender,
		MessageSendEvent::SendChannelReestablish,
		receiver.node.get_our_node_id()
	)
}

fn queued_reestablish(sender: &Node, receiver: &Node) -> msgs::ChannelReestablish {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	match &peer.pending_msg_events[0] {
		MessageSendEvent::SendChannelReestablish { msg, .. } => msg.clone(),
		other => panic!("unexpected queued event: {:?}", other),
	}
}

fn queue_suffix(sender: &Node, receiver: &Node) {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	peer.pending_msg_events.push(MessageSendEvent::SendPeerStorage {
		node_id: sender.node.get_our_node_id(),
		msg: msgs::PeerStorage { data: vec![42] },
	});
}

fn take_report(events: &mut Vec<MessageSendEvent>) -> msgs::ChannelReestablish {
	match events.remove(0) {
		MessageSendEvent::SendChannelReestablish { msg, .. } => msg,
		other => panic!("unexpected first event: {:?}", other),
	}
}

#[test]
fn ffor_activation_reestablish_waits_for_latest_phase_and_preserves_peer_order() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	prepare(sender, receiver, id);
	let activating_write = receiver.node.capture_ffor_persistence();
	let _activating_bytes = receiver.node.encode();
	let (ack_wire, hash) = ack(sender, receiver, id);
	let mut remote_report = reconnect(sender, receiver);
	let mut expected = queued_reestablish(sender, receiver);
	queue_suffix(sender, receiver);
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	remote_report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		state: ReportedState::Active,
		activation_hash: hash,
	}));
	receiver.node.handle_channel_reestablish(sender.node.get_our_node_id(), &remote_report);
	let active = receiver
		.node
		.accept_ffor_receiver_activation_ack(&id, &sender.node.get_our_node_id(), EPOCH, &ack_wire)
		.unwrap();
	receiver.node.ffor_persistence_completed(activating_write).unwrap();
	assert!(!receiver.node.is_ffor_state_persisted(&active));
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(
		queued_reestablish(sender, receiver).ffor_reestablish.unwrap().report().state,
		ReportedState::Activating
	);
	persist(receiver);
	let mut events = receiver.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	expected.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		state: ReportedState::Active,
		activation_hash: hash,
	}));
	assert_eq!(take_report(&mut events), expected);
	assert!(
		matches!(&events[0], MessageSendEvent::SendPeerStorage { msg, .. } if msg.data == [42])
	);
}

#[test]
fn ffor_activation_reestablish_failed_or_canceled_write_retains_exact_queue() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	prepare(sender, receiver, id);
	let _remote = reconnect(sender, receiver);
	let expected = queued_reestablish(sender, receiver);
	queue_suffix(sender, receiver);
	for encode_before_failure in [false, true] {
		let failed = receiver.node.capture_ffor_persistence();
		if encode_before_failure {
			let _not_stored = receiver.node.encode();
		}
		drop(failed);
		assert!(receiver.node.get_and_clear_needs_persistence());
		assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
		assert_eq!(queued_reestablish(sender, receiver), expected);
	}
	persist(receiver);
	let mut events = receiver.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	assert_eq!(take_report(&mut events), expected);
	assert!(
		matches!(&events[0], MessageSendEvent::SendPeerStorage { msg, .. } if msg.data == [42])
	);
}

#[test]
fn ffor_activation_reestablish_force_close_discards_unsent_report() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	prepare(sender, receiver, id);
	let _remote = reconnect(sender, receiver);
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	receiver
		.node
		.force_close_broadcasting_latest_txn(
			&id,
			&sender.node.get_our_node_id(),
			"reconnect queue test".into(),
		)
		.unwrap();
	let events = receiver.node.get_and_clear_pending_msg_events();
	assert!(!events
		.iter()
		.any(|event| matches!(event, MessageSendEvent::SendChannelReestablish { .. })));
	assert!(events.iter().any(|event| matches!(event, MessageSendEvent::HandleError { .. })));
	assert!(receiver.node.list_channels().is_empty());
	let closed = receiver.node.get_and_clear_pending_events();
	assert!(closed.iter().any(
		|event| matches!(event, events::Event::ChannelClosed { channel_id, .. } if *channel_id == id)
	));
	check_added_monitors!(receiver, 1);
	persist(receiver);
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn ffor_activation_reestablish_disconnect_rebind_clears_connection_work() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	prepare(sender, receiver, id);
	let _remote = reconnect(sender, receiver);
	queue_suffix(sender, receiver);
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	let init = msgs::Init {
		features: sender.init_features(receiver.node.get_our_node_id()),
		networks: None,
		remote_network_address: None,
	};
	receiver.node.peer_connected(sender.node.get_our_node_id(), &init, false).unwrap();
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	persist(receiver);
	let mut events = receiver.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	assert_eq!(
		take_report(&mut events).ffor_reestablish.unwrap().report(),
		Reestablish { epoch_id: EPOCH, state: ReportedState::Activating, activation_hash: [0; 32] }
	);
}

#[test]
fn ffor_activation_reestablish_terminal_abort_precedes_stock_drain() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	prepare(sender, receiver, id);
	persist(receiver);
	let remote = reconnect(sender, receiver);
	let mut expected = queued_reestablish(sender, receiver);
	let peer = sender.node.get_our_node_id();
	receiver.node.handle_channel_reestablish(peer, &remote);
	assert_eq!(fence(sender, receiver, id), Some(FFORReceiverFencePhase::Aborting));
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	persist(receiver);
	assert!(receiver.node.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
	assert_eq!(fence(sender, receiver, id), None);
	let mut events = receiver.node.get_and_clear_pending_msg_events();
	expected.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		state: ReportedState::Aborted,
		activation_hash: [0; 32],
	}));
	assert_eq!(take_report(&mut events), expected);
	assert_eq!(events.len(), 1);
	assert!(matches!(&events[0], MessageSendEvent::UpdateHTLCs { updates, .. }
		if updates.update_fail_htlcs.len() == 1 && updates.update_fulfill_htlcs.is_empty()));
	check_added_monitors!(receiver, 1);
}
