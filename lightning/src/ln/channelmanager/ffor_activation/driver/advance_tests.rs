use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::ffor_activation::drain_tests::drain;
use crate::ln::ffor_tests::quiescence::complete_handshake;
use lightning_ffor::reestablish::{Reestablish, ReportedState};
use lightning_ffor::wire::{Abort, CloseAck, Preimage};

fn advance_monitor(
	receiver: &Node, id: &FFORReceiverId, connection: &FFORPeerConnection,
) -> Result<FFORReceiverProgress, FFORReceiverError> {
	let snapshot = get_monitor!(receiver, id.channel_id()).ffor_commitment_snapshot().unwrap();
	receiver.node.advance_ffor_receiver_with_monitor(id, connection, snapshot, |_| {
		panic!("proof emits no custom wire")
	})
}

fn park(
	sender: &Node, receiver: &Node, channel: ChannelId,
) -> (FFORReceiverId, FFORPeerConnection, FFORVoucher, PaymentPreimage) {
	let preimage = PaymentPreimage([*receiver.network_payment_count.as_ref().borrow(); 32]);
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	let init = emit(receiver, &id, &connection);
	let accepted = accept(sender, receiver, channel, voucher, &init).encode().unwrap();
	receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap();
	persist(receiver);
	assert_eq!(
		advance_monitor(receiver, &id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingVoucherCommitments
	);
	deliver_parked_voucher(sender, receiver, update);
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &connection, |_| panic!("no proof")).unwrap(),
		FFORReceiverProgress::NeedsMonitorSnapshot
	);
	assert_eq!(
		advance_monitor(receiver, &id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &connection, |_| panic!("negotiating STFU"))
			.unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	complete_handshake(sender, receiver);
	assert_eq!(
		advance_monitor(receiver, &id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	(id, connection, voucher, preimage)
}

fn signed(sender: &Node, id: &FFORReceiverId, payload: Payload) -> Vec<u8> {
	let mut message = FFORMessage {
		header: Header { channel_id: id.channel_id().0, epoch_id: id.epoch_id() },
		payload,
		extensions: Vec::new(),
		signature: [0; 64],
	};
	sign(&mut message, sender);
	message.encode().unwrap()
}

fn activation_ack(sender: &Node, id: &FFORReceiverId, activate: &[u8]) -> (Vec<u8>, [u8; 32]) {
	let message = FFORMessage::decode(activate).unwrap();
	let activation = match message.payload {
		Payload::Activate(activation) => activation,
		_ => panic!("expected Activate"),
	};
	let hash = transcript::activation_hash(
		&activation.setup_hash,
		&activation.book_hash,
		&activation.commit_hash,
		activation.epoch_start_height,
	);
	(signed(sender, id, Payload::ActivateAck(hash)), hash)
}

fn settlement_exits_stfu(sender: &Node, receiver: &Node, channel: ChannelId) {
	// The stock settlement test node has no sender FFOR engine. Model its signed Active response.
	let peers = sender.node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
	peer.channel_by_id.get_mut(&channel).unwrap().as_funded_mut().unwrap().exit_quiescence();
}

#[test]
fn ffor_driver_lifecycle_orders_real_activation_close_and_drain() {
	for receiver_funds in [false, true] {
		for settled in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let config = anchor_config();
			let managers =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
			let nodes = create_network(2, &node_cfgs, &managers);
			let channel =
				create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
			let (sender, receiver) =
				if receiver_funds { (&nodes[1], &nodes[0]) } else { (&nodes[0], &nodes[1]) };
			let persister = &chanmon_cfgs[usize::from(!receiver_funds)].persister;
			let (id, connection, voucher, preimage) = park(sender, receiver, channel);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("unpersisted Activate"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			persist(receiver);
			let mut refused = Vec::new();
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |bytes| {
						refused = bytes.to_vec();
						Err(())
					})
					.unwrap(),
				FFORReceiverProgress::Backpressured
			);
			let activate = emit(receiver, &id, &connection);
			assert_eq!(activate, refused);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("duplicate Activate"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPeer
			);
			let (ack, hash) = activation_ack(sender, &id, &activate);
			assert_eq!(
				receiver.node.handle_ffor_receiver_message(&connection, &ack).unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("unpersisted ACK"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			persist(receiver);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("Active wire"))
					.unwrap(),
				FFORReceiverProgress::Active
			);
			assert!(receiver.node.list_usable_channels().is_empty());
			settlement_exits_stfu(sender, receiver, channel);
			assert_eq!(
				receiver.node.request_ffor_receiver_close(&id, &connection).unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("unpersisted Close"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			persist(receiver);
			let mut close_retry = Vec::new();
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |bytes| {
						close_retry = bytes.to_vec();
						Err(())
					})
					.unwrap(),
				FFORReceiverProgress::Backpressured
			);
			assert_eq!(emit(receiver, &id, &connection), close_retry);
			assert_eq!(FFORMessage::decode(&close_retry).unwrap().payload, Payload::Close(hash));
			let close_ack = signed(
				sender,
				&id,
				Payload::CloseAck(CloseAck {
					activation_hash: hash,
					num_slots: 1,
					settled: vec![u8::from(settled)],
					preimages: if settled {
						vec![Preimage { slot: 1, value: preimage.0 }]
					} else {
						Vec::new()
					},
					preimages_tlv_present: true,
				}),
			);
			assert_eq!(
				receiver.node.handle_ffor_receiver_message(&connection, &close_ack).unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("unpersisted drain"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			persist(receiver);
			if settled {
				persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			}
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("drain custom wire"))
					.unwrap(),
				FFORReceiverProgress::Draining
			);
			if settled {
				assert!(receiver.node.get_and_clear_pending_msg_events().iter().all(
					|event| matches!(
						event,
						MessageSendEvent::SendChannelUpdate { .. }
							| MessageSendEvent::BroadcastChannelUpdate { .. }
					)
				));
				let update = get_monitor!(receiver, channel).get_latest_update_id();
				persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
				receiver
					.chain_monitor
					.chain_monitor
					.channel_monitor_updated(channel, update)
					.unwrap();
			}
			assert_eq!(
				drain(sender, receiver),
				if settled {
					(vec![voucher.htlc_id], Vec::new())
				} else {
					(Vec::new(), vec![voucher.htlc_id])
				}
			);
			sender.node.get_and_clear_pending_events();
			assert_eq!(drain(sender, receiver), (Vec::new(), Vec::new()));
			assert_eq!(
				advance_monitor(receiver, &id, &connection).unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("unpersisted Closed"))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			let before_release = persist(receiver);
			let monitor = get_monitor!(receiver, channel).encode();
			let restored = restore(receiver, &before_release, &monitor).unwrap();
			let sender_id = sender.node.get_our_node_id();
			restored
				.peer_connected(
					sender_id,
					&msgs::Init {
						features: sender.init_features(receiver.node.get_our_node_id()),
						networks: None,
						remote_network_address: None,
					},
					false,
				)
				.unwrap();
			let next = restored.ffor_peer_connection(&sender_id).unwrap();
			assert_eq!(
				restored
					.advance_ffor_receiver(&id, &next, |_| panic!(
						"restored Closed before persistence"
					))
					.unwrap(),
				FFORReceiverProgress::AwaitingPersistence
			);
			assert!(restored.get_and_clear_pending_msg_events().is_empty());
			let token = restored.capture_ffor_persistence();
			let _ = restored.encode();
			restored.ffor_persistence_completed(token).unwrap();
			assert!(restored.get_and_clear_pending_msg_events().is_empty());
			assert_eq!(
				restored
					.advance_ffor_receiver(&id, &next, |_| panic!("restored Closed release"))
					.unwrap(),
				FFORReceiverProgress::Closed
			);
			assert!(restore(receiver, &restored.encode(), &monitor).is_ok());
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("Closed wire"))
					.unwrap(),
				FFORReceiverProgress::Closed
			);
			assert_eq!(
				receiver
					.node
					.advance_ffor_receiver(&id, &connection, |_| panic!("Closed retry wire"))
					.unwrap(),
				FFORReceiverProgress::Closed
			);
			receiver.node.handle_ffor_receiver_message(&connection, &ack).unwrap();
			receiver.node.handle_ffor_receiver_message(&connection, &close_ack).unwrap();
			let bytes = persist(receiver);
			assert!(restore(receiver, &bytes, &get_monitor!(receiver, channel).encode()).is_ok());
			send_payment(sender, &[receiver], 1_000_000);
		}
	}
}

#[test]
fn ffor_driver_expired_unsent_activation_keeps_fence_and_requires_reconnect() {
	for (backpressure, sent, cross_deadline) in
		[(false, false, false), (true, false, false), (false, true, true)]
	{
		fixture!(nodes, sender, receiver, channel, false);
		let (id, connection, voucher, _) = park(sender, receiver, channel);
		if sent {
			persist(receiver);
			emit(receiver, &id, &connection);
		}
		if backpressure {
			persist(receiver);
			assert_eq!(
				receiver.node.advance_ffor_receiver(&id, &connection, |_| Err(())).unwrap(),
				FFORReceiverProgress::Backpressured
			);
		}
		if cross_deadline {
			receiver.node.best_block.write().unwrap().height = voucher.cltv_expiry - 20;
		} else {
			receiver.node.best_block.write().unwrap().height += 7;
		}
		persist(receiver);
		assert_eq!(
			receiver
				.node
				.advance_ffor_receiver(&id, &connection, |_| panic!("stale Activate"))
				.unwrap(),
			FFORReceiverProgress::ReconnectRequired
		);
		let peers = receiver.node.per_peer_state.read().unwrap();
		let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
		assert_eq!(
			peer.channel_by_id
				.get(&channel)
				.unwrap()
				.as_funded()
				.unwrap()
				.ffor_receiver_fence()
				.unwrap()
				.0,
			FFORReceiverFencePhase::Activating
		);
		drop(peer);
		drop(peers);
		assert!(receiver.node.get_and_clear_pending_msg_events().iter().any(|event| matches!(
			event,
			MessageSendEvent::HandleError {
				action: msgs::ErrorAction::DisconnectPeerWithWarning { .. },
				..
			}
		)));
	}
}

#[test]
fn ffor_driver_signed_abort_during_activation_never_drops_fence() {
	fixture!(nodes, sender, receiver, channel, false);
	let (id, connection, _, _) = park(sender, receiver, channel);
	persist(receiver);
	emit(receiver, &id, &connection);
	let setup_hash = {
		let registry = receiver.node.ffor_recovery.lock().unwrap();
		registry
			.get(&FFORRecoveryKey { channel_id: channel, epoch_id: id.epoch_id() })
			.unwrap()
			.validate_recovery()
			.unwrap()
			.setup_hash()
	};
	let wrong = signed(
		sender,
		&id,
		Payload::Abort(Abort { transcript_hash: [0; 32], reason: 7, data: Vec::new() }),
	);
	assert!(receiver.node.handle_ffor_receiver_message(&connection, &wrong).is_err());
	let abort = signed(
		sender,
		&id,
		Payload::Abort(Abort { transcript_hash: setup_hash, reason: 7, data: Vec::new() }),
	);
	assert_eq!(
		receiver.node.handle_ffor_receiver_message(&connection, &abort).unwrap(),
		FFORReceiverProgress::ReconnectRequired
	);
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	assert_eq!(
		peer.channel_by_id
			.get(&channel)
			.unwrap()
			.as_funded()
			.unwrap()
			.ffor_receiver_fence()
			.unwrap()
			.0,
		FFORReceiverFencePhase::Activating
	);
	drop(peer);
	drop(peers);
	receiver.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_driver_restored_ack_loss_uses_current_generation_and_accepts_late_exact_ack() {
	fixture!(nodes, sender, receiver, channel, false);
	let (id, connection, _, _) = park(sender, receiver, channel);
	persist(receiver);
	let activate = emit(receiver, &id, &connection);
	let (ack, hash) = activation_ack(sender, &id, &activate);
	let bytes = persist(receiver);
	let monitor = get_monitor!(receiver, channel).encode();
	let restored = restore(receiver, &bytes, &monitor).unwrap();
	assert!(restored.handle_ffor_receiver_message(&connection, &ack).is_err());
	let token = restored.capture_ffor_persistence();
	let _ = restored.encode();
	restored.ffor_persistence_completed(token).unwrap();
	let sender_id = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	restored
		.peer_connected(
			sender_id,
			&msgs::Init {
				features: sender.init_features(receiver_id),
				networks: None,
				remote_network_address: None,
			},
			false,
		)
		.unwrap();
	let replacement = restored.ffor_peer_connection(&sender_id).unwrap();
	assert_ne!(replacement, connection);
	assert!(restored
		.advance_ffor_receiver(&id, &connection, |_| panic!("old generation"))
		.is_err());
	assert!(restored.request_ffor_receiver_close(&id, &connection).is_err());
	assert!(restored.cancel_ffor_receiver_setup(&id, &connection).is_err());
	assert_eq!(
		restored.advance_ffor_receiver(&id, &replacement, |_| panic!("restored Activate")).unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	sender.node.peer_disconnected(receiver_id);
	sender
		.node
		.peer_connected(
			receiver_id,
			&msgs::Init {
				features: receiver.init_features(sender_id),
				networks: None,
				remote_network_address: None,
			},
			true,
		)
		.unwrap();
	let mut report = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: id.epoch_id(),
		activation_hash: hash,
		state: ReportedState::Active,
	}));
	restored.handle_channel_reestablish(sender_id, &report);
	restored.best_block.write().unwrap().height = 400;
	assert_eq!(
		restored.advance_ffor_receiver(&id, &replacement, |_| panic!("ACK-loss Activate")).unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	assert_eq!(
		restored.handle_ffor_receiver_message(&replacement, &ack).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	let token = restored.capture_ffor_persistence();
	let saved = restored.encode();
	restored.ffor_persistence_completed(token).unwrap();
	assert_eq!(
		restored.advance_ffor_receiver(&id, &replacement, |_| panic!("late Active wire")).unwrap(),
		FFORReceiverProgress::Active
	);
	assert!(restore(receiver, &saved, &monitor).is_ok());
	sender.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_driver_conflicting_reconnect_cannot_release_close_or_restore_active_progress() {
	fixture!(nodes, sender, receiver, channel, false);
	let (id, connection, _, _) = park(sender, receiver, channel);
	persist(receiver);
	let activate = emit(receiver, &id, &connection);
	let (ack, _) = activation_ack(sender, &id, &activate);
	receiver.node.handle_ffor_receiver_message(&connection, &ack).unwrap();
	persist(receiver);
	settlement_exits_stfu(sender, receiver, channel);
	receiver.node.request_ffor_receiver_close(&id, &connection).unwrap();
	persist(receiver);
	let sender_id = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	receiver.node.peer_disconnected(sender_id);
	sender.node.peer_disconnected(receiver_id);
	connect_nodes(sender, receiver);
	let replacement = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	let mut report = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: id.epoch_id(),
		activation_hash: [42; 32],
		state: ReportedState::Active,
	}));
	receiver.node.handle_channel_reestablish(sender_id, &report);
	assert!(receiver
		.node
		.advance_ffor_receiver(&id, &connection, |_| panic!("old generation Close"))
		.is_err());
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &replacement, |_| panic!("conflicting Close"))
			.unwrap(),
		FFORReceiverProgress::ResolutionRequired
	);
	assert!(receiver.node.request_ffor_receiver_close(&id, &replacement).is_err());
	// Historical exact ACK remains idempotent, but cannot erase the conflicting observation.
	receiver.node.handle_ffor_receiver_message(&replacement, &ack).unwrap();
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &replacement, |_| panic!("conflicting ACK replay"))
			.unwrap(),
		FFORReceiverProgress::ResolutionRequired
	);
	receiver.node.get_and_clear_pending_msg_events();
	sender.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_driver_retained_close_replay_requires_fresh_connection_before_stock_drain() {
	fixture!(nodes, sender, receiver, channel, false);
	let (id, connection, voucher, _) = park(sender, receiver, channel);
	persist(receiver);
	let activate = emit(receiver, &id, &connection);
	let (ack, hash) = activation_ack(sender, &id, &activate);
	receiver.node.handle_ffor_receiver_message(&connection, &ack).unwrap();
	persist(receiver);
	settlement_exits_stfu(sender, receiver, channel);
	receiver.node.request_ffor_receiver_close(&id, &connection).unwrap();
	persist(receiver);
	let close = emit(receiver, &id, &connection);
	let close_ack = signed(
		sender,
		&id,
		Payload::CloseAck(CloseAck {
			activation_hash: hash,
			num_slots: 1,
			settled: vec![0],
			preimages: Vec::new(),
			preimages_tlv_present: true,
		}),
	);
	receiver.node.handle_ffor_receiver_message(&connection, &close_ack).unwrap();
	persist(receiver);
	let sender_id = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	receiver.node.peer_disconnected(sender_id);
	sender.node.peer_disconnected(receiver_id);
	connect_nodes(sender, receiver);
	let replay_connection = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	// The local durable release must run before accepting any saved peer stock flight.
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &replay_connection, |_| panic!(
				"reconnect drain custom wire"
			))
			.unwrap(),
		FFORReceiverProgress::Draining
	);
	let mut report = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: id.epoch_id(),
		activation_hash: hash,
		state: ReportedState::Active,
	}));
	receiver.node.handle_channel_reestablish(sender_id, &report);
	assert_eq!(emit(receiver, &id, &replay_connection), close);
	assert_eq!(
		receiver.node.handle_ffor_receiver_message(&replay_connection, &close_ack).unwrap(),
		FFORReceiverProgress::ReconnectRequired
	);
	assert!(receiver
		.node
		.release_ffor_receiver_drain_on_connection(
			&channel,
			&sender_id,
			id.epoch_id(),
			Some(&replay_connection)
		)
		.is_err());
	let events = receiver.node.get_and_clear_pending_msg_events();
	assert!(events.iter().any(|event| matches!(
		event,
		MessageSendEvent::HandleError {
			action: msgs::ErrorAction::DisconnectPeerWithWarning { .. },
			..
		}
	)));
	assert!(!events.iter().any(|event| matches!(
		event,
		MessageSendEvent::UpdateHTLCs { .. } | MessageSendEvent::SendRevokeAndACK { .. }
	)));
	receiver.node.peer_disconnected(sender_id);
	sender.node.peer_disconnected(receiver_id);
	connect_nodes(sender, receiver);
	let fresh = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	assert!(receiver.node.handle_ffor_receiver_message(&replay_connection, &close_ack).is_err());
	assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &fresh, |_| panic!("fresh drain custom wire"))
			.unwrap(),
		FFORReceiverProgress::Draining
	);
	let mut report = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: id.epoch_id(),
		activation_hash: hash,
		state: ReportedState::Draining,
	}));
	receiver.node.handle_channel_reestablish(sender_id, &report);
	assert_eq!(drain(sender, receiver), (Vec::new(), vec![voucher.htlc_id]));
	sender.node.get_and_clear_pending_events();
	assert_eq!(
		advance_monitor(receiver, &id, &fresh).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver);
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &fresh, |_| panic!("Closed wire")).unwrap(),
		FFORReceiverProgress::Closed
	);
}

#[test]
fn ffor_driver_cancel_owned_stfu_drives_reconnect_and_gates_failures_on_durable_abort() {
	fixture!(nodes, sender, receiver, channel, false);
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let sender_id = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	let connection = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters(&voucher)).unwrap();
	persist(receiver);
	let init = emit(receiver, &id, &connection);
	let accepted = accept(sender, receiver, channel, voucher, &init).encode().unwrap();
	receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap();
	deliver_parked_voucher(sender, receiver, update);
	persist(receiver);
	assert_eq!(
		advance_monitor(receiver, &id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	complete_handshake(sender, receiver);
	assert_eq!(
		receiver.node.cancel_ffor_receiver_setup(&id, &connection).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	let events = receiver.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	assert!(matches!(
		events[0],
		MessageSendEvent::HandleError {
			action: msgs::ErrorAction::DisconnectPeerWithWarning { .. },
			..
		}
	));
	// Process the required disconnect before either the cancel or disconnect revision is stored.
	receiver.node.peer_disconnected(sender_id);
	sender.node.peer_disconnected(receiver_id);
	connect_nodes(sender, receiver);
	let fresh = receiver.node.ffor_peer_connection(&sender_id).unwrap();
	assert_eq!(drain(sender, receiver), (Vec::new(), Vec::new()));
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &fresh, |_| panic!("cancel Init")).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver);
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &fresh, |_| panic!("gate release wire")).unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	assert_eq!(drain(sender, receiver), (Vec::new(), vec![voucher.htlc_id]));
	sender.node.get_and_clear_pending_events();
	persist(receiver);
	assert_eq!(
		receiver.node.advance_ffor_receiver(&id, &fresh, |_| panic!("aborted retry")).unwrap(),
		FFORReceiverProgress::Aborted { reason: FFORReceiverAbortReason::Requested }
	);
	send_payment(sender, &[receiver], 1_000_000);
}
