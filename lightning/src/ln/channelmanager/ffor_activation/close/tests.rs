use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::ffor_activation::drain_tests::{drain, park_two};
use crate::ln::channelmanager::ffor_recovery_tests::claim_ffor_preimage_for_test;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};
use lightning_ffor::wire::{CloseAck, Preimage};

const EPOCH: [u8; 32] = [81; 32];

fn persist(node: &Node) -> Vec<u8> {
	let token = node.node.capture_ffor_persistence();
	let bytes = node.node.encode();
	node.node.ffor_persistence_completed(token).unwrap();
	bytes
}

fn signed(node: &Node, receiver: &Node, id: ChannelId, payload: Payload) -> Vec<u8> {
	let registry = receiver.node.ffor_recovery.lock().unwrap();
	let header = registry
		.get(&FFORRecoveryKey { channel_id: id, epoch_id: EPOCH })
		.unwrap()
		.validate_recovery()
		.unwrap()
		.header();
	let mut message = FFORMessage { header, payload, extensions: Vec::new(), signature: [0; 64] };
	message.signature = node
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
	message.encode().unwrap()
}

fn activate(sender: &Node, receiver: &Node, id: ChannelId) -> ([u8; 32], Vec<u8>) {
	let key = FFORRecoveryKey { channel_id: id, epoch_id: EPOCH };
	let hash = {
		let registry = receiver.node.ffor_recovery.lock().unwrap();
		registry.get_activation(&key).unwrap().activation_hash(registry.get(&key).unwrap()).unwrap()
	};
	assert!(receiver
		.node
		.release_ffor_receiver_activation(&id, &sender.node.get_our_node_id(), EPOCH, |_| Ok(()))
		.unwrap());
	let ack = signed(sender, receiver, id, Payload::ActivateAck(hash));
	receiver
		.node
		.accept_ffor_receiver_activation_ack(&id, &sender.node.get_our_node_id(), EPOCH, &ack)
		.unwrap();
	persist(receiver);
	// The settlement test node models its signed Active response and exits its stock STFU state.
	let peers = sender.node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
	peer.channel_by_id.get_mut(&id).unwrap().as_funded_mut().unwrap().exit_quiescence();
	(hash, ack)
}

fn assert_no_htlc_wire(node: &Node) {
	for event in node.node.get_and_clear_pending_msg_events() {
		assert!(
			matches!(
				event,
				MessageSendEvent::SendChannelUpdate { .. }
					| MessageSendEvent::BroadcastChannelUpdate { .. }
			),
			"unexpected wire {event:?}"
		);
	}
}

#[test]
fn ffor_close_manager_drains_both_views_and_persists_closed_before_ordinary_payment() {
	for receiver_funds in [false, true] {
		for (settled, learned, delay_monitor, restart_mid_round) in [
			(false, false, false, false),
			(false, true, false, false),
			(true, false, false, false),
			(true, false, true, false),
			(true, false, false, true),
		] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let (persister, chain_monitor);
			let (mid_persister, mid_monitor, mid_manager);
			let reloaded;
			let config = anchor_config();
			let managers =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
			let mut nodes = create_network(2, &node_cfgs, &managers);
			let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
			let id = create_announced_chan_between_nodes_with_value(
				&nodes, funder, other, 100_000, 40_000_000,
			)
			.2;
			let peer = nodes[0].node.get_our_node_id();
			let receiver_id = nodes[1].node.get_our_node_id();
			let (vouchers, preimage) = park_two(&nodes[0], &nodes[1], id);
			let (hash, activation_ack) = activate(&nodes[0], &nodes[1], id);
			let old_monitor = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
			if learned {
				claim_ffor_preimage_for_test(
					&nodes[0],
					&nodes[1],
					id,
					vouchers[0].htlc_id,
					preimage,
				);
				check_added_monitors(&nodes[1], 1);
			}
			let old_token = nodes[1].node.capture_ffor_persistence();
			let close_requirement =
				nodes[1].node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap();
			assert_eq!(
				nodes[1].node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap(),
				close_requirement
			);
			nodes[1].node.ffor_persistence_completed(old_token).unwrap();
			assert!(!nodes[1]
				.node
				.release_ffor_receiver_close(&id, &peer, EPOCH, |_| panic!("unpersisted close"))
				.unwrap());
			persist(&nodes[1]);
			let mut close_wire = Vec::new();
			assert!(nodes[1]
				.node
				.release_ffor_receiver_close(&id, &peer, EPOCH, |wire| {
					close_wire = wire.to_vec();
					Ok(())
				})
				.unwrap());
			assert!(nodes[1]
				.node
				.release_ffor_receiver_close(&id, &peer, EPOCH, |wire| {
					assert_eq!(wire, close_wire);
					Ok(())
				})
				.unwrap());
			let ack = signed(
				&nodes[0],
				&nodes[1],
				id,
				Payload::CloseAck(CloseAck {
					activation_hash: hash,
					num_slots: 2,
					settled: vec![u8::from(settled)],
					preimages: if settled {
						vec![Preimage { slot: 1, value: preimage.0 }]
					} else {
						Vec::new()
					},
					preimages_tlv_present: true,
				}),
			);
			let requirement =
				nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap();
			assert_eq!(
				nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap(),
				requirement
			);
			assert_eq!(
				nodes[1]
					.node
					.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &activation_ack)
					.unwrap(),
				requirement
			);
			assert!(!nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
			assert_no_htlc_wire(&nodes[1]);
			assert!(nodes[1]
				.node
				.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &old_monitor)
				.is_err());
			persist(&nodes[1]);
			if delay_monitor {
				chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			}
			assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
			if delay_monitor {
				assert_no_htlc_wire(&nodes[1]);
				let update = get_monitor!(nodes[1], id).get_latest_update_id();
				chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
				nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(id, update).unwrap();
			}
			if restart_mid_round {
				// Persist after signing removals, then lose that entire outbound commitment flight.
				let flight = nodes[1].node.get_and_clear_pending_msg_events();
				assert!(flight
					.iter()
					.any(|event| matches!(event, MessageSendEvent::UpdateHTLCs { .. })));
				let incomplete = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
				assert!(nodes[1]
					.node
					.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &incomplete)
					.is_err());
				let manager = persist(&nodes[1]);
				let monitor = get_monitor!(nodes[1], id).encode();
				nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
				nodes[0].node.peer_disconnected(receiver_id);
				reload_node!(
					nodes[1],
					config.clone(),
					&manager,
					&[&monitor],
					mid_persister,
					mid_monitor,
					mid_manager
				);
				assert!(!nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
				persist(&nodes[1]);
				connect_nodes(&nodes[0], &nodes[1]);
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
				// The settlement test node supplies its authenticated connection's retained epoch report.
				for event in nodes[0].node.get_and_clear_pending_msg_events() {
					match event {
						MessageSendEvent::SendChannelReestablish { mut msg, .. } => {
							msg.ffor_reestablish =
								Some(msgs::FFORChannelReestablish::new(Reestablish {
									epoch_id: EPOCH,
									activation_hash: hash,
									state: ReportedState::Active,
								}));
							nodes[1].node.handle_channel_reestablish(peer, &msg);
						},
						MessageSendEvent::SendChannelUpdate { .. }
						| MessageSendEvent::BroadcastChannelUpdate { .. } => {},
						other => panic!("unexpected reconnect wire {other:?}"),
					}
				}
				assert!(nodes[1]
					.node
					.release_ffor_receiver_close(&id, &peer, EPOCH, |wire| {
						assert_eq!(wire, close_wire);
						Ok(())
					})
					.unwrap());
				nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap();
				assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).is_err());
				for event in nodes[1].node.get_and_clear_pending_msg_events() {
					match event {
						MessageSendEvent::SendChannelReestablish { msg, .. } => {
							nodes[0].node.handle_channel_reestablish(receiver_id, &msg)
						},
						MessageSendEvent::SendChannelUpdate { .. }
						| MessageSendEvent::BroadcastChannelUpdate { .. } => {},
						other => panic!("stock replay before close reconciliation {other:?}"),
					}
				}
				// Exact ACK authorizes no forgotten stock replay on this connection. Reconnect first.
				nodes[0].node.peer_disconnected(receiver_id);
				nodes[1].node.peer_disconnected(peer);
				assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
				connect_nodes(&nodes[0], &nodes[1]);
				for event in nodes[0].node.get_and_clear_pending_msg_events() {
					match event {
						MessageSendEvent::SendChannelReestablish { mut msg, .. } => {
							msg.ffor_reestablish =
								Some(msgs::FFORChannelReestablish::new(Reestablish {
									epoch_id: EPOCH,
									activation_hash: hash,
									state: ReportedState::Draining,
								}));
							nodes[1].node.handle_channel_reestablish(peer, &msg);
						},
						MessageSendEvent::SendChannelUpdate { .. }
						| MessageSendEvent::BroadcastChannelUpdate { .. } => {},
						other => panic!("unexpected fresh reconnect wire {other:?}"),
					}
				}
			}
			let (fulfilled, failed) = drain(&nodes[0], &nodes[1]);
			assert_eq!(
				fulfilled,
				if settled || learned { vec![vouchers[0].htlc_id] } else { Vec::new() }
			);
			assert_eq!(
				failed,
				vouchers
					.iter()
					.skip(usize::from(settled || learned))
					.map(|v| v.htlc_id)
					.collect::<Vec<_>>()
			);
			nodes[0].node.get_and_clear_pending_events();
			assert!(nodes[1].node.list_usable_channels().is_empty());
			assert!(nodes[1]
				.node
				.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &old_monitor)
				.is_err());
			let snapshot = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
			let closed =
				nodes[1].node.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &snapshot).unwrap();
			assert_eq!(
				nodes[1]
					.node
					.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &activation_ack)
					.unwrap(),
				closed
			);
			assert!(!nodes[1].node.is_ffor_state_persisted(&closed));
			assert!(!nodes[1].node.release_ffor_receiver_closed(&id, &peer, EPOCH).unwrap());
			persist(&nodes[1]);
			nodes[0].node.peer_disconnected(receiver_id);
			nodes[1].node.peer_disconnected(peer);
			connect_nodes(&nodes[0], &nodes[1]);
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			assert!(nodes[1].node.release_ffor_receiver_closed(&id, &peer, EPOCH).unwrap());
			assert_eq!(
				nodes[1]
					.node
					.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &activation_ack)
					.unwrap(),
				closed
			);
			assert_eq!(drain(&nodes[0], &nodes[1]), (Vec::new(), Vec::new()));
			assert_eq!(nodes[1].node.list_usable_channels().len(), 1);
			let manager = persist(&nodes[1]);
			let monitor = get_monitor!(nodes[1], id).encode();
			nodes[0].node.peer_disconnected(receiver_id);
			reload_node!(
				nodes[1],
				config,
				&manager,
				&[&monitor],
				persister,
				chain_monitor,
				reloaded
			);
			persist(&nodes[1]);
			nodes[1]
				.node
				.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &activation_ack)
				.unwrap();
			connect_nodes(&nodes[0], &nodes[1]);
			assert_eq!(drain(&nodes[0], &nodes[1]), (Vec::new(), Vec::new()));
			send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		}
	}
}

#[test]
fn ffor_close_manager_force_close_retains_draining_archive_and_monitor_preimage() {
	for receiver_funds in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let (persister, chain_monitor, reloaded);
		let config = anchor_config();
		let managers =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let mut nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let peer = nodes[0].node.get_our_node_id();
		let (vouchers, preimage) = park_two(&nodes[0], &nodes[1], id);
		let (hash, _) = activate(&nodes[0], &nodes[1], id);
		let activation_update = get_monitor!(nodes[1], id).get_latest_update_id();
		nodes[1].node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap();
		persist(&nodes[1]);
		assert!(nodes[1].node.release_ffor_receiver_close(&id, &peer, EPOCH, |_| Ok(())).unwrap());
		let ack = signed(
			&nodes[0],
			&nodes[1],
			id,
			Payload::CloseAck(CloseAck {
				activation_hash: hash,
				num_slots: 2,
				settled: vec![1],
				preimages: vec![Preimage { slot: 1, value: preimage.0 }],
				preimages_tlv_present: true,
			}),
		);
		nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap();
		persist(&nodes[1]);
		assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
		// Lose the removal flight. Both stock monitors still own their unresolved commitments.
		let flight = nodes[1].node.get_and_clear_pending_msg_events();
		assert!(flight.iter().any(|event| matches!(event, MessageSendEvent::UpdateHTLCs { .. })));
		assert!(get_monitor!(nodes[1], id).get_latest_update_id() > activation_update);
		assert_eq!(
			get_monitor!(nodes[1], id).get_stored_preimages()[&vouchers[0].payment_hash].0,
			preimage
		);
		let archive = nodes[1].node.ffor_recovery.lock().unwrap().encode();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&id, &peer, "draining recovery test".into())
			.unwrap();
		assert!(nodes[1].node.list_channels().is_empty());
		assert!(nodes[1]
			.node
			.get_and_clear_pending_events()
			.iter()
			.any(|event| matches!(event, Event::ChannelClosed { .. })));
		nodes[1].node.get_and_clear_pending_msg_events();
		nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
		let manager = persist(&nodes[1]);
		let monitor = get_monitor!(nodes[1], id).encode();
		let without_monitor = <(BlockHash, TestChannelManager)>::read(
			&mut &manager[..],
			ChannelManagerReadArgs::new(
				nodes[1].keys_manager,
				nodes[1].keys_manager,
				nodes[1].keys_manager,
				nodes[1].fee_estimator,
				nodes[1].chain_monitor,
				nodes[1].tx_broadcaster,
				nodes[1].router,
				nodes[1].message_router,
				nodes[1].logger,
				config.clone(),
				vec![],
			),
		);
		assert!(without_monitor.is_err());
		reload_node!(nodes[1], config, &manager, &[&monitor], persister, chain_monitor, reloaded);
		assert!(nodes[1].node.list_channels().is_empty());
		assert_eq!(nodes[1].node.ffor_recovery.lock().unwrap().encode(), archive);
		assert_eq!(
			get_monitor!(nodes[1], id).get_stored_preimages()[&vouchers[0].payment_hash].0,
			preimage
		);
		let key = FFORRecoveryKey { channel_id: id, epoch_id: EPOCH };
		let recovery = nodes[1].node.ffor_recovery.lock().unwrap();
		let close = recovery.get_activation(&key).unwrap().close_record().unwrap();
		assert_eq!(close.acknowledgement_wire().unwrap(), ack.as_slice());
		assert!(!close.is_closed());
	}
}

#[test]
fn ffor_close_manager_refuses_replay_during_conflicting_reconnect() {
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
		let peer = nodes[0].node.get_our_node_id();
		let receiver = nodes[1].node.get_our_node_id();
		park_two(&nodes[0], &nodes[1], id);
		let (hash, _) = activate(&nodes[0], &nodes[1], id);
		nodes[1].node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap();
		persist(&nodes[1]);
		for conflicting in [true, false] {
			nodes[0].node.peer_disconnected(receiver);
			nodes[1].node.peer_disconnected(peer);
			connect_nodes(&nodes[0], &nodes[1]);
			let local = get_event_msg!(&nodes[1], MessageSendEvent::SendChannelReestablish, peer);
			let mut remote =
				get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReestablish, receiver);
			let mut reported_hash = hash;
			if conflicting {
				reported_hash[0] ^= 1;
			}
			remote.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
				epoch_id: EPOCH,
				activation_hash: reported_hash,
				state: ReportedState::Active,
			}));
			nodes[0].node.handle_channel_reestablish(receiver, &local);
			nodes[1].node.handle_channel_reestablish(peer, &remote);
			if conflicting {
				{
					let peers = nodes[1].node.per_peer_state.read().unwrap();
					let peer_state = peers.get(&peer).unwrap().lock().unwrap();
					let channel = peer_state.channel_by_id.get(&id).unwrap().as_funded().unwrap();
					assert!(channel.context.is_connected());
					assert!(matches!(
						channel.ffor_receiver_reconnect_outcome(),
						Some(FFORReestablishOutcome::ResolutionRequired { .. })
					));
				}
				assert!(nodes[1]
					.node
					.release_ffor_receiver_close(&id, &peer, EPOCH, |_| panic!(
						"conflicting replay"
					))
					.is_err());
			} else {
				assert!(nodes[1]
					.node
					.release_ffor_receiver_close(&id, &peer, EPOCH, |_| Ok(()))
					.unwrap());
			}
			assert_no_htlc_wire(&nodes[0]);
			assert_no_htlc_wire(&nodes[1]);
		}
	}
}
