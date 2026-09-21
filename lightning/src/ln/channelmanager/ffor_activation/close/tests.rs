use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::ffor_activation::drain_tests::{drain, park_two, park_two_epoch};
use crate::ln::channelmanager::ffor_recovery_tests::{claim_ffor_preimage_for_test, restore};
use crate::ln::ffor::{
	FFORReceiverAbortReason, FFORReceiverId, FFORReceiverParameters, FFORVoucherOutcome,
};
use crate::ln::ffor_recovery::tests::fill_registry;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};
use lightning_ffor::wire::{CloseAck, Preimage};

const EPOCH: [u8; 32] = [81; 32];
const EPOCH2: [u8; 32] = [82; 32];

fn persist(node: &Node) -> Vec<u8> {
	let token = node.node.capture_ffor_persistence();
	let bytes = node.node.encode();
	node.node.ffor_persistence_completed(token).unwrap();
	bytes
}

fn signed(node: &Node, receiver: &Node, id: ChannelId, payload: Payload) -> Vec<u8> {
	signed_epoch(node, receiver, id, EPOCH, payload)
}

fn signed_epoch(
	node: &Node, receiver: &Node, id: ChannelId, epoch: [u8; 32], payload: Payload,
) -> Vec<u8> {
	let registry = receiver.node.ffor_recovery.lock().unwrap();
	let header = registry
		.get(&FFORRecoveryKey { channel_id: id, epoch_id: epoch })
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
	activate_epoch(sender, receiver, id, EPOCH)
}

fn activate_epoch(
	sender: &Node, receiver: &Node, id: ChannelId, epoch: [u8; 32],
) -> ([u8; 32], Vec<u8>) {
	let key = FFORRecoveryKey { channel_id: id, epoch_id: epoch };
	let hash = {
		let registry = receiver.node.ffor_recovery.lock().unwrap();
		registry.get_activation(&key).unwrap().activation_hash(registry.get(&key).unwrap()).unwrap()
	};
	assert!(receiver
		.node
		.release_ffor_receiver_activation(&id, &sender.node.get_our_node_id(), epoch, |_| Ok(()))
		.unwrap());
	let ack = signed_epoch(sender, receiver, id, epoch, Payload::ActivateAck(hash));
	receiver
		.node
		.accept_ffor_receiver_activation_ack(&id, &sender.node.get_our_node_id(), epoch, &ack)
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
			let outcome = |node: &Node, slot: u16| {
				let context = node.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
				let voucher = vouchers[usize::from(slot.clamp(1, 2)) - 1];
				node.node.ffor_receiver_voucher_outcome(
					&context,
					slot,
					voucher.payment_hash,
					voucher.amount_msat,
				)
			};
			let expected_first = if settled || learned {
				FFORVoucherOutcome::Fulfilled
			} else {
				FFORVoucherOutcome::Failed
			};
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
			// Every slot is journaled, but nothing is reported before the retained Closed proof.
			assert_eq!(outcome(&nodes[1], 1), Ok(None));
			assert_eq!(outcome(&nodes[1], 2), Ok(None));
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
			assert_eq!(outcome(&nodes[1], 1), Ok(Some(expected_first)));
			assert_eq!(outcome(&nodes[1], 2), Ok(Some(FFORVoucherOutcome::Failed)));
			assert!(outcome(&nodes[1], 0).is_err());
			assert!(outcome(&nodes[1], 3).is_err());
			{
				let context = nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
				assert!(nodes[1]
					.node
					.ffor_receiver_voucher_outcome(
						&context,
						1,
						vouchers[1].payment_hash,
						vouchers[0].amount_msat
					)
					.is_err());
				assert!(nodes[1]
					.node
					.ffor_receiver_voucher_outcome(
						&context,
						1,
						vouchers[0].payment_hash,
						vouchers[0].amount_msat + 1
					)
					.is_err());
			}
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
			// A restored manager reports nothing until its own fresh write completes.
			assert!(outcome(&nodes[1], 1).is_err());
			persist(&nodes[1]);
			assert_eq!(outcome(&nodes[1], 1), Ok(Some(expected_first)));
			assert_eq!(outcome(&nodes[1], 2), Ok(Some(FFORVoucherOutcome::Failed)));
			nodes[1]
				.node
				.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &activation_ack)
				.unwrap();
			connect_nodes(&nodes[0], &nodes[1]);
			assert_eq!(drain(&nodes[0], &nodes[1]), (Vec::new(), Vec::new()));
			send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
			if settled && !delay_monitor && !restart_mid_round {
				// Archive-only history after the channel is gone still reports the same outcomes.
				nodes[1]
					.node
					.force_close_broadcasting_latest_txn(&id, &peer, "archive only".into())
					.unwrap();
				nodes[1].node.get_and_clear_pending_events();
				nodes[1].node.get_and_clear_pending_msg_events();
				nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
				assert!(nodes[1].node.list_channels().is_empty());
				assert_eq!(outcome(&nodes[1], 1), Ok(Some(expected_first)));
				persist(&nodes[1]);
				assert_eq!(outcome(&nodes[1], 1), Ok(Some(expected_first)));
				assert_eq!(outcome(&nodes[1], 2), Ok(Some(FFORVoucherOutcome::Failed)));
			}
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
		persist(&nodes[1]);
		let context = nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
		assert_eq!(
			nodes[1]
				.node
				.ffor_receiver_voucher_outcome(
					&context,
					1,
					vouchers[0].payment_hash,
					vouchers[0].amount_msat
				)
				.unwrap(),
			None
		);
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

/// Drive an Active epoch through signed close, drain and the retained Closed proof until the
/// fence is released. Returns the exact close acknowledgement and the drained HTLC IDs.
fn close_epoch<'a, 'b, 'c>(
	sender: &Node<'a, 'b, 'c>, receiver: &Node<'a, 'b, 'c>, id: ChannelId, epoch: [u8; 32],
	hash: [u8; 32], settled_preimage: Option<PaymentPreimage>,
) -> (Vec<u8>, Vec<u64>, Vec<u64>) {
	let peer = sender.node.get_our_node_id();
	receiver.node.prepare_ffor_receiver_close(&id, &peer, epoch).unwrap();
	persist(receiver);
	assert!(receiver.node.release_ffor_receiver_close(&id, &peer, epoch, |_| Ok(())).unwrap());
	let ack = signed_epoch(
		sender,
		receiver,
		id,
		epoch,
		Payload::CloseAck(CloseAck {
			activation_hash: hash,
			num_slots: 2,
			settled: vec![u8::from(settled_preimage.is_some())],
			preimages: settled_preimage
				.map(|preimage| vec![Preimage { slot: 1, value: preimage.0 }])
				.unwrap_or_default(),
			preimages_tlv_present: true,
		}),
	);
	receiver.node.accept_ffor_receiver_close_ack(&id, &peer, epoch, &ack).unwrap();
	persist(receiver);
	assert!(receiver.node.release_ffor_receiver_drain(&id, &peer, epoch).unwrap());
	let (fulfilled, failed) = drain(sender, receiver);
	// PaymentSent releases the sender's held monitor update once its event is processed.
	sender.node.get_and_clear_pending_events();
	sender.chain_monitor.added_monitors.lock().unwrap().clear();
	let snapshot = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
	receiver.node.prepare_ffor_receiver_closed(&id, &peer, epoch, &snapshot).unwrap();
	persist(receiver);
	assert!(receiver.node.release_ffor_receiver_closed(&id, &peer, epoch).unwrap());
	(ack, fulfilled, failed)
}

fn outcome(
	node: &Node, id: ChannelId, epoch: [u8; 32], voucher: &FFORVoucher, slot: u16,
) -> Result<Option<FFORVoucherOutcome>, FFORReceiverError> {
	let context = node.node.ffor_receiver_recovery_context(&id, epoch)?;
	node.node.ffor_receiver_voucher_outcome(
		&context,
		slot,
		voucher.payment_hash,
		voucher.amount_msat,
	)
}

/// The channel's current epoch and the epoch that book replaced.
fn book_epochs(
	sender: &Node, receiver: &Node, id: ChannelId,
) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get(&id).unwrap().as_funded().unwrap();
	(channel.ffor_receiver_epoch_id(), channel.ffor_receiver_predecessor_epoch())
}

/// Stage a new epoch through the public pre-init facade on the current connection.
fn attempt_reuse(
	sender: &Node, receiver: &Node, id: ChannelId, voucher: &FFORVoucher,
	local_request_id: [u8; 32],
) -> Result<FFORReceiverId, FFORReceiverError> {
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let parameters = FFORReceiverParameters {
		local_request_id,
		amounts_msat: vec![voucher.amount_msat],
		minimum_payment_msat: voucher.amount_msat,
		settlement_deadline: voucher.cltv_expiry - 20,
		voucher_expiry: voucher.cltv_expiry,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		claim_margin_blocks: 20,
		witness_peers: None,
		hash_chain: false,
	};
	receiver.node.prepare_ffor_receiver(&id, &connection, parameters)
}

#[test]
fn ffor_close_manager_reuses_channel_after_closed_epoch_and_retains_history() {
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
		let receiver_id = nodes[1].node.get_our_node_id();
		let (first, first_preimage) = park_two(&nodes[0], &nodes[1], id);
		let (first_hash, _) = activate(&nodes[0], &nodes[1], id);
		let (_, fulfilled, failed) =
			close_epoch(&nodes[0], &nodes[1], id, EPOCH, first_hash, Some(first_preimage));
		assert_eq!(fulfilled, vec![first[0].htlc_id]);
		assert_eq!(failed, vec![first[1].htlc_id]);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[0], 1),
			Ok(Some(FFORVoucherOutcome::Fulfilled))
		);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[1], 2),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH), None));
		assert_eq!(nodes[1].node.list_ffor_receiver_recovery_contexts().unwrap().len(), 1);
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		// The second epoch replaces the channel book while the first epoch's archive record,
		// journal and Closed proof stay readable by their own epoch ID.
		let (second, _) = park_two_epoch(&nodes[0], &nodes[1], id, EPOCH2);
		assert_ne!(second[0].payment_hash, first[0].payment_hash);
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH2), Some(EPOCH)));
		assert_eq!(nodes[1].node.list_ffor_receiver_recovery_contexts().unwrap().len(), 2);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[0], 1),
			Ok(Some(FFORVoucherOutcome::Fulfilled))
		);
		let (second_hash, _) = activate_epoch(&nodes[0], &nodes[1], id, EPOCH2);
		assert_eq!(outcome(&nodes[1], id, EPOCH2, &second[0], 1), Ok(None));
		assert!(nodes[1].node.release_ffor_receiver_closed(&id, &peer, EPOCH).is_err());
		let (_, fulfilled, failed) =
			close_epoch(&nodes[0], &nodes[1], id, EPOCH2, second_hash, None);
		assert!(fulfilled.is_empty());
		assert_eq!(failed, vec![second[0].htlc_id, second[1].htlc_id]);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH2, &second[0], 1),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH2, &second[1], 2),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[0], 1),
			Ok(Some(FFORVoucherOutcome::Fulfilled))
		);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[1], 2),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		// Slots and hashes are bound to their own epoch.
		assert!(outcome(&nodes[1], id, EPOCH, &second[0], 1).is_err());
		assert!(outcome(&nodes[1], id, EPOCH2, &first[0], 1).is_err());
		let history = nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
		assert_eq!(history.epoch_id(), EPOCH);
		assert_eq!(history.activation_hash(), first_hash);
		assert!(nodes[1].node.ffor_receiver_invoice_for_storage(&history).unwrap().is_none());
		assert_eq!(nodes[1].node.list_usable_channels().len(), 1);
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		let manager = persist(&nodes[1]);
		let monitor = get_monitor!(nodes[1], id).encode();
		nodes[0].node.peer_disconnected(receiver_id);
		reload_node!(nodes[1], config, &manager, &[&monitor], persister, chain_monitor, reloaded);
		// Stock restore replays the ordinary claim; no voucher event is ever synthesized.
		for event in nodes[1].node.get_and_clear_pending_events() {
			assert!(matches!(event, Event::PaymentClaimed { .. }), "unexpected {event:?}");
		}
		assert!(outcome(&nodes[1], id, EPOCH, &first[0], 1).is_err());
		persist(&nodes[1]);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &first[0], 1),
			Ok(Some(FFORVoucherOutcome::Fulfilled))
		);
		assert_eq!(
			outcome(&nodes[1], id, EPOCH2, &second[0], 1),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH2), Some(EPOCH)));
		assert_eq!(nodes[1].node.list_ffor_receiver_recovery_contexts().unwrap().len(), 2);
		connect_nodes(&nodes[0], &nodes[1]);
		assert_eq!(drain(&nodes[0], &nodes[1]), (Vec::new(), Vec::new()));
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_close_manager_refuses_reuse_until_previous_epoch_is_terminal() {
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
		let (vouchers, _) = park_two(&nodes[0], &nodes[1], id);
		let attempt = || attempt_reuse(&nodes[0], &nodes[1], id, &vouchers[0], [93; 32]);
		let refused = Err(FFORReceiverError::AlreadyRegistered);
		assert_eq!(attempt(), refused);
		let (hash, _) = activate(&nodes[0], &nodes[1], id);
		assert_eq!(attempt(), refused);
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
				settled: vec![0],
				preimages: Vec::new(),
				preimages_tlv_present: true,
			}),
		);
		nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap();
		assert_eq!(attempt(), refused);
		persist(&nodes[1]);
		assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
		assert_eq!(attempt(), refused);
		assert_eq!(
			drain(&nodes[0], &nodes[1]),
			(Vec::new(), vec![vouchers[0].htlc_id, vouchers[1].htlc_id])
		);
		nodes[0].node.get_and_clear_pending_events();
		// Every voucher is removed, but Draining without the retained Closed proof is not terminal.
		assert_eq!(attempt(), refused);
		let snapshot = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
		nodes[1].node.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &snapshot).unwrap();
		// ClosedPendingPersistence before the final write, and still fenced after it.
		assert_eq!(attempt(), refused);
		persist(&nodes[1]);
		assert_eq!(attempt(), refused);
		assert!(nodes[1].node.release_ffor_receiver_closed(&id, &peer, EPOCH).unwrap());
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH), None));
		let next = attempt().unwrap();
		assert_eq!(next.channel_id(), id);
		assert_ne!(next.epoch_id(), EPOCH);
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(next.epoch_id()), Some(EPOCH)));
		// An exact retry of the new request is idempotent; the replaced epoch keeps its history.
		assert_eq!(attempt(), Ok(next));
		assert!(nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).is_ok());
		assert_eq!(
			outcome(&nodes[1], id, EPOCH, &vouchers[0], 1),
			Ok(Some(FFORVoucherOutcome::Failed))
		);
		let manager = persist(&nodes[1]);
		let monitor = get_monitor!(nodes[1], id).encode();
		assert!(restore(&nodes[1], &manager, &monitor).is_ok());
		// A closed channel cannot host another epoch, while its history stays readable.
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&id, &peer, "reuse after close".into())
			.unwrap();
		nodes[1].node.get_and_clear_pending_events();
		nodes[1].node.get_and_clear_pending_msg_events();
		nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
		assert_eq!(
			attempt_reuse(&nodes[0], &nodes[1], id, &vouchers[0], [94; 32]),
			Err(FFORCommitmentError::ChannelUnavailable.into())
		);
		assert!(nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).is_ok());
		assert_eq!(nodes[1].node.list_ffor_receiver_recovery_contexts().unwrap().len(), 1);
	}
}

#[test]
fn ffor_close_manager_refuses_reuse_while_aborting_and_permits_it_after_aborted_drain() {
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
		let receiver_id = nodes[1].node.get_our_node_id();
		let (vouchers, _) = park_two(&nodes[0], &nodes[1], id);
		let attempt = || attempt_reuse(&nodes[0], &nodes[1], id, &vouchers[0], [95; 32]);
		let refused = Err(FFORReceiverError::AlreadyRegistered);
		nodes[0].node.peer_disconnected(receiver_id);
		nodes[1].node.peer_disconnected(peer);
		connect_nodes(&nodes[0], &nodes[1]);
		let receiver_report =
			get_event_msg!(&nodes[1], MessageSendEvent::SendChannelReestablish, peer);
		let sender_report =
			get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReestablish, receiver_id);
		nodes[0].node.handle_channel_reestablish(receiver_id, &receiver_report);
		nodes[1].node.handle_channel_reestablish(peer, &sender_report);
		// Aborting: the terminal abort is retained but not yet durable.
		assert_eq!(attempt(), refused);
		assert!(!nodes[1].node.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		persist(&nodes[1]);
		assert!(nodes[1].node.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		// Durable abort, but the owned vouchers are still pending in the channel.
		assert_eq!(attempt(), refused);
		assert_eq!(
			drain(&nodes[0], &nodes[1]),
			(Vec::new(), vec![vouchers[0].htlc_id, vouchers[1].htlc_id])
		);
		nodes[0].node.get_and_clear_pending_events();
		let snapshot = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
		assert_eq!(
			nodes[1].node.ffor_receiver_book_status(&id, &peer, &snapshot).unwrap(),
			FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::Disconnected }
		);
		let next = attempt().unwrap();
		assert_ne!(next.epoch_id(), EPOCH);
		assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(next.epoch_id()), Some(EPOCH)));
		assert_eq!(nodes[1].node.list_ffor_receiver_recovery_contexts().unwrap().len(), 1);
		assert!(nodes[1].node.ffor_receiver_recovery_context(&id, EPOCH).is_ok());
		let manager = persist(&nodes[1]);
		let monitor = get_monitor!(nodes[1], id).encode();
		assert!(restore(&nodes[1], &manager, &monitor).is_ok());
		nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
	}
}

#[test]
fn ffor_close_manager_refuses_reuse_when_archive_capacity_is_exhausted() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (vouchers, _) = park_two(&nodes[0], &nodes[1], id);
	let (hash, _) = activate(&nodes[0], &nodes[1], id);
	close_epoch(&nodes[0], &nodes[1], id, EPOCH, hash, None);
	let saved = nodes[1].node.ffor_recovery.lock().unwrap().encode();
	fill_registry(&mut *nodes[1].node.ffor_recovery.lock().unwrap());
	assert_eq!(
		attempt_reuse(&nodes[0], &nodes[1], id, &vouchers[0], [96; 32]),
		Err(FFORReceiverError::RecoveryUnavailable)
	);
	// Capacity refusal leaves the terminal book and its history untouched.
	assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH), None));
	*nodes[1].node.ffor_recovery.lock().unwrap() =
		<FFORRecoveryRegistry as Readable>::read(&mut &saved[..]).unwrap();
	assert_eq!(nodes[1].node.find_ffor_receiver_request([96; 32]).unwrap(), None);
	let next = attempt_reuse(&nodes[0], &nodes[1], id, &vouchers[0], [96; 32]).unwrap();
	assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(next.epoch_id()), Some(EPOCH)));
	assert_eq!(
		outcome(&nodes[1], id, EPOCH, &vouchers[0], 1),
		Ok(Some(FFORVoucherOutcome::Failed))
	);
}

/// Split a serialized registry into its version byte and framed activation records.
fn archive_records(bytes: &[u8]) -> (u8, Vec<Vec<u8>>) {
	let count = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
	let mut offset = 3;
	let mut records = Vec::new();
	for _ in 0..count {
		let length = u32::from_be_bytes([
			bytes[offset],
			bytes[offset + 1],
			bytes[offset + 2],
			bytes[offset + 3],
		]) as usize;
		records.push(bytes[offset + 4..offset + 4 + length].to_vec());
		offset += 4 + length;
	}
	(bytes[0], records)
}

#[test]
fn ffor_close_manager_restore_rejects_later_epoch_without_terminal_predecessor_record() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let peer = nodes[0].node.get_our_node_id();
	park_two(&nodes[0], &nodes[1], id);
	let (hash, _) = activate(&nodes[0], &nodes[1], id);
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
			settled: vec![0],
			preimages: Vec::new(),
			preimages_tlv_present: true,
		}),
	);
	nodes[1].node.accept_ffor_receiver_close_ack(&id, &peer, EPOCH, &ack).unwrap();
	persist(&nodes[1]);
	assert!(nodes[1].node.release_ffor_receiver_drain(&id, &peer, EPOCH).unwrap());
	let draining_archive = nodes[1].node.ffor_recovery.lock().unwrap().encode();
	drain(&nodes[0], &nodes[1]);
	nodes[0].node.get_and_clear_pending_events();
	let snapshot = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
	nodes[1].node.prepare_ffor_receiver_closed(&id, &peer, EPOCH, &snapshot).unwrap();
	persist(&nodes[1]);
	assert!(nodes[1].node.release_ffor_receiver_closed(&id, &peer, EPOCH).unwrap());
	park_two_epoch(&nodes[0], &nodes[1], id, EPOCH2);
	assert_eq!(book_epochs(&nodes[0], &nodes[1], id), (Some(EPOCH2), Some(EPOCH)));
	let manager = persist(&nodes[1]);
	let monitor = get_monitor!(nodes[1], id).encode();
	assert!(restore(&nodes[1], &manager, &monitor).is_ok());
	// The same channel bytes with an archive that lacks the replaced epoch fail closed.
	let key = FFORRecoveryKey { channel_id: id, epoch_id: EPOCH2 };
	let mut without_first = FFORRecoveryRegistry::new();
	{
		let recovery = nodes[1].node.ffor_recovery.lock().unwrap();
		let setup = recovery.get(&key).unwrap().clone();
		let activation = recovery.get_activation(&key).unwrap().clone();
		without_first.prepare_insert(&setup).unwrap().commit();
		without_first.prepare_activation(&setup, &activation).unwrap().commit();
	}
	let complete =
		core::mem::replace(&mut *nodes[1].node.ffor_recovery.lock().unwrap(), without_first);
	let damaged = nodes[1].node.encode();
	*nodes[1].node.ffor_recovery.lock().unwrap() = complete;
	assert!(matches!(restore(&nodes[1], &damaged, &monitor), Err(DecodeError::InvalidValue)));
	// An archive holding an unresolved first epoch beside the second is refused by the reader.
	let (version, draining) = archive_records(&draining_archive);
	let (_, current) = archive_records(&nodes[1].node.ffor_recovery.lock().unwrap().encode());
	assert_eq!(draining.len(), 1);
	assert_eq!(current.len(), 2);
	let mut spliced = vec![version, 0, 2];
	for record in [&draining[0], &current[1]] {
		spliced.extend_from_slice(&(record.len() as u32).to_be_bytes());
		spliced.extend_from_slice(record);
	}
	assert!(matches!(
		<FFORRecoveryRegistry as Readable>::read(&mut &spliced[..]),
		Err(DecodeError::InvalidValue)
	));
	assert!(restore(&nodes[1], &manager, &monitor).is_ok());
}
