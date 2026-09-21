use super::*;
use crate::ln::channel::{ffor_setup_test_messages, DISCONNECT_PEER_AWAITING_RESPONSE_TICKS};

const EPOCH: [u8; 32] = [81; 32];

fn register_signed(sender: &Node, receiver: &Node, channel_id: ChannelId, voucher: FFORVoucher) {
	let (init, accept) = ffor_setup_test_messages(sender, receiver, channel_id, voucher);
	let requirement = receiver
		.node
		.register_ffor_receiver_setup(
			&channel_id,
			&sender.node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		)
		.unwrap();
	let token = receiver.node.capture_ffor_persistence();
	let _persisted = receiver.node.encode();
	receiver.node.ffor_persistence_completed(token).unwrap();
	assert!(receiver.node.is_ffor_state_persisted(&requirement));
}

fn request(sender: &Node, receiver: &Node, channel_id: ChannelId) -> Result<(), FFORReceiverError> {
	receiver.node.request_ffor_receiver_quiescence(
		&channel_id,
		&sender.node.get_our_node_id(),
		EPOCH,
		snapshot(receiver, channel_id),
	)
}

fn status(
	sender: &Node, receiver: &Node, channel_id: ChannelId,
) -> Result<FFORReceiverQuiescenceStatus, FFORReceiverError> {
	receiver.node.ffor_receiver_quiescence_status(
		&channel_id,
		&sender.node.get_our_node_id(),
		EPOCH,
	)
}

fn complete_handshake(sender: &Node, receiver: &Node) {
	let receiver_id = receiver.node.get_our_node_id();
	let sender_id = sender.node.get_our_node_id();
	let proposed = get_event_msg!(receiver, MessageSendEvent::SendStfu, sender_id);
	assert!(proposed.initiator);
	sender.node.handle_stfu(receiver_id, &proposed);
	let response = get_event_msg!(sender, MessageSendEvent::SendStfu, receiver_id);
	assert!(!response.initiator);
	receiver.node.handle_stfu(sender_id, &response);
}

fn expect_disconnect(node: &Node) {
	let events = node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1, "{events:?}");
	assert!(matches!(
		events[0],
		MessageSendEvent::HandleError {
			action: msgs::ErrorAction::DisconnectPeerWithWarning { .. },
			..
		}
	));
	check_added_monitors(node, 0);
}

#[test]
fn ffor_quiescence_exchanges_stfu_and_retains_ownership_until_abort() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_signed(&nodes[0], &nodes[1], channel_id, voucher);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	request(&nodes[0], &nodes[1], channel_id).unwrap();
	assert_eq!(
		status(&nodes[0], &nodes[1], channel_id),
		Ok(FFORReceiverQuiescenceStatus::Negotiating)
	);
	complete_handshake(&nodes[0], &nodes[1]);
	assert_eq!(
		status(&nodes[0], &nodes[1], channel_id),
		Ok(FFORReceiverQuiescenceStatus::Quiescent)
	);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	nodes[1]
		.node
		.abort_ffor_receiver_book(&channel_id, &nodes[0].node.get_our_node_id(), EPOCH)
		.unwrap();
	expect_disconnect(&nodes[1]);
	assert!(status(&nodes[0], &nodes[1], channel_id).is_err());
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
	pump_ffor_reconnection(&nodes[0], &nodes[1]);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::Requested }
	);
	expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn ffor_quiescence_rejects_raw_setup_missing_support_and_competing_action() {
	for rejection in 0..3 {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		if rejection == 1 {
			let mut features = node_chanmgrs[0].init_features();
			features.clear_quiescence();
			*node_cfgs[0].override_init_features.borrow_mut() = Some(features);
		}
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		if rejection == 0 {
			register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
		} else {
			register_signed(&nodes[0], &nodes[1], channel_id, voucher);
		}
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		if rejection == 2 {
			nodes[1]
				.node
				.maybe_propose_quiescence(&nodes[0].node.get_our_node_id(), &channel_id)
				.unwrap();
		}
		assert!(nodes[1]
			.node
			.request_ffor_receiver_quiescence(
				&channel_id,
				&nodes[0].node.get_our_node_id(),
				if rejection == 0 { RECEIVER_EPOCH } else { EPOCH },
				snapshot(&nodes[1], channel_id),
			)
			.is_err());
		if rejection == 2 {
			complete_handshake(&nodes[0], &nodes[1]);
			assert!(nodes[0]
				.node
				.exit_quiescence(&nodes[1].node.get_our_node_id(), &channel_id)
				.unwrap());
			assert!(nodes[1]
				.node
				.exit_quiescence(&nodes[0].node.get_our_node_id(), &channel_id)
				.unwrap());
		} else {
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		}
	}
}

#[test]
fn ffor_quiescence_rejects_partial_rounds_and_stale_monitor_evidence() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_signed(&nodes[0], &nodes[1], channel_id, voucher);
	let before_round = snapshot(&nodes[1], channel_id);
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	nodes[1]
		.node
		.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update.update_add_htlcs[0]);
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	let sender_id = nodes[0].node.get_our_node_id();
	let receiver_id = nodes[1].node.get_our_node_id();
	nodes[1].node.handle_commitment_signed_batch_test(sender_id, &update.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	let (revoke, commitment) = get_revoke_commit_msgs!(&nodes[1], sender_id);
	nodes[0].node.handle_revoke_and_ack(receiver_id, &revoke);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(receiver_id, &commitment);
	check_added_monitors(&nodes[0], 1);
	let revoke = get_event_msg!(&nodes[0], MessageSendEvent::SendRevokeAndACK, receiver_id);
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_revoke_and_ack(sender_id, &revoke);
	check_added_monitors(&nodes[1], 1);
	assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let update_id = get_monitor!(nodes[1], channel_id).get_latest_update_id();
	nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(channel_id, update_id).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	expect_and_process_pending_htlcs(&nodes[1], false);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1]
		.node
		.request_ffor_receiver_quiescence(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			EPOCH,
			before_round,
		)
		.is_err());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	request(&nodes[0], &nodes[1], channel_id).unwrap();
	complete_handshake(&nodes[0], &nodes[1]);
	assert_eq!(
		status(&nodes[0], &nodes[1], channel_id),
		Ok(FFORReceiverQuiescenceStatus::Quiescent)
	);
}

#[test]
fn ffor_quiescence_finishes_inflight_round_then_rejects_changed_book() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let sender_id = nodes[0].node.get_our_node_id();
	let receiver_id = nodes[1].node.get_our_node_id();
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_signed(&nodes[0], &nodes[1], channel_id, voucher);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	request(&nodes[0], &nodes[1], channel_id).unwrap();
	let proposed = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, sender_id);
	// The peer has not received our STFU, so its already-started stock round is still legal.
	let (update, extra, _) = offer_voucher(&nodes[0], &nodes[1], 1_000_000);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	nodes[0].node.handle_stfu(receiver_id, &proposed);
	let response = get_event_msg!(&nodes[0], MessageSendEvent::SendStfu, receiver_id);
	nodes[1].node.handle_stfu(sender_id, &response);
	expect_disconnect(&nodes[1]);
	assert!(status(&nodes[0], &nodes[1], channel_id).is_err());
	nodes[0].node.peer_disconnected(receiver_id);
	nodes[1].node.peer_disconnected(sender_id);
	pump_ffor_reconnection(&nodes[0], &nodes[1]);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::VoucherMismatch }
	);
	let mut failures = [Vec::new(), Vec::new()];
	for event in nodes[0].node.get_and_clear_pending_events() {
		let hash = match &event {
			crate::events::Event::PaymentPathFailed { payment_hash, .. } => *payment_hash,
			crate::events::Event::PaymentFailed { payment_hash: Some(payment_hash), .. } => {
				*payment_hash
			},
			_ => panic!("Unexpected event {event:?}"),
		};
		let index = if hash == voucher.payment_hash {
			0
		} else {
			assert_eq!(hash, extra.payment_hash);
			1
		};
		failures[index].push(event);
	}
	for (events, hash) in failures.into_iter().zip([voucher.payment_hash, extra.payment_hash]) {
		expect_payment_failed_conditions_event(events, hash, false, PaymentFailedConditions::new());
	}
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn ffor_quiescence_disconnect_timeout_and_restart_abort_and_drain() {
	for recovery in 0..3 {
		for completed in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let (persister, chain_monitor);
			let config = anchor_config();
			let node_chanmgrs =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
			let reloaded;
			let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
			let sender_id = nodes[0].node.get_our_node_id();
			let receiver_id = nodes[1].node.get_our_node_id();
			let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
			register_signed(&nodes[0], &nodes[1], channel_id, voucher);
			deliver_parked_voucher(&nodes[0], &nodes[1], update);
			request(&nodes[0], &nodes[1], channel_id).unwrap();
			if completed {
				complete_handshake(&nodes[0], &nodes[1]);
			} else {
				let _undelivered = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, sender_id);
			}
			if recovery == 1 {
				for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
					nodes[1].node.timer_tick_occurred();
				}
				expect_disconnect(&nodes[1]);
			}
			nodes[0].node.peer_disconnected(receiver_id);
			if recovery == 2 {
				let monitor_encoded = get_monitor!(nodes[1], channel_id).encode();
				let manager_encoded = nodes[1].node.encode();
				reload_node!(
					nodes[1],
					config,
					&manager_encoded,
					&[&monitor_encoded],
					persister,
					chain_monitor,
					reloaded
				);
			} else {
				nodes[1].node.peer_disconnected(sender_id);
			}
			pump_ffor_reconnection(&nodes[0], &nodes[1]);
			assert!(status(&nodes[0], &nodes[1], channel_id).is_err());
			assert_eq!(
				receiver_status(&nodes[1], &nodes[0], channel_id),
				FFORReceiverStatus::Aborted {
					reason: if recovery == 2 {
						FFORReceiverAbortReason::Restarted
					} else {
						FFORReceiverAbortReason::Disconnected
					},
				}
			);
			expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
			send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		}
	}
}

#[test]
fn ffor_quiescence_rechecks_deadline_and_same_book_after_fee_round() {
	for change in 0..3 {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let sender_id = nodes[0].node.get_our_node_id();
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		register_signed(&nodes[0], &nodes[1], channel_id, voucher);
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		if change != 0 {
			request(&nodes[0], &nodes[1], channel_id).unwrap();
		}
		if change < 2 {
			let deadline = voucher.cltv_expiry - 20;
			let blocks = deadline - nodes[1].node.current_best_block().height;
			connect_blocks(&nodes[1], blocks);
			assert_eq!(nodes[1].node.current_best_block().height, deadline);
		} else {
			// This stock fee round is legal before the sender has received our STFU. It keeps
			// the exact vouchers but invalidates the retained commitment and monitor proof.
			*chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap() += 20;
			nodes[0].node.timer_tick_occurred();
			check_added_monitors(&nodes[0], 1);
			let update = get_htlc_update_msgs!(&nodes[0], nodes[1].node.get_our_node_id());
			nodes[1].node.handle_update_fee(sender_id, update.update_fee.as_ref().unwrap());
			// Consume the pending request before the commitment dance inspects outgoing messages.
			let proposed = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, sender_id);
			commitment_signed_dance!(&nodes[1], &nodes[0], update.commitment_signed, false);
			assert!(matches!(
				receiver_status(&nodes[1], &nodes[0], channel_id),
				FFORReceiverStatus::Parked { .. }
			));
			nodes[0].node.handle_stfu(nodes[1].node.get_our_node_id(), &proposed);
			let response = get_event_msg!(
				&nodes[0],
				MessageSendEvent::SendStfu,
				nodes[1].node.get_our_node_id()
			);
			nodes[1].node.handle_stfu(sender_id, &response);
		}
		if change == 0 {
			assert!(request(&nodes[0], &nodes[1], channel_id).is_err());
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			nodes[1].node.abort_ffor_receiver_book(&channel_id, &sender_id, EPOCH).unwrap();
			drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
		} else {
			if change == 1 {
				complete_handshake(&nodes[0], &nodes[1]);
			}
			expect_disconnect(&nodes[1]);
			nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
			nodes[1].node.peer_disconnected(sender_id);
			pump_ffor_reconnection(&nodes[0], &nodes[1]);
			assert_eq!(
				receiver_status(&nodes[1], &nodes[0], channel_id),
				FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::QuiescenceFailed }
			);
			expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
		}
	}
}

#[test]
fn ffor_quiescence_losing_initiator_tie_aborts_and_pending_abort_drains() {
	for tie in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let sender_id = nodes[0].node.get_our_node_id();
		let receiver_id = nodes[1].node.get_our_node_id();
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		register_signed(&nodes[0], &nodes[1], channel_id, voucher);
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		request(&nodes[0], &nodes[1], channel_id).unwrap();
		let proposed = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, sender_id);
		if tie {
			nodes[0].node.maybe_propose_quiescence(&receiver_id, &channel_id).unwrap();
			let competing = get_event_msg!(&nodes[0], MessageSendEvent::SendStfu, receiver_id);
			assert!(competing.initiator && proposed.initiator);
			nodes[0].node.handle_stfu(receiver_id, &proposed);
			nodes[1].node.handle_stfu(sender_id, &competing);
		} else {
			nodes[1].node.abort_ffor_receiver_book(&channel_id, &sender_id, EPOCH).unwrap();
		}
		expect_disconnect(&nodes[1]);
		nodes[0].node.peer_disconnected(receiver_id);
		nodes[1].node.peer_disconnected(sender_id);
		pump_ffor_reconnection(&nodes[0], &nodes[1]);
		assert_eq!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Aborted {
				reason: if tie {
					FFORReceiverAbortReason::QuiescenceFailed
				} else {
					FFORReceiverAbortReason::Requested
				}
			}
		);
		expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_quiescence_preserves_force_close() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_signed(&nodes[0], &nodes[1], channel_id, voucher);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	request(&nodes[0], &nodes[1], channel_id).unwrap();
	complete_handshake(&nodes[0], &nodes[1]);
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			"quiescence force close test".into(),
		)
		.unwrap();
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[1]
		.node
		.get_and_clear_pending_events()
		.iter()
		.any(|event| matches!(event, crate::events::Event::ChannelClosed { .. })));
	handle_bump_close_event(&nodes[1]);
	assert!(!nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	nodes[1].node.get_and_clear_pending_msg_events();
	check_added_monitors(&nodes[1], 1);
}
