use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channel::ffor_setup_test_messages;
use crate::ln::channelmanager::ffor_recovery_tests::claim_ffor_preimage_for_test;
use crate::ln::ffor::FFORReceiverAbortReason;
use crate::ln::ffor_tests::quiescence::{complete_handshake, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;

const EPOCH: [u8; 32] = [81; 32];

fn persist(node: &Node) -> Vec<u8> {
	let token = node.node.capture_ffor_persistence();
	let encoded = node.node.encode();
	node.node.ffor_persistence_completed(token).unwrap();
	encoded
}

fn sign(message: &mut FFORMessage, node: &Node) {
	message.signature = node
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
}

/// Reserve two actual outgoing payment hashes before delivering either voucher to the receiver.
pub(super) fn park_two(
	sender: &Node, receiver: &Node, id: ChannelId,
) -> ([FFORVoucher; 2], PaymentPreimage) {
	park_two_with_witnesses(sender, receiver, id, None)
}

pub(super) fn park_two_with_witnesses(
	sender: &Node, receiver: &Node, id: ChannelId, witnesses: Option<Vec<PublicKey>>,
) -> ([FFORVoucher; 2], PaymentPreimage) {
	let preimage = PaymentPreimage([*receiver.network_payment_count.as_ref().borrow(); 32]);
	let (first, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let (mut route, hash, _, secret) = get_route_and_payment_hash!(sender, receiver, 2_000_000);
	route.paths[0].hops[0].cltv_expiry_delta = 144;
	let second_voucher =
		FFORVoucher { htlc_id: voucher.htlc_id + 1, payment_hash: hash, ..voucher };
	let (mut init, mut accept) = ffor_setup_test_messages(sender, receiver, id, voucher);
	if let Payload::Init(terms) = &mut init.payload {
		terms.witness_peers = witnesses;
		terms.budget_msat += second_voucher.amount_msat;
		terms.amounts_msat.push(second_voucher.amount_msat);
	} else {
		unreachable!();
	}
	sign(&mut init, receiver);
	if let Payload::Accept(accepted) = &mut accept.payload {
		accepted.payment_hashes.push(second_voucher.payment_hash.0);
		accepted.amounts_msat.push(second_voucher.amount_msat);
		accepted.init_hash = transcript::init_hash(&init.encode().unwrap());
	} else {
		unreachable!();
	}
	sign(&mut accept, sender);
	receiver
		.node
		.register_ffor_receiver_setup(
			&id,
			&sender.node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		)
		.unwrap();
	persist(receiver);
	deliver_parked_voucher(sender, receiver, first);
	sender
		.node
		.send_payment_with_route(
			route,
			hash,
			RecipientOnionFields::secret_only(secret),
			PaymentId(hash.0),
		)
		.unwrap();
	check_added_monitors(sender, 1);
	let second = get_htlc_update_msgs!(sender, receiver.node.get_our_node_id());
	assert_eq!(second.update_add_htlcs.len(), 1);
	assert_eq!(second.update_add_htlcs[0].htlc_id, second_voucher.htlc_id);
	assert_eq!(second.update_add_htlcs[0].cltv_expiry, second_voucher.cltv_expiry);
	deliver_parked_voucher(sender, receiver, second);
	request(sender, receiver, id).unwrap();
	complete_handshake(sender, receiver);
	let snapshot = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
	receiver
		.node
		.prepare_ffor_receiver_activation(&id, &sender.node.get_our_node_id(), EPOCH, &snapshot)
		.unwrap();
	persist(receiver);
	([voucher, second_voucher], preimage)
}

fn phase(sender: &Node, receiver: &Node, id: ChannelId) -> Option<FFORReceiverFencePhase> {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	peer.channel_by_id
		.get(&id)
		.unwrap()
		.as_funded()
		.unwrap()
		.ffor_receiver_fence()
		.map(|(phase, _)| phase)
}

fn assert_no_update_wire(node: &Node) {
	for event in node.node.get_and_clear_pending_msg_events() {
		assert!(
			matches!(
				event,
				MessageSendEvent::SendChannelUpdate { .. }
					| MessageSendEvent::BroadcastChannelUpdate { .. }
			),
			"premature wire: {event:?}"
		);
	}
}

/// Complete native commitment and revoke rounds, recording the actual terminal wire for every HTLC.
pub(super) fn drain<'a, 'b, 'c>(
	sender: &Node<'a, 'b, 'c>, receiver: &Node<'a, 'b, 'c>,
) -> (Vec<u64>, Vec<u64>) {
	let mut fulfilled = Vec::new();
	let mut failed = Vec::new();
	for _ in 0..30 {
		let mut progressed = false;
		for (from, to) in [(sender, receiver), (receiver, sender)] {
			for event in from.node.get_and_clear_pending_msg_events() {
				progressed = true;
				let from_id = from.node.get_our_node_id();
				match event {
					MessageSendEvent::SendChannelReestablish { msg, .. } => {
						to.node.handle_channel_reestablish(from_id, &msg)
					},
					MessageSendEvent::SendChannelReady { msg, .. } => {
						to.node.handle_channel_ready(from_id, &msg)
					},
					MessageSendEvent::SendRevokeAndACK { msg, .. } => {
						to.node.handle_revoke_and_ack(from_id, &msg)
					},
					MessageSendEvent::SendAnnouncementSignatures { msg, .. } => {
						to.node.handle_announcement_signatures(from_id, &msg)
					},
					MessageSendEvent::UpdateHTLCs { updates, .. } => {
						assert!(updates.update_add_htlcs.is_empty());
						assert!(updates.update_fee.is_none());
						for msg in updates.update_fulfill_htlcs {
							assert_eq!(from_id, receiver.node.get_our_node_id());
							fulfilled.push(msg.htlc_id);
							to.node.handle_update_fulfill_htlc(from_id, msg);
						}
						for msg in updates.update_fail_htlcs {
							assert_eq!(from_id, receiver.node.get_our_node_id());
							failed.push(msg.htlc_id);
							to.node.handle_update_fail_htlc(from_id, &msg);
						}
						for msg in updates.update_fail_malformed_htlcs {
							assert_eq!(from_id, receiver.node.get_our_node_id());
							failed.push(msg.htlc_id);
							to.node.handle_update_fail_malformed_htlc(from_id, &msg);
						}
						to.node.handle_commitment_signed_batch_test(
							from_id,
							&updates.commitment_signed,
						);
					},
					MessageSendEvent::BroadcastChannelAnnouncement { .. }
					| MessageSendEvent::BroadcastChannelUpdate { .. }
					| MessageSendEvent::SendChannelUpdate { .. } => {},
					other => panic!("unexpected drain wire: {other:?}"),
				}
			}
			if from.node.needs_pending_htlc_processing() {
				from.node.process_pending_htlc_forwards();
				progressed = true;
			}
			from.chain_monitor.added_monitors.lock().unwrap().clear();
		}
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
		if !progressed {
			return (fulfilled, failed);
		}
	}
	panic!("ordinary voucher drain failed to converge");
}

#[test]
fn ffor_activation_manager_abort_drains_mixed_preimages_and_reloads_for_ordinary_payment() {
	for receiver_funds in [false, true] {
		for (learn_preimage, delay_monitor, restart_before_drain) in
			[(false, false, false), (true, false, false), (true, true, false), (true, false, true)]
		{
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let (persister, chain_monitor);
			let (abort_persister, abort_chain_monitor, abort_manager);
			let config = anchor_config();
			let managers =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
			let reloaded;
			let mut nodes = create_network(2, &node_cfgs, &managers);
			let (funder, peer_index) = if receiver_funds { (1, 0) } else { (0, 1) };
			let id = create_announced_chan_between_nodes_with_value(
				&nodes, funder, peer_index, 100_000, 40_000_000,
			)
			.2;
			let (vouchers, preimage) = park_two(&nodes[0], &nodes[1], id);
			let peer = nodes[0].node.get_our_node_id();
			let receiver_id = nodes[1].node.get_our_node_id();
			let preimage_update = if learn_preimage {
				if delay_monitor {
					chanmon_cfgs[1]
						.persister
						.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
				}
				let update = claim_ffor_preimage_for_test(
					&nodes[0],
					&nodes[1],
					id,
					vouchers[0].htlc_id,
					preimage,
				);
				check_added_monitors(&nodes[1], 1);
				assert_eq!(
					get_monitor!(nodes[1], id).get_stored_preimages()[&vouchers[0].payment_hash].0,
					preimage
				);
				Some(update)
			} else {
				None
			};
			assert_no_update_wire(&nodes[1]);
			nodes[0].node.peer_disconnected(receiver_id);
			nodes[1].node.peer_disconnected(peer);
			connect_nodes(&nodes[0], &nodes[1]);
			let receiver_report =
				get_event_msg!(&nodes[1], MessageSendEvent::SendChannelReestablish, peer);
			let sender_report =
				get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReestablish, receiver_id);
			assert!(sender_report.ffor_reestablish.is_none());
			nodes[0].node.handle_channel_reestablish(receiver_id, &receiver_report);
			nodes[1].node.handle_channel_reestablish(peer, &sender_report);
			assert_eq!(phase(&nodes[0], &nodes[1], id), Some(FFORReceiverFencePhase::Aborting));
			assert!(!nodes[1]
				.node
				.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH)
				.unwrap());
			assert_no_update_wire(&nodes[1]);
			check_added_monitors(&nodes[1], 0);
			persist(&nodes[1]);
			assert!(nodes[1]
				.node
				.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH)
				.unwrap());
			assert_eq!(phase(&nodes[0], &nodes[1], id), None);
			if delay_monitor {
				assert_no_update_wire(&nodes[1]);
				check_added_monitors(&nodes[1], 0);
				chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
				nodes[1]
					.chain_monitor
					.chain_monitor
					.channel_monitor_updated(id, preimage_update.unwrap())
					.unwrap();
			}
			if restart_before_drain {
				// The claimed voucher remains in the holding cell when the abort fence is released.
				// Restore that state before any fulfill or failure commitment has been generated.
				let released = persist(&nodes[1]);
				let monitor = get_monitor!(nodes[1], id).encode();
				nodes[0].node.peer_disconnected(receiver_id);
				reload_node!(
					nodes[1],
					config.clone(),
					&released,
					&[&monitor],
					abort_persister,
					abort_chain_monitor,
					abort_manager
				);
				persist(&nodes[1]);
				connect_nodes(&nodes[0], &nodes[1]);
			}
			let (fulfilled, failed) = drain(&nodes[0], &nodes[1]);
			assert_eq!(
				fulfilled,
				if learn_preimage { vec![vouchers[0].htlc_id] } else { Vec::new() }
			);
			let expected_failed: Vec<_> = vouchers
				.iter()
				.skip(if learn_preimage { 1 } else { 0 })
				.map(|v| v.htlc_id)
				.collect();
			assert_eq!(failed, expected_failed);
			let mut sent = Vec::new();
			let mut failed_hashes = Vec::new();
			for event in nodes[0].node.get_and_clear_pending_events() {
				match event {
					Event::PaymentSent { payment_hash, payment_preimage, .. } => {
						assert_eq!(payment_preimage, preimage);
						sent.push(payment_hash);
					},
					Event::PaymentFailed { payment_hash, .. } => {
						failed_hashes.push(payment_hash.unwrap())
					},
					Event::PaymentPathSuccessful { .. } | Event::PaymentPathFailed { .. } => {},
					other => panic!("unexpected sender event: {other:?}"),
				}
			}
			assert_eq!(
				sent,
				if learn_preimage { vec![vouchers[0].payment_hash] } else { Vec::new() }
			);
			assert_eq!(failed_hashes.len(), expected_failed.len());
			for voucher in vouchers.iter().skip(if learn_preimage { 1 } else { 0 }) {
				assert!(failed_hashes.contains(&voucher.payment_hash));
			}
			for node in &nodes {
				let channels = node.node.list_channels();
				assert_eq!(channels.len(), 1);
				assert!(channels[0].pending_inbound_htlcs.is_empty());
				assert!(channels[0].pending_outbound_htlcs.is_empty());
				node.chain_monitor.added_monitors.lock().unwrap().clear();
			}
			let snapshot = get_monitor!(nodes[1], id).ffor_commitment_snapshot().unwrap();
			assert_eq!(
				nodes[1].node.ffor_receiver_book_status(&id, &peer, &snapshot).unwrap(),
				FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::Disconnected }
			);
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
			connect_nodes(&nodes[0], &nodes[1]);
			assert_eq!(drain(&nodes[0], &nodes[1]), (Vec::new(), Vec::new()));
			assert_eq!(phase(&nodes[0], &nodes[1], id), None);
			send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		}
	}
}
