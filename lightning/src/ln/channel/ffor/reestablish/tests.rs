use super::*;
use crate::ln::channelmanager::ffor_recovery_tests::install_ffor_activation_for_test;
use crate::ln::ffor_tests::quiescence::{complete_handshake, register_signed, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, MessageSendEvent};
use crate::util::ser::{ReadableArgs, Writeable};

fn with_channel<'a, 'b, 'c, T>(
	receiver: &Node<'a, 'b, 'c>, sender: &Node, id: ChannelId,
	body: impl FnOnce(&mut FundedChannel<&'b crate::util::test_utils::TestKeysInterface>) -> T,
) -> T {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	body(peer.channel_by_id.get_mut(&id).unwrap().as_funded_mut().unwrap())
}

fn prepare(
	sender: &Node, receiver: &Node, id: ChannelId, phase: FFORReceiverFencePhase,
) -> [u8; 32] {
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	register_signed(sender, receiver, id, voucher);
	deliver_parked_voucher(sender, receiver, update);
	request(sender, receiver, id).unwrap();
	complete_handshake(sender, receiver);
	install_ffor_activation_for_test(sender, receiver, id, phase)
}

fn assert_no_wire(response: ReestablishResponses) {
	assert!(response.channel_ready.is_none());
	assert!(response.raa.is_none());
	assert!(response.commitment_update.is_none());
	assert!(response.announcement_sigs.is_none());
	assert!(response.shutdown_msg.is_none());
	assert!(response.tx_signatures.is_none());
	assert!(response.tx_abort.is_none());
	assert!(response.inferred_splice_locked.is_none());
}

fn handle<SP: Deref>(
	channel: &mut FundedChannel<SP>, receiver: &Node, message: &msgs::ChannelReestablish,
) -> Result<ReestablishResponses, ChannelError>
where
	SP::Target: SignerProvider,
{
	channel.channel_reestablish(
		message,
		&receiver.logger,
		&receiver.keys_manager,
		ChainHash::using_genesis_block(bitcoin::Network::Testnet),
		&anchor_config(),
		&receiver.node.current_best_block(),
		|_| unreachable!(),
	)
}

#[test]
fn ffor_reestablish_reports_both_phases_and_funders_without_ordinary_retransmission() {
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		for receiver_funds in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let config = anchor_config();
			let node_chanmgrs =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
			let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let id =
				create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
			let (sender, receiver) =
				if receiver_funds { (&nodes[1], &nodes[0]) } else { (&nodes[0], &nodes[1]) };
			let hash = prepare(sender, receiver, id, phase);
			let commitments = with_channel(receiver, sender, id, |channel| {
				channel.ffor_frozen_commitments(&receiver.logger).unwrap()
			});
			sender.node.peer_disconnected(receiver.node.get_our_node_id());
			receiver.node.peer_disconnected(sender.node.get_our_node_id());
			let mut peer_message = with_channel(sender, receiver, id, |channel| {
				channel.get_channel_reestablish(&sender.logger).unwrap()
			});
			let peer_report = Reestablish {
				epoch_id: [81; 32],
				state: ReportedState::Active,
				activation_hash: hash,
			};
			peer_message.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(peer_report));
			receiver
				.node
				.peer_connected(
					sender.node.get_our_node_id(),
					&msgs::Init {
						features: sender.node.init_features(),
						networks: None,
						remote_network_address: None,
					},
					true,
				)
				.unwrap();
			let report = get_event_msg!(
				receiver,
				MessageSendEvent::SendChannelReestablish,
				sender.node.get_our_node_id()
			);
			with_channel(receiver, sender, id, |channel| {
				assert_eq!(
					report.next_local_commitment_number,
					peer_message.next_remote_commitment_number + 1
				);
				assert_eq!(
					report.next_remote_commitment_number + 1,
					peer_message.next_local_commitment_number
				);
				assert_eq!(
					report.ffor_reestablish.unwrap().report(),
					Reestablish {
						epoch_id: [81; 32],
						state: if phase == FFORReceiverFencePhase::Active {
							ReportedState::Active
						} else {
							ReportedState::Activating
						},
						activation_hash: if phase == FFORReceiverFencePhase::Active {
							hash
						} else {
							[0; 32]
						},
					}
				);
				assert_no_wire(handle(channel, receiver, &peer_message).unwrap());
				assert_eq!(
					channel.ffor_receiver_reconnect_outcome(),
					Some(&FFORReestablishOutcome::MatchingActive { peer_report })
				);
				assert_eq!(channel.ffor_receiver_fence(), Some((phase, hash)));
				assert_eq!(channel.ffor_frozen_commitments(&receiver.logger).unwrap(), commitments);
				assert!(!channel.context.channel_state.is_peer_disconnected());
				let encoded = channel.encode();
				let features = crate::ln::channelmanager::provided_channel_type_features(&config);
				let restored = FundedChannel::read(
					&mut &encoded[..],
					(&receiver.keys_manager, &receiver.keys_manager, &features),
				)
				.unwrap();
				assert!(restored.ffor_receiver_reconnect_outcome().is_none());
				assert_eq!(restored.ffor_receiver_fence(), Some((phase, hash)));
			});
			// A reconnect observation cannot survive connection loss or become a durable ACK.
			receiver.node.peer_disconnected(sender.node.get_our_node_id());
			with_channel(receiver, sender, id, |channel| {
				assert!(channel.ffor_receiver_reconnect_outcome().is_none())
			});
			assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
			assert!(receiver.node.get_and_clear_pending_events().is_empty());
			check_added_monitors(receiver, 0);
		}
	}
}

#[test]
fn ffor_reestablish_missing_conflicting_and_aborting_reports_retain_fence() {
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let hash = prepare(sender, receiver, id, phase);
		sender.node.peer_disconnected(receiver.node.get_our_node_id());
		receiver.node.peer_disconnected(sender.node.get_our_node_id());
		let original = with_channel(sender, receiver, id, |channel| {
			channel.get_channel_reestablish(&sender.logger).unwrap()
		});
		let bytes = with_channel(receiver, sender, id, |channel| channel.encode());
		let features = crate::ln::channelmanager::provided_channel_type_features(&config);
		let read = || {
			FundedChannel::read(
				&mut &bytes[..],
				(&receiver.keys_manager, &receiver.keys_manager, &features),
			)
			.unwrap()
		};
		let mut reports = vec![None];
		for state in [
			ReportedState::Negotiating,
			ReportedState::VouchersCommitted,
			ReportedState::Activating,
			ReportedState::Aborted,
			ReportedState::Active,
			ReportedState::Draining,
			ReportedState::Closed,
		] {
			for epoch_id in [[81; 32], [99; 32]] {
				reports.push(Some(Reestablish { epoch_id, state, activation_hash: [99; 32] }));
			}
		}
		for peer_report in reports {
			let mut channel = read();
			let before = channel.ffor_frozen_commitments(&receiver.logger).unwrap();
			let mut message = original.clone();
			message.ffor_reestablish = peer_report.map(msgs::FFORChannelReestablish::new);
			assert_no_wire(handle(&mut channel, receiver, &message).unwrap());
			let pre_active = peer_report.map_or(true, |r| {
				matches!(
					r.state,
					ReportedState::Negotiating
						| ReportedState::VouchersCommitted
						| ReportedState::Activating
						| ReportedState::Aborted
				)
			});
			let expected = if phase == FFORReceiverFencePhase::Activating && pre_active {
				FFORReestablishOutcome::AbortRequired { peer_report }
			} else {
				FFORReestablishOutcome::ResolutionRequired { peer_report }
			};
			assert_eq!(channel.ffor_receiver_reconnect_outcome(), Some(&expected));
			assert_eq!(channel.ffor_receiver_fence(), Some((phase, hash)));
			assert_eq!(channel.ffor_frozen_commitments(&receiver.logger).unwrap(), before);
			assert!(channel.context.ffor_receiver_book.as_ref().unwrap().abort_reason.is_none());
		}
		// A pending durable abort still keeps the exact commitment pair and emits zero H_act.
		let mut channel = read();
		let book = channel.context.ffor_receiver_book.as_mut().unwrap();
		book.fence.as_mut().unwrap().phase = FFORReceiverFencePhase::Aborting;
		book.abort_reason = Some(crate::ln::ffor::FFORReceiverAbortReason::Disconnected);
		let message = channel.get_channel_reestablish(&receiver.logger).unwrap();
		assert_eq!(
			message.ffor_reestablish.unwrap().report(),
			Reestablish {
				epoch_id: [81; 32],
				state: ReportedState::Aborted,
				activation_hash: [0; 32],
			}
		);
		assert_no_wire(handle(&mut channel, receiver, &original).unwrap());
		assert_eq!(
			channel.ffor_receiver_reconnect_outcome(),
			Some(&FFORReestablishOutcome::AbortRequired { peer_report: None })
		);
		assert_eq!(channel.ffor_receiver_fence(), Some((FFORReceiverFencePhase::Aborting, hash)));
	}
}

#[test]
fn ffor_reestablish_keeps_stock_counter_secret_and_data_loss_protection() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	// Advance history enough to exercise a valid but very old revocation counter.
	send_payment(sender, &[receiver], 1_000_000);
	prepare(sender, receiver, id, FFORReceiverFencePhase::Active);
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	let original = with_channel(sender, receiver, id, |channel| {
		channel.get_channel_reestablish(&sender.logger).unwrap()
	});
	let bytes = with_channel(receiver, sender, id, |channel| channel.encode());
	let features = crate::ln::channelmanager::provided_channel_type_features(&config);
	let read = || {
		FundedChannel::read(
			&mut &bytes[..],
			(&receiver.keys_manager, &receiver.keys_manager, &features),
		)
		.unwrap()
	};
	for fault in 0..11 {
		let mut channel = read();
		let mut message = original.clone();
		match fault {
			0 => message.next_local_commitment_number = 0,
			1 => message.next_local_commitment_number = INITIAL_COMMITMENT_NUMBER,
			2 => message.next_remote_commitment_number = INITIAL_COMMITMENT_NUMBER,
			3 => message.your_last_per_commitment_secret = [0; 32],
			4 => message.your_last_per_commitment_secret = [42; 32],
			5 => message.next_local_commitment_number += 1,
			6 => message.next_local_commitment_number -= 1,
			7 => {
				message.next_remote_commitment_number -= 1;
				message.your_last_per_commitment_secret = channel
					.context
					.holder_signer
					.as_ecdsa()
					.unwrap()
					.inner
					.release_commitment_secret(
						INITIAL_COMMITMENT_NUMBER - message.next_remote_commitment_number + 1,
					)
					.unwrap();
			},
			8 => {
				message.next_remote_commitment_number = 0;
				message.your_last_per_commitment_secret = [0; 32];
			},
			9 => {
				message.next_funding = Some(msgs::NextFunding {
					txid: bitcoin::Txid::from_byte_array([42; 32]),
					retransmit_flags: 0,
				})
			},
			10 => {
				message.my_current_funding_locked = Some(msgs::FundingLocked {
					txid: bitcoin::Txid::from_byte_array([42; 32]),
					retransmit_flags: 0,
				})
			},
			_ => unreachable!(),
		}
		let before = channel.encode();
		let result = handle(&mut channel, receiver, &message);
		match (fault, result) {
			(0..=5, Err(ChannelError::Close(_))) => {},
			(6..=7 | 9..=10, Err(ChannelError::WarnAndDisconnect(_))) => {},
			(8, Err(ChannelError::Warn(_))) => {},
			_ => panic!("unexpected rejection for fault {fault}"),
		}
		assert_eq!(channel.encode(), before);
		assert!(channel.ffor_receiver_reconnect_outcome().is_none());
	}
	for fault in 0..3 {
		let mut channel = read();
		match fault {
			0 => channel.context.signer_pending_commitment_update = true,
			1 => channel.context.pending_inbound_htlcs[0].amount_msat += 1000,
			2 => {
				channel.context.pending_inbound_htlcs[0].state = InboundHTLCState::LocalRemoved(
					InboundHTLCRemovalReason::FailMalformed(([0; 32], 0x8004)),
				)
			},
			_ => unreachable!(),
		}
		assert!(channel.get_channel_reestablish(&receiver.logger).is_err());
		assert!(matches!(
			handle(&mut channel, receiver, &original),
			Err(ChannelError::WarnAndDisconnect(_))
		));
		assert!(channel.ffor_receiver_reconnect_outcome().is_none());
	}
	// A valid proof that our stored state was revoked preserves the stock fatal safety guard.
	let mut channel = read();
	let mut message = original;
	message.next_remote_commitment_number += 1;
	message.your_last_per_commitment_secret = channel
		.context
		.holder_signer
		.as_ecdsa()
		.unwrap()
		.inner
		.release_commitment_secret(
			INITIAL_COMMITMENT_NUMBER - message.next_remote_commitment_number + 1,
		)
		.unwrap();
	let before = channel.encode();
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		handle(&mut channel, receiver, &message)
	}));
	let panic = result.err().expect("A proven revoked local state must not continue");
	let message = panic
		.downcast_ref::<&str>()
		.copied()
		.or_else(|| panic.downcast_ref::<String>().map(String::as_str))
		.unwrap();
	assert!(message.contains("We have fallen behind"));
	assert_eq!(channel.encode(), before);
	assert!(channel.ffor_receiver_reconnect_outcome().is_none());
}
