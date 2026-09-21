use super::*;
use crate::ln::channelmanager::ffor_recovery_tests::install_ffor_activation_for_test;
use crate::ln::ffor_tests::quiescence::{complete_handshake, register_signed, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, MessageSendEvent};
use crate::util::ser::Writeable;

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
) -> (msgs::CommitmentUpdate, FFORVoucher) {
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	register_signed(sender, receiver, id, voucher);
	deliver_parked_voucher(sender, receiver, update.clone());
	request(sender, receiver, id).unwrap();
	complete_handshake(sender, receiver);
	let activation_hash = install_ffor_activation_for_test(sender, receiver, id, phase);
	with_channel(receiver, sender, id, |channel| {
		// Deliberately remove stock STFU flags. The durable fence must stand independently.
		assert!(channel.exit_quiescence());
		assert_eq!(channel.ffor_receiver_fence(), Some((phase, activation_hash)));
	});
	(update, voucher)
}

fn expect_fenced<T>(result: Result<T, ChannelError>) {
	match result {
		Err(ChannelError::WarnAndDisconnect(message)) => assert_eq!(message, FFOR_FROZEN_MESSAGE),
		_ => panic!("Ordinary mutation did not hit the FFOR fence"),
	}
}

#[test]
fn ffor_fence_rejects_ordinary_mutations_without_stock_quiescence() {
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		for receiver_funds in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let config = anchor_config();
			let node_chanmgrs =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
			let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let id =
				create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
			let (sender, receiver) =
				if receiver_funds { (&nodes[1], &nodes[0]) } else { (&nodes[0], &nodes[1]) };
			let (update, voucher) = prepare(sender, receiver, id, phase);
			let fee = LowerBoundedFeeEstimator::new(receiver.fee_estimator);
			with_channel(receiver, sender, id, |channel| {
				let before = channel.encode();
				expect_fenced(channel.update_add_htlc(&update.update_add_htlcs[0], &fee));
				expect_fenced(channel.update_fulfill_htlc(&msgs::UpdateFulfillHTLC {
					channel_id: id,
					htlc_id: voucher.htlc_id,
					payment_preimage: PaymentPreimage([0; 32]),
					attribution_data: None,
				}));
				let reason = || {
					HTLCFailReason::from_failure_code(LocalHTLCFailureReason::TemporaryNodeFailure)
				};
				expect_fenced(channel.update_fail_htlc(
					&msgs::UpdateFailHTLC {
						channel_id: id,
						htlc_id: voucher.htlc_id,
						reason: Vec::new(),
						attribution_data: None,
					},
					reason(),
				));
				expect_fenced(channel.update_fail_malformed_htlc(
					&msgs::UpdateFailMalformedHTLC {
						channel_id: id,
						htlc_id: voucher.htlc_id,
						sha256_of_onion: [0; 32],
						failure_code: 0x8004,
					},
					reason(),
				));
				expect_fenced(channel.update_fee(
					&fee,
					&msgs::UpdateFee { channel_id: id, feerate_per_kw: 500 },
					&receiver.logger,
				));
				expect_fenced(channel.commitment_signed(
					&update.commitment_signed[0],
					&fee,
					&receiver.logger,
				));
				expect_fenced(channel.commitment_signed_batch(
					update.commitment_signed.clone(),
					&fee,
					&receiver.logger,
				));
				expect_fenced(channel.revoke_and_ack(
					&msgs::RevokeAndACK {
						channel_id: id,
						per_commitment_secret: [0; 32],
						next_per_commitment_point: sender.node.get_our_node_id(),
						#[cfg(taproot)]
						next_local_nonce: None,
						release_htlc_message_paths: Vec::new(),
					},
					&fee,
					&receiver.logger,
					false,
				));
				assert!(channel
					.send_htlc_and_commit(
						1_000_000,
						PaymentHash([7; 32]),
						voucher.cltv_expiry,
						HTLCSource::dummy(),
						update.update_add_htlcs[0].onion_routing_packet.clone(),
						None,
						false,
						&fee,
						&receiver.logger
					)
					.is_err());
				assert!(channel
					.queue_fail_htlc(
						voucher.htlc_id,
						msgs::OnionErrorPacket { data: Vec::new(), attribution_data: None },
						&receiver.logger
					)
					.is_err());
				assert!(channel
					.queue_fail_malformed_htlc(voucher.htlc_id, 0x8004, [0; 32], &receiver.logger)
					.is_err());
				channel.queue_update_fee(500, &fee, &receiver.logger);
				assert!(channel.maybe_free_holding_cell_htlcs(&fee, &receiver.logger).0.is_none());
				assert!(channel.free_holding_cell_htlcs(&fee, &receiver.logger).0.is_none());
				expect_fenced(channel.build_commitment_no_status_check(&receiver.logger));
				expect_fenced(channel.send_commitment_no_state_update_for_funding(
					&channel.funding,
					&receiver.logger,
				));
				assert!(channel.get_last_commitment_update_for_send(&receiver.logger).is_err());
				assert!(channel
					.get_last_revoke_and_ack(|_| unreachable!(), &receiver.logger)
					.is_none());
				assert!(channel.get_channel_reestablish(&receiver.logger).is_err());
				expect_fenced(
					channel.stfu(&msgs::Stfu { channel_id: id, initiator: true }, &receiver.logger),
				);
				assert!(channel
					.propose_quiescence(&receiver.logger, QuiescentAction::DoNothing)
					.is_err());
				expect_fenced(channel.validate_splice_init(
					&msgs::SpliceInit {
						channel_id: id,
						funding_contribution_satoshis: 1000,
						funding_feerate_per_kw: 500,
						locktime: 0,
						funding_pubkey: sender.node.get_our_node_id(),
						require_confirmed_inputs: None,
					},
					SignedAmount::ZERO,
				));
				expect_fenced(channel.shutdown(
					&receiver.keys_manager,
					&sender.node.init_features(),
					&msgs::Shutdown { channel_id: id, scriptpubkey: ScriptBuf::new() },
				));
				expect_fenced(channel.closing_signed(
					&fee,
					&msgs::ClosingSigned {
						channel_id: id,
						fee_satoshis: 100,
						signature: update.commitment_signed[0].signature,
						fee_range: None,
					},
					&receiver.logger,
				));
				assert!(channel
					.get_shutdown(&receiver.keys_manager, &sender.node.init_features(), None, None)
					.is_err());
				assert!(channel.abort_ffor_receiver_book([81; 32]).is_err());
				channel.ffor_queue_aborted_vouchers(&receiver.logger);
				assert_eq!(channel.encode(), before);
			});
			check_added_monitors(receiver, 0);
			assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
			assert!(receiver.node.get_and_clear_pending_events().is_empty());
			if receiver_funds {
				*receiver.fee_estimator.sat_per_kw.lock().unwrap() += 20;
				receiver.node.timer_tick_occurred();
				check_added_monitors(receiver, 0);
				assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
			}
		}
	}
}

fn expect_no_released_updates(updates: MonitorRestoreUpdates) {
	assert!(updates.raa.is_none());
	assert!(updates.commitment_update.is_none());
	assert!(updates.accepted_htlcs.is_empty());
	assert!(updates.failed_htlcs.is_empty());
	assert!(updates.finalized_claimed_htlcs.is_empty());
	assert!(updates.pending_update_adds.is_empty());
	assert!(updates.funding_broadcastable.is_none());
	assert!(updates.channel_ready.is_none());
	assert!(updates.announcement_sigs.is_none());
	assert!(updates.tx_signatures.is_none());
}

#[test]
fn ffor_fence_preserves_preimage_and_limits_restart_wire_to_reconciliation() {
	use crate::chain::{ChannelMonitorUpdateStatus, Watch};
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		for restart_before_completion in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let (persister, chain_monitor);
			let config = anchor_config();
			let node_chanmgrs =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
			let reloaded;
			let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
			let preimage = PaymentPreimage([*nodes[1].network_payment_count.borrow(); 32]);
			let (_, voucher) = prepare(&nodes[0], &nodes[1], id, phase);
			assert_eq!(
				PaymentHash(Sha256::hash(&preimage.0).to_byte_array()),
				voucher.payment_hash
			);
			let activation = with_channel(&nodes[1], &nodes[0], id, |channel| {
				channel.ffor_receiver_fence().unwrap()
			});
			let update = with_channel(&nodes[1], &nodes[0], id, |channel| {
				let before = channel.encode();
				assert!(matches!(
					channel.get_update_fulfill_htlc_and_commit(
						voucher.htlc_id,
						PaymentPreimage([99; 32]),
						None,
						None,
						&nodes[1].logger
					),
					UpdateFulfillCommitFetch::DuplicateClaim {}
				));
				assert!(matches!(
					channel.get_update_fulfill_htlc_and_commit(
						voucher.htlc_id + 1,
						preimage,
						None,
						None,
						&nodes[1].logger
					),
					UpdateFulfillCommitFetch::DuplicateClaim {}
				));
				assert_eq!(channel.encode(), before);
				let update = match channel.get_update_fulfill_htlc_and_commit(
					voucher.htlc_id,
					preimage,
					None,
					None,
					&nodes[1].logger,
				) {
					UpdateFulfillCommitFetch::NewClaim { monitor_update, htlc_value_msat } => {
						assert_eq!(htlc_value_msat, voucher.amount_msat);
						monitor_update
					},
					_ => panic!("Valid owned preimage was not retained"),
				};
				assert_eq!(update.updates.len(), 1);
				assert!(channel.context.ffor_monitor_update_allowed(&update));
				assert!(channel.is_awaiting_monitor_update());
				assert_eq!(channel.context.holding_cell_htlc_updates.len(), 1);
				assert!(matches!(
					channel.context.pending_inbound_htlcs[0].state,
					InboundHTLCState::Committed
				));
				assert!(channel.validate_ffor_fence().is_ok());
				assert!(matches!(
					channel.get_update_fulfill_htlc_and_commit(
						voucher.htlc_id,
						preimage,
						None,
						None,
						&nodes[1].logger
					),
					UpdateFulfillCommitFetch::DuplicateClaim {}
				));
				update
			});
			assert_eq!(
				nodes[1].chain_monitor.update_channel(id, &update),
				ChannelMonitorUpdateStatus::Completed
			);
			check_added_monitors(&nodes[1], 1);
			assert_eq!(
				get_monitor!(nodes[1], id).get_stored_preimages()[&voucher.payment_hash].0,
				preimage
			);
			if !restart_before_completion {
				with_channel(&nodes[1], &nodes[0], id, |channel| {
					expect_no_released_updates(channel.monitor_updating_restored(
						&nodes[1].logger,
						&nodes[1].keys_manager,
						ChainHash::using_genesis_block(bitcoin::Network::Testnet),
						&config,
						nodes[1].node.current_best_block().height,
						|_| unreachable!(),
					));
				});
			}
			let manager = nodes[1].node.encode();
			let monitor = get_monitor!(nodes[1], id).encode();
			nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
			reload_node!(
				nodes[1],
				config,
				&manager,
				&[&monitor],
				persister,
				chain_monitor,
				reloaded
			);
			assert_eq!(
				get_monitor!(nodes[1], id).get_stored_preimages()[&voucher.payment_hash].0,
				preimage
			);
			with_channel(&nodes[1], &nodes[0], id, |channel| {
				assert_eq!(channel.ffor_receiver_fence(), Some(activation));
				assert!(channel
					.context
					.ffor_receiver_book
					.as_ref()
					.unwrap()
					.abort_reason
					.is_none());
				assert_eq!(channel.context.holding_cell_htlc_updates.len(), 1);
				assert!(matches!(
					channel.context.pending_inbound_htlcs[0].state,
					InboundHTLCState::Committed
				));
				let fee = LowerBoundedFeeEstimator::new(nodes[1].fee_estimator);
				assert!(channel.maybe_free_holding_cell_htlcs(&fee, &nodes[1].logger).0.is_none());
				let signer = channel.signer_maybe_unblocked(&nodes[1].logger, |_| unreachable!());
				assert!(signer.commitment_update.is_none() && signer.revoke_and_ack.is_none());
				assert!(signer.channel_ready.is_none() && signer.closing_signed.is_none());
				assert!(channel.abort_ffor_receiver_book([81; 32]).is_err());
			});
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			let restored_token = nodes[1].node.capture_ffor_persistence();
			let _restored_manager = nodes[1].node.encode();
			nodes[1].node.ffor_persistence_completed(restored_token).unwrap();
			for _ in 0..2 {
				nodes[1]
					.node
					.peer_connected(
						nodes[0].node.get_our_node_id(),
						&msgs::Init {
							features: nodes[0].node.init_features(),
							networks: None,
							remote_network_address: None,
						},
						true,
					)
					.unwrap();
				let events = nodes[1].node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1, "{events:?}");
				assert!(matches!(
					&events[0],
					MessageSendEvent::SendChannelReestablish { msg, .. }
						if msg.ffor_reestablish.is_some()
				));
				nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
				with_channel(&nodes[1], &nodes[0], id, |channel| {
					assert_eq!(channel.ffor_receiver_fence(), Some(activation))
				});
			}
			// The fence must preserve the existing force-close and monitor claim path.
			nodes[1]
				.node
				.force_close_broadcasting_latest_txn(
					&id,
					&nodes[0].node.get_our_node_id(),
					"fence recovery test".into(),
				)
				.unwrap();
			assert!(nodes[1].node.list_channels().is_empty());
			handle_bump_close_event(&nodes[1]);
			assert!(!nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
			assert_eq!(
				get_monitor!(nodes[1], id).get_stored_preimages()[&voucher.payment_hash].0,
				preimage
			);
			assert!(nodes[1]
				.node
				.get_and_clear_pending_events()
				.iter()
				.any(|event| matches!(event, crate::events::Event::ChannelClosed { .. })));
			nodes[1].node.get_and_clear_pending_msg_events();
			nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
		}
	}
}

#[test]
fn ffor_fence_refuses_pending_state_on_restore_and_blocks_signer_monitor_replay() {
	use crate::util::ser::ReadableArgs;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (_, voucher) = prepare(&nodes[0], &nodes[1], id, FFORReceiverFencePhase::Active);
	let encoded = with_channel(&nodes[1], &nodes[0], id, |channel| channel.encode());
	let features = crate::ln::channelmanager::provided_channel_type_features(&config);
	let read = |bytes: &[u8]| {
		FundedChannel::read(
			&mut &bytes[..],
			(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
		)
	};
	assert!(read(&encoded).unwrap().validate_ffor_fence().is_ok());
	for fault in 0..16 {
		let mut channel = read(&encoded).unwrap();
		match fault {
			0 => {
				channel.context.pending_update_fee =
					Some((500, FeeUpdateState::AwaitingRemoteRevokeToAnnounce))
			},
			1 => channel.context.holding_cell_update_fee = Some(500),
			2 => channel.context.signer_pending_commitment_update = true,
			3 => channel.context.signer_pending_revoke_and_ack = true,
			4 => channel.context.signer_pending_closing = true,
			5 => channel.context.signer_pending_funding = true,
			6 => channel.context.signer_pending_channel_ready = true,
			7 => channel.context.monitor_pending_commitment_signed = true,
			8 => channel.context.monitor_pending_revoke_and_ack = true,
			9 => channel.context.monitor_pending_channel_ready = true,
			10 => {
				channel.context.ffor_receiver_book.as_mut().unwrap().abort_reason =
					Some(FFORReceiverAbortReason::Requested)
			},
			11 => channel.context.ffor_receiver_book.as_mut().unwrap().setup = None,
			12 => {
				channel.context.pending_inbound_htlcs[0].state = InboundHTLCState::LocalRemoved(
					InboundHTLCRemovalReason::Fulfill(PaymentPreimage([99; 32]), None),
				)
			},
			13 => {
				channel.context.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
					htlc_id: voucher.htlc_id,
					payment_preimage: PaymentPreimage([99; 32]),
					attribution_data: None,
				})
			},
			14 => channel.context.ffor_receiver_book.as_mut().unwrap().received[0].failure = None,
			15 => channel.context.blocked_monitor_updates.push(PendingChannelMonitorUpdate {
				update: ChannelMonitorUpdate {
					update_id: channel.context.latest_monitor_update_id + 1,
					channel_id: Some(id),
					updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed {
						should_broadcast: false,
					}],
				},
			}),
			_ => unreachable!(),
		}
		assert!(channel.validate_ffor_fence().is_err(), "fault {fault}");
		// Even malformed restored bookkeeping must not bypass an installed fence before refusal.
		let signer = channel.signer_maybe_unblocked(&nodes[1].logger, |_| unreachable!());
		assert!(signer.commitment_update.is_none() && signer.revoke_and_ack.is_none());
		assert!(signer.open_channel.is_none() && signer.accept_channel.is_none());
		assert!(signer.funding_created.is_none() && signer.funding_signed.is_none());
		assert!(signer.channel_ready.is_none() && signer.closing_signed.is_none());
		assert!(signer.signed_closing_tx.is_none() && signer.shutdown_result.is_none());
		if fault == 15 {
			assert!(channel.unblock_next_blocked_monitor_update().is_none());
			assert_eq!(channel.context.blocked_monitor_updates.len(), 1);
		} else {
			channel.context.channel_state.set_monitor_update_in_progress();
			expect_no_released_updates(channel.monitor_updating_restored(
				&nodes[1].logger,
				&nodes[1].keys_manager,
				ChainHash::using_genesis_block(bitcoin::Network::Testnet),
				&config,
				nodes[1].node.current_best_block().height,
				|_| unreachable!(),
			));
		}
		if (2..=6).contains(&fault) {
			// Stock signer retry flags are transient and are not serialized.
			assert!(read(&channel.encode()).unwrap().validate_ffor_fence().is_ok());
		} else {
			assert!(read(&channel.encode()).is_err(), "fault {fault}");
		}
	}
}

#[test]
fn ffor_fence_required_field_refuses_a_reader_without_fence_support() {
	use crate::util::ser::Readable;
	struct BeforeFenceBook {
		epoch_id: [u8; 32],
		vouchers: Vec<FFORVoucher>,
		received: Vec<FFORReceivedVoucher>,
		abort_reason: Option<FFORReceiverAbortReason>,
		setup: Option<FFORReceiverSetup>,
	}
	impl_writeable_tlv_based!(BeforeFenceBook, {
		(0, epoch_id, required),
		(2, vouchers, required_vec),
		(4, received, required_vec),
		(6, abort_reason, option),
		(8, setup, option),
	});
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	prepare(&nodes[0], &nodes[1], id, FFORReceiverFencePhase::Activating);
	with_channel(&nodes[1], &nodes[0], id, |channel| {
		let book = channel.context.ffor_receiver_book.as_mut().unwrap();
		assert!(matches!(
			BeforeFenceBook::read(&mut &book.encode()[..]),
			Err(DecodeError::UnknownRequiredFeature)
		));
		let fence = book.fence.take();
		assert!(BeforeFenceBook::read(&mut &book.encode()[..]).is_ok());
		book.fence = fence;
	});
}

#[test]
fn ffor_fence_force_close_completes_delayed_preimage_after_channel_removal() {
	use crate::chain::ChannelMonitorUpdateStatus;
	use crate::ln::channelmanager::ffor_recovery_tests::claim_ffor_preimage_for_test;
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let preimage = PaymentPreimage([*nodes[1].network_payment_count.borrow(); 32]);
		let (_, voucher) = prepare(&nodes[0], &nodes[1], id, phase);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		let preimage_update =
			claim_ffor_preimage_for_test(&nodes[0], &nodes[1], id, voucher.htlc_id, preimage);
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		with_channel(&nodes[1], &nodes[0], id, |channel| {
			assert!(channel.is_awaiting_monitor_update());
			assert!(channel.validate_ffor_fence().is_ok());
		});
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(
				&id,
				&nodes[0].node.get_our_node_id(),
				"delayed fenced preimage".into(),
			)
			.unwrap();
		assert!(nodes[1].node.list_channels().is_empty());
		check_added_monitors(&nodes[1], 1);
		let close_update = get_monitor!(nodes[1], id).get_latest_update_id();
		assert_eq!(close_update, preimage_update + 1);
		assert_eq!(
			get_monitor!(nodes[1], id).get_stored_preimages()[&voucher.payment_hash].0,
			preimage
		);
		assert!(nodes[1]
			.node
			.get_and_clear_pending_events()
			.iter()
			.any(|event| matches!(event, crate::events::Event::ChannelClosed { .. })));
		nodes[1].node.get_and_clear_pending_msg_events();
		// Both writes complete after the live channel has been removed.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(id, preimage_update).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(id, close_update).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		handle_bump_close_event(&nodes[1]);
		assert!(!nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
		assert_eq!(
			get_monitor!(nodes[1], id).get_stored_preimages()[&voucher.payment_hash].0,
			preimage
		);
		check_added_monitors(&nodes[1], 0);
	}
}
