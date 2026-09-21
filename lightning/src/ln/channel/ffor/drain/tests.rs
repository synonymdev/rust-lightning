use super::*;
use crate::ln::channelmanager::ffor_recovery_tests::install_ffor_activation_for_test;
use crate::ln::ffor_recovery::FFORReceiverActivation;
use crate::ln::ffor_tests::quiescence::{complete_handshake, register_signed, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::sign::ffor::FFORSigningRequest;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Activate, CloseAck, Message, Payload};

fn sign(message: &mut Message, node: &Node) {
	message.signature = node
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
}

#[test]
fn ffor_drain_restored_permission_and_duplicate_hash_fail_closed() {
	for receiver_funds in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let id =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
		let (sender, receiver) =
			if receiver_funds { (&nodes[1], &nodes[0]) } else { (&nodes[0], &nodes[1]) };
		let preimage = PaymentPreimage([*receiver.network_payment_count.as_ref().borrow(); 32]);
		let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
		register_signed(sender, receiver, id, voucher);
		deliver_parked_voucher(sender, receiver, update.clone());
		request(sender, receiver, id).unwrap();
		complete_handshake(sender, receiver);
		let hash =
			install_ffor_activation_for_test(sender, receiver, id, FFORReceiverFencePhase::Active);
		let encoded = {
			let peers = receiver.node.per_peer_state.read().unwrap();
			let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
			peer.channel_by_id.get(&id).unwrap().as_funded().unwrap().encode()
		};
		let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let args = (&receiver.keys_manager, &receiver.keys_manager, &features);
		let mut channel = FundedChannel::read(&mut &encoded[..], args).unwrap();
		channel.quiescent_action = None;
		channel.context.channel_state.clear_quiescent();
		channel.context.channel_state.clear_remote_stfu_sent();
		channel.context.channel_state.clear_local_stfu_sent();
		channel.context.channel_state.clear_peer_disconnected();
		let setup = channel.ffor_receiver_setup_record().unwrap().unwrap();
		let authenticated = setup.validate_recovery().unwrap();
		let monitor = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
		let commitments = channel
			.ffor_voucher_commitments(
				FFORSettlementParty::Counterparty,
				&[voucher],
				&monitor,
				&receiver.logger,
			)
			.unwrap();
		let mut message = Message {
			header: authenticated.header(),
			payload: Payload::Activate(Activate {
				setup_hash: authenticated.setup_hash(),
				book_hash: authenticated.book_hash(),
				commit_hash: transcript::commitment_hash(
					commitments.holder.number,
					&commitments.holder.txid.to_byte_array(),
					commitments.counterparty.number,
					&commitments.counterparty.txid.to_byte_array(),
				),
				epoch_start_height: receiver.node.current_best_block().height,
			}),
			extensions: Vec::new(),
			signature: [0; 64],
		};
		sign(&mut message, receiver);
		let activation = FFORReceiverActivation::prepare(
			&setup,
			&message.encode().unwrap(),
			commitments,
			&monitor,
			receiver.node.current_best_block().height,
		)
		.unwrap();
		assert_eq!(activation.activation_hash(&setup).unwrap(), hash);
		message.payload = Payload::ActivateAck(hash);
		sign(&mut message, sender);
		let activation = activation.with_ack(&setup, &message.encode().unwrap()).unwrap();
		message.payload = Payload::Close(hash);
		sign(&mut message, receiver);
		let close = activation.with_close(&setup, &message.encode().unwrap()).unwrap();
		message.payload = Payload::CloseAck(CloseAck {
			activation_hash: hash,
			num_slots: 1,
			settled: vec![0],
			preimages: Vec::new(),
			preimages_tlv_present: true,
		});
		sign(&mut message, sender);
		let close = close.with_close_ack(&setup, &message.encode().unwrap()).unwrap();
		channel.install_ffor_receiver_drain(close.close_record().unwrap()).unwrap();
		assert!(channel.context.ffor_blocks_commitment_round());
		assert!(channel
			.queue_fail_htlc(
				voucher.htlc_id,
				msgs::OnionErrorPacket { data: vec![], attribution_data: None },
				&receiver.logger
			)
			.is_err());
		channel
			.enable_ffor_receiver_drain(
				[81; 32],
				close.close_record().unwrap().acknowledgement_hash().unwrap(),
			)
			.unwrap();
		assert!(!channel.context.ffor_blocks_commitment_round());
		let fee = LowerBoundedFeeEstimator::new(receiver.fee_estimator);
		assert!(channel.update_add_htlc(&update.update_add_htlcs[0], &fee).is_err());
		assert!(channel
			.update_fee(
				&fee,
				&msgs::UpdateFee { channel_id: id, feerate_per_kw: 500 },
				&receiver.logger
			)
			.is_err());
		assert!(channel.propose_quiescence(&receiver.logger, QuiescentAction::DoNothing).is_err());
		let persisted = channel.encode();
		let mut restored = FundedChannel::read(&mut &persisted[..], args).unwrap();
		assert!(restored.context.ffor_blocks_commitment_round());
		assert_eq!(restored.ffor_receiver_abort_reason(), None);
		let message = restored.get_channel_reestablish(&receiver.logger).unwrap();
		let replay = FFORReestablishOutcome::CloseReplayRequired {
			peer_report: lightning_ffor::reestablish::Reestablish {
				epoch_id: [81; 32],
				activation_hash: hash,
				state: lightning_ffor::reestablish::ReportedState::Active,
			},
		};
		restored.ffor_reconnect_outcome = Some(replay);
		assert!(restored.ffor_check_drain_reestablish(&message, &receiver.logger).is_err());
		assert_eq!(restored.ffor_receiver_reconnect_outcome(), Some(&replay));
		assert!(restored
			.enable_ffor_receiver_drain(
				[81; 32],
				close.close_record().unwrap().acknowledgement_hash().unwrap()
			)
			.is_err());

		for failure_signed in [false, true] {
			let mut claiming = FundedChannel::read(&mut &persisted[..], args).unwrap();
			claiming.context.channel_state.clear_peer_disconnected();
			claiming
				.enable_ffor_receiver_drain(
					[81; 32],
					close.close_record().unwrap().acknowledgement_hash().unwrap(),
				)
				.unwrap();
			let unchanged = claiming.encode();
			assert!(matches!(
				claiming.get_update_fulfill_htlc_and_commit(
					voucher.htlc_id,
					PaymentPreimage([255; 32]),
					None,
					None,
					&receiver.logger
				),
				UpdateFulfillCommitFetch::DuplicateClaim {}
			));
			assert_eq!(claiming.encode(), unchanged);
			claiming.ffor_queue_draining_vouchers(&receiver.logger);
			assert!(matches!(
				claiming.context.holding_cell_htlc_updates[0],
				HTLCUpdateAwaitingACK::FailHTLC { .. }
			));
			if failure_signed {
				assert!(claiming.maybe_free_holding_cell_htlcs(&fee, &receiver.logger).0.is_some());
			}
			let monitor = match claiming.get_update_fulfill_htlc_and_commit(
				voucher.htlc_id,
				preimage,
				None,
				None,
				&receiver.logger,
			) {
				UpdateFulfillCommitFetch::NewClaim { monitor_update, .. } => monitor_update,
				_ => panic!("owned preimage must be persisted"),
			};
			assert!(monitor.updates.iter().any(|step| matches!(step, ChannelMonitorUpdateStep::PaymentPreimage { payment_preimage, .. } if *payment_preimage == preimage)));
			assert!(!claiming
				.context
				.holding_cell_htlc_updates
				.iter()
				.any(|update| matches!(update, HTLCUpdateAwaitingACK::FailHTLC { .. })));
			if failure_signed {
				assert_eq!(monitor.updates.len(), 1);
				assert!(matches!(
					claiming.context.pending_inbound_htlcs[0].state,
					InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailRelay(_))
				));
			} else {
				assert!(matches!(
					claiming.context.pending_inbound_htlcs[0].state,
					InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(_, _))
				));
			}
			let claimed_bytes = claiming.encode();
			assert!(FundedChannel::read(&mut &claimed_bytes[..], args).is_ok());
		}

		channel
			.context
			.ffor_receiver_book
			.as_mut()
			.unwrap()
			.drain
			.as_mut()
			.unwrap()
			.activation_hash[0] ^= 1;
		let corrupt = channel.encode();
		assert!(matches!(
			FundedChannel::read(&mut &corrupt[..], args),
			Err(DecodeError::InvalidValue)
		));
	}
}
