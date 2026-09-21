use super::*;
use crate::chain::channelmonitor::ChannelMonitor;
use crate::ln::channel::{ffor_setup_test_messages, FFORReceiverFencePhase, FFORReceiverSetup};
use crate::ln::ffor_recovery::tests::full_registry;
use crate::ln::ffor_recovery::{FFORReceiverActivation, FFORRecoveryKey};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::sign::ffor::FFORSigningRequest;
use crate::sign::{KeysManager, NodeSigner, Recipient};
use crate::util::test_channel_signer::TestChannelSigner;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Activate, Message as FFORMessage, Payload};

fn sign_activation(message: &mut FFORMessage, node: &Node) {
	let keys = KeysManager::new(&node.node_seed, 0, 0, true);
	assert_eq!(keys.get_node_id(Recipient::Node).unwrap(), node.node.get_our_node_id());
	let wire = message.unsigned_wire().unwrap();
	message.signature = keys
		.sign_ffor_message(&FFORSigningRequest::new(&wire).unwrap())
		.unwrap()
		.serialize_compact();
}

/// Test-only composition of genuine signed evidence and native fence installation. This helper
/// sends no activation wire and does not provide an operational activation or invoice API.
pub(crate) fn install_ffor_activation_for_test(
	sender: &Node, receiver: &Node, channel_id: ChannelId, phase: FFORReceiverFencePhase,
) -> [u8; 32] {
	let monitor = get_monitor!(receiver, channel_id).ffor_commitment_snapshot().unwrap();
	let current_height = receiver.node.current_best_block().height;
	let sender_id = sender.node.get_our_node_id();
	let hash;
	{
		let peers = receiver.node.per_peer_state.read().unwrap();
		let mut peer = peers.get(&sender_id).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
		let setup = channel.ffor_receiver_setup_record().unwrap().unwrap();
		let authenticated = setup.validate_recovery().unwrap();
		let commitments =
			match channel.ffor_receiver_book_status(&monitor, &receiver.logger).unwrap() {
				FFORReceiverStatus::Parked { commitments } => commitments,
				other => panic!("unexpected setup state: {:?}", other),
			};
		let commit_hash = transcript::commitment_hash(
			commitments.holder.number,
			&commitments.holder.txid.to_byte_array(),
			commitments.counterparty.number,
			&commitments.counterparty.txid.to_byte_array(),
		);
		let mut activate = FFORMessage {
			header: authenticated.header(),
			payload: Payload::Activate(Activate {
				setup_hash: authenticated.setup_hash(),
				book_hash: authenticated.book_hash(),
				commit_hash,
				epoch_start_height: current_height,
			}),
			extensions: vec![],
			signature: [0; 64],
		};
		sign_activation(&mut activate, receiver);
		hash = authenticated.validate_activation(&activate, commit_hash, current_height).unwrap();
		let activating = FFORReceiverActivation::prepare(
			&setup,
			&activate.encode().unwrap(),
			commitments,
			&monitor,
			current_height,
		)
		.unwrap();
		let mut recovery = receiver.node.ffor_recovery.lock().unwrap();
		let requirement = receiver.node.ffor_persistence.lock().unwrap().request().unwrap();
		let insertion = recovery.prepare_activation(&setup, &activating).unwrap();
		channel
			.install_ffor_fence_for_test(phase, hash, &monitor, current_height, &receiver.logger)
			.unwrap();
		insertion.commit();
		if phase == FFORReceiverFencePhase::Active {
			let mut ack = FFORMessage {
				header: authenticated.header(),
				payload: Payload::ActivateAck(hash),
				extensions: vec![],
				signature: [0; 64],
			};
			sign_activation(&mut ack, sender);
			let active = activating.with_ack(&setup, &ack.encode().unwrap()).unwrap();
			recovery.prepare_activation(&setup, &active).unwrap().commit();
		}
		receiver.node.ffor_activation.lock().unwrap().record(
			FFORRecoveryKey { channel_id, epoch_id: authenticated.header().epoch_id },
			requirement,
			false,
		);
	}
	let token = receiver.node.capture_ffor_persistence();
	let _persisted = receiver.node.encode();
	receiver.node.ffor_persistence_completed(token).unwrap();
	hash
}

/// Exercises the stock manager claim and monitor persistence path for a privately fenced voucher.
pub(crate) fn claim_ffor_preimage_for_test(
	sender: &Node, receiver: &Node, channel_id: ChannelId, htlc_id: u64, preimage: PaymentPreimage,
) -> u64 {
	let source = {
		let peers = receiver.node.per_peer_state.read().unwrap();
		let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
		assert!(channel.ffor_receiver_fence().is_some());
		HTLCClaimSource {
			counterparty_node_id: sender.node.get_our_node_id(),
			funding_txo: channel.funding_outpoint(),
			channel_id,
			htlc_id,
		}
	};
	receiver.node.claim_mpp_part(source, preimage, None, None, |amount, duplicate| {
		assert!(amount.is_some());
		assert!(!duplicate);
		(None, None)
	});
	get_monitor!(receiver, channel_id).get_latest_update_id()
}

fn setup_messages(sender: &Node, receiver: &Node, channel_id: ChannelId) -> (Vec<u8>, Vec<u8>) {
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([91; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 300,
	};
	let (init, accept) = ffor_setup_test_messages(sender, receiver, channel_id, voucher);
	(init.encode().unwrap(), accept.encode().unwrap())
}

fn prepare_record(
	sender: &Node, receiver: &Node, channel_id: ChannelId, margin: u32,
) -> FFORReceiverSetup {
	let (init, accept) = setup_messages(sender, receiver, channel_id);
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
	channel
		.prepare_ffor_receiver_setup(
			&init,
			&accept,
			receiver.node.get_our_node_id(),
			receiver.node.chain_hash,
			receiver.node.current_best_block().height,
			margin,
		)
		.unwrap()
}

fn register(sender: &Node, receiver: &Node, channel_id: ChannelId) -> FFORReceiverSetup {
	let (init, accept) = setup_messages(sender, receiver, channel_id);
	receiver
		.node
		.register_ffor_receiver_setup(
			&channel_id,
			&sender.node.get_our_node_id(),
			&init,
			&accept,
			20,
		)
		.unwrap();
	let peers = receiver.node.per_peer_state.read().unwrap();
	let peer = peers.get(&sender.node.get_our_node_id()).unwrap().lock().unwrap();
	peer.channel_by_id
		.get(&channel_id)
		.unwrap()
		.as_funded()
		.unwrap()
		.ffor_receiver_setup_record()
		.unwrap()
		.unwrap()
}

pub(crate) fn restore<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, manager: &[u8], monitor: &[u8],
) -> Result<TestChannelManager<'b, 'c>, DecodeError> {
	let (_, monitor) = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
		&mut &monitor[..],
		(node.keys_manager, node.keys_manager),
	)?;
	let (_, restored) = <(BlockHash, TestChannelManager<'b, 'c>)>::read(
		&mut &manager[..],
		ChannelManagerReadArgs::new(
			node.keys_manager,
			node.keys_manager,
			node.keys_manager,
			node.fee_estimator,
			node.chain_monitor,
			node.tx_broadcaster,
			node.router,
			node.message_router,
			node.logger,
			anchor_config(),
			vec![&monitor],
		),
	)?;
	Ok(restored)
}

fn drain_close_events(node: &Node) {
	node.node.get_and_clear_pending_msg_events();
	let events = node.node.get_and_clear_pending_events();
	assert!(events.iter().any(|event| matches!(event, Event::ChannelClosed { .. })));
	node.chain_monitor.added_monitors.lock().unwrap().clear();
}

#[test]
fn ffor_activation_archive_real_channel_requires_fence_and_retains_closed_evidence() {
	for phase in [FFORReceiverFencePhase::Activating, FFORReceiverFencePhase::Active] {
		for receiver_funds in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let config = anchor_config();
			let managers =
				create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
			let nodes = create_network(2, &node_cfgs, &managers);
			let (funder, peer) = if receiver_funds { (1, 0) } else { (0, 1) };
			let channel_id = create_announced_chan_between_nodes_with_value(
				&nodes, funder, peer, 100_000, 40_000_000,
			)
			.2;
			let sender = &nodes[0];
			let receiver = &nodes[1];
			let sender_id = sender.node.get_our_node_id();
			let receiver_id = receiver.node.get_our_node_id();
			let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
			let (init, accept) = ffor_setup_test_messages(sender, receiver, channel_id, voucher);
			receiver
				.node
				.register_ffor_receiver_setup(
					&channel_id,
					&sender_id,
					&init.encode().unwrap(),
					&accept.encode().unwrap(),
					20,
				)
				.unwrap();
			deliver_parked_voucher(sender, receiver, update);
			let monitor = get_monitor!(receiver, channel_id).ffor_commitment_snapshot().unwrap();
			receiver
				.node
				.request_ffor_receiver_quiescence(
					&channel_id,
					&sender_id,
					init.header.epoch_id,
					monitor,
				)
				.unwrap();
			let proposed = get_event_msg!(receiver, MessageSendEvent::SendStfu, sender_id);
			sender.node.handle_stfu(receiver_id, &proposed);
			let response = get_event_msg!(sender, MessageSendEvent::SendStfu, receiver_id);
			receiver.node.handle_stfu(sender_id, &response);
			let hash = install_ffor_activation_for_test(sender, receiver, channel_id, phase);
			let key = FFORRecoveryKey { channel_id, epoch_id: init.header.epoch_id };
			let archive = receiver.node.ffor_recovery.lock().unwrap().encode();
			let monitor = get_monitor!(receiver, channel_id).encode();
			let restored = restore(receiver, &receiver.node.encode(), &monitor).unwrap();
			assert_eq!(restored.ffor_recovery.lock().unwrap().encode(), archive);
			{
				let peers = restored.per_peer_state.read().unwrap();
				let peer = peers.get(&sender_id).unwrap().lock().unwrap();
				assert_eq!(
					peer.channel_by_id
						.get(&channel_id)
						.unwrap()
						.as_funded()
						.unwrap()
						.ffor_receiver_fence(),
					Some((phase, hash))
				);
			}
			let retained = core::mem::replace(
				&mut *receiver.node.ffor_recovery.lock().unwrap(),
				FFORRecoveryRegistry::new(),
			);
			assert!(restore(receiver, &receiver.node.encode(), &monitor).is_err());
			*receiver.node.ffor_recovery.lock().unwrap() = retained;
			receiver
				.node
				.force_close_broadcasting_latest_txn(
					&channel_id,
					&sender_id,
					"activation archive test".into(),
				)
				.unwrap();
			drain_close_events(receiver);
			let monitor = get_monitor!(receiver, channel_id).encode();
			let encoded = receiver.node.encode();
			let restored = restore(receiver, &encoded, &monitor).unwrap();
			assert!(restored.list_channels().is_empty());
			assert_eq!(restored.ffor_recovery.lock().unwrap().encode(), archive);
			assert_eq!(
				restored.ffor_recovery.lock().unwrap().get_activation(&key).unwrap().is_active(),
				phase == FFORReceiverFencePhase::Active
			);
			let without_monitor = <(BlockHash, TestChannelManager)>::read(
				&mut &encoded[..],
				ChannelManagerReadArgs::new(
					receiver.keys_manager,
					receiver.keys_manager,
					receiver.keys_manager,
					receiver.fee_estimator,
					receiver.chain_monitor,
					receiver.tx_broadcaster,
					receiver.router,
					receiver.message_router,
					receiver.logger,
					anchor_config(),
					vec![],
				),
			);
			assert!(without_monitor.is_err());
		}
	}
}

#[test]
fn ffor_recovery_explicit_and_monitor_closure_retain_setup_after_reload() {
	for monitor_closes in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let record = register(&nodes[0], &nodes[1], channel_id);
		let evidence = nodes[1].node.ffor_recovery.lock().unwrap().encode();
		if monitor_closes {
			get_monitor!(nodes[1], channel_id).broadcast_latest_holder_commitment_txn(
				&nodes[1].tx_broadcaster,
				&nodes[1].fee_estimator,
				&nodes[1].logger,
			);
			// The normal message poll processes monitor events under manager consistency.
			nodes[1].node.get_and_clear_pending_msg_events();
		} else {
			nodes[1]
				.node
				.force_close_broadcasting_latest_txn(
					&channel_id,
					&nodes[0].node.get_our_node_id(),
					"recovery retention test".into(),
				)
				.unwrap();
		}
		assert!(nodes[1].node.list_channels().is_empty());
		drain_close_events(&nodes[1]);
		let manager = nodes[1].node.encode();
		let monitor = get_monitor!(nodes[1], channel_id).encode();
		let restored = restore(&nodes[1], &manager, &monitor).unwrap();
		assert!(restored.list_channels().is_empty());
		assert_eq!(restored.ffor_recovery.lock().unwrap().encode(), evidence);
		assert!(restored.ffor_recovery.lock().unwrap().contains_exact(&record));
	}
}

#[test]
fn ffor_recovery_stale_manager_disposal_retains_the_removed_channel_evidence() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let record = register(&nodes[0], &nodes[1], channel_id);
	let stale_manager = nodes[1].node.encode();
	let evidence = nodes[1].node.ffor_recovery.lock().unwrap().encode();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			"newer monitor test".into(),
		)
		.unwrap();
	drain_close_events(&nodes[1]);
	let monitor = get_monitor!(nodes[1], channel_id).encode();
	let restored = restore(&nodes[1], &stale_manager, &monitor).unwrap();
	assert!(restored.list_channels().is_empty());
	assert_eq!(restored.ffor_recovery.lock().unwrap().encode(), evidence);
	assert!(restored.ffor_recovery.lock().unwrap().contains_exact(&record));
	assert!(restored.get_and_clear_pending_events().iter().any(|event| matches!(
		event,
		Event::ChannelClosed { reason: ClosureReason::OutdatedChannelManager, .. }
	)));
	nodes[1].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_events();
	nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
}

#[test]
fn ffor_recovery_live_channel_refuses_missing_or_conflicting_archived_setup() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let different_admission = prepare_record(&nodes[0], &nodes[1], channel_id, 19);
	register(&nodes[0], &nodes[1], channel_id);
	let monitor = get_monitor!(nodes[1], channel_id).encode();
	for conflicting in [false, true] {
		let mut invalid = FFORRecoveryRegistry::new();
		if conflicting {
			invalid.prepare_insert(&different_admission).unwrap().commit();
		}
		let original =
			core::mem::replace(&mut *nodes[1].node.ffor_recovery.lock().unwrap(), invalid);
		let encoded = nodes[1].node.encode();
		*nodes[1].node.ffor_recovery.lock().unwrap() = original;
		assert!(matches!(restore(&nodes[1], &encoded, &monitor), Err(DecodeError::InvalidValue)));
	}
}

#[test]
fn ffor_recovery_capacity_failure_does_not_register_the_live_channel() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (init, accept) = setup_messages(&nodes[0], &nodes[1], channel_id);
	let original =
		core::mem::replace(&mut *nodes[1].node.ffor_recovery.lock().unwrap(), full_registry());
	let before = nodes[1].node.ffor_recovery.lock().unwrap().encode();
	let result = nodes[1].node.register_ffor_receiver_setup(
		&channel_id,
		&nodes[0].node.get_our_node_id(),
		&init,
		&accept,
		20,
	);
	assert!(matches!(result, Err(FFORReceiverError::RecoveryUnavailable)));
	assert_eq!(nodes[1].node.ffor_recovery.lock().unwrap().encode(), before);
	*nodes[1].node.ffor_recovery.lock().unwrap() = original;
	let peers = nodes[1].node.per_peer_state.read().unwrap();
	let peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
	assert!(channel.ffor_receiver_setup_record().unwrap().is_none());
	drop(peer);
	drop(peers);
	// A valid request remains possible after storage becomes available.
	register(&nodes[0], &nodes[1], channel_id);
}

#[test]
fn ffor_recovery_archive_only_manager_preserves_required_tlv_and_exports_legacy_fixture() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	register(&nodes[0], &nodes[1], channel_id);
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			"archive compatibility fixture".into(),
		)
		.unwrap();
	drain_close_events(&nodes[1]);
	let archive = nodes[1].node.encode();
	let monitor = get_monitor!(nodes[1], channel_id).encode();
	let evidence = core::mem::replace(
		&mut *nodes[1].node.ffor_recovery.lock().unwrap(),
		FFORRecoveryRegistry::new(),
	);
	let ordinary = nodes[1].node.encode();
	*nodes[1].node.ffor_recovery.lock().unwrap() = evidence;
	assert!(archive.len() > ordinary.len());
	assert!(restore(&nodes[1], &ordinary, &monitor)
		.unwrap()
		.ffor_recovery
		.lock()
		.unwrap()
		.is_empty());
	assert!(!restore(&nodes[1], &archive, &monitor)
		.unwrap()
		.ffor_recovery
		.lock()
		.unwrap()
		.is_empty());
	if let Ok(directory) = std::env::var("FFOR_RECOVERY_FIXTURE_DIR") {
		let path = std::path::Path::new(&directory);
		std::fs::create_dir_all(path).unwrap();
		std::fs::write(path.join("archive-only-manager.bin"), &archive).unwrap();
		std::fs::write(path.join("ordinary-manager.bin"), &ordinary).unwrap();
		std::fs::write(path.join("closed-monitor.bin"), &monitor).unwrap();
		std::fs::write(path.join("test-node-seed.bin"), &nodes[1].node_seed).unwrap();
	}
}
