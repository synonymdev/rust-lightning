use super::*;
use crate::chain::channelmonitor::ChannelMonitor;
use crate::ln::channel::{ffor_setup_test_messages, FFORReceiverSetup};
use crate::ln::ffor_recovery::tests::full_registry;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use crate::util::test_channel_signer::TestChannelSigner;

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

fn restore<'a, 'b, 'c>(
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
