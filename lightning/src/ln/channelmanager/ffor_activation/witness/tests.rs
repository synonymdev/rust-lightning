use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::ffor_activation::drain_tests::{park_two, park_two_with_witnesses};
use crate::ln::channelmanager::ffor_recovery_tests::{claim_ffor_preimage_for_test, restore};
use crate::ln::ffor_recovery::ffor_test_witness_manifests as manifests;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;
use bitcoin::secp256k1::{Message as SecpMessage, Secp256k1, SecretKey};
use lightning_ffor::witness::{ManifestParameters, UnsignedManifest};

const EPOCH: [u8; 32] = [81; 32];

fn persist(node: &TestChannelManager) -> Vec<u8> {
	let token = node.capture_ffor_persistence();
	let bytes = node.encode();
	node.ffor_persistence_completed(token).unwrap();
	bytes
}

fn activate(sender: &Node, receiver: &Node, id: ChannelId) -> FFORReceiverRecoveryContext {
	let context = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
	let mut ack = FFORMessage {
		header: context.setup().header(),
		payload: Payload::ActivateAck(context.activation_hash()),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	ack.signature = sender
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&ack.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
	receiver
		.node
		.accept_ffor_receiver_activation_ack(
			&id,
			&sender.node.get_our_node_id(),
			EPOCH,
			&ack.encode().unwrap(),
		)
		.unwrap();
	receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap()
}

fn modified_manifest(
	context: &FFORReceiverRecoveryContext, parameters: ManifestParameters,
) -> SignedManifest {
	let unsigned = UnsignedManifest::new(context.setup(), parameters).unwrap();
	let signature = Secp256k1::new()
		.sign_ecdsa(
			&SecpMessage::from_digest(unsigned.signing_digest()),
			&SecretKey::from_slice(&[100; 32]).unwrap(),
		)
		.serialize_compact();
	unsigned.authenticate(signature).unwrap()
}

fn export_node_fixture(receiver: &Node, context: &FFORReceiverRecoveryContext) {
	let directory = match std::env::var_os("FFOR_NODE_WITNESS_FIXTURE_DIR") {
		Some(directory) => std::path::PathBuf::from(directory),
		None => return,
	};
	std::fs::create_dir_all(&directory).unwrap();
	std::fs::write(directory.join("active-manager.bin"), persist(receiver.node)).unwrap();
	std::fs::write(
		directory.join("active-monitor.bin"),
		get_monitor!(receiver, context.channel_id()).encode(),
	)
	.unwrap();
	let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
	std::fs::write(directory.join("fixture.txt"), format!(
		"network=testnet\nwallet_seed={}\nchannel_id={}\nepoch_id={}\nreceiver={}\nsettlement={}\nfunding_txid={}\nfunding_vout={}\ngenerator=ffor_witness_registration_release_requires_current_durability_and_survives_archive_only_restore\nbase_revision=a20b34f98\n",
		hex(&[91; 64]), hex(&context.channel_id().0), hex(&context.epoch_id()),
		context.receiver_node_id(), context.settlement_node_id(), context.funding_txo().txid, context.funding_txo().index,
	)).unwrap();
}

#[test]
fn ffor_witness_registration_release_requires_current_durability_and_survives_archive_only_restore()
{
	for receiver_funds in [false, true] {
		let mut chanmon_cfgs = create_chanmon_cfgs(2);
		let wallet_root =
			bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[91; 64]).unwrap();
		chanmon_cfgs[1].keys_manager = crate::util::test_utils::TestKeysInterface::new(
			&wallet_root.private_key.secret_bytes(),
			bitcoin::Network::Testnet,
		);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		node_cfgs[1].node_seed = wallet_root.private_key.secret_bytes();
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if receiver_funds { (1, 0) } else { (0, 1) };
		let id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let (sender, receiver) = (&nodes[0], &nodes[1]);
		let peer = sender.node.get_our_node_id();
		park_two(sender, receiver, id);
		let no_ack = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
		assert!(receiver
			.node
			.register_ffor_receiver_witnesses(&no_ack, &manifests(&no_ack, 1))
			.is_err());
		let context = activate(sender, receiver, id);
		let selected = manifests(&context, 4);
		assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected).is_err());
		persist(receiver.node);
		if !receiver_funds {
			export_node_fixture(receiver, &context);
		}
		assert!(receiver.node.register_ffor_receiver_witnesses(&no_ack, &selected).is_err());
		let old_active =
			receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
		let older_write = receiver.node.capture_ffor_persistence();
		let requirement =
			receiver.node.register_ffor_receiver_witnesses(&context, &selected).unwrap();
		receiver.node.ffor_persistence_completed(older_write).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(&requirement));
		let mut reordered = selected.clone();
		reordered.reverse();
		assert_eq!(
			receiver.node.register_ffor_receiver_witnesses(&context, &reordered).unwrap(),
			requirement
		);
		let metadata = receiver.node.ffor_receiver_witness_registration(&context).unwrap().unwrap();
		assert_eq!(metadata.witnesses().len(), 4);
		assert_eq!(metadata.context_digest(), context.context_digest());
		let provision = Provision::new([44; 16], selected[0].1.clone());
		assert!(receiver
			.node
			.release_ffor_receiver_witness_provision(
				&old_active,
				&selected[0].0,
				&provision,
				|_| panic!("unpersisted registration released")
			)
			.is_err());
		assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected[..1]).is_err());
		let saved = persist(receiver.node);
		assert!(receiver.node.is_ffor_state_persisted(&requirement));
		assert!(receiver
			.node
			.release_ffor_receiver_witness_provision(
				&old_active,
				&selected[0].0,
				&provision,
				|_| panic!("stale context released")
			)
			.is_err());
		let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
		assert!(!receiver
			.node
			.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| Err(
				()
			))
			.unwrap());
		sender.node.peer_disconnected(receiver.node.get_our_node_id());
		receiver.node.peer_disconnected(peer);
		assert!(receiver
			.node
			.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |exact| {
				assert_eq!(exact, &provision);
				Ok(())
			})
			.unwrap());
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &saved, &monitor).unwrap();
		assert_eq!(
			restored.ffor_receiver_witness_registration(&context).unwrap(),
			Some(metadata.clone())
		);
		assert!(restored
			.release_ffor_receiver_witness_provision(
				&active,
				&selected[0].0,
				&provision,
				|_| panic!("old instance released")
			)
			.is_err());
		assert!(restored.capture_ffor_receiver_active_context(&id, &peer, EPOCH).is_err());
		let restored_requirement =
			restored.register_ffor_receiver_witnesses(&context, &selected).unwrap();
		assert!(!restored.is_ffor_state_persisted(&restored_requirement));
		persist(&restored);
		let fresh = restored.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
		assert!(restored
			.release_ffor_receiver_witness_provision(&fresh, &selected[0].0, &provision, |_| Ok(()))
			.unwrap());
		assert!(receiver
			.node
			.release_ffor_receiver_witness_provision(
				&fresh,
				&selected[0].0,
				&provision,
				|_| panic!("other manager released")
			)
			.is_err());
		receiver
			.node
			.force_close_broadcasting_latest_txn(&id, &peer, "witness archive test".into())
			.unwrap();
		receiver.node.get_and_clear_pending_msg_events();
		assert!(receiver
			.node
			.get_and_clear_pending_events()
			.iter()
			.any(|event| matches!(event, Event::ChannelClosed { .. })));
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		let closed_monitor = get_monitor!(receiver, id).encode();
		let closed = restore(receiver, &persist(receiver.node), &closed_monitor).unwrap();
		assert!(closed.list_channels().is_empty());
		assert_eq!(closed.ffor_receiver_witness_registration(&context).unwrap(), Some(metadata));
		assert!(closed
			.release_ffor_receiver_witness_provision(
				&active,
				&selected[0].0,
				&provision,
				|_| panic!("removed channel released")
			)
			.is_err());
	}
}

#[test]
fn ffor_witness_release_refuses_conflicting_reconnect_without_callback() {
	use lightning_ffor::reestablish::{Reestablish, ReportedState};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let peer = sender.node.get_our_node_id();
	let receiver_id = receiver.node.get_our_node_id();
	park_two(sender, receiver, id);
	let context = activate(sender, receiver, id);
	persist(receiver.node);
	let selected = manifests(&context, 1);
	receiver.node.register_ffor_receiver_witnesses(&context, &selected).unwrap();
	persist(receiver.node);
	let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
	let provision = Provision::new([1; 16], selected[0].1.clone());
	sender.node.peer_disconnected(receiver_id);
	receiver.node.peer_disconnected(peer);
	connect_nodes(sender, receiver);
	let local = get_event_msg!(receiver, MessageSendEvent::SendChannelReestablish, peer);
	let mut remote = get_event_msg!(sender, MessageSendEvent::SendChannelReestablish, receiver_id);
	let mut conflicting = context.activation_hash();
	conflicting[0] ^= 1;
	remote.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		activation_hash: conflicting,
		state: ReportedState::Active,
	}));
	sender.node.handle_channel_reestablish(receiver_id, &local);
	receiver.node.handle_channel_reestablish(peer, &remote);
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| panic!(
			"conflicting reconnect released"
		))
		.is_err());
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected).is_err());
	assert!(receiver.node.ffor_receiver_witness_registration(&context).unwrap().is_some());
	sender.node.get_and_clear_pending_msg_events();
	receiver.node.get_and_clear_pending_msg_events();
}

#[test]
fn ffor_witness_registration_refuses_wrong_terms_selection_and_deadline() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let peer = sender.node.get_our_node_id();
	let selected_peer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[90; 32]).unwrap());
	park_two_with_witnesses(sender, receiver, id, Some(vec![selected_peer]));
	let context = activate(sender, receiver, id);
	persist(receiver.node);
	let selected = manifests(&context, 1);
	assert_eq!(selected[0].0, selected_peer);
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &[]).is_err());
	assert!(receiver
		.node
		.register_ffor_receiver_witnesses(&context, &manifests(&context, 5))
		.is_err());
	assert!(receiver
		.node
		.register_ffor_receiver_witnesses(&context, &manifests(&context, 2))
		.is_err());
	let mut duplicated = selected.clone();
	duplicated.push(selected[0].clone());
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &duplicated).is_err());
	let mut parameters = *selected[0].1.unsigned().parameters();
	parameters.commitment_hash[0] ^= 1;
	let wrong = modified_manifest(&context, parameters);
	assert!(receiver
		.node
		.register_ffor_receiver_witnesses(&context, &[(selected_peer, wrong)])
		.is_err());
	let mut parameters = *selected[0].1.unsigned().parameters();
	parameters.encryption_public_key = parameters.fetch_public_key;
	let reused_key = modified_manifest(&context, parameters);
	assert!(receiver
		.node
		.register_ffor_receiver_witnesses(&context, &[(selected_peer, reused_key)])
		.is_err());
	assert!(receiver.node.ffor_receiver_witness_registration(&context).unwrap().is_none());
	receiver.node.register_ffor_receiver_witnesses(&context, &selected).unwrap();
	persist(receiver.node);
	let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
	let provision = Provision::new([1; 16], selected[0].1.clone());
	let mut parameters = *selected[0].1.unsigned().parameters();
	parameters.mailbox_id[0] ^= 1;
	let changed = modified_manifest(&context, parameters);
	assert!(receiver
		.node
		.register_ffor_receiver_witnesses(&context, &[(selected_peer, changed.clone())])
		.is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(
			&active,
			&selected_peer,
			&Provision::new([1; 16], changed),
			|_| panic!("changed manifest released")
		)
		.is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &peer, &provision, |_| panic!(
			"unselected peer released"
		))
		.is_err());
	let deadline = context.setup().terms().settlement_deadline;
	receiver.node.best_block.write().unwrap().height = deadline - 1;
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected_peer, &provision, |_| Ok(()))
		.unwrap());
	receiver.node.best_block.write().unwrap().height = deadline;
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected).is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected_peer, &provision, |_| panic!(
			"expired epoch released"
		))
		.is_err());
	// The immutable historical ownership is still visible after expiration.
	assert!(receiver.node.ffor_receiver_witness_registration(&context).unwrap().is_some());
}

#[test]
fn ffor_witness_release_waits_for_owned_preimage_monitor_and_refuses_close() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let id = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 40_000_000).2;
	let (sender, receiver) = (&nodes[0], &nodes[1]);
	let peer = sender.node.get_our_node_id();
	let (vouchers, preimage) = park_two(sender, receiver, id);
	let context = activate(sender, receiver, id);
	persist(receiver.node);
	let selected = manifests(&context, 1);
	receiver.node.register_ffor_receiver_witnesses(&context, &selected).unwrap();
	persist(receiver.node);
	let active = receiver.node.capture_ffor_receiver_active_context(&id, &peer, EPOCH).unwrap();
	let provision = Provision::new([1; 16], selected[0].1.clone());
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let update = claim_ffor_preimage_for_test(sender, receiver, id, vouchers[0].htlc_id, preimage);
	check_added_monitors(receiver, 1);
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| panic!(
			"unpersisted monitor released"
		))
		.is_err());
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected).is_err());
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	receiver.chain_monitor.chain_monitor.channel_monitor_updated(id, update).unwrap();
	receiver.node.get_and_clear_pending_msg_events();
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| Ok(()))
		.unwrap());
	receiver.node.prepare_ffor_receiver_close(&id, &peer, EPOCH).unwrap();
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| panic!(
			"closing epoch released"
		))
		.is_err());
	assert!(receiver.node.register_ffor_receiver_witnesses(&context, &selected).is_err());
	persist(receiver.node);
	assert!(receiver
		.node
		.release_ffor_receiver_witness_provision(&active, &selected[0].0, &provision, |_| panic!(
			"durable close released"
		))
		.is_err());
}
