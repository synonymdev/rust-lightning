use super::*;
use crate::ln::channelmanager::ffor_recovery_tests::restore;
use crate::ln::ffor_tests::quiescence::{complete_handshake, register_signed, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};

const EPOCH: [u8; 32] = [81; 32];

macro_rules! channel_fixture {
	($sender:ident, $receiver:ident, $id:ident, $receiver_funds:expr) => {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let $id =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
		let ($sender, $receiver) =
			if $receiver_funds { (&nodes[1], &nodes[0]) } else { (&nodes[0], &nodes[1]) };
	};
}

fn park(sender: &Node, receiver: &Node, id: ChannelId) {
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	register_signed(sender, receiver, id, voucher);
	deliver_parked_voucher(sender, receiver, update);
	request(sender, receiver, id).unwrap();
	complete_handshake(sender, receiver);
}

fn prepare(sender: &Node, receiver: &Node, id: ChannelId) -> FFORPersistenceRequirement {
	let snapshot = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
	receiver
		.node
		.prepare_ffor_receiver_activation(&id, &sender.node.get_our_node_id(), EPOCH, &snapshot)
		.unwrap()
}

fn persist(receiver: &Node) -> Vec<u8> {
	let token = receiver.node.capture_ffor_persistence();
	let bytes = receiver.node.encode();
	receiver.node.ffor_persistence_completed(token).unwrap();
	bytes
}

fn ack(sender: &Node, receiver: &Node, id: ChannelId) -> (Vec<u8>, [u8; 32]) {
	let key = FFORRecoveryKey { channel_id: id, epoch_id: EPOCH };
	let recovery = receiver.node.ffor_recovery.lock().unwrap();
	let setup = recovery.get(&key).unwrap();
	let hash = recovery.get_activation(&key).unwrap().activation_hash(setup).unwrap();
	let mut message = FFORMessage {
		header: setup.validate_recovery().unwrap().header(),
		payload: Payload::ActivateAck(hash),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	let unsigned = message.unsigned_wire().unwrap();
	message.signature = sender
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&unsigned).unwrap())
		.unwrap()
		.serialize_compact();
	(message.encode().unwrap(), hash)
}

fn fence(sender: &Node, receiver: &Node, id: ChannelId) -> Option<FFORReceiverFencePhase> {
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

#[test]
fn ffor_activation_manager_orders_signing_wire_and_ack_persistence() {
	for receiver_funds in [false, true] {
		channel_fixture!(sender, receiver, id, receiver_funds);
		park(sender, receiver, id);
		let peer = sender.node.get_our_node_id();
		receiver.keys_manager.unavailable_ffor_signer.store(true, Ordering::Release);
		let snapshot = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
		assert_eq!(
			receiver.node.prepare_ffor_receiver_activation(&id, &peer, EPOCH, &snapshot),
			Err(FFORReceiverError::SignerUnavailable)
		);
		assert_eq!(fence(sender, receiver, id), None);
		assert!(receiver
			.node
			.ffor_recovery
			.lock()
			.unwrap()
			.get_activation(&FFORRecoveryKey { channel_id: id, epoch_id: EPOCH })
			.is_none());
		receiver.keys_manager.unavailable_ffor_signer.store(false, Ordering::Release);
		let older = receiver.node.capture_ffor_persistence();
		let requirement = prepare(sender, receiver, id);
		assert!(receiver.node.list_usable_channels().is_empty());
		assert!(!receiver.node.list_channels()[0].is_usable);
		assert_eq!(prepare(sender, receiver, id), requirement);
		receiver.node.ffor_persistence_completed(older).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(&requirement));
		assert!(!receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| panic!("unpersisted wire"))
			.unwrap());
		drop(receiver.node.capture_ffor_persistence());
		assert!(receiver.node.get_and_clear_needs_persistence());
		persist(receiver);
		assert!(receiver.node.is_ffor_state_persisted(&requirement));
		assert!(!receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| Err(()))
			.unwrap());
		let mut activation_wire = Vec::new();
		assert!(receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |wire| {
				activation_wire = wire.to_vec();
				Ok(())
			})
			.unwrap());
		assert!(matches!(
			FFORMessage::decode(&activation_wire).unwrap().payload,
			Payload::Activate(_)
		));
		assert!(!receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| panic!("duplicate wire"))
			.unwrap());
		let (ack_wire, _) = ack(sender, receiver, id);
		let mut corrupt = ack_wire.clone();
		*corrupt.last_mut().unwrap() ^= 1;
		assert!(receiver
			.node
			.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &corrupt)
			.is_err());
		assert_eq!(fence(sender, receiver, id), Some(FFORReceiverFencePhase::Activating));
		let preceding = receiver.node.capture_ffor_persistence();
		let active = receiver
			.node
			.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack_wire)
			.unwrap();
		assert_eq!(fence(sender, receiver, id), Some(FFORReceiverFencePhase::Active));
		assert!(!receiver.node.is_ffor_state_persisted(&active));
		receiver.node.ffor_persistence_completed(preceding).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(&active));
		assert_eq!(
			receiver
				.node
				.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack_wire)
				.unwrap(),
			active
		);
		persist(receiver);
		assert!(receiver.node.is_ffor_state_persisted(&active));
		assert!(!receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| panic!("active replay"))
			.unwrap());
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
		assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
	}
}

#[test]
fn ffor_activation_manager_refuses_stale_initial_wire_without_expiring_history() {
	for height_delta in [6, 7] {
		channel_fixture!(sender, receiver, id, false);
		park(sender, receiver, id);
		prepare(sender, receiver, id);
		persist(receiver);
		receiver.node.best_block.write().unwrap().height += height_delta;
		let sent = receiver.node.release_ffor_receiver_activation(
			&id,
			&sender.node.get_our_node_id(),
			EPOCH,
			|_| Ok(()),
		);
		if height_delta == 6 {
			assert_eq!(sent, Ok(true));
		} else {
			assert!(sent.is_err());
		}
		let encoded = receiver.node.encode();
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &encoded, &monitor).unwrap();
		assert!(restored.get_and_clear_needs_persistence());
		assert!(!restored
			.release_ffor_receiver_activation(
				&id,
				&sender.node.get_our_node_id(),
				EPOCH,
				|_| panic!("restart replay")
			)
			.unwrap());
	}
}

#[test]
fn ffor_activation_manager_recovers_ack_loss_after_restart_and_deadline() {
	channel_fixture!(sender, receiver, id, false);
	park(sender, receiver, id);
	let old_requirement = prepare(sender, receiver, id);
	let bytes = persist(receiver);
	let monitor = get_monitor!(receiver, id).encode();
	let (ack_wire, hash) = ack(sender, receiver, id);
	let restored = restore(receiver, &bytes, &monitor).unwrap();
	assert!(restored.get_event_or_persist_condvar_value());
	assert!(!restored.is_ffor_state_persisted(&old_requirement));
	assert!(restored
		.accept_ffor_receiver_activation_ack(&id, &sender.node.get_our_node_id(), EPOCH, &ack_wire)
		.is_err());
	let token = restored.capture_ffor_persistence();
	let _saved = restored.encode();
	restored.ffor_persistence_completed(token).unwrap();
	let peer = sender.node.get_our_node_id();
	let init = msgs::Init {
		features: sender.init_features(receiver.node.get_our_node_id()),
		networks: None,
		remote_network_address: None,
	};
	restored.peer_connected(peer, &init, false).unwrap();
	sender.node.peer_disconnected(receiver.node.get_our_node_id());
	let receiver_init = msgs::Init {
		features: receiver.init_features(peer),
		networks: None,
		remote_network_address: None,
	};
	sender.node.peer_connected(receiver.node.get_our_node_id(), &receiver_init, true).unwrap();
	let mut report = get_event_msg!(
		sender,
		MessageSendEvent::SendChannelReestablish,
		receiver.node.get_our_node_id()
	);
	report.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(Reestablish {
		epoch_id: EPOCH,
		state: ReportedState::Active,
		activation_hash: hash,
	}));
	restored.handle_channel_reestablish(peer, &report);
	assert!(!restored
		.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| panic!("reconnect replay"))
		.unwrap());
	restored.best_block.write().unwrap().height = 400;
	let active =
		restored.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack_wire).unwrap();
	assert!(!restored.is_ffor_state_persisted(&active));
	let token = restored.capture_ffor_persistence();
	let active_bytes = restored.encode();
	restored.ffor_persistence_completed(token).unwrap();
	assert!(restored.is_ffor_state_persisted(&active));
	let recovered_active = restore(receiver, &active_bytes, &monitor).unwrap();
	assert!(!recovered_active.is_ffor_state_persisted(&active));
	let peers = recovered_active.per_peer_state.read().unwrap();
	let peer_state = peers.get(&peer).unwrap().lock().unwrap();
	assert_eq!(
		peer_state.channel_by_id.get(&id).unwrap().as_funded().unwrap().ffor_receiver_fence(),
		Some((FFORReceiverFencePhase::Active, hash))
	);
}

#[test]
fn ffor_activation_manager_persists_reconnect_abort_before_releasing_vouchers() {
	for receiver_funds in [false, true] {
		channel_fixture!(sender, receiver, id, receiver_funds);
		park(sender, receiver, id);
		prepare(sender, receiver, id);
		persist(receiver);
		let (ack_wire, _) = ack(sender, receiver, id);
		let peer = sender.node.get_our_node_id();
		sender.node.peer_disconnected(receiver.node.get_our_node_id());
		receiver.node.peer_disconnected(peer);
		connect_nodes(sender, receiver);
		let report = get_event_msg!(
			sender,
			MessageSendEvent::SendChannelReestablish,
			receiver.node.get_our_node_id()
		);
		receiver.node.handle_channel_reestablish(peer, &report);
		assert_eq!(fence(sender, receiver, id), Some(FFORReceiverFencePhase::Aborting));
		assert!(!receiver.node.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		assert!(receiver
			.node
			.accept_ffor_receiver_activation_ack(&id, &peer, EPOCH, &ack_wire)
			.is_err());
		let aborting_bytes = persist(receiver);
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &aborting_bytes, &monitor).unwrap();
		assert!(!restored.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		let token = restored.capture_ffor_persistence();
		let _saved = restored.encode();
		restored.ffor_persistence_completed(token).unwrap();
		assert!(restored.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		let released = restored.encode();
		assert!(restore(receiver, &released, &monitor).is_ok());
		assert!(receiver.node.release_ffor_receiver_reconnect_abort(&id, &peer, EPOCH).unwrap());
		assert_eq!(fence(sender, receiver, id), None);
		assert!(!receiver
			.node
			.release_ffor_receiver_activation(&id, &peer, EPOCH, |_| panic!("aborted replay"))
			.unwrap());
		let messages = receiver.node.get_and_clear_pending_msg_events();
		assert!(messages.iter().all(|event| matches!(
			event,
			MessageSendEvent::SendChannelReestablish { .. } | MessageSendEvent::UpdateHTLCs { .. }
		)));
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
	}
}

mod reestablish;
