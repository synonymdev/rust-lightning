use super::*;
use crate::ln::ffor::{FFORPeerConnection, FFORWitnessProvisionAttempt};
use lightning_ffor::witness::{Acknowledgement, AcknowledgementResult};

macro_rules! fixture {
	($sender:ident, $receiver:ident, $id:ident, $context:ident, $selected:ident, $receiver_funds:expr) => {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &managers);
		let (funder, other) = if $receiver_funds { (1, 0) } else { (0, 1) };
		let $id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, other, 100_000, 40_000_000,
		)
		.2;
		let ($sender, $receiver) = (&nodes[0], &nodes[1]);
		park_two($sender, $receiver, $id);
		let $context = activate($sender, $receiver, $id);
		persist($receiver.node);
		let $selected = manifests(&$context, 2);
		$receiver.node.register_ffor_receiver_witnesses(&$context, &$selected).unwrap();
	};
}

pub(super) fn connect(receiver: &Node, witness: PublicKey) -> FFORPeerConnection {
	let init = msgs::Init {
		features: receiver.node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	receiver.node.peer_connected(witness, &init, false).unwrap();
	receiver.node.ffor_peer_connection(&witness).unwrap()
}

fn ack(provision: &Provision, witness: PublicKey, retention_until: u32) -> Acknowledgement {
	Acknowledgement::new(
		provision.request_id(),
		AcknowledgementResult::Accepted { witness, retention_until },
	)
	.unwrap()
}

fn staged(
	receiver: &Node, context: &FFORReceiverRecoveryContext, selected: &(PublicKey, SignedManifest),
	id: u8,
) -> (FFORPeerConnection, Provision, FFORWitnessProvisionAttempt) {
	let connection = connect(receiver, selected.0);
	let provision = Provision::new([id; 16], selected.1.clone());
	let attempt = receiver
		.node
		.stage_ffor_receiver_witness_provision(context, &connection, &provision)
		.unwrap();
	(connection, provision, attempt)
}

#[test]
fn ffor_witness_ack_requires_native_sent_request_and_manager_durability() {
	for receiver_funds in [false, true] {
		fixture!(sender, receiver, id, context, selected, receiver_funds);
		let (connection, provision, attempt) = staged(receiver, &context, &selected[0], 1);
		let retention = selected[0].1.unsigned().parameters().retention_until;
		let response = ack(&provision, selected[0].0, retention);
		assert!(receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).is_err());
		assert!(receiver
			.node
			.capture_ffor_receiver_active_context(&id, &context.settlement_node_id(), EPOCH)
			.is_err());
		persist(receiver.node);
		let active = receiver
			.node
			.capture_ffor_receiver_active_context(&id, &context.settlement_node_id(), EPOCH)
			.unwrap();
		assert!(!receiver
			.node
			.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| Err(()))
			.unwrap());
		assert!(receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).is_err());
		// The legacy release does not mark a staged native attempt sent.
		assert!(receiver
			.node
			.release_ffor_receiver_witness_provision(
				&active,
				&selected[0].0,
				&provision,
				|_| Ok(())
			)
			.unwrap());
		assert!(receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).is_err());
		assert!(receiver
			.node
			.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |wire| {
				assert_eq!(wire.encode(), provision.encode());
				Ok(())
			})
			.unwrap());
		assert!(receiver
			.node
			.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| panic!(
				"duplicate enqueue"
			))
			.unwrap());
		let requirement =
			receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(&requirement));
		assert_eq!(
			receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).unwrap(),
			requirement
		);
		assert!(receiver
			.node
			.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| panic!(
				"stale requirement"
			))
			.is_err());
		let token = receiver.node.capture_ffor_persistence();
		let _ = receiver.node.encode();
		drop(token);
		assert!(!receiver.node.is_ffor_state_persisted(&requirement));
		let original =
			receiver.node.ffor_receiver_witness_acknowledgements(&context).unwrap().unwrap();
		assert_eq!(original.acknowledgements().len(), 1);
		assert_eq!(original.acknowledgements()[0].request_id(), provision.request_id());
		persist(receiver.node);
		assert!(receiver.node.is_ffor_state_persisted(&requirement));
		let active = receiver
			.node
			.capture_ffor_receiver_active_context(&id, &context.settlement_node_id(), EPOCH)
			.unwrap();
		// A sidecar may have retained an earlier ACK before a disconnect. Each store preserves its
		// own first valid promise; a later successful attempt never replaces native evidence.
		let later = Provision::new([2; 16], selected[0].1.clone());
		let later_attempt = receiver
			.node
			.stage_ffor_receiver_witness_provision(&context, &connection, &later)
			.unwrap();
		receiver
			.node
			.release_ffor_receiver_witness_attempt(&active, &later_attempt, &later, |_| Ok(()))
			.unwrap();
		let before = receiver.node.encode();
		assert_eq!(
			receiver
				.node
				.retain_ffor_receiver_witness_ack(
					&connection,
					&ack(&later, selected[0].0, retention + 1)
				)
				.unwrap(),
			requirement
		);
		assert_eq!(before, receiver.node.encode());
		assert_eq!(
			receiver.node.ffor_receiver_witness_acknowledgements(&context).unwrap().unwrap(),
			original
		);
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
	}
}

#[test]
fn ffor_witness_ack_rejects_wrong_correlation_and_retains_refusal_tombstone() {
	fixture!(sender, receiver, id, context, selected, false);
	persist(receiver.node);
	let (connection, provision, attempt) = staged(receiver, &context, &selected[0], 1);
	let other_connection = connect(receiver, selected[1].0);
	let active = receiver
		.node
		.capture_ffor_receiver_active_context(&id, &sender.node.get_our_node_id(), EPOCH)
		.unwrap();
	let substituted = Provision::new(provision.request_id(), selected[1].1.clone());
	assert!(receiver
		.node
		.stage_ffor_receiver_witness_provision(&context, &connection, &substituted)
		.is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &substituted, |_| panic!(
			"substitution"
		))
		.is_err());
	receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| Ok(()))
		.unwrap();
	let retention = selected[0].1.unsigned().parameters().retention_until;
	assert!(receiver
		.node
		.retain_ffor_receiver_witness_ack(
			&other_connection,
			&ack(&provision, selected[0].0, retention)
		)
		.is_err());
	assert!(receiver
		.node
		.retain_ffor_receiver_witness_ack(&connection, &ack(&provision, selected[1].0, retention))
		.is_err());
	assert!(receiver
		.node
		.retain_ffor_receiver_witness_ack(
			&connection,
			&ack(&provision, selected[0].0, retention - 1)
		)
		.is_err());
	let unknown = Provision::new([9; 16], selected[0].1.clone());
	assert!(receiver
		.node
		.retain_ffor_receiver_witness_ack(&connection, &ack(&unknown, selected[0].0, retention))
		.is_err());
	let refused =
		Acknowledgement::new(provision.request_id(), AcknowledgementResult::Refused(vec![1]))
			.unwrap();
	assert!(receiver.node.retain_ffor_receiver_witness_ack(&connection, &refused).is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| panic!(
			"refused retry"
		))
		.is_err());
	assert!(receiver
		.node
		.stage_ffor_receiver_witness_provision(&context, &connection, &provision)
		.is_err());
	assert!(receiver
		.node
		.retain_ffor_receiver_witness_ack(&connection, &ack(&provision, selected[0].0, retention))
		.is_err());
	assert!(receiver
		.node
		.ffor_receiver_witness_acknowledgements(&context)
		.unwrap()
		.unwrap()
		.acknowledgements()
		.is_empty());
}

#[test]
fn ffor_witness_ack_connection_loss_requires_fresh_native_attempt() {
	fixture!(sender, receiver, id, context, selected, false);
	persist(receiver.node);
	let (connection, provision, attempt) = staged(receiver, &context, &selected[0], 1);
	let active = receiver
		.node
		.capture_ffor_receiver_active_context(&id, &sender.node.get_our_node_id(), EPOCH)
		.unwrap();
	receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| Ok(()))
		.unwrap();
	let retention = selected[0].1.unsigned().parameters().retention_until;
	// The application may already have persisted this ACK. Native lost the connection first.
	let observed = ack(&provision, selected[0].0, retention);
	receiver.node.peer_disconnected(selected[0].0);
	assert!(receiver.node.retain_ffor_receiver_witness_ack(&connection, &observed).is_err());
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| panic!(
			"disconnected enqueue"
		))
		.is_err());
	let replacement = connect(receiver, selected[0].0);
	assert_ne!(connection, replacement);
	assert!(receiver.node.retain_ffor_receiver_witness_ack(&replacement, &observed).is_err());
	let fresh = Provision::new([2; 16], selected[0].1.clone());
	let fresh_attempt = receiver
		.node
		.stage_ffor_receiver_witness_provision(&context, &replacement, &fresh)
		.unwrap();
	receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &fresh_attempt, &fresh, |_| Ok(()))
		.unwrap();
	receiver
		.node
		.retain_ffor_receiver_witness_ack(&replacement, &ack(&fresh, selected[0].0, retention + 1))
		.unwrap();
	let saved = receiver.node.ffor_receiver_witness_acknowledgements(&context).unwrap().unwrap();
	assert_eq!(saved.acknowledgements()[0].request_id(), fresh.request_id());
	assert_eq!(saved.acknowledgements()[0].retention_until(), retention + 1);
}

#[test]
fn ffor_witness_ack_restore_and_archive_only_history_never_restore_attempts() {
	fixture!(sender, receiver, id, context, selected, false);
	persist(receiver.node);
	let (connection, provision, attempt) = staged(receiver, &context, &selected[0], 1);
	let active = receiver
		.node
		.capture_ffor_receiver_active_context(&id, &sender.node.get_our_node_id(), EPOCH)
		.unwrap();
	receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| Ok(()))
		.unwrap();
	let response =
		ack(&provision, selected[0].0, selected[0].1.unsigned().parameters().retention_until);
	receiver.node.retain_ffor_receiver_witness_ack(&connection, &response).unwrap();
	let metadata = receiver.node.ffor_receiver_witness_acknowledgements(&context).unwrap().unwrap();
	let bytes = persist(receiver.node);
	let monitor = get_monitor!(receiver, id).encode();
	let restored = restore(receiver, &bytes, &monitor).unwrap();
	assert_eq!(
		restored.ffor_receiver_witness_acknowledgements(&context).unwrap(),
		Some(metadata.clone())
	);
	assert!(restored.retain_ffor_receiver_witness_ack(&connection, &response).is_err());
	assert!(restored
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| panic!(
			"restored attempt"
		))
		.is_err());
	let requirement = restored.register_ffor_receiver_witnesses(&context, &selected).unwrap();
	assert!(!restored.is_ffor_state_persisted(&requirement));
	persist(&restored);
	assert!(restored.is_ffor_state_persisted(&requirement));
	receiver
		.node
		.force_close_broadcasting_latest_txn(
			&id,
			&sender.node.get_our_node_id(),
			"witness ACK archive".into(),
		)
		.unwrap();
	receiver.node.get_and_clear_pending_msg_events();
	receiver.node.get_and_clear_pending_events();
	receiver.chain_monitor.added_monitors.lock().unwrap().clear();
	let closed =
		restore(receiver, &persist(receiver.node), &get_monitor!(receiver, id).encode()).unwrap();
	assert!(closed.list_channels().is_empty());
	assert_eq!(closed.ffor_receiver_witness_acknowledgements(&context).unwrap(), Some(metadata));
}

#[test]
fn ffor_witness_ack_attempt_budget_preserves_exact_retry_until_disconnect() {
	fixture!(sender, receiver, id, context, selected, false);
	persist(receiver.node);
	let (connection, first, first_attempt) = staged(receiver, &context, &selected[0], 0);
	for index in 1..64 {
		let provision = Provision::new([index; 16], selected[0].1.clone());
		receiver
			.node
			.stage_ffor_receiver_witness_provision(&context, &connection, &provision)
			.unwrap();
	}
	let repeated =
		receiver.node.stage_ffor_receiver_witness_provision(&context, &connection, &first).unwrap();
	assert!(Arc::ptr_eq(&repeated.identity, &first_attempt.identity));
	assert!(matches!(
		receiver.node.stage_ffor_receiver_witness_provision(
			&context,
			&connection,
			&Provision::new([64; 16], selected[0].1.clone())
		),
		Err(FFORReceiverError::RecoveryUnavailable)
	));
	receiver.node.peer_disconnected(selected[0].0);
	let replacement = connect(receiver, selected[0].0);
	assert!(receiver
		.node
		.stage_ffor_receiver_witness_provision(
			&context,
			&replacement,
			&Provision::new([65; 16], selected[0].1.clone()),
		)
		.is_ok());
}

#[test]
fn ffor_witness_ack_release_is_offline_capable_but_rechecks_current_deadline() {
	fixture!(sender, receiver, id, context, selected, false);
	persist(receiver.node);
	let (connection, provision, attempt) = staged(receiver, &context, &selected[0], 1);
	receiver.node.peer_disconnected(sender.node.get_our_node_id());
	persist(receiver.node);
	let active = receiver
		.node
		.capture_ffor_receiver_active_context(&id, &context.settlement_node_id(), EPOCH)
		.unwrap();
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| {
			// White-box evidence that the native generation replacement guard spans the callback.
			// Production callbacks must only check their paired transport token and bounded queue.
			assert!(receiver.node.per_peer_state.try_write().is_err());
			Ok(())
		})
		.unwrap());
	let later = Provision::new([2; 16], selected[0].1.clone());
	let later_attempt =
		receiver.node.stage_ffor_receiver_witness_provision(&context, &connection, &later).unwrap();
	receiver.node.best_block.write().unwrap().height = context.setup().terms().settlement_deadline;
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &later_attempt, &later, |_| panic!(
			"expired enqueue"
		))
		.is_err());
	// An already observed storage promise remains retainable as historical evidence after D.
	receiver
		.node
		.retain_ffor_receiver_witness_ack(
			&connection,
			&ack(&provision, selected[0].0, selected[0].1.unsigned().parameters().retention_until),
		)
		.unwrap();
}
