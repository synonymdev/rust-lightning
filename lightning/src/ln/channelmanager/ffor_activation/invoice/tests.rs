use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channel::ffor_setup_test_messages;
use crate::ln::channelmanager::ffor_recovery_tests::{claim_ffor_preimage_for_test, restore};
use crate::ln::ffor_recovery::ffor_test_witness_manifests as manifests;
use crate::ln::ffor_tests::quiescence::{complete_handshake, request};
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use bitcoin::hashes::{sha256, Hash};
use lightning_ffor::witness::{Acknowledgement, AcknowledgementResult, Provision, SignedManifest};

const EPOCH: [u8; 32] = [81; 32];

#[path = "fixture_tests.rs"]
mod fixture_tests;

fn persist(node: &TestChannelManager) -> Vec<u8> {
	let token = node.capture_ffor_persistence();
	let bytes = node.encode();
	node.ffor_persistence_completed(token).unwrap();
	bytes
}
fn sign(message: &mut FFORMessage, node: &Node) {
	message.signature = node
		.keys_manager
		.sign_ffor_message(&FFORSigningRequest::new(&message.unsigned_wire().unwrap()).unwrap())
		.unwrap()
		.serialize_compact();
}
fn park_single(
	sender: &Node, receiver: &Node, id: ChannelId, witnesses: Option<Vec<PublicKey>>,
) -> (FFORReceiverRecoveryContext, FFORVoucher, PaymentPreimage) {
	let preimage = PaymentPreimage([*receiver.network_payment_count.as_ref().borrow(); 32]);
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let (mut init, mut accept) = ffor_setup_test_messages(sender, receiver, id, voucher);
	if let Payload::Init(terms) = &mut init.payload {
		terms.witness_peers = witnesses;
	}
	sign(&mut init, receiver);
	if let Payload::Accept(terms) = &mut accept.payload {
		terms.init_hash = lightning_ffor::transcript::init_hash(&init.encode().unwrap());
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
	persist(receiver.node);
	deliver_parked_voucher(sender, receiver, update);
	request(sender, receiver, id).unwrap();
	complete_handshake(sender, receiver);
	let snapshot = get_monitor!(receiver, id).ffor_commitment_snapshot().unwrap();
	receiver
		.node
		.prepare_ffor_receiver_activation(&id, &sender.node.get_our_node_id(), EPOCH, &snapshot)
		.unwrap();
	persist(receiver.node);
	let context = receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap();
	let mut ack = FFORMessage {
		header: context.setup().header(),
		payload: Payload::ActivateAck(context.activation_hash()),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	sign(&mut ack, sender);
	receiver
		.node
		.accept_ffor_receiver_activation_ack(
			&id,
			&sender.node.get_our_node_id(),
			EPOCH,
			&ack.encode().unwrap(),
		)
		.unwrap();
	persist(receiver.node);
	(receiver.node.ffor_receiver_recovery_context(&id, EPOCH).unwrap(), voucher, preimage)
}

macro_rules! fixture {
 ($sender:ident, $receiver:ident, $witness:ident, $id:ident, $context:ident, $voucher:ident, $preimage:ident, $route:ident, $selected:ident, $funds:expr $(, $persister:ident)? $(; $policy:expr)?) => {
  let chanmon_cfgs = create_chanmon_cfgs(3);
  $(let $persister = &chanmon_cfgs[1].persister;)?
  let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
  let config = anchor_config();
  let managers = create_node_chanmgrs(3, &node_cfgs, &[Some(config.clone()), Some(config.clone()), Some(config)]);
  let nodes = create_network(3, &node_cfgs, &managers);
  let (funder, other) = if $funds { (1, 0) } else { (0, 1) };
  let $id = create_announced_chan_between_nodes_with_value(&nodes, funder, other, 100_000, 40_000_000).2;
  let public = create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100_000, 40_000_000);
  let ($sender, $receiver, $witness) = (&nodes[0], &nodes[1], &nodes[2]);
  let announcement = nodes[0].network_graph.read_only().channels().get(&public.0.contents.short_channel_id).unwrap().announcement_message.clone().unwrap();
  let mut update = public.0;
  update.contents.timestamp = invoice_time().unwrap() as u32;
  update.signature = $witness.keys_manager.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(&update.contents)).unwrap();
  let $route = FFORWitnessRouteEvidence { announcement, update };
  let second_witness = PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &bitcoin::secp256k1::SecretKey::from_slice(&[91; 32]).unwrap());
  let invoice_witnesses = Some(vec![$witness.node.get_our_node_id(), second_witness]);
  $(let invoice_witnesses = ($policy)(invoice_witnesses);)?
  let ($context, $voucher, $preimage) = park_single($sender, $receiver, $id, invoice_witnesses);
  let mut $selected = manifests(&$context, 2);
  $selected[0].0 = $witness.node.get_our_node_id();
  $receiver.node.register_ffor_receiver_witnesses(&$context, &$selected).unwrap();
  persist($receiver.node);
 };
}
fn intent() -> FFORInvoiceIntent {
	FFORInvoiceIntent {
		description: "Offline receipt".into(),
		expiry_seconds: 3600,
		safety_margin_seconds: 120,
	}
}
fn acknowledge(
	receiver: &Node, context: &FFORReceiverRecoveryContext, selected: &(PublicKey, SignedManifest),
	request: u8,
) {
	let init = msgs::Init {
		features: receiver.node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	if receiver.node.ffor_peer_connection(&selected.0).is_err() {
		receiver.node.peer_connected(selected.0, &init, false).unwrap();
	}
	let connection = receiver.node.ffor_peer_connection(&selected.0).unwrap();
	let provision = Provision::new([request; 16], selected.1.clone());
	let attempt = receiver
		.node
		.stage_ffor_receiver_witness_provision(context, &connection, &provision)
		.unwrap();
	let active = receiver
		.node
		.capture_ffor_receiver_active_context(
			&context.channel_id(),
			&context.settlement_node_id(),
			context.epoch_id(),
		)
		.unwrap();
	assert!(receiver
		.node
		.release_ffor_receiver_witness_attempt(&active, &attempt, &provision, |_| Ok(()))
		.unwrap());
	let ack = Acknowledgement::new(
		provision.request_id(),
		AcknowledgementResult::Accepted {
			witness: selected.0,
			retention_until: selected.1.unsigned().parameters().retention_until,
		},
	)
	.unwrap();
	receiver.node.retain_ffor_receiver_witness_ack(&connection, &ack).unwrap();
}
fn all_acknowledged(
	receiver: &Node, context: &FFORReceiverRecoveryContext,
	selected: &[(PublicKey, SignedManifest)],
) {
	for (index, witness) in selected.iter().enumerate() {
		acknowledge(receiver, context, witness, index as u8);
		persist(receiver.node);
	}
}

#[test]
fn ffor_invoice_requires_every_durable_ack_and_retains_one_exact_no_mpp_route() {
	for receiver_funds in [false, true] {
		fixture!(
			sender,
			receiver,
			witness,
			id,
			context,
			voucher,
			_preimage,
			route,
			selected,
			receiver_funds
		);
		assert!(receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).is_err());
		acknowledge(receiver, &context, &selected[0], 0);
		persist(receiver.node);
		assert!(receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).is_err());
		acknowledge(receiver, &context, &selected[1], 1);
		assert!(receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).is_err());
		persist(receiver.node);
		let older = receiver.node.capture_ffor_persistence();
		let prepared =
			receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(prepared.persistence_requirement()));
		assert!(receiver.node.ffor_receiver_invoice_for_storage(&context).is_err());
		receiver.node.ffor_persistence_completed(older).unwrap();
		assert!(!receiver.node.is_ffor_state_persisted(prepared.persistence_requirement()));
		assert_eq!(
			receiver
				.node
				.prepare_ffor_receiver_invoice(&context, &intent(), &route)
				.unwrap()
				.invoice_digest(),
			prepared.invoice_digest()
		);
		let mut changed = intent();
		changed.description.push('!');
		assert_eq!(
			receiver.node.prepare_ffor_receiver_invoice(&context, &changed, &route).unwrap_err(),
			FFORReceiverError::AlreadyRegistered
		);
		let manager = persist(receiver.node);
		let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
		assert_eq!(stored.intent(), &intent());
		assert_eq!(stored.invoice_digest(), prepared.invoice_digest());
		let invoice: Bolt11Invoice = stored.invoice_for_storage().parse().unwrap();
		assert_eq!(invoice.amount_milli_satoshis(), Some(voucher.amount_msat));
		assert_eq!(invoice.payment_hash().to_byte_array(), voucher.payment_hash.0);
		assert_eq!(invoice.get_payee_pub_key(), receiver.node.get_our_node_id());
		assert!(!invoice.features().unwrap().supports_basic_mpp());
		let routes = invoice.private_routes();
		assert_eq!(routes.len(), 1);
		assert_eq!(routes[0].0.len(), 2);
		assert_eq!(routes[0].0[0].src_node_id, witness.node.get_our_node_id());
		assert_eq!(routes[0].0[1].src_node_id, sender.node.get_our_node_id());
		assert_eq!(routes[0].0[1].fees.base_msat, context.setup().terms().fees.base_msat);
		assert!(!receiver.node.release_ffor_receiver_invoice(&stored, |_| Err(())).unwrap());
		assert!(receiver
			.node
			.release_ffor_receiver_invoice(&stored, |wire| {
				assert_eq!(wire, stored.invoice_for_storage());
				Ok(())
			})
			.unwrap());
		let monitor = get_monitor!(receiver, id).encode();
		let restored = restore(receiver, &manager, &monitor).unwrap();
		assert!(restored.ffor_receiver_invoice_for_storage(&context).is_err());
		assert!(restored
			.release_ffor_receiver_invoice(&stored, |_| panic!("old manager handle"))
			.is_err());
		persist(&restored);
		let fresh = restored.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
		assert_eq!(fresh.invoice_for_storage(), stored.invoice_for_storage());
		assert!(restored.release_ffor_receiver_invoice(&fresh, |_| Ok(())).unwrap());
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
	}
}

#[test]
fn ffor_invoice_rejects_signed_wrong_route_policy_and_stale_updates() {
	fixture!(sender, receiver, witness, id, context, _voucher, _preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	for fault in 0..7 {
		let mut bad = route.clone();
		match fault {
			0 => bad.update.contents.channel_flags ^= 1,
			1 => bad.update.contents.channel_flags |= 2,
			2 => bad.update.contents.htlc_maximum_msat = 1,
			3 => bad.update.contents.short_channel_id += 1,
			4 => bad.update.contents.timestamp = 1,
			5 => bad.update.contents.chain_hash = bitcoin::constants::ChainHash::BITCOIN,
			6 => bad.announcement.node_signature_1 = bad.announcement.bitcoin_signature_1,
			_ => unreachable!(),
		}
		bad.update.signature = witness
			.keys_manager
			.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(&bad.update.contents))
			.unwrap();
		assert!(
			receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &bad).is_err(),
			"fault {fault}"
		);
		assert!(receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().is_none());
	}
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	receiver.node.prepare_ffor_receiver_close(&id, &sender.node.get_our_node_id(), EPOCH).unwrap();
	assert!(receiver
		.node
		.release_ffor_receiver_invoice(&stored, |_| panic!("closed intent"))
		.is_err());
	persist(receiver.node);
	assert_eq!(
		receiver
			.node
			.ffor_receiver_invoice_for_storage(&context)
			.unwrap()
			.unwrap()
			.invoice_for_storage(),
		stored.invoice_for_storage()
	);
}

#[test]
fn ffor_invoice_signing_capture_cannot_commit_after_deadline_or_native_route_change() {
	fixture!(_sender, receiver, _witness, id, context, _voucher, _preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	let capture =
		receiver.node.capture_ffor_invoice(&context, &intent(), &route).unwrap().err().unwrap();
	let mut record = capture.record;
	let registration = receiver.node.ffor_receiver_witness_registration(&context).unwrap().unwrap();
	let raw = record
		.unsigned(&context, &registration, invoice_time().unwrap(), PaymentSecret([1; 32]))
		.unwrap();
	let signature = receiver.keys_manager.sign_invoice(&raw, Recipient::Node).unwrap();
	record.invoice = Bolt11Invoice::from_signed(raw.sign::<_, ()>(|_| Ok(signature)).unwrap())
		.unwrap()
		.to_string();
	let original = receiver.node.best_block.read().unwrap().height;
	receiver.node.best_block.write().unwrap().height = context.setup().terms().settlement_deadline;
	assert!(receiver
		.node
		.commit_ffor_invoice(&context, record.clone(), capture.requirement.clone())
		.is_err());
	receiver.node.best_block.write().unwrap().height = original;
	record.settlement_scid ^= 1;
	assert!(receiver.node.commit_ffor_invoice(&context, record, capture.requirement).is_err());
	assert!(receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().is_none());
}

#[test]
fn ffor_invoice_actual_monitor_rejects_known_preimage_without_counter_change() {
	fixture!(_sender, receiver, _witness, id, context, voucher, preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	let monitor = get_monitor!(receiver, id);
	let update_id = monitor.get_latest_update_id();
	assert_eq!(sha256::Hash::hash(&preimage.0).to_byte_array(), voucher.payment_hash.0);
	monitor.provide_payment_preimage_unsafe_legacy(
		&voucher.payment_hash,
		&preimage,
		&receiver.tx_broadcaster,
		&crate::chain::chaininterface::LowerBoundedFeeEstimator::new(receiver.fee_estimator),
		&receiver.logger,
	);
	assert_eq!(monitor.get_latest_update_id(), update_id);
	drop(monitor);
	assert!(receiver
		.node
		.release_ffor_receiver_invoice(&stored, |_| panic!("known preimage"))
		.is_err());
	assert!(receiver.node.get_and_clear_pending_events().is_empty());
}

#[test]
fn ffor_invoice_monitor_persistence_and_funding_spend_exclude_publication() {
	for direct_close in [false, true] {
		fixture!(
			sender, receiver, _witness, id, context, voucher, preimage, route, selected, false,
			persister
		);
		all_acknowledged(receiver, &context, &selected);
		receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
		persist(receiver.node);
		let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
		if direct_close {
			let monitor = get_monitor!(receiver, id);
			let before = monitor.get_latest_update_id();
			monitor.broadcast_latest_holder_commitment_txn(
				&receiver.tx_broadcaster,
				&receiver.fee_estimator,
				&receiver.logger,
			);
			assert_eq!(monitor.get_latest_update_id(), before);
			drop(monitor);
		} else {
			persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			let update =
				claim_ffor_preimage_for_test(sender, receiver, id, voucher.htlc_id, preimage);
			assert!(receiver
				.node
				.release_ffor_receiver_invoice(&stored, |_| panic!("pending preimage"))
				.is_err());
			persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
			receiver.chain_monitor.chain_monitor.channel_monitor_updated(id, update).unwrap();
			receiver.node.process_pending_events(&|_: Event| Ok(()));
			receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		}
		assert!(receiver
			.node
			.release_ffor_receiver_invoice(&stored, |_| panic!("monitor state changed"))
			.is_err());
		receiver.node.get_and_clear_pending_msg_events();
		receiver.node.get_and_clear_pending_events();
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
	}
}

#[test]
fn ffor_invoice_archive_rejects_corruption_and_reserves_terminal_capacity() {
	fixture!(sender, receiver, _witness, id, context, _voucher, _preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let key = FFORRecoveryKey { channel_id: id, epoch_id: EPOCH };
	crate::ln::ffor_recovery::invoice::tests::check_archive(
		&receiver.node.ffor_recovery.lock().unwrap(),
		key,
	);
	receiver.node.prepare_ffor_receiver_close(&id, &sender.node.get_our_node_id(), EPOCH).unwrap();
	persist(receiver.node);
	crate::ln::ffor_recovery::invoice::tests::check_archive(
		&receiver.node.ffor_recovery.lock().unwrap(),
		key,
	);
}

#[test]
fn ffor_invoice_monitor_tip_ahead_of_manager_blocks_conservative_expiry() {
	fixture!(_sender, receiver, _witness, id, context, _voucher, _preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	let manager_height = receiver.node.current_best_block().height;
	let block = create_dummy_header(
		receiver.node.current_best_block().block_hash,
		invoice_time().unwrap() as u32,
	);
	get_monitor!(receiver, id).best_block_updated(
		&block,
		context.setup().terms().settlement_deadline - 1,
		receiver.tx_broadcaster,
		receiver.fee_estimator,
		&receiver.logger,
	);
	assert_eq!(receiver.node.current_best_block().height, manager_height);
	assert!(receiver
		.node
		.release_ffor_receiver_invoice(&stored, |_| panic!("monitor height advanced"))
		.is_err());
}

#[test]
fn ffor_invoice_confirmed_funding_spend_blocks_before_manager_observes_close() {
	use crate::chain::Confirm;
	fixture!(sender, receiver, _witness, id, context, _voucher, _preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	let before = get_monitor!(receiver, id).get_latest_update_id();
	let commitment = get_local_commitment_txn!(sender, id).remove(0);
	let header = create_dummy_header(
		receiver.node.current_best_block().block_hash,
		invoice_time().unwrap() as u32,
	);
	receiver.chain_monitor.chain_monitor.transactions_confirmed(
		&header,
		&[(0, &commitment)],
		receiver.node.current_best_block().height + 1,
	);
	assert_eq!(get_monitor!(receiver, id).get_latest_update_id(), before);
	assert!(receiver
		.node
		.capture_ffor_receiver_active_context(&id, &context.settlement_node_id(), EPOCH)
		.is_ok());
	assert!(receiver
		.node
		.release_ffor_receiver_invoice(&stored, |_| panic!("funding already spent"))
		.is_err());
	receiver.node.process_pending_events(&|_: Event| Ok(()));
	receiver.node.get_and_clear_pending_msg_events();
	receiver.chain_monitor.added_monitors.lock().unwrap().clear();
}

#[test]
fn ffor_invoice_wrong_signer_cannot_reserve_or_expose_a_slot() {
	fixture!(
		_sender, receiver, _witness, _id, context, _voucher, _preimage, route, selected, false
	);
	all_acknowledged(receiver, &context, &selected);
	receiver.keys_manager.wrong_invoice_signer.store(true, core::sync::atomic::Ordering::Release);
	assert!(receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).is_err());
	assert!(receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().is_none());
	receiver.keys_manager.wrong_invoice_signer.store(false, core::sync::atomic::Ordering::Release);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
}

#[test]
fn ffor_invoice_publication_holds_actual_monitor_through_callback() {
	fixture!(_sender, receiver, _witness, id, context, voucher, preimage, route, selected, false);
	all_acknowledged(receiver, &context, &selected);
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	let chain_monitor = &receiver.chain_monitor.chain_monitor;
	let broadcaster = receiver.tx_broadcaster;
	let fee_estimator = receiver.fee_estimator;
	let logger = &receiver.logger;
	let start = std::sync::Barrier::new(2);
	let (blocked_send, blocked_receive) = std::sync::mpsc::channel();
	let (finished_send, finished_receive) = std::sync::mpsc::channel();
	std::thread::scope(|scope| {
		let start = &start;
		let worker = scope.spawn(move || {
			start.wait();
			let monitor = chain_monitor.get_monitor(id).unwrap();
			blocked_send.send(monitor.inner.try_lock().is_err()).unwrap();
			monitor.provide_payment_preimage_unsafe_legacy(
				&voucher.payment_hash,
				&preimage,
				&broadcaster,
				&crate::chain::chaininterface::LowerBoundedFeeEstimator::new(fee_estimator),
				logger,
			);
			finished_send.send(()).unwrap();
		});
		// The waits are a deterministic test probe only. Production callbacks must remain bounded
		// in-memory publication and never wait for monitor work or another native operation.
		assert!(receiver
			.node
			.release_ffor_receiver_invoice(&stored, |_| {
				start.wait();
				assert!(blocked_receive.recv().unwrap());
				assert!(finished_receive.try_recv().is_err());
				Ok(())
			})
			.unwrap());
		worker.join().unwrap();
	});
	assert!(receiver
		.node
		.release_ffor_receiver_invoice(&stored, |_| panic!("preimage now known"))
		.is_err());
}

#[test]
fn ffor_invoice_rejects_correctly_signed_identity_loops_and_reversed_endpoints() {
	use crate::routing::gossip::{verify_channel_announcement, NodeId};
	use bitcoin::secp256k1::Secp256k1;
	fixture!(sender, receiver, witness, _id, context, _voucher, _preimage, route, selected, false);
	for (first, second, selected_witness, reversed) in [
		(sender, sender, sender, false),
		(sender, receiver, receiver, false),
		(witness, sender, witness, true),
	] {
		let mut evidence = route.clone();
		let (first, second) = if (first.node.get_our_node_id().serialize()
			> second.node.get_our_node_id().serialize())
			== reversed
		{
			(first, second)
		} else {
			(second, first)
		};
		evidence.announcement.contents.node_id_1 =
			NodeId::from_pubkey(&first.node.get_our_node_id());
		evidence.announcement.contents.node_id_2 =
			NodeId::from_pubkey(&second.node.get_our_node_id());
		evidence.announcement.contents.bitcoin_key_1 = evidence.announcement.contents.node_id_1;
		evidence.announcement.contents.bitcoin_key_2 = evidence.announcement.contents.node_id_2;
		let signature1 = first
			.keys_manager
			.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(
				&evidence.announcement.contents,
			))
			.unwrap();
		let signature2 = second
			.keys_manager
			.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(
				&evidence.announcement.contents,
			))
			.unwrap();
		evidence.announcement.node_signature_1 = signature1;
		evidence.announcement.bitcoin_signature_1 = signature1;
		evidence.announcement.node_signature_2 = signature2;
		evidence.announcement.bitcoin_signature_2 = signature2;
		verify_channel_announcement(&evidence.announcement, &Secp256k1::verification_only())
			.unwrap();
		evidence.update.contents.channel_flags =
			if first.node.get_our_node_id() == selected_witness.node.get_our_node_id() {
				0
			} else {
				1
			};
		evidence.update.signature = selected_witness
			.keys_manager
			.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(
				&evidence.update.contents,
			))
			.unwrap();
		let metadata =
			crate::ln::ffor::FFORReceiverWitnessRegistration::from_manifests(&context, &selected)
				.unwrap();
		assert!(validate_route(&context, &metadata, &evidence, invoice_time().unwrap()).is_err());
	}
}

#[test]
fn ffor_invoice_requires_exact_signed_witness_restriction() {
	for unrestricted in [true, false] {
		fixture!(
			_sender, receiver, _witness, _id, context, _voucher, _preimage, route, selected, false;
			|restriction: Option<Vec<PublicKey>>| {
				if unrestricted {
					None
				} else {
					let mut allowed = restriction.unwrap();
					allowed.push(PublicKey::from_secret_key(
						&bitcoin::secp256k1::Secp256k1::new(),
						&bitcoin::secp256k1::SecretKey::from_slice(&[92; 32]).unwrap(),
					));
					Some(allowed)
				}
			}
		);
		all_acknowledged(receiver, &context, &selected);
		assert!(receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).is_err());
		assert!(receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().is_none());
	}
}
