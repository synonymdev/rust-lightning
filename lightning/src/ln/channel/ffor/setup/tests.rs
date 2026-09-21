use super::*;
use crate::ln::ffor_tests::{anchor_config, deliver_parked_voucher, offer_voucher};
use crate::ln::functional_test_utils::*;
use crate::sign::ffor::FFORSigningRequest;
use crate::sign::{KeysManager, NodeSigner, Recipient};
use lightning_ffor::transcript;
use lightning_ffor::wire::{Accept, Header, Init, Tlv};

fn chain_hash() -> ChainHash {
	ChainHash::using_genesis_block(bitcoin::Network::Testnet)
}

fn sign(message: &mut Message, node: &Node) {
	let keys = KeysManager::new(&node.node_seed, 0, 0, true);
	assert_eq!(keys.get_node_id(Recipient::Node).unwrap(), node.node.get_our_node_id());
	let wire = message.unsigned_wire().unwrap();
	message.signature = keys
		.sign_ffor_message(&FFORSigningRequest::new(&wire).unwrap())
		.unwrap()
		.serialize_compact();
}

pub(crate) fn messages(
	sender: &Node, receiver: &Node, channel_id: ChannelId, voucher: FFORVoucher,
) -> (Message, Message) {
	let number = {
		let peers = sender.node.per_peer_state.read().unwrap();
		let peer = peers.get(&receiver.node.get_our_node_id()).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
		// The sender's own current view supplies n0 independently of the receiver's peer counter.
		INITIAL_COMMITMENT_NUMBER - channel.holder_commitment_point.current_transaction_number()
	};
	let mut init = Message {
		header: Header { channel_id: channel_id.0, epoch_id: [81; 32] },
		payload: Payload::Init(Init {
			budget_msat: voucher.amount_msat,
			min_payment_msat: voucher.amount_msat,
			settlement_deadline: voucher.cltv_expiry - 20,
			voucher_expiry: voucher.cltv_expiry,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			amounts_msat: vec![voucher.amount_msat],
			witness_peers: None,
			hash_chain: false,
		}),
		extensions: vec![Tlv { kind: 101, value: vec![9, 8, 7] }],
		signature: [0; 64],
	};
	sign(&mut init, receiver);
	let mut accept = Message {
		header: init.header,
		payload: Payload::Accept(Accept {
			s_commitment_number: number,
			payment_hashes: vec![voucher.payment_hash.0],
			s_htlc_id_base: voucher.htlc_id,
			amounts_msat: vec![voucher.amount_msat],
			init_hash: transcript::init_hash(&init.encode().unwrap()),
		}),
		extensions: vec![Tlv { kind: 103, value: vec![6, 5] }],
		signature: [0; 64],
	};
	sign(&mut accept, sender);
	(init, accept)
}

#[test]
fn ffor_setup_authenticates_both_funder_roles_and_persists_exact_wire() {
	for receiver_funds in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let (funder, peer) = if receiver_funds { (1, 0) } else { (0, 1) };
		let channel_id = create_announced_chan_between_nodes_with_value(
			&nodes, funder, peer, 100_000, 40_000_000,
		)
		.2;
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
		let init_wire = init.encode().unwrap();
		let accept_wire = accept.encode().unwrap();
		let requirement = nodes[1]
			.node
			.register_ffor_receiver_setup(
				&channel_id,
				&nodes[0].node.get_our_node_id(),
				&init_wire,
				&accept_wire,
				20,
			)
			.unwrap();
		assert!(!nodes[1].node.is_ffor_state_persisted(&requirement));
		let token = nodes[1].node.capture_ffor_persistence();
		let _persisted = nodes[1].node.encode();
		nodes[1].node.ffor_persistence_completed(token).unwrap();
		assert!(nodes[1].node.is_ffor_state_persisted(&requirement));

		{
			let peers = nodes[1].node.per_peer_state.read().unwrap();
			let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
			let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
			channel
				.ffor_validate_receiver_identity(nodes[1].node.get_our_node_id(), chain_hash())
				.unwrap();
			assert!(channel
				.ffor_validate_receiver_identity(nodes[0].node.get_our_node_id(), chain_hash())
				.is_err());
			assert!(channel
				.ffor_validate_receiver_identity(
					nodes[1].node.get_our_node_id(),
					ChainHash::using_genesis_block(bitcoin::Network::Bitcoin)
				)
				.is_err());
			let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
			let encoded = channel.encode();
			let restored = FundedChannel::read(
				&mut &encoded[..],
				(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
			)
			.unwrap();
			let book = restored.context.ffor_receiver_book.as_ref().unwrap();
			assert_eq!(book.abort_reason, Some(FFORReceiverAbortReason::Restarted));
			let record = book.setup.as_ref().unwrap();
			assert_eq!(record.init_wire, init_wire);
			assert_eq!(record.accept_wire, accept_wire);
			assert_eq!(record.settlement_is_funder, !receiver_funds);
		}
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		let monitor = get_monitor!(nodes[1], channel_id).ffor_commitment_snapshot().unwrap();
		assert!(matches!(
			nodes[1]
				.node
				.ffor_receiver_book_status(&channel_id, &nodes[0].node.get_our_node_id(), &monitor)
				.unwrap(),
			FFORReceiverStatus::Parked { .. }
		));
		let peers = nodes[1].node.per_peer_state.read().unwrap();
		let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
		let encoded = channel.encode();
		let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let mut restored = FundedChannel::read(
			&mut &encoded[..],
			(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
		)
		.unwrap();
		assert_eq!(
			restored.context.ffor_receiver_book.as_ref().unwrap().setup.as_ref().unwrap().init_wire,
			init_wire
		);
		assert_eq!(
			restored.register_ffor_receiver_setup(
				&init_wire,
				&accept_wire,
				nodes[1].node.get_our_node_id(),
				chain_hash(),
				nodes[1].node.current_best_block().height,
				20
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
	}
}

#[test]
fn ffor_setup_rejects_signed_mismatches_without_registering() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([55; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 300,
	};
	for mutation in 0..8 {
		let (mut init, mut accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
		match mutation {
			0 => {
				init.header.channel_id[0] ^= 1;
				accept.header = init.header;
			},
			1 => {
				if let Payload::Accept(terms) = &mut accept.payload {
					terms.s_htlc_id_base += 1;
				}
			},
			2 => {
				if let Payload::Accept(terms) = &mut accept.payload {
					terms.s_commitment_number += 1;
				}
			},
			3 => {
				if let Payload::Accept(terms) = &mut accept.payload {
					terms.amounts_msat[0] += 1;
				}
			},
			4 => {
				if let Payload::Init(terms) = &mut init.payload {
					terms.voucher_expiry -= 1;
				}
			},
			_ => {},
		}
		sign(&mut init, &nodes[1]);
		if let Payload::Accept(terms) = &mut accept.payload {
			terms.init_hash = transcript::init_hash(&init.encode().unwrap());
		}
		sign(&mut accept, &nodes[0]);
		if mutation == 5 {
			sign(&mut accept, &nodes[1]);
		}
		let mut init_wire = init.encode().unwrap();
		if mutation == 6 {
			let last = init_wire.len() - 1;
			init_wire[last] ^= 1;
		}
		let peers = nodes[1].node.per_peer_state.read().unwrap();
		let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
		let result = channel.register_ffor_receiver_setup(
			&init_wire,
			&accept.encode().unwrap(),
			nodes[1].node.get_our_node_id(),
			chain_hash(),
			nodes[1].node.current_best_block().height,
			if mutation == 7 { 0 } else { 20 },
		);
		assert_eq!(result, Err(invalid_setup()), "mutation {}", mutation);
		assert!(channel.context.ffor_receiver_book.is_none());
	}
}

#[test]
fn ffor_setup_rejects_timestamp_expiry_before_registration_and_restore() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([55; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 499_999_999,
	};
	crate::ln::ffor::validate_vouchers(&[voucher]).unwrap();
	assert!(matches!(
		nodes[1].node.register_ffor_receiver_book(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			[81; 32],
			&[FFORVoucher { cltv_expiry: 500_000_000, ..voucher }],
		),
		Err(FFORReceiverError::ChannelState(FFORCommitmentError::InvalidVoucherBook))
	));
	let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
	let (timestamp_init, timestamp_accept) = messages(
		&nodes[0],
		&nodes[1],
		channel_id,
		FFORVoucher { cltv_expiry: 500_000_000, ..voucher },
	);
	let timestamp_init_wire = timestamp_init.encode().unwrap();
	let timestamp_accept_wire = timestamp_accept.encode().unwrap();
	// Both statements are authentic and mutually bound; only native height eligibility fails.
	AuthenticatedSetup::new(
		&timestamp_init,
		&timestamp_accept,
		nodes[1].node.get_our_node_id(),
		nodes[0].node.get_our_node_id(),
	)
	.unwrap();
	assert!(matches!(
		nodes[1].node.register_ffor_receiver_setup(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			&timestamp_init_wire,
			&timestamp_accept_wire,
			20,
		),
		Err(FFORReceiverError::ChannelState(FFORCommitmentError::InvalidVoucherBook))
	));
	// Refusing the invalid setup leaves the same channel available for a valid registration.
	nodes[1]
		.node
		.register_ffor_receiver_setup(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		)
		.unwrap();
	let peers = nodes[1].node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
	let original = channel.context.ffor_receiver_book.as_ref().unwrap().encode();
	let record = channel.context.ffor_receiver_book.as_ref().unwrap().setup.as_ref().unwrap();
	record.validate_recovery().unwrap();
	let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	FundedChannel::read(
		&mut &channel.encode()[..],
		(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
	)
	.unwrap();
	for abort_reason in [None, Some(FFORReceiverAbortReason::Requested)] {
		let book = channel.context.ffor_receiver_book.as_mut().unwrap();
		book.abort_reason = abort_reason;
		book.vouchers[0].cltv_expiry = 500_000_000;
		let record = book.setup.as_mut().unwrap();
		record.init_wire = timestamp_init_wire.clone();
		record.accept_wire = timestamp_accept_wire.clone();
		assert!(matches!(record.validate_recovery(), Err(DecodeError::InvalidValue)));
		let encoded = channel.encode();
		channel.context.ffor_receiver_book =
			Some(FFORReceiverBook::read(&mut &original[..]).unwrap());
		assert!(matches!(
			FundedChannel::read(
				&mut &encoded[..],
				(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
			),
			Err(DecodeError::InvalidValue)
		));
	}
}

#[test]
fn ffor_setup_history_range_is_bounded_before_scanning() {
	let end = INITIAL_COMMITMENT_NUMBER + 1;
	assert_eq!(checked_history_start(end), Ok(end));
	assert_eq!(
		checked_history_start(end - MAX_SETUP_COMMITMENT_HISTORY),
		Ok(end - MAX_SETUP_COMMITMENT_HISTORY)
	);
	assert_eq!(checked_history_start(end - MAX_SETUP_COMMITMENT_HISTORY - 1), Err(invalid_setup()));
	assert_eq!(checked_history_start(0), Err(invalid_setup()));
	assert_eq!(checked_history_start(end + 1), Err(invalid_setup()));
}

#[test]
fn ffor_setup_rejects_revealed_history_and_unwinds_n0_reuse() {
	use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
	use crate::ln::msgs::ChannelMessageHandler;
	for revealed_before_setup in [true, false] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let secret = if revealed_before_setup {
			send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
			let peers = nodes[1].node.per_peer_state.read().unwrap();
			let peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
			let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
			channel
				.context
				.commitment_secrets
				.get_secret(channel.context.commitment_secrets.get_min_seen_secret())
				.unwrap()
		} else {
			let peers = nodes[0].node.per_peer_state.read().unwrap();
			let peer = peers.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
			let channel = peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap();
			// Only this test reconstructs the sender's known fixture seed to imitate a malicious
			// sender. The receiver production path can access only already revealed secrets.
			let keys = KeysManager::new(&nodes[0].node_seed, 0, 0, true);
			let signer = keys.derive_channel_signer(channel.context.channel_keys_id);
			let index = channel.holder_commitment_point.current_transaction_number();
			let secret = chan_utils::build_commitment_secret(&signer.commitment_seed, index);
			assert_eq!(
				PublicKey::from_secret_key(
					&Secp256k1::new(),
					&SecretKey::from_slice(&secret).unwrap()
				),
				channel.holder_commitment_point.current_point().unwrap()
			);
			secret
		};
		let hash = PaymentHash(Sha256::hash(&secret).to_byte_array());
		let (mut route, _, _, payment_secret) =
			get_route_and_payment_hash!(&nodes[0], &nodes[1], 2_000_000);
		route.paths[0].hops[0].cltv_expiry_delta = 144;
		nodes[0]
			.node
			.send_payment_with_route(
				route,
				hash,
				RecipientOnionFields::secret_only(payment_secret),
				PaymentId(hash.0),
			)
			.unwrap();
		check_added_monitors(&nodes[0], 1);
		let update = get_htlc_update_msgs!(&nodes[0], nodes[1].node.get_our_node_id());
		let add = &update.update_add_htlcs[0];
		let voucher = FFORVoucher {
			htlc_id: add.htlc_id,
			payment_hash: hash,
			amount_msat: add.amount_msat,
			cltv_expiry: add.cltv_expiry,
		};
		let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
		let result = nodes[1].node.register_ffor_receiver_setup(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		);
		if revealed_before_setup {
			assert!(matches!(
				result,
				Err(FFORReceiverError::ChannelState(FFORCommitmentError::InvalidVoucherBook))
			));
			// The test sender has already offered an add; finish it through an explicitly
			// aborted raw registration to leave its ordinary commitment round well formed.
			nodes[1]
				.node
				.register_ffor_receiver_book(
					&channel_id,
					&nodes[0].node.get_our_node_id(),
					init.header.epoch_id,
					&[voucher],
				)
				.unwrap();
			nodes[1]
				.node
				.abort_ffor_receiver_book(
					&channel_id,
					&nodes[0].node.get_our_node_id(),
					init.header.epoch_id,
				)
				.unwrap();
		} else {
			result.unwrap();
		}
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		let monitor = get_monitor!(nodes[1], channel_id).ffor_commitment_snapshot().unwrap();
		let status = nodes[1]
			.node
			.ffor_receiver_book_status(&channel_id, &nodes[0].node.get_our_node_id(), &monitor)
			.unwrap();
		assert_eq!(
			status,
			FFORReceiverStatus::Aborting {
				reason: if revealed_before_setup {
					FFORReceiverAbortReason::Requested
				} else {
					FFORReceiverAbortReason::CommitmentSecretReused
				}
			}
		);
		let update = get_htlc_update_msgs!(&nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors(&nodes[1], 1);
		assert_eq!(update.update_fail_htlcs.len(), 1);
		nodes[0]
			.node
			.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &update.update_fail_htlcs[0]);
		commitment_signed_dance!(&nodes[0], &nodes[1], update.commitment_signed, false);
		expect_payment_failed!(&nodes[0], hash, false);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_setup_rechecks_live_limits_and_refuses_stale_preparation() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([55; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 300,
	};
	let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
	let peers = nodes[1].node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
	let prepare = |channel: &FundedChannel<_>| {
		channel.prepare_ffor_receiver_setup(
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			nodes[1].node.get_our_node_id(),
			chain_hash(),
			nodes[1].node.current_best_block().height,
			20,
		)
	};
	let original_secrets = channel.context.commitment_secrets.encode();
	let mut corrupt_secrets = original_secrets.clone();
	corrupt_secrets[32..40].copy_from_slice(&0_u64.to_be_bytes());
	channel.context.commitment_secrets =
		CounterpartyCommitmentSecrets::read(&mut &corrupt_secrets[..]).unwrap();
	assert!(matches!(
		prepare(channel),
		Err(FFORReceiverError::ChannelState(FFORCommitmentError::InvalidVoucherBook))
	));
	channel.context.commitment_secrets =
		CounterpartyCommitmentSecrets::read(&mut &original_secrets[..]).unwrap();
	for mutation in 0..8 {
		let prepared = prepare(channel).unwrap();
		let original = (
			channel.context.holder_max_accepted_htlcs,
			channel.context.holder_max_htlc_value_in_flight_msat,
			channel.context.holder_htlc_minimum_msat,
			channel.context.holder_dust_limit_satoshis,
			channel.context.counterparty_dust_limit_satoshis,
			channel.funding.holder_selected_channel_reserve_satoshis,
			channel.context.feerate_per_kw,
			channel.funding.value_to_self_msat,
		);
		match mutation {
			0 => channel.context.holder_max_accepted_htlcs = 0,
			1 => channel.context.holder_max_htlc_value_in_flight_msat = voucher.amount_msat - 1,
			2 => channel.context.holder_htlc_minimum_msat = voucher.amount_msat + 1,
			3 => channel.context.holder_dust_limit_satoshis = voucher.amount_msat / 1000 + 1,
			4 => channel.context.counterparty_dust_limit_satoshis = voucher.amount_msat / 1000 + 1,
			5 => {
				channel.funding.holder_selected_channel_reserve_satoshis =
					channel.funding.get_value_satoshis()
			},
			6 => channel.context.feerate_per_kw += 1,
			_ => channel.funding.value_to_self_msat += 1,
		}
		assert_eq!(
			channel.install_prepared_ffor_receiver_setup(prepared),
			Err(invalid_setup()),
			"mutation {}",
			mutation
		);
		assert!(channel.context.ffor_receiver_book.is_none());
		(
			channel.context.holder_max_accepted_htlcs,
			channel.context.holder_max_htlc_value_in_flight_msat,
			channel.context.holder_htlc_minimum_msat,
			channel.context.holder_dust_limit_satoshis,
			channel.context.counterparty_dust_limit_satoshis,
			channel.funding.holder_selected_channel_reserve_satoshis,
			channel.context.feerate_per_kw,
			channel.funding.value_to_self_msat,
		) = original;
	}
}

#[test]
fn ffor_setup_restore_reauthenticates_before_restart_and_requires_its_fence() {
	struct OldBook {
		epoch_id: [u8; 32],
		vouchers: Vec<FFORVoucher>,
		received: Vec<FFORReceivedVoucher>,
		abort_reason: Option<FFORReceiverAbortReason>,
	}
	impl_writeable_tlv_based!(OldBook, { (0, epoch_id, required), (2, vouchers, required_vec), (4, received, required_vec), (6, abort_reason, option) });
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([55; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 300,
	};
	let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
	nodes[1]
		.node
		.register_ffor_receiver_setup(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		)
		.unwrap();
	let peers = nodes[1].node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
	let original = channel.context.ffor_receiver_book.as_ref().unwrap().encode();
	assert!(matches!(OldBook::read(&mut &original[..]), Err(DecodeError::UnknownRequiredFeature)));
	for mutation in 0..6 {
		let book = channel.context.ffor_receiver_book.as_mut().unwrap();
		let record = book.setup.as_mut().unwrap();
		match mutation {
			0 => record.receiver = nodes[0].node.get_our_node_id(),
			1 => {
				let len = record.accept_wire.len();
				record.accept_wire[len - 1] ^= 1;
			},
			2 => book.vouchers[0].payment_hash.0[0] ^= 1,
			3 => record.funding_txo.index ^= 1,
			4 => record.receiver_balance_msat = u64::MAX,
			_ => record.claim_margin_blocks = 0,
		}
		let encoded = channel.encode();
		channel.context.ffor_receiver_book =
			Some(FFORReceiverBook::read(&mut &original[..]).unwrap());
		let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let restored = FundedChannel::read(
			&mut &encoded[..],
			(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
		);
		assert!(matches!(restored, Err(DecodeError::InvalidValue)), "mutation {}", mutation);
	}
	// A fully drained, explicitly aborted tombstone retains its old funding scope, allowing
	// ordinary splicing to proceed without turning the old record back into live evidence.
	channel.context.ffor_receiver_book.as_mut().unwrap().abort(FFORReceiverAbortReason::Requested);
	let old_txo = channel.funding.channel_transaction_parameters.funding_outpoint;
	channel.funding.channel_transaction_parameters.funding_outpoint.as_mut().unwrap().index ^= 1;
	let encoded = channel.encode();
	channel.funding.channel_transaction_parameters.funding_outpoint = old_txo;
	let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	let mut restored = FundedChannel::read(
		&mut &encoded[..],
		(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
	)
	.unwrap();
	assert_eq!(
		restored.context.ffor_receiver_book.as_ref().unwrap().abort_reason,
		Some(FFORReceiverAbortReason::Requested)
	);
	assert_eq!(
		restored.register_ffor_receiver_setup(
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			nodes[1].node.get_our_node_id(),
			chain_hash(),
			nodes[1].node.current_best_block().height,
			20
		),
		Err(FFORReceiverError::AlreadyRegistered)
	);
}

#[test]
fn ffor_setup_manager_restore_rebinds_actual_node_and_chain() {
	use crate::ln::channelmanager::ChannelManagerReadArgs;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([55; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 300,
	};
	let (init, accept) = messages(&nodes[0], &nodes[1], channel_id, voucher);
	nodes[1]
		.node
		.register_ffor_receiver_setup(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			&init.encode().unwrap(),
			&accept.encode().unwrap(),
			20,
		)
		.unwrap();
	let encoded = nodes[1].node.encode();
	let monitor_bytes = get_monitor!(nodes[1], channel_id).encode();
	let (_, monitor) =
		<(BlockHash, ChannelMonitor<crate::util::test_channel_signer::TestChannelSigner>)>::read(
			&mut &monitor_bytes[..],
			(nodes[1].keys_manager, nodes[1].keys_manager),
		)
		.unwrap();
	for mutation in 0..3 {
		let mut bytes = encoded.clone();
		if mutation == 2 {
			// The manager's chain hash is the first field following its two version bytes.
			bytes[2..34]
				.copy_from_slice(&ChainHash::using_genesis_block(bitcoin::Network::Bitcoin)[..]);
		}
		let mut channel_monitors = new_hash_map();
		channel_monitors.insert(channel_id, &monitor);
		let node = &nodes[1];
		let result = <(BlockHash, TestChannelManager)>::read(
			&mut &bytes[..],
			ChannelManagerReadArgs {
				config: config.clone(),
				entropy_source: node.keys_manager,
				node_signer: if mutation == 1 { nodes[0].keys_manager } else { node.keys_manager },
				signer_provider: node.keys_manager,
				fee_estimator: node.fee_estimator,
				router: node.router,
				message_router: node.message_router,
				chain_monitor: node.chain_monitor,
				tx_broadcaster: node.tx_broadcaster,
				logger: node.logger,
				channel_monitors,
			},
		);
		if mutation == 0 {
			assert!(result.is_ok());
		} else {
			assert!(matches!(result, Err(DecodeError::InvalidValue)), "mutation {}", mutation);
		}
	}
}
