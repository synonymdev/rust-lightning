use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::ffor::*;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::types::ChannelId;
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::util::config::UserConfig;
use crate::util::ser::Writeable;

fn anchor_config() -> UserConfig {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.manually_accept_inbound_channels = true;
	config
}

fn snapshot(node: &Node, channel_id: ChannelId) -> FFORMonitorSnapshot {
	get_monitor!(node, channel_id).ffor_commitment_snapshot().unwrap()
}

fn verify(
	node: &Node, counterparty: &Node, channel_id: ChannelId, party: FFORSettlementParty,
	vouchers: &[FFORVoucher],
) -> Result<FFORVoucherCommitments, FFORCommitmentError> {
	let monitor = snapshot(node, channel_id);
	node.node.ffor_voucher_commitments(
		&channel_id,
		&counterparty.node.get_our_node_id(),
		party,
		vouchers,
		&monitor,
	)
}

fn offer_voucher(
	sender: &Node, receiver: &Node, amount_msat: u64,
) -> (msgs::CommitmentUpdate, FFORVoucher, PaymentSecret) {
	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(sender, receiver, amount_msat);
	route.paths[0].hops[0].cltv_expiry_delta = 144;
	sender
		.node
		.send_payment_with_route(
			route,
			payment_hash,
			RecipientOnionFields::secret_only(payment_secret),
			PaymentId(payment_hash.0),
		)
		.unwrap();
	check_added_monitors(sender, 1);
	let update = get_htlc_update_msgs!(sender, receiver.node.get_our_node_id());
	let add = &update.update_add_htlcs[0];
	let voucher = FFORVoucher {
		htlc_id: add.htlc_id,
		payment_hash: add.payment_hash,
		amount_msat: add.amount_msat,
		cltv_expiry: add.cltv_expiry,
	};
	(update, voucher, payment_secret)
}

fn commit_voucher(sender: &Node, receiver: &Node, amount_msat: u64) -> FFORVoucher {
	let (update, voucher, secret) = offer_voucher(sender, receiver, amount_msat);
	receiver
		.node
		.handle_update_add_htlc(sender.node.get_our_node_id(), &update.update_add_htlcs[0]);
	commitment_signed_dance!(receiver, sender, update.commitment_signed, false);
	expect_and_process_pending_htlcs(receiver, false);
	expect_payment_claimable!(receiver, voucher.payment_hash, secret, amount_msat);
	voucher
}

#[test]
fn ffor_requires_both_commitment_rounds_and_completed_persistence() {
	for pending_persistence in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let sender = &nodes[0];
		let receiver = &nodes[1];
		let sender_id = sender.node.get_our_node_id();
		let receiver_id = receiver.node.get_our_node_id();
		let (update, voucher, secret) = offer_voucher(sender, receiver, 2_000_000);
		let book = [voucher];
		assert_eq!(
			verify(sender, receiver, channel_id, FFORSettlementParty::Holder, &book),
			Err(FFORCommitmentError::PendingUpdates)
		);
		receiver.node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
		assert_eq!(
			verify(receiver, sender, channel_id, FFORSettlementParty::Counterparty, &book),
			Err(FFORCommitmentError::PendingUpdates)
		);
		receiver.node.handle_commitment_signed_batch_test(sender_id, &update.commitment_signed);
		check_added_monitors(receiver, 1);
		let (revoke, commitment) = get_revoke_commit_msgs!(receiver, sender_id);
		sender.node.handle_revoke_and_ack(receiver_id, &revoke);
		check_added_monitors(sender, 1);
		assert_eq!(
			verify(sender, receiver, channel_id, FFORSettlementParty::Holder, &book),
			Err(FFORCommitmentError::PendingUpdates)
		);
		sender.node.handle_commitment_signed_batch_test(receiver_id, &commitment);
		check_added_monitors(sender, 1);
		let revoke = get_event_msg!(sender, MessageSendEvent::SendRevokeAndACK, receiver_id);
		assert_eq!(
			verify(receiver, sender, channel_id, FFORSettlementParty::Counterparty, &book),
			Err(FFORCommitmentError::PendingUpdates)
		);
		if pending_persistence {
			chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		}
		receiver.node.handle_revoke_and_ack(sender_id, &revoke);
		check_added_monitors(receiver, 1);
		if pending_persistence {
			assert_eq!(
				verify(receiver, sender, channel_id, FFORSettlementParty::Counterparty, &book),
				Err(FFORCommitmentError::PendingUpdates)
			);
			chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
			let update_id = get_monitor!(receiver, channel_id).get_latest_update_id();
			receiver
				.chain_monitor
				.chain_monitor
				.channel_monitor_updated(channel_id, update_id)
				.unwrap();
			assert!(receiver.node.get_and_clear_pending_msg_events().is_empty());
		}
		expect_and_process_pending_htlcs(receiver, false);
		expect_payment_claimable!(receiver, voucher.payment_hash, secret, voucher.amount_msat);
		let local =
			verify(sender, receiver, channel_id, FFORSettlementParty::Holder, &book).unwrap();
		let remote =
			verify(receiver, sender, channel_id, FFORSettlementParty::Counterparty, &book).unwrap();
		assert_eq!(local.holder, remote.counterparty);
		assert_eq!(local.counterparty, remote.holder);
		assert_eq!(local.holder.number, 1);
		assert_eq!(local.counterparty.number, 1);
	}
}

#[test]
fn ffor_checks_complete_book_claim_material_and_stale_snapshots() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let first = commit_voucher(&nodes[0], &nodes[1], 2_000_123);
	let stale = snapshot(&nodes[1], channel_id);
	let second = commit_voucher(&nodes[0], &nodes[1], 3_000_456);
	let book = [first, second];
	let check = |vouchers: &[FFORVoucher], monitor: &FFORMonitorSnapshot| {
		nodes[1].node.ffor_voucher_commitments(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			FFORSettlementParty::Counterparty,
			vouchers,
			monitor,
		)
	};
	assert_eq!(check(&book, &stale), Err(FFORCommitmentError::MonitorMismatch));
	let monitor = snapshot(&nodes[1], channel_id);
	assert!(check(&book, &monitor).is_ok());
	assert_eq!(check(&book[..1], &monitor), Err(FFORCommitmentError::InvalidVoucherBook));
	assert_eq!(check(&[], &monitor), Err(FFORCommitmentError::InvalidVoucherBook));
	for mutation in 0..6 {
		let mut wrong = book;
		match mutation {
			0 => wrong[0].htlc_id += 1,
			1 => wrong[0].payment_hash = PaymentHash([42; 32]),
			2 => wrong[0].amount_msat += 1,
			3 => wrong[0].cltv_expiry += 1,
			4 => wrong[1].payment_hash = wrong[0].payment_hash,
			_ => wrong[0].amount_msat = 0,
		}
		assert_eq!(check(&wrong, &monitor), Err(FFORCommitmentError::InvalidVoucherBook));
	}
	let mut missing = snapshot(&nodes[1], channel_id);
	missing.holder.counterparty_htlc_sigs.pop();
	assert_eq!(check(&book, &missing), Err(FFORCommitmentError::InvalidClaimMaterial));
	let mut invalid = snapshot(&nodes[1], channel_id);
	invalid.holder.counterparty_htlc_sigs[0] = invalid.holder.counterparty_sig;
	assert_eq!(check(&book, &invalid), Err(FFORCommitmentError::InvalidClaimMaterial));
	let mut wrong_id = snapshot(&nodes[1], channel_id);
	wrong_id.update_id -= 1;
	assert_eq!(check(&book, &wrong_id), Err(FFORCommitmentError::MonitorMismatch));
	assert_eq!(
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Holder, &book),
		Err(FFORCommitmentError::InvalidVoucherBook)
	);
}

#[test]
fn ffor_rejects_trimmed_vouchers_and_unsupported_channel_types() {
	for anchors in [false, true] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let mut config = anchor_config();
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = anchors;
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let book = [commit_voucher(&nodes[0], &nodes[1], 100_000)];
		let expected = if anchors {
			FFORCommitmentError::TrimmedVoucher
		} else {
			FFORCommitmentError::UnsupportedChannelType
		};
		assert_eq!(
			verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &book),
			Err(expected)
		);
		assert_eq!(
			verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book),
			Err(expected)
		);
	}
}

#[test]
fn ffor_commitments_survive_manager_and_monitor_reload() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister, chain_monitor);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let reloaded;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let book = [commit_voucher(&nodes[0], &nodes[1], 2_000_000)];
	let before =
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book).unwrap();
	let monitor_encoded = get_monitor!(nodes[1], channel_id).encode();
	let manager_encoded = nodes[1].node.encode();
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	reload_node!(
		nodes[1],
		config,
		&manager_encoded,
		&[&monitor_encoded],
		persister,
		chain_monitor,
		reloaded
	);
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	let after =
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book).unwrap();
	assert_eq!(before, after);
}

#[test]
fn ffor_rejects_extra_reverse_htlcs_and_remains_read_only() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let book = [commit_voucher(&nodes[0], &nodes[1], 2_000_000)];
	let before =
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book).unwrap();
	let stale = snapshot(&nodes[1], channel_id);
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let after =
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book).unwrap();
	assert!(after.holder.number > before.holder.number);
	assert!(after.counterparty.number > before.counterparty.number);
	assert_eq!(
		nodes[1].node.ffor_voucher_commitments(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			FFORSettlementParty::Counterparty,
			&book,
			&stale,
		),
		Err(FFORCommitmentError::MonitorMismatch)
	);
	commit_voucher(&nodes[1], &nodes[0], 1_000_000);
	assert_eq!(
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &book),
		Err(FFORCommitmentError::InvalidVoucherBook)
	);
	assert_eq!(
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book),
		Err(FFORCommitmentError::InvalidVoucherBook)
	);
}

#[test]
fn ffor_validates_book_id_overflow_slot_limit_and_uniform_expiry() {
	let voucher = FFORVoucher {
		htlc_id: u64::MAX,
		payment_hash: PaymentHash([1; 32]),
		amount_msat: 1_000_000,
		cltv_expiry: 200,
	};
	assert!(validate_vouchers(&[voucher]).is_ok());
	let mut next = voucher;
	next.htlc_id = 0;
	next.payment_hash = PaymentHash([2; 32]);
	assert_eq!(validate_vouchers(&[voucher, next]), Err(FFORCommitmentError::InvalidVoucherBook));
	let oversized = vec![voucher; 484];
	assert_eq!(validate_vouchers(&oversized), Err(FFORCommitmentError::InvalidVoucherBook));
	let mut book: Vec<_> = (0..483u64)
		.map(|index| {
			let mut hash = [0; 32];
			hash[..8].copy_from_slice(&index.to_be_bytes());
			FFORVoucher { htlc_id: index, payment_hash: PaymentHash(hash), ..voucher }
		})
		.collect();
	assert!(validate_vouchers(&book).is_ok());
	book[482].cltv_expiry += 1;
	assert_eq!(validate_vouchers(&book), Err(FFORCommitmentError::InvalidVoucherBook));
}

#[test]
fn ffor_rejects_partial_round_after_reload_until_reestablishment_completes() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister, chain_monitor);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let reloaded;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, secret) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	let sender_id = nodes[0].node.get_our_node_id();
	let receiver_id = nodes[1].node.get_our_node_id();
	nodes[1].node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(sender_id, &update.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (revoke, _) = get_revoke_commit_msgs!(&nodes[1], sender_id);
	nodes[0].node.handle_revoke_and_ack(receiver_id, &revoke);
	check_added_monitors(&nodes[0], 1);
	let monitor_encoded = get_monitor!(nodes[0], channel_id).encode();
	let manager_encoded = nodes[0].node.encode();
	nodes[1].node.peer_disconnected(sender_id);
	reload_node!(
		nodes[0],
		config,
		&manager_encoded,
		&[&monitor_encoded],
		persister,
		chain_monitor,
		reloaded
	);
	assert!(
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &[voucher]).is_err()
	);
	let mut reconnect = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect.pending_responding_commitment_signed = (true, false);
	reconnect.send_announcement_sigs = (true, false);
	reconnect_nodes(reconnect);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(&nodes[1], voucher.payment_hash, secret, voucher.amount_msat);
	assert!(
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &[voucher]).is_ok()
	);
	assert!(verify(
		&nodes[1],
		&nodes[0],
		channel_id,
		FFORSettlementParty::Counterparty,
		&[voucher]
	)
	.is_ok());
}

#[test]
fn ffor_receiver_funder_uses_both_contest_delays_and_dust_limits() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut recipient_config = anchor_config();
	recipient_config.channel_handshake_config.our_to_self_delay = 144;
	let mut settlement_config = anchor_config();
	settlement_config.channel_handshake_config.our_to_self_delay = 288;
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(recipient_config), Some(settlement_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	// LDK's public configuration uses a fixed dust limit. Configure the fixture's two matching
	// views before the voucher round to model peers negotiating different dust limits.
	for index in 0..2 {
		let peer_id = nodes[1 - index].node.get_our_node_id();
		let peers = nodes[index].node.per_peer_state.read().unwrap();
		let mut peer = peers.get(&peer_id).unwrap().lock().unwrap();
		let channel = peer.channel_by_id.get_mut(&channel_id).unwrap();
		channel.context_mut().holder_dust_limit_satoshis = if index == 0 { 1000 } else { 354 };
		channel.context_mut().counterparty_dust_limit_satoshis =
			if index == 0 { 354 } else { 1000 };
	}
	let first = commit_voucher(&nodes[1], &nodes[0], 2_000_123);
	let recipient =
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Counterparty, &[first])
			.unwrap();
	let settlement =
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Holder, &[first]).unwrap();
	assert_eq!(recipient.holder, settlement.counterparty);
	assert_eq!(recipient.counterparty, settlement.holder);

	let second = commit_voucher(&nodes[1], &nodes[0], 400_000);
	assert_eq!(snapshot(&nodes[0], channel_id).holder.nondust_htlcs().len(), 1);
	assert_eq!(snapshot(&nodes[1], channel_id).holder.nondust_htlcs().len(), 2);
	let book = [first, second];
	assert_eq!(
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Counterparty, &book),
		Err(FFORCommitmentError::TrimmedVoucher)
	);
	assert_eq!(
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Holder, &book),
		Err(FFORCommitmentError::TrimmedVoucher)
	);
}

#[test]
fn ffor_rejects_pending_fee_updates() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let book = [commit_voucher(&nodes[0], &nodes[1], 2_000_000)];
	*chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap() += 20;
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let update = get_htlc_update_msgs!(&nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(
		verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &book),
		Err(FFORCommitmentError::PendingUpdates)
	);
	nodes[1]
		.node
		.handle_update_fee(nodes[0].node.get_our_node_id(), update.update_fee.as_ref().unwrap());
	assert_eq!(
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book),
		Err(FFORCommitmentError::PendingUpdates)
	);
	commitment_signed_dance!(&nodes[1], &nodes[0], update.commitment_signed, false);
	assert!(verify(&nodes[0], &nodes[1], channel_id, FFORSettlementParty::Holder, &book).is_ok());
	assert!(
		verify(&nodes[1], &nodes[0], channel_id, FFORSettlementParty::Counterparty, &book).is_ok()
	);
}
