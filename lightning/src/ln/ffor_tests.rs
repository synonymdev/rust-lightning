use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::ffor::*;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::types::ChannelId;
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::util::config::UserConfig;
use crate::util::ser::Writeable;
use core::sync::atomic::Ordering;

pub(crate) mod quiescence;

pub(super) fn anchor_config() -> UserConfig {
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

pub(super) fn offer_voucher(
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
	let mut invalid_funding = snapshot(&nodes[1], channel_id);
	invalid_funding.holder.counterparty_sig = invalid_funding.holder.counterparty_htlc_sigs[0];
	assert_eq!(check(&book, &invalid_funding), Err(FFORCommitmentError::InvalidClaimMaterial));
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

const RECEIVER_EPOCH: [u8; 32] = [91; 32];

pub(super) fn register_book(
	receiver: &Node, sender: &Node, channel_id: ChannelId, book: &[FFORVoucher],
) {
	receiver
		.node
		.register_ffor_receiver_book(
			&channel_id,
			&sender.node.get_our_node_id(),
			RECEIVER_EPOCH,
			book,
		)
		.unwrap();
}

fn receiver_status(receiver: &Node, sender: &Node, channel_id: ChannelId) -> FFORReceiverStatus {
	let monitor = snapshot(receiver, channel_id);
	receiver
		.node
		.ffor_receiver_book_status(&channel_id, &sender.node.get_our_node_id(), &monitor)
		.unwrap()
}

pub(super) fn deliver_parked_voucher(
	sender: &Node, receiver: &Node, update: msgs::CommitmentUpdate,
) {
	for add in update.update_add_htlcs.iter() {
		receiver.node.handle_update_add_htlc(sender.node.get_our_node_id(), add);
	}
	commitment_signed_dance!(receiver, sender, update.commitment_signed, false);
	expect_and_process_pending_htlcs(receiver, false);
	assert!(receiver.node.get_and_clear_pending_events().is_empty());
}

fn drain_voucher_failures(sender: &Node, receiver: &Node, hashes: &[PaymentHash]) {
	let update = get_htlc_update_msgs!(receiver, sender.node.get_our_node_id());
	check_added_monitors(receiver, 1);
	assert_eq!(
		update.update_fail_htlcs.len() + update.update_fail_malformed_htlcs.len(),
		hashes.len()
	);
	assert!(update.update_add_htlcs.is_empty());
	assert!(update.update_fulfill_htlcs.is_empty());
	for fail in update.update_fail_htlcs.iter() {
		sender.node.handle_update_fail_htlc(receiver.node.get_our_node_id(), fail);
	}
	for fail in update.update_fail_malformed_htlcs.iter() {
		sender.node.handle_update_fail_malformed_htlc(receiver.node.get_our_node_id(), fail);
	}
	commitment_signed_dance!(sender, receiver, update.commitment_signed, false);
	for hash in hashes {
		expect_payment_failed!(sender, *hash, false);
	}
	assert!(receiver.node.get_and_clear_pending_events().is_empty());
}

#[test]
fn ffor_parking_proves_both_views_and_abort_restores_ordinary_receiving() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Registered { parked_vouchers: 0, total_vouchers: 1 }
	);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	assert!(matches!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Parked { .. }
	));
	assert_eq!(
		nodes[1].node.abort_ffor_receiver_book(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			[0; 32],
		),
		Err(FFORReceiverError::UnknownEpoch)
	);
	nodes[1]
		.node
		.abort_ffor_receiver_book(&channel_id, &nodes[0].node.get_our_node_id(), RECEIVER_EPOCH)
		.unwrap();
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Aborting { reason: FFORReceiverAbortReason::Requested }
	);
	drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::Requested }
	);
	for epoch in [RECEIVER_EPOCH, [92; 32]] {
		assert_eq!(
			nodes[1].node.register_ffor_receiver_book(
				&channel_id,
				&nodes[0].node.get_our_node_id(),
				epoch,
				&[voucher],
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
	}
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn ffor_parking_requires_empty_connected_channel_and_exact_next_id() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 1,
		payment_hash: PaymentHash([1; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let register = |voucher| {
		nodes[1].node.register_ffor_receiver_book(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			RECEIVER_EPOCH,
			&[voucher],
		)
	};
	assert_eq!(register(voucher), Err(FFORCommitmentError::InvalidVoucherBook.into()));
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	assert_eq!(
		register(FFORVoucher { htlc_id: 0, ..voucher }),
		Err(FFORCommitmentError::ChannelUnavailable.into())
	);
	pump_ffor_reconnection(&nodes[0], &nodes[1]);
	commit_voucher(&nodes[0], &nodes[1], 2_000_000);
	assert_eq!(register(voucher), Err(FFORCommitmentError::InvalidVoucherBook.into()));
}

#[test]
fn ffor_parking_mismatches_abort_without_payment_events() {
	for mutation in 0..5 {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let (mut update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		let mut expected = voucher;
		match mutation {
			0 => expected.amount_msat += 1,
			1 => expected.payment_hash = PaymentHash([42; 32]),
			2 => expected.cltv_expiry += 1,
			3 => update.update_add_htlcs[0].hold_htlc = Some(()),
			_ => update.update_add_htlcs[0].skimmed_fee_msat = Some(1),
		}
		register_book(&nodes[1], &nodes[0], channel_id, &[expected]);
		deliver_parked_voucher(&nodes[0], &nodes[1], update);
		assert_eq!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Aborting { reason: FFORReceiverAbortReason::VoucherMismatch }
		);
		drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
		assert_eq!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::VoucherMismatch }
		);
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_parking_partial_book_never_reports_parked() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	let second = FFORVoucher { htlc_id: 1, payment_hash: PaymentHash([2; 32]), ..voucher };
	register_book(&nodes[1], &nodes[0], channel_id, &[voucher, second]);
	deliver_parked_voucher(&nodes[0], &nodes[1], update);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Registered { parked_vouchers: 1, total_vouchers: 2 }
	);
	nodes[1]
		.node
		.abort_ffor_receiver_book(&channel_id, &nodes[0].node.get_our_node_id(), RECEIVER_EPOCH)
		.unwrap();
	drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
	// An unused voucher slot must not prevent an ordinary payment after the abort drains.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

/// Complete real peer messages, deferred adds, and failure commitment rounds after a crash.
fn pump_ffor_reconnection<'a, 'b, 'c>(sender: &Node<'a, 'b, 'c>, receiver: &Node<'a, 'b, 'c>) {
	connect_nodes(sender, receiver);
	for _ in 0..20 {
		let mut progressed = false;
		for (from, to) in [(sender, receiver), (receiver, sender)] {
			for event in from.node.get_and_clear_pending_msg_events() {
				progressed = true;
				let from_id = from.node.get_our_node_id();
				match event {
					MessageSendEvent::SendChannelReestablish { msg, .. } => {
						to.node.handle_channel_reestablish(from_id, &msg)
					},
					MessageSendEvent::SendChannelReady { msg, .. } => {
						to.node.handle_channel_ready(from_id, &msg)
					},
					MessageSendEvent::SendRevokeAndACK { msg, .. } => {
						to.node.handle_revoke_and_ack(from_id, &msg)
					},
					MessageSendEvent::SendAnnouncementSignatures { msg, .. } => {
						to.node.handle_announcement_signatures(from_id, &msg)
					},
					MessageSendEvent::UpdateHTLCs { updates, .. } => {
						assert!(updates.update_fulfill_htlcs.is_empty());
						assert!(updates.update_fee.is_none());
						for add in updates.update_add_htlcs {
							to.node.handle_update_add_htlc(from_id, &add);
						}
						for fail in updates.update_fail_htlcs {
							to.node.handle_update_fail_htlc(from_id, &fail);
						}
						for fail in updates.update_fail_malformed_htlcs {
							to.node.handle_update_fail_malformed_htlc(from_id, &fail);
						}
						to.node.handle_commitment_signed_batch_test(
							from_id,
							&updates.commitment_signed,
						);
					},
					MessageSendEvent::BroadcastChannelAnnouncement { .. }
					| MessageSendEvent::BroadcastChannelUpdate { .. }
					| MessageSendEvent::SendChannelUpdate { .. } => {},
					other => panic!("Unexpected peer event during voucher unwind: {:?}", other),
				}
			}
			if from.node.needs_pending_htlc_processing() {
				from.node.process_pending_htlc_forwards();
				progressed = true;
			}
			from.chain_monitor.added_monitors.lock().unwrap().clear();
		}
		assert!(receiver.node.get_and_clear_pending_events().is_empty());
		if !progressed {
			return;
		}
	}
	panic!("Voucher unwind did not converge");
}

#[test]
fn ffor_parking_crash_boundaries_preserve_identity_and_drain_stock_htlcs() {
	// Registration, uncommitted add, first commitment, both commitments before interception,
	// parked, explicit abort, failure commitment sent, and fully drained tombstone.
	for crash_at in 0..8 {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let (persister, chain_monitor);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let reloaded;
		let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let sender_id = nodes[0].node.get_our_node_id();
		let receiver_id = nodes[1].node.get_our_node_id();
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
		if crash_at >= 1 {
			nodes[1].node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
		}
		if crash_at == 2 {
			nodes[1].node.handle_commitment_signed_batch_test(sender_id, &update.commitment_signed);
			check_added_monitors(&nodes[1], 1);
			let _undelivered = get_revoke_commit_msgs!(&nodes[1], sender_id);
		}
		if crash_at >= 3 {
			commitment_signed_dance!(&nodes[1], &nodes[0], update.commitment_signed, false);
		}
		if crash_at >= 4 {
			expect_and_process_pending_htlcs(&nodes[1], false);
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		}
		if crash_at >= 5 {
			nodes[1]
				.node
				.abort_ffor_receiver_book(&channel_id, &sender_id, RECEIVER_EPOCH)
				.unwrap();
		}
		if crash_at == 6 {
			let _undelivered = get_htlc_update_msgs!(&nodes[1], sender_id);
			check_added_monitors(&nodes[1], 1);
		}
		if crash_at == 7 {
			drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
		}
		let monitor_encoded = get_monitor!(nodes[1], channel_id).encode();
		let manager_encoded = nodes[1].node.encode();
		nodes[0].node.peer_disconnected(receiver_id);
		reload_node!(
			nodes[1],
			config,
			&manager_encoded,
			&[&monitor_encoded],
			persister,
			chain_monitor,
			reloaded
		);
		assert_eq!(
			nodes[1].node.register_ffor_receiver_book(
				&channel_id,
				&sender_id,
				RECEIVER_EPOCH,
				&[voucher]
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
		pump_ffor_reconnection(&nodes[0], &nodes[1]);
		assert_eq!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Aborted {
				reason: if crash_at >= 5 {
					FFORReceiverAbortReason::Requested
				} else {
					FFORReceiverAbortReason::Restarted
				},
			},
			"crash checkpoint {}",
			crash_at
		);
		if crash_at != 7 {
			expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
		}
		// Both stock commitment sets have drained. The one-registration tombstone remains.
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_parking_serialization_requires_the_channel_compatibility_fence() {
	use crate::ln::channel::FundedChannel;
	use crate::types::features::ChannelTypeFeatures;
	use crate::util::ser::ReadableArgs;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let serialize_channel = || {
		let peers = nodes[1].node.per_peer_state.read().unwrap();
		let peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		peer.channel_by_id.get(&channel_id).unwrap().as_funded().unwrap().encode()
	};
	let ordinary = serialize_channel();
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([1; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
	let registered = serialize_channel();
	let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	let read_channel = |bytes: &[u8]| {
		FundedChannel::read(
			&mut &bytes[..],
			(&nodes[1].keys_manager, &nodes[1].keys_manager, &features),
		)
	};
	assert!(read_channel(&ordinary).is_ok());
	assert!(read_channel(&registered).is_ok());
	// This deliberately simple book contains no 0xfdfffe sequence itself, so the last occurrence
	// is the channel's required type. Model a reader that does not recognize that even type.
	let mut unknown = registered.clone();
	let offset = unknown.windows(3).rposition(|bytes| bytes == [0xfd, 0xff, 0xfe]).unwrap();
	unknown[offset + 2] = 0xfc;
	assert!(matches!(read_channel(&unknown), Err(msgs::DecodeError::UnknownRequiredFeature)));
	if let Ok(directory) = std::env::var("FFOR_LEGACY_FIXTURE_DIR") {
		std::fs::write(std::path::Path::new(&directory).join("ordinary-channel.bin"), &ordinary)
			.unwrap();
		std::fs::write(
			std::path::Path::new(&directory).join("registered-channel.bin"),
			&registered,
		)
		.unwrap();
	}
}

#[test]
fn ffor_parking_waits_for_both_rounds_and_monitor_completion() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let sender_id = nodes[0].node.get_our_node_id();
	let receiver_id = nodes[1].node.get_our_node_id();
	let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
	let assert_unparked = || {
		assert_eq!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Registered { parked_vouchers: 0, total_vouchers: 1 }
		);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	};
	nodes[1].node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
	assert_unparked();
	nodes[1].node.handle_commitment_signed_batch_test(sender_id, &update.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (revoke, commitment) = get_revoke_commit_msgs!(&nodes[1], sender_id);
	assert_unparked();
	nodes[0].node.handle_revoke_and_ack(receiver_id, &revoke);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(receiver_id, &commitment);
	check_added_monitors(&nodes[0], 1);
	let revoke = get_event_msg!(&nodes[0], MessageSendEvent::SendRevokeAndACK, receiver_id);
	assert_unparked();
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_revoke_and_ack(sender_id, &revoke);
	check_added_monitors(&nodes[1], 1);
	assert_unparked();
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let update_id = get_monitor!(nodes[1], channel_id).get_latest_update_id();
	nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(channel_id, update_id).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	expect_and_process_pending_htlcs(&nodes[1], false);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(matches!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Parked { .. }
	));
}

#[test]
fn ffor_parking_multiple_rounds_and_extra_add_abort_the_entire_book() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (first_update, first, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
	let (mut route, second_hash, _, secret) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], 3_000_000);
	route.paths[0].hops[0].cltv_expiry_delta = 144;
	let second = FFORVoucher {
		htlc_id: first.htlc_id + 1,
		payment_hash: second_hash,
		amount_msat: 3_000_000,
		..first
	};
	register_book(&nodes[1], &nodes[0], channel_id, &[first, second]);
	deliver_parked_voucher(&nodes[0], &nodes[1], first_update);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Registered { parked_vouchers: 1, total_vouchers: 2 }
	);
	nodes[0]
		.node
		.send_payment_with_route(
			route,
			second_hash,
			RecipientOnionFields::secret_only(secret),
			PaymentId(second_hash.0),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let second_update = get_htlc_update_msgs!(&nodes[0], nodes[1].node.get_our_node_id());
	deliver_parked_voucher(&nodes[0], &nodes[1], second_update);
	assert!(matches!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Parked { .. }
	));
	let (extra, _, _) = offer_voucher(&nodes[0], &nodes[1], 1_000_000);
	nodes[1]
		.node
		.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &extra.update_add_htlcs[0]);
	// Abort queues the older, committed vouchers even while this extra add is still in flight.
	// Use the same real message pump after disconnect to exercise their combined unwind safely.
	nodes[1].node.handle_commitment_signed_batch_test(
		nodes[0].node.get_our_node_id(),
		&extra.commitment_signed,
	);
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
	pump_ffor_reconnection(&nodes[0], &nodes[1]);
	assert_eq!(
		receiver_status(&nodes[1], &nodes[0], channel_id),
		FFORReceiverStatus::Aborted { reason: FFORReceiverAbortReason::VoucherMismatch }
	);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(
		events
			.iter()
			.filter(|event| matches!(event, crate::events::Event::PaymentFailed { .. }))
			.count(),
		3
	);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn ffor_parking_retries_unavailable_node_signer_before_and_after_restart() {
	// Recovery while registered, after explicit abort, and after a persisted restart abort.
	for recovery in 0..3 {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let (persister, chain_monitor);
		let config = anchor_config();
		let node_chanmgrs =
			create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
		let reloaded;
		let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let sender_id = nodes[0].node.get_our_node_id();
		let receiver_id = nodes[1].node.get_our_node_id();
		let (update, voucher, _) = offer_voucher(&nodes[0], &nodes[1], 2_000_000);
		register_book(&nodes[1], &nodes[0], channel_id, &[voucher]);
		nodes[1].node.handle_update_add_htlc(sender_id, &update.update_add_htlcs[0]);
		commitment_signed_dance!(&nodes[1], &nodes[0], update.commitment_signed, false);
		nodes[1].keys_manager.unavailable_node_ecdh.store(true, Ordering::Release);

		for _ in 0..3 {
			assert!(nodes[1].node.needs_pending_htlc_processing());
			nodes[1].node.process_pending_htlc_forwards();
			assert!(nodes[1].node.needs_pending_htlc_processing());
			assert_eq!(
				receiver_status(&nodes[1], &nodes[0], channel_id),
				FFORReceiverStatus::Registered { parked_vouchers: 0, total_vouchers: 1 }
			);
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		}

		if recovery == 1 {
			nodes[1]
				.node
				.abort_ffor_receiver_book(&channel_id, &sender_id, RECEIVER_EPOCH)
				.unwrap();
		} else if recovery == 2 {
			let monitor_encoded = get_monitor!(nodes[1], channel_id).encode();
			let manager_encoded = nodes[1].node.encode();
			nodes[0].node.peer_disconnected(receiver_id);
			reload_node!(
				nodes[1],
				config,
				&manager_encoded,
				&[&monitor_encoded],
				persister,
				chain_monitor,
				reloaded
			);
		}

		if recovery != 0 {
			nodes[1].node.process_pending_htlc_forwards();
			assert!(nodes[1].node.needs_pending_htlc_processing());
			assert_eq!(
				receiver_status(&nodes[1], &nodes[0], channel_id),
				FFORReceiverStatus::Aborting {
					reason: if recovery == 1 {
						FFORReceiverAbortReason::Requested
					} else {
						FFORReceiverAbortReason::Restarted
					}
				}
			);
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		}

		nodes[1].keys_manager.unavailable_node_ecdh.store(false, Ordering::Release);
		if recovery == 2 {
			pump_ffor_reconnection(&nodes[0], &nodes[1]);
			expect_payment_failed!(&nodes[0], voucher.payment_hash, false);
		} else {
			nodes[1].node.process_pending_htlc_forwards();
			if recovery == 0 {
				assert!(matches!(
					receiver_status(&nodes[1], &nodes[0], channel_id),
					FFORReceiverStatus::Parked { .. }
				));
				assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
				nodes[1]
					.node
					.abort_ffor_receiver_book(&channel_id, &sender_id, RECEIVER_EPOCH)
					.unwrap();
			}
			drain_voucher_failures(&nodes[0], &nodes[1], &[voucher.payment_hash]);
		}
		assert!(!nodes[1].node.needs_pending_htlc_processing());
		assert!(matches!(
			receiver_status(&nodes[1], &nodes[0], channel_id),
			FFORReceiverStatus::Aborted { .. }
		));
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	}
}

#[test]
fn ffor_registration_waits_for_its_own_durable_snapshot() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let config = anchor_config();
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config)],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let first_channel = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let second_channel = create_announced_chan_between_nodes(&nodes, 2, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([3; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let receiver = nodes[1].node;
	let first = receiver
		.register_ffor_receiver_book(
			&first_channel,
			&nodes[0].node.get_our_node_id(),
			[4; 32],
			&[voucher],
		)
		.unwrap();
	assert!(!receiver.is_ffor_state_persisted(&first));
	let earlier_snapshot = receiver.capture_ffor_persistence();
	let second = receiver
		.register_ffor_receiver_book(
			&second_channel,
			&nodes[2].node.get_our_node_id(),
			[5; 32],
			&[voucher],
		)
		.unwrap();
	// This later serialization contains both registrations, but the earlier captured token
	// deliberately acknowledges only the first. A failed/cancelled write acknowledges neither.
	let stored = receiver.encode();
	assert!(!stored.is_empty());
	assert!(!receiver.is_ffor_state_persisted(&first));
	assert!(!receiver.is_ffor_state_persisted(&second));
	for _ in 0..3 {
		assert!(receiver.get_and_clear_needs_persistence());
	}
	receiver.ffor_persistence_completed(earlier_snapshot).unwrap();
	assert!(receiver.is_ffor_state_persisted(&first));
	assert!(!receiver.is_ffor_state_persisted(&second));
	assert!(receiver.get_and_clear_needs_persistence());
	let latest = receiver.capture_ffor_persistence();
	let _stored = receiver.encode();
	receiver.ffor_persistence_completed(latest).unwrap();
	assert!(receiver.is_ffor_state_persisted(&second));
	assert!(!receiver.get_and_clear_needs_persistence());
	assert!(!nodes[0].node.is_ffor_state_persisted(&first));
	assert!(receiver.ffor_persistence_completed(nodes[0].node.capture_ffor_persistence()).is_err());
}

#[test]
fn ffor_persistence_tokens_do_not_authorize_a_restored_manager() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister, chain_monitor);
	let config = anchor_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let reloaded;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([7; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let requirement = nodes[1]
		.node
		.register_ffor_receiver_book(
			&channel_id,
			&nodes[0].node.get_our_node_id(),
			[8; 32],
			&[voucher],
		)
		.unwrap();
	let old_token = nodes[1].node.capture_ffor_persistence();
	let manager = nodes[1].node.encode();
	let monitor = get_monitor!(nodes[1], channel_id).encode();
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	reload_node!(nodes[1], config, &manager, &[&monitor], persister, chain_monitor, reloaded);
	assert!(nodes[1].node.ffor_persistence_completed(old_token).is_err());
	assert!(!nodes[1].node.is_ffor_state_persisted(&requirement));
}
