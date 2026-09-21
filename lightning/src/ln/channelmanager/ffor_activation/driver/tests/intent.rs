use super::*;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

#[test]
fn ffor_driver_read_only_intent_matches_every_original_parameter() {
	fixture!(nodes, sender, receiver, channel, false);
	let voucher = FFORVoucher {
		htlc_id: 0,
		payment_hash: PaymentHash([9; 32]),
		amount_msat: 2_000_000,
		cltv_expiry: 200,
	};
	let peer = sender.node.get_our_node_id();
	let connection = receiver.node.ffor_peer_connection(&peer).unwrap();
	let mut params = parameters(&voucher);
	params.amounts_msat.push(3_000_000);
	params.witness_peers = Some(
		[101, 102]
			.iter()
			.map(|byte| {
				PublicKey::from_secret_key(
					&Secp256k1::new(),
					&SecretKey::from_slice(&[*byte; 32]).unwrap(),
				)
			})
			.collect(),
	);
	assert_eq!(
		receiver.node.validate_ffor_receiver_request_intent(
			params.local_request_id,
			&channel,
			&peer,
			&params,
		),
		Ok(None)
	);
	let id = receiver.node.prepare_ffor_receiver(&channel, &connection, params.clone()).unwrap();
	let before = receiver.node.encode();
	assert_eq!(
		receiver.node.validate_ffor_receiver_request_intent(
			params.local_request_id,
			&channel,
			&peer,
			&params,
		),
		Ok(Some(id))
	);
	let changes: &[fn(&mut FFORReceiverParameters)] = &[
		|params| params.local_request_id[0] ^= 1,
		|params| params.amounts_msat[0] += 1,
		|params| params.amounts_msat.reverse(),
		|params| params.amounts_msat.clear(),
		|params| params.minimum_payment_msat += 1,
		|params| params.settlement_deadline -= 1,
		|params| params.voucher_expiry += 1,
		|params| params.fee_base_msat += 1,
		|params| params.fee_proportional_millionths += 1,
		|params| params.claim_margin_blocks += 1,
		|params| params.witness_peers.as_mut().unwrap().reverse(),
		|params| {
			params.witness_peers.as_mut().unwrap().pop();
		},
		|params| params.witness_peers = None,
		|params| params.hash_chain = true,
	];
	for (index, change) in changes.iter().enumerate() {
		let mut changed = params.clone();
		change(&mut changed);
		assert_eq!(
			receiver.node.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&changed,
			),
			Err(FFORReceiverError::AlreadyRegistered),
			"parameter change {} was accepted",
			index
		);
	}
	for (other_channel, other_peer) in
		[(ChannelId([0; 32]), peer), (channel, receiver.node.get_our_node_id())]
	{
		assert_eq!(
			receiver.node.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&other_channel,
				&other_peer,
				&params,
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
	}
	let mut absent = params.clone();
	absent.local_request_id = [0; 32];
	assert_eq!(
		receiver.node.validate_ffor_receiver_request_intent(
			absent.local_request_id,
			&channel,
			&peer,
			&absent,
		),
		Ok(None)
	);
	assert_eq!(before, receiver.node.encode());
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver(&id, &connection, |_| panic!("read released Init"))
			.unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	// Historical correlation does not require a connection, unexpired deadline or live request.
	receiver.node.peer_disconnected(peer);
	receiver.node.best_block.write().unwrap().height = params.settlement_deadline;
	let bytes = persist(receiver);
	let monitor = get_monitor!(receiver, channel).encode();
	let restored = restore(receiver, &bytes, &monitor).unwrap();
	assert!(restored.ffor_peer_connection(&peer).is_err());
	assert_eq!(
		restored.validate_ffor_receiver_request_intent(
			params.local_request_id,
			&channel,
			&peer,
			&params
		),
		Ok(Some(id))
	);
	assert!(restored.get_and_clear_pending_msg_events().is_empty());
	assert!(restored.get_and_clear_pending_events().is_empty());
}

#[test]
fn ffor_driver_read_only_intent_preserves_promoted_and_removed_history() {
	for receiver_funds in [false, true] {
		fixture!(nodes, sender, receiver, channel, receiver_funds);
		let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
		let peer = sender.node.get_our_node_id();
		let params = parameters(&voucher);
		let connection = receiver.node.ffor_peer_connection(&peer).unwrap();
		let id =
			receiver.node.prepare_ffor_receiver(&channel, &connection, params.clone()).unwrap();
		persist(receiver);
		let init = emit(receiver, &id, &connection);
		let accepted = accept(sender, receiver, channel, voucher, &init).encode().unwrap();
		receiver.node.handle_ffor_receiver_message(&connection, &accepted).unwrap();
		assert_eq!(
			receiver.node.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&params
			),
			Ok(Some(id))
		);
		deliver_parked_voucher(sender, receiver, update);
		let bytes = persist(receiver);
		let monitor = get_monitor!(receiver, channel).encode();
		let restored = restore(receiver, &bytes, &monitor).unwrap();
		assert_eq!(
			restored.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&params
			),
			Ok(Some(id))
		);
		let mut conflict = params.clone();
		conflict.claim_margin_blocks += 1;
		assert_eq!(
			restored.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&conflict
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
		assert!(restored.get_and_clear_pending_events().is_empty());
		receiver
			.node
			.force_close_broadcasting_latest_txn(&channel, &peer, "request intent history".into())
			.unwrap();
		receiver.node.get_and_clear_pending_msg_events();
		receiver.node.get_and_clear_pending_events();
		receiver.chain_monitor.added_monitors.lock().unwrap().clear();
		assert!(receiver.node.list_channels().is_empty());
		assert_eq!(
			receiver.node.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&params
			),
			Ok(Some(id))
		);
		let closed_bytes = persist(receiver);
		let closed_monitor = get_monitor!(receiver, channel).encode();
		let closed = restore(receiver, &closed_bytes, &closed_monitor).unwrap();
		assert!(closed.list_channels().is_empty());
		assert_eq!(
			closed.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&params
			),
			Ok(Some(id))
		);
		assert_eq!(
			closed.validate_ffor_receiver_request_intent(
				params.local_request_id,
				&channel,
				&peer,
				&conflict
			),
			Err(FFORReceiverError::AlreadyRegistered)
		);
		assert!(closed.get_and_clear_pending_events().is_empty());
	}
}
