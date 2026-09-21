//! Optional public-seed fixture for the Node storage join, generated through the real driver.
use super::*;
use crate::ln::ffor::{FFORReceiverParameters, FFORReceiverProgress};
use bitcoin::constants::ChainHash;

fn emit(
	receiver: &Node, id: &crate::ln::ffor::FFORReceiverId,
	connection: &crate::ln::ffor::FFORPeerConnection,
) -> Vec<u8> {
	let mut wire = Vec::new();
	receiver
		.node
		.advance_ffor_receiver(id, connection, |message| {
			wire = message.to_vec();
			Ok(())
		})
		.unwrap();
	assert!(!wire.is_empty());
	wire
}

#[test]
fn ffor_invoice_public_driver_one_slot_fixture_preserves_native_request() {
	let mut chanmon_cfgs = create_chanmon_cfgs(3);
	let wallet_root =
		bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[91; 64]).unwrap();
	chanmon_cfgs[1].keys_manager = crate::util::test_utils::TestKeysInterface::new(
		&wallet_root.private_key.secret_bytes(),
		bitcoin::Network::Testnet,
	);
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	node_cfgs[1].node_seed = wallet_root.private_key.secret_bytes();
	let config = anchor_config();
	let managers = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config)],
	);
	let nodes = create_network(3, &node_cfgs, &managers);
	let channel =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let public = create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100_000, 40_000_000);
	let (sender, receiver, witness) = (&nodes[0], &nodes[1], &nodes[2]);
	let announcement = nodes[0]
		.network_graph
		.read_only()
		.channels()
		.get(&public.0.contents.short_channel_id)
		.unwrap()
		.announcement_message
		.clone()
		.unwrap();
	let mut update = public.0;
	update.contents.timestamp = invoice_time().unwrap() as u32;
	update.signature = witness
		.keys_manager
		.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(&update.contents))
		.unwrap();
	let route = FFORWitnessRouteEvidence { announcement, update };
	let (update, voucher, _) = offer_voucher(sender, receiver, 2_000_000);
	let mut local = b"ldk-node/ffor/request-id/v1".to_vec();
	local.extend_from_slice(&ChainHash::TESTNET3.to_bytes());
	local.extend_from_slice(&receiver.node.get_our_node_id().serialize());
	local.extend_from_slice(&(b"request-fixture".len() as u16).to_be_bytes());
	local.extend_from_slice(b"request-fixture");
	let local_request_id = sha256::Hash::hash(&local).to_byte_array();
	let parameters = FFORReceiverParameters {
		local_request_id,
		amounts_msat: vec![voucher.amount_msat],
		minimum_payment_msat: voucher.amount_msat,
		settlement_deadline: voucher.cltv_expiry - 20,
		voucher_expiry: voucher.cltv_expiry,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		claim_margin_blocks: 20,
		witness_peers: Some(vec![witness.node.get_our_node_id()]),
		hash_chain: false,
	};
	let connection = receiver.node.ffor_peer_connection(&sender.node.get_our_node_id()).unwrap();
	let id =
		receiver.node.prepare_ffor_receiver(&channel, &connection, parameters.clone()).unwrap();
	persist(receiver.node);
	let init_wire = emit(receiver, &id, &connection);
	let init = FFORMessage::decode(&init_wire).unwrap();
	let (_, mut accept) = ffor_setup_test_messages(sender, receiver, channel, voucher);
	accept.header = init.header;
	if let Payload::Accept(terms) = &mut accept.payload {
		terms.init_hash = transcript::init_hash(&init_wire);
	}
	sign(&mut accept, sender);
	receiver.node.handle_ffor_receiver_message(&connection, &accept.encode().unwrap()).unwrap();
	persist(receiver.node);
	deliver_parked_voucher(sender, receiver, update);
	let snapshot = get_monitor!(receiver, channel).ffor_commitment_snapshot().unwrap();
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver_with_monitor(&id, &connection, snapshot, |_| panic!(
				"no custom wire during STFU"
			))
			.unwrap(),
		FFORReceiverProgress::AwaitingPeer
	);
	complete_handshake(sender, receiver);
	let snapshot = get_monitor!(receiver, channel).ffor_commitment_snapshot().unwrap();
	assert_eq!(
		receiver
			.node
			.advance_ffor_receiver_with_monitor(&id, &connection, snapshot, |_| panic!(
				"not durable"
			))
			.unwrap(),
		FFORReceiverProgress::AwaitingPersistence
	);
	persist(receiver.node);
	let activate = FFORMessage::decode(&emit(receiver, &id, &connection)).unwrap();
	let context = receiver.node.ffor_receiver_recovery_context(&channel, id.epoch_id()).unwrap();
	let mut ack = FFORMessage {
		header: activate.header,
		payload: Payload::ActivateAck(context.activation_hash()),
		extensions: Vec::new(),
		signature: [0; 64],
	};
	sign(&mut ack, sender);
	receiver.node.handle_ffor_receiver_message(&connection, &ack.encode().unwrap()).unwrap();
	persist(receiver.node);
	let context = receiver.node.ffor_receiver_recovery_context(&channel, id.epoch_id()).unwrap();
	let mut selected = manifests(&context, 1);
	selected[0].0 = witness.node.get_our_node_id();
	receiver.node.register_ffor_receiver_witnesses(&context, &selected).unwrap();
	persist(receiver.node);
	all_acknowledged(receiver, &context, &selected);
	assert_eq!(
		receiver
			.node
			.validate_ffor_receiver_request_intent(
				local_request_id,
				&channel,
				&sender.node.get_our_node_id(),
				&parameters
			)
			.unwrap(),
		Some(id)
	);
	let active_manager = persist(receiver.node);
	let monitor = get_monitor!(receiver, channel).encode();
	receiver.node.prepare_ffor_receiver_invoice(&context, &intent(), &route).unwrap();
	let issued_manager = persist(receiver.node);
	let stored = receiver.node.ffor_receiver_invoice_for_storage(&context).unwrap().unwrap();
	assert!(receiver.node.release_ffor_receiver_invoice(&stored, |_| Ok(())).unwrap());
	let directory = match std::env::var_os("FFOR_NODE_INVOICE_FIXTURE_DIR") {
		Some(directory) => std::path::PathBuf::from(directory),
		None => return,
	};
	std::fs::create_dir_all(&directory).unwrap();
	for (name, bytes) in [
		("active-manager.bin", active_manager),
		("issued-manager.bin", issued_manager),
		("monitor.bin", monitor),
		("route-announcement.bin", route.announcement.encode()),
		("route-update.bin", route.update.encode()),
		("witness-manifest.bin", selected[0].1.encode()),
	] {
		std::fs::write(directory.join(name), bytes).unwrap();
	}
	let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
	std::fs::write(directory.join("fixture.txt"), format!(
  "network=testnet\nwallet_seed={}\nclient_id=request-fixture\nlocal_request_id={}\nchannel_id={}\nepoch_id={}\nreceiver={}\nsettlement={}\nwitness={}\nwitness_node_seed={}\nfunding_txid={}\nfunding_vout={}\nheight={}\namount_msat={}\nminimum_payment_msat={}\nsettlement_deadline={}\nvoucher_expiry={}\nfee_base_msat=0\nfee_proportional_millionths=0\nclaim_margin_blocks=20\nhash_chain=false\ndescription={}\nexpiry_seconds={}\nsafety_margin_seconds={}\nfetch_secret={}\nencryption_secret={}\ngenerator=ffor_invoice_public_driver_one_slot_fixture_preserves_native_request\nbase_revision=016778d\n",
  hex(&[91;64]), hex(&local_request_id), hex(&channel.0), hex(&id.epoch_id()), context.receiver_node_id(), context.settlement_node_id(), witness.node.get_our_node_id(), hex(&witness.node_seed),
  context.funding_txo().txid, context.funding_txo().index, receiver.node.current_best_block().height,
  voucher.amount_msat, voucher.amount_msat, parameters.settlement_deadline, parameters.voucher_expiry,
  intent().description, intent().expiry_seconds, intent().safety_margin_seconds, hex(&[100;32]), hex(&[120;32]),
 )).unwrap();
}
