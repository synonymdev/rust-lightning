use super::*;
use crate::ln::channel::ffor::{FFORReceivedVoucher, FFORReceiverDrain, FFORReceiverFence};
use crate::ln::ffor::FFORReceiverParameters;
use crate::ln::ffor_tests::anchor_config;
use crate::ln::functional_test_utils::*;

// Exact previous book schema: an older reader understands parking, setup, fence and drain,
// but must refuse the new required request gate rather than accepting an empty ordinary book.
struct PreviousBook {
	epoch_id: [u8; 32],
	vouchers: Vec<FFORVoucher>,
	received: Vec<FFORReceivedVoucher>,
	abort_reason: Option<FFORReceiverAbortReason>,
	setup: Option<FFORReceiverSetup>,
	fence: Option<FFORReceiverFence>,
	drain: Option<FFORReceiverDrain>,
}
impl_writeable_tlv_based!(PreviousBook, {
	(0, epoch_id, required), (2, vouchers, required_vec), (4, received, required_vec),
	(6, abort_reason, option), (8, setup, option), (10, fence, option), (12, drain, option),
});

#[test]
fn ffor_driver_request_gate_restore_and_previous_reader_refusal() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = anchor_config();
	let managers = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &managers);
	let channel_id =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000).2;
	let connection = nodes[1].node.ffor_peer_connection(&nodes[0].node.get_our_node_id()).unwrap();
	nodes[1]
		.node
		.prepare_ffor_receiver(
			&channel_id,
			&connection,
			FFORReceiverParameters {
				local_request_id: [34; 32],
				amounts_msat: vec![2_000_000],
				minimum_payment_msat: 2_000_000,
				settlement_deadline: 180,
				voucher_expiry: 200,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				claim_margin_blocks: 20,
				witness_peers: None,
				hash_chain: false,
			},
		)
		.unwrap();
	let peers = nodes[1].node.per_peer_state.read().unwrap();
	let mut peer = peers.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
	let channel = peer.channel_by_id.get_mut(&channel_id).unwrap().as_funded_mut().unwrap();
	let original = channel.context.ffor_receiver_book.as_ref().unwrap().encode();
	assert!(matches!(
		PreviousBook::read(&mut &original[..]),
		Err(DecodeError::UnknownRequiredFeature)
	));
	let features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	for mutation in 0..3 {
		let book = channel.context.ffor_receiver_book.as_mut().unwrap();
		match mutation {
			0 => book.request = None,
			1 => book.request_gate_released = Some(true),
			_ => book.request_gate_released = Some(false),
		}
		let damaged = channel.encode();
		channel.context.ffor_receiver_book =
			Some(FFORReceiverBook::read(&mut &original[..]).unwrap());
		assert!(matches!(
			FundedChannel::read(
				&mut &damaged[..],
				(&nodes[1].keys_manager, &nodes[1].keys_manager, &features)
			),
			Err(DecodeError::InvalidValue)
		));
	}
	let ordinary = PreviousBook {
		epoch_id: [2; 32],
		vouchers: vec![FFORVoucher {
			htlc_id: 0,
			payment_hash: PaymentHash([3; 32]),
			amount_msat: 2_000_000,
			cltv_expiry: 200,
		}],
		received: vec![],
		abort_reason: None,
		setup: None,
		fence: None,
		drain: None,
	}
	.encode();
	// Absence of request metadata retains byte compatibility with the preceding book format.
	assert_eq!(FFORReceiverBook::read(&mut &ordinary[..]).unwrap().encode(), ordinary);
}
