//! Experimental observations of retained receiver evidence and current durable activation.
//!
//! Neither context grants invoice readiness or authorizes a later side effect. A driver must
//! recheck live authority while holding the manager's transition locks before releasing work.

use alloc::vec::Vec;
use core::fmt;

use bitcoin::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Script, ScriptBuf};
use lightning_ffor::setup::AuthenticatedSetup;

use crate::chain::transaction::OutPoint;
use crate::ln::ffor::FFORVoucherCommitments;
use crate::ln::ffor_persistence::FFORPersistenceRequirement;
use crate::ln::types::ChannelId;

/// Immutable historical evidence retained even when its live channel has been removed.
///
/// This value authenticates the recorded setup and activation. It does not assert that the
/// channel is still active, that its latest state is durable, or that receiving is ready.
/// Its stable digest lets a protected application record identify the same native epoch after
/// restart. Possession of that record or digest does not confer native transition authority.
#[derive(Clone)]
pub struct FFORReceiverRecoveryContext {
	pub(crate) data: FFORReceiverRecoveryContextData,
	context_digest: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct FFORReceiverRecoveryContextData {
	pub(crate) setup: AuthenticatedSetup,
	pub(crate) chain_hash: ChainHash,
	pub(crate) receiver: PublicKey,
	pub(crate) settlement: PublicKey,
	pub(crate) funding_txo: OutPoint,
	pub(crate) activate_wire: Vec<u8>,
	pub(crate) activation_hash: [u8; 32],
	pub(crate) ack_wire: Option<Vec<u8>>,
	pub(crate) commitments: FFORVoucherCommitments,
	pub(crate) monitor_update_id: u64,
	pub(crate) preparation_height: u32,
	pub(crate) destination_script: ScriptBuf,
}

impl FFORReceiverRecoveryContext {
	pub(crate) fn from_authenticated(
		data: FFORReceiverRecoveryContextData, exact_setup: &[u8],
	) -> Self {
		let mut engine = sha256::Hash::engine();
		engine.input(b"ffor/native-receiver-context/v1");
		// Every component has a fixed u64 byte length prefix, including fixed-size fields.
		// Exact setup serialization includes its authenticated identities and admission facts.
		for bytes in [
			exact_setup,
			data.setup.canonical_book(),
			&data.activate_wire,
			&data.activation_hash,
			&data.commitments.holder.number.to_be_bytes(),
			data.commitments.holder.txid.as_byte_array(),
			&data.commitments.counterparty.number.to_be_bytes(),
			data.commitments.counterparty.txid.as_byte_array(),
			&data.monitor_update_id.to_be_bytes(),
			&data.preparation_height.to_be_bytes(),
			data.destination_script.as_bytes(),
		] {
			engine.input(&(bytes.len() as u64).to_be_bytes());
			engine.input(bytes);
		}
		Self { data, context_digest: sha256::Hash::from_engine(engine).to_byte_array() }
	}

	/// Original chain authenticated by the native setup record.
	pub fn chain_hash(&self) -> ChainHash {
		self.data.chain_hash
	}
	/// Receiver identity authenticated by the native setup record.
	pub fn receiver_node_id(&self) -> PublicKey {
		self.data.receiver
	}
	/// Settlement identity authenticated by the native setup record.
	pub fn settlement_node_id(&self) -> PublicKey {
		self.data.settlement
	}
	/// Original channel identifier retained by the signed setup.
	pub fn channel_id(&self) -> ChannelId {
		ChannelId(self.data.setup.header().channel_id)
	}
	/// Epoch identifier retained by the signed setup.
	pub fn epoch_id(&self) -> [u8; 32] {
		self.data.setup.header().epoch_id
	}
	/// Original funding output, even after a completed epoch allows later channel splices.
	pub fn funding_txo(&self) -> OutPoint {
		self.data.funding_txo
	}
	/// Immutable authenticated setup and its canonical book.
	pub fn setup(&self) -> &AuthenticatedSetup {
		&self.data.setup
	}
	/// Exact retained receiver activation message, including its signature.
	pub fn activation_wire(&self) -> &[u8] {
		&self.data.activate_wire
	}
	/// Authenticated activation digest. This does not assert a current Active channel.
	pub fn activation_hash(&self) -> [u8; 32] {
		self.data.activation_hash
	}
	/// Exact settlement activation acknowledgement, if one was retained.
	pub fn activation_ack_wire(&self) -> Option<&[u8]> {
		self.data.ack_wire.as_deref()
	}
	/// Original commitment identities checked during native activation preparation.
	pub fn commitments(&self) -> FFORVoucherCommitments {
		self.data.commitments
	}
	/// Original monitor-owned recovery destination retained during activation preparation.
	pub fn recovery_destination(&self) -> &Script {
		&self.data.destination_script
	}
	/// Stable local context binding, excluding acknowledgement presence and later lifecycle state.
	///
	/// The digest is an application record key, not a message signature or authorization token.
	pub fn context_digest(&self) -> [u8; 32] {
		self.context_digest
	}
}

impl fmt::Debug for FFORReceiverRecoveryContext {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("FFORReceiverRecoveryContext")
			.field("channel_id", &self.channel_id())
			.field("epoch_id", &self.epoch_id())
			.finish_non_exhaustive()
	}
}

/// An opaque, manager-instance-bound observation of a currently durable Active epoch.
///
/// Capture requires an exact signed settlement acknowledgement, current native fence and frozen
/// commitment pair, and completion of the epoch's latest persistence requirement. It cannot be
/// restored or constructed by an application. A later native transition or conflicting reconnect
/// can invalidate it immediately. Validate it again when observing current state, and let the
/// manager perform another locked check before any future action. This describes the retained native
/// phase even after its admission deadline; it authorizes neither witness provisioning nor invoices.
#[derive(Clone, Debug)]
pub struct FFORReceiverActiveContext {
	pub(crate) recovery: FFORReceiverRecoveryContext,
	pub(crate) requirement: FFORPersistenceRequirement,
}

impl FFORReceiverActiveContext {
	/// Historical metadata only. Reading it does not refresh this context's live validity.
	pub fn recovery_context(&self) -> &FFORReceiverRecoveryContext {
		&self.recovery
	}
}
