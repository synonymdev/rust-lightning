//! Experimental receiver parking and commitment verification for FFOR Variant D.
//!
//! Parking keeps registered vouchers out of ordinary payment processing. It does not authenticate
//! an epoch, freeze commitment state, or activate offline receiving. Neither parking nor commitment
//! verification authorizes invoice exposure or preimage release. Future activation must recheck
//! the commitments while atomically freezing channel state.

use alloc::collections::{BTreeMap, BTreeSet};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LOCK_TIME_THRESHOLD;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::Txid;
use core::fmt;

use crate::chain::transaction::OutPoint;
use crate::ln::chan_utils::{
	self, ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
	HolderCommitmentTransaction,
};
use crate::ln::channel::INITIAL_COMMITMENT_NUMBER;
use crate::ln::types::ChannelId;
use crate::ln::{msgs, onion_utils};
use crate::prelude::*;
use crate::sign::{NodeSigner, Recipient};
use crate::types::payment::PaymentHash;

/// Which channel participant offers every voucher HTLC in the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORSettlementParty {
	/// The local node is the settlement peer and offers the voucher HTLCs.
	Holder,
	/// The remote node is the settlement peer and offers the voucher HTLCs.
	Counterparty,
}

/// The public terms of one voucher from an authenticated FFOR Variant D book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFORVoucher {
	/// The settlement peer's offered HTLC ID.
	pub htlc_id: u64,
	/// The voucher's payment hash. This API neither needs nor returns a preimage.
	pub payment_hash: PaymentHash,
	/// The exact value in millisatoshis, before on-chain rounding.
	pub amount_msat: u64,
	/// The absolute CLTV expiry height shared by every voucher, strictly below Bitcoin's
	/// locktime threshold. Timestamp locktimes are not valid voucher expiries.
	pub cltv_expiry: u32,
}

impl_writeable_tlv_based!(FFORVoucher, {
	(0, htlc_id, required),
	(2, payment_hash, required),
	(4, amount_msat, required),
	(6, cltv_expiry, required),
});

/// Why a receiver registration was irreversibly aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORReceiverAbortReason {
	/// The application explicitly requested an unwind.
	Requested,
	/// An incoming HTLC differed from the registered book or used an unsupported onion header.
	VoucherMismatch,
	/// The channel disconnected before a durable activation mechanism existed.
	Disconnected,
	/// The channel was restored from storage before a durable activation mechanism existed.
	Restarted,
	/// The first voucher hash reused a revealed counterparty commitment secret.
	CommitmentSecretReused,
}

impl_writeable_tlv_based_enum!(FFORReceiverAbortReason,
	(0, Requested) => {},
	(2, VoucherMismatch) => {},
	(4, Disconnected) => {},
	(6, Restarted) => {},
	(8, CommitmentSecretReused) => {},
);

/// Receiver-side state of one experimental voucher registration.
///
/// Even `Parked` is only point-in-time evidence. It does not freeze commitments or authorize an
/// offline invoice. A disconnect or restart aborts this experimental registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORReceiverStatus {
	/// The book is registered, but not all vouchers have been irrevocably committed and parked.
	Registered {
		/// Number of fully committed vouchers intercepted before ordinary payment processing.
		parked_vouchers: u16,
		/// Number of vouchers in the registered book.
		total_vouchers: u16,
	},
	/// Every voucher is parked and the supplied monitor proves both current commitment views.
	Parked {
		/// Verified current commitment identities, subject to subsequent channel updates.
		commitments: FFORVoucherCommitments,
	},
	/// Failure updates are pending, or the channel is not yet synchronized after an abort.
	Aborting {
		/// The first reason the registration was aborted.
		reason: FFORReceiverAbortReason,
	},
	/// All owned HTLCs have drained and the channel is synchronized again.
	Aborted {
		/// The first reason the registration was aborted.
		reason: FFORReceiverAbortReason,
	},
}

/// Why an experimental receiver registration or status operation could not be performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORReceiverError {
	/// The channel or supplied commitment evidence does not meet the required conditions.
	ChannelState(FFORCommitmentError),
	/// This channel already has a registration, including a permanently retained aborted one.
	AlreadyRegistered,
	/// This channel has no receiver registration.
	NotRegistered,
	/// The supplied epoch does not identify this channel's registration.
	UnknownEpoch,
	/// No unused persistence revision remains in this manager instance.
	PersistenceUnavailable,
	/// Retained recovery storage is full or conflicts with an existing setup.
	RecoveryUnavailable,
}

impl From<FFORCommitmentError> for FFORReceiverError {
	fn from(error: FFORCommitmentError) -> Self {
		Self::ChannelState(error)
	}
}

impl fmt::Display for FFORReceiverError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::ChannelState(error) => error.fmt(f),
			Self::AlreadyRegistered => f.write_str("FFOR receiver already registered on channel"),
			Self::NotRegistered => f.write_str("no FFOR receiver registration on channel"),
			Self::UnknownEpoch => f.write_str("unknown FFOR receiver epoch"),
			Self::PersistenceUnavailable => f.write_str("FFOR persistence revision exhausted"),
			Self::RecoveryUnavailable => f.write_str("FFOR recovery record cannot be retained"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for FFORReceiverError {}

#[derive(Clone)]
pub(crate) enum FFORVoucherFailure {
	Relay { packet: Vec<u8> },
	Malformed { sha256_of_onion: [u8; 32], failure_code: u16 },
}

impl_writeable_tlv_based_enum!(FFORVoucherFailure,
	(0, Relay) => { (0, packet, required_vec) },
	(2, Malformed) => {
		(0, sha256_of_onion, required),
		(2, failure_code, required),
	},
);

/// Derive only the material needed to unwind a voucher. Do not decode or act on its payload.
pub(crate) fn voucher_failure<NS: NodeSigner + ?Sized>(
	msg: &msgs::UpdateAddHTLC, node_signer: &NS,
) -> Result<FFORVoucherFailure, ()> {
	use onion_utils::LocalHTLCFailureReason as Failure;
	let malformed = if msg.blinding_point.is_some() {
		Some((Failure::InvalidOnionBlinding, [0; 32]))
	} else if msg.onion_routing_packet.public_key.is_err() {
		Some((
			Failure::InvalidOnionKey,
			bitcoin::hashes::sha256::Hash::hash(&msg.onion_routing_packet.hop_data).to_byte_array(),
		))
	} else if msg.onion_routing_packet.version != 0 {
		Some((
			Failure::InvalidOnionVersion,
			bitcoin::hashes::sha256::Hash::hash(&msg.onion_routing_packet.hop_data).to_byte_array(),
		))
	} else {
		None
	};
	if let Some((reason, sha256_of_onion)) = malformed {
		return Ok(FFORVoucherFailure::Malformed {
			sha256_of_onion,
			failure_code: reason.failure_code(),
		});
	}
	let public_key = msg.onion_routing_packet.public_key.as_ref().map_err(|_| ())?;
	let shared_secret = node_signer.ecdh(Recipient::Node, public_key, None)?;
	let packet = onion_utils::build_failure_packet(
		&shared_secret.secret_bytes(),
		Failure::TemporaryNodeFailure,
		&[],
		0,
	);
	Ok(FFORVoucherFailure::Relay { packet: packet.data })
}

/// An actual current commitment transaction identified for the FFOR activation transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFORCommitment {
	/// The forward-counting BOLT commitment number, starting at zero.
	pub number: u64,
	/// The commitment transaction ID. FFOR hashes its internal byte order.
	pub txid: Txid,
}

/// Verified identities of both commitment views at one instant.
///
/// This result does not reserve the channel or establish an active FFOR epoch. Ordinary channel
/// updates may invalidate it immediately after the verification returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFORVoucherCommitments {
	/// The local node's commitment.
	pub holder: FFORCommitment,
	/// The remote node's commitment.
	pub counterparty: FFORCommitment,
}

/// Why the current channel state cannot prove an enforceable Variant D voucher book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORCommitmentError {
	/// The channel does not exist or is not fully established and open.
	ChannelUnavailable,
	/// Only ECDSA static-remote-key channels with zero-fee-HTLC anchors are supported.
	UnsupportedChannelType,
	/// A channel update, signer operation, monitor persistence operation, or splice is pending.
	PendingUpdates,
	/// The expected book is empty, oversized, ambiguous, or differs from the full HTLC set.
	InvalidVoucherBook,
	/// At least one expected voucher is trimmed from a commitment transaction.
	TrimmedVoucher,
	/// The monitor snapshot is stale, belongs to another channel, or differs from rebuilt state.
	MonitorMismatch,
	/// The holder commitment or one of its second-stage HTLC signatures is invalid or missing.
	InvalidClaimMaterial,
}

impl fmt::Display for FFORCommitmentError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"{}",
			match self {
				Self::ChannelUnavailable => "channel unavailable for FFOR verification",
				Self::UnsupportedChannelType => "unsupported FFOR channel type",
				Self::PendingUpdates => "FFOR vouchers are not fully committed",
				Self::InvalidVoucherBook => "invalid committed FFOR voucher book",
				Self::TrimmedVoucher => "FFOR voucher is trimmed",
				Self::MonitorMismatch => "FFOR monitor snapshot does not match channel state",
				Self::InvalidClaimMaterial => "invalid FFOR claim signatures",
			}
		)
	}
}

#[cfg(feature = "std")]
impl std::error::Error for FFORCommitmentError {}

/// Opaque commitment and claim material captured by a channel monitor.
///
/// Obtain this from [`ChannelMonitor::ffor_commitment_snapshot`], release any monitor lock, then
/// pass it to [`ChannelManager::ffor_voucher_commitments`]. Its presence alone does not prove that
/// monitor persistence has completed. The manager also checks update IDs and pending operations.
/// Applications remain responsible for honoring the [`Watch`] persistence completion contract.
///
/// [`ChannelMonitor::ffor_commitment_snapshot`]: crate::chain::channelmonitor::ChannelMonitor::ffor_commitment_snapshot
/// [`ChannelManager::ffor_voucher_commitments`]: crate::ln::channelmanager::ChannelManager::ffor_voucher_commitments
/// [`Watch`]: crate::chain::Watch
pub struct FFORMonitorSnapshot {
	pub(crate) channel_id: ChannelId,
	pub(crate) funding_txo: OutPoint,
	pub(crate) update_id: u64,
	pub(crate) holder: HolderCommitmentTransaction,
	pub(crate) holder_number: u64,
	pub(crate) counterparty_txid: Txid,
	pub(crate) counterparty_number: u64,
	pub(crate) counterparty_htlcs: Vec<HTLCOutputInCommitment>,
	pub(crate) revoked_through: u64,
}

pub(crate) fn validate_vouchers(vouchers: &[FFORVoucher]) -> Result<(), FFORCommitmentError> {
	let first = vouchers.first().ok_or(FFORCommitmentError::InvalidVoucherBook)?;
	if vouchers.len() > 483 {
		return Err(FFORCommitmentError::InvalidVoucherBook);
	}
	let mut hashes = BTreeSet::new();
	for (index, voucher) in vouchers.iter().enumerate() {
		if first.htlc_id.checked_add(index as u64) != Some(voucher.htlc_id)
			|| voucher.amount_msat == 0
			|| voucher.cltv_expiry == 0
			|| voucher.cltv_expiry >= LOCK_TIME_THRESHOLD
			|| voucher.cltv_expiry != first.cltv_expiry
			|| !hashes.insert(voucher.payment_hash.0)
		{
			return Err(FFORCommitmentError::InvalidVoucherBook);
		}
	}
	Ok(())
}

pub(crate) fn verify_outputs(
	commitment: &CommitmentTransaction, offered: bool, vouchers: &[FFORVoucher],
) -> Result<(), FFORCommitmentError> {
	if commitment.nondust_htlcs().len() != vouchers.len() {
		return Err(FFORCommitmentError::TrimmedVoucher);
	}
	let mut by_hash: BTreeMap<_, _> = vouchers.iter().map(|v| (v.payment_hash.0, v)).collect();
	let trusted = commitment.trust();
	let tx = &trusted.built_transaction().transaction;
	let mut output_indices = BTreeSet::new();
	for htlc in commitment.nondust_htlcs() {
		let voucher =
			by_hash.remove(&htlc.payment_hash.0).ok_or(FFORCommitmentError::InvalidVoucherBook)?;
		if htlc.offered != offered
			|| htlc.amount_msat != voucher.amount_msat
			|| htlc.cltv_expiry != voucher.cltv_expiry
		{
			return Err(FFORCommitmentError::InvalidVoucherBook);
		}
		let index = htlc.transaction_output_index.ok_or(FFORCommitmentError::TrimmedVoucher)?;
		let output = tx.output.get(index as usize).ok_or(FFORCommitmentError::TrimmedVoucher)?;
		let script = chan_utils::get_htlc_redeemscript(
			htlc,
			trusted.channel_type_features(),
			trusted.keys(),
		);
		if !output_indices.insert(index)
			|| output.value != htlc.to_bitcoin_amount()
			|| output.script_pubkey != script.to_p2wsh()
		{
			return Err(FFORCommitmentError::InvalidVoucherBook);
		}
	}
	Ok(())
}

pub(crate) fn verify_claim_signatures(
	holder: &CommitmentTransaction, stored: &HolderCommitmentTransaction,
	parameters: &ChannelTransactionParameters,
) -> Result<(), FFORCommitmentError> {
	let counterparty = parameters
		.counterparty_parameters
		.as_ref()
		.ok_or(FFORCommitmentError::InvalidClaimMaterial)?;
	let trusted = holder.trust();
	let built = trusted.built_transaction();
	let funding_script = parameters.make_funding_redeemscript();
	let secp_ctx = Secp256k1::verification_only();
	let sighash = built.get_sighash_all(&funding_script, parameters.channel_value_satoshis);
	secp_ctx
		.verify_ecdsa(&sighash, &stored.counterparty_sig, &counterparty.pubkeys.funding_pubkey)
		.map_err(|_| FFORCommitmentError::InvalidClaimMaterial)?;
	if stored.counterparty_htlc_sigs.len() != holder.nondust_htlcs().len() {
		return Err(FFORCommitmentError::InvalidClaimMaterial);
	}
	let keys = trusted.keys();
	for (htlc, signature) in holder.nondust_htlcs().iter().zip(&stored.counterparty_htlc_sigs) {
		let tx = chan_utils::build_htlc_transaction(
			&built.txid,
			holder.negotiated_feerate_per_kw(),
			counterparty.selected_contest_delay,
			htlc,
			&parameters.channel_type_features,
			&keys.broadcaster_delayed_payment_key,
			&keys.revocation_key,
		);
		let script =
			chan_utils::get_htlc_redeemscript(htlc, &parameters.channel_type_features, keys);
		let hash = SighashCache::new(&tx)
			.p2wsh_signature_hash(
				0,
				&script,
				htlc.to_bitcoin_amount(),
				EcdsaSighashType::SinglePlusAnyoneCanPay,
			)
			.map_err(|_| FFORCommitmentError::InvalidClaimMaterial)?;
		let message = Message::from_digest(hash.to_byte_array());
		secp_ctx
			.verify_ecdsa(&message, signature, &keys.countersignatory_htlc_key.to_public_key())
			.map_err(|_| FFORCommitmentError::InvalidClaimMaterial)?;
	}
	Ok(())
}

pub(crate) fn commitment_identity(commitment: &CommitmentTransaction) -> FFORCommitment {
	FFORCommitment {
		number: INITIAL_COMMITMENT_NUMBER - commitment.commitment_number(),
		txid: commitment.trust().txid(),
	}
}
