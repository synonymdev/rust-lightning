//! Point-in-time verification of the committed voucher book for FFOR Variant D.
//!
//! These checks do not park HTLCs, freeze a channel, authenticate an epoch, or activate offline
//! receiving. A successful result must never by itself authorize invoice exposure or preimage
//! release. Future activation must recheck the commitments while atomically freezing channel state.

use alloc::collections::{BTreeMap, BTreeSet};
use bitcoin::hashes::Hash;
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
use crate::prelude::*;
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
	/// The absolute CLTV expiry height shared by every voucher in the book.
	pub cltv_expiry: u32,
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
