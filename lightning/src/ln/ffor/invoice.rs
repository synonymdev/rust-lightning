//! Immutable one-slot invoice intent and protected publication inputs.

use super::{FFORReceiverError, FFORReceiverRecoveryContext, FFORVoucherCommitments};
use crate::chain::transaction::OutPoint;
use crate::ln::channelmanager::FFORPersistenceRequirement;
use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate};
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::types::payment::PaymentHash;
use bitcoin::secp256k1::PublicKey;

/// Application presentation and conservative expiry policy for one fixed native voucher.
/// Amount, payment hash, routes and node identities cannot be supplied by the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORInvoiceIntent {
	/// Direct BOLT 11 description, subject to the standard invoice description bound.
	pub description: String,
	/// Requested lifetime, capped at eight minutes per remaining block before admission closes.
	pub expiry_seconds: u32,
	/// Additional seconds subtracted from the conservative remaining-block estimate.
	pub safety_margin_seconds: u32,
}

/// Signed public-channel evidence for a registered witness immediately before settlement.
/// This is untrusted input until the manager validates both identities, signatures and direction.
/// Issuance also requires the signed Init witness restriction to exactly match every registered
/// witness, with all native acknowledgements durable. Public gossip signatures do not establish
/// on-chain funding or current forwarding liquidity; a BOLT 11 route hint remains advisory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFORWitnessRouteEvidence {
	/// Full announcement signed by both channel nodes and their funding keys, without excess data.
	pub announcement: ChannelAnnouncement,
	/// Enabled witness-to-settlement update for the same chain and public short channel ID.
	pub update: ChannelUpdate,
}

/// A retained immutable invoice assignment. Wait for its requirement before storage retrieval.
#[derive(Clone, Debug)]
pub struct FFORInvoicePreparation {
	pub(crate) invoice_digest: [u8; 32],
	pub(crate) requirement: FFORPersistenceRequirement,
}

impl FFORInvoicePreparation {
	/// Digest of the exact retained signed BOLT 11 string.
	pub fn invoice_digest(&self) -> [u8; 32] {
		self.invoice_digest
	}
	/// Native manager write which must complete before retrieving the invoice for application
	/// storage.
	pub fn persistence_requirement(&self) -> &FFORPersistenceRequirement {
		&self.requirement
	}
}

/// Exact invoice bytes retrieved only for protected application storage and recovery.
///
/// This is not permission to display, return or otherwise expose an invoice to a payer. Persist
/// these bytes and the matching Pending payment first, then use the manager's publication method.
/// Restored application bytes alone do not recreate this manager-instance-bound handle.
#[derive(Clone)]
pub struct FFORStoredInvoice {
	pub(crate) context: FFORReceiverRecoveryContext,
	pub(crate) invoice: String,
	pub(crate) digest: [u8; 32],
	pub(crate) intent: FFORInvoiceIntent,
	pub(crate) requirement: FFORPersistenceRequirement,
}

impl FFORStoredInvoice {
	/// Exact signed invoice for storage only, never a replacement constructed on retry.
	pub fn invoice_for_storage(&self) -> &str {
		&self.invoice
	}
	/// Digest to join the native assignment to confirmed application writes.
	pub fn invoice_digest(&self) -> [u8; 32] {
		self.digest
	}
	/// Exact original presentation and expiry intent, for joining confirmed application storage.
	pub fn intent(&self) -> &FFORInvoiceIntent {
		&self.intent
	}
	/// Immutable epoch context for the application record.
	pub fn recovery_context(&self) -> &FFORReceiverRecoveryContext {
		&self.context
	}
}

/// Engine-created conditions for an atomic check against the actual watched monitor.
///
/// A custom [`crate::chain::Watch`] implementation can pass this to its actual monitor's
/// `validate_and_publish_ffor_invoice` method. A clone or detached monitor is insufficient.
/// No application constructor exists. The check itself grants no publication authority.
#[derive(Clone, Debug)]
pub struct FFORInvoiceMonitorCheck {
	pub(crate) channel_id: ChannelId,
	pub(crate) funding_txo: OutPoint,
	pub(crate) settlement: PublicKey,
	pub(crate) update_id: u64,
	pub(crate) commitments: FFORVoucherCommitments,
	pub(crate) payment_hash: PaymentHash,
	pub(crate) amount_msat: u64,
	pub(crate) voucher_expiry: u32,
	pub(crate) deadline: u32,
	pub(crate) manager_height: u32,
	pub(crate) invoice_expires_at: u64,
	pub(crate) safety_margin_seconds: u32,
}

impl FFORInvoiceMonitorCheck {
	/// Actual channel whose watched monitor must be locked during publication.
	pub fn channel_id(&self) -> ChannelId {
		self.channel_id
	}

	pub(crate) fn validate_time(&self, monitor_height: u32) -> Result<(), FFORReceiverError> {
		let now = invoice_time()?;
		let height = core::cmp::max(monitor_height, self.manager_height);
		let remaining = self
			.deadline
			.checked_sub(height)
			.and_then(|blocks| u64::from(blocks).checked_mul(480))
			.and_then(|seconds| seconds.checked_sub(u64::from(self.safety_margin_seconds)))
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		if remaining == 0
			|| self.invoice_expires_at <= now
			|| self.invoice_expires_at
				> now.checked_add(remaining).ok_or(FFORReceiverError::InvalidInvoice)?
		{
			return Err(FFORReceiverError::InvalidInvoice);
		}
		Ok(())
	}
}

pub(crate) fn invoice_time() -> Result<u64, FFORReceiverError> {
	#[cfg(feature = "std")]
	{
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|time| time.as_secs())
			.map_err(|_| FFORReceiverError::InvalidInvoice)
	}
	#[cfg(not(feature = "std"))]
	{
		Err(FFORReceiverError::InvalidInvoice)
	}
}

impl core::fmt::Debug for FFORStoredInvoice {
	fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		formatter
			.debug_struct("FFORStoredInvoice")
			.field("context", &self.context)
			.field("invoice_digest", &self.digest)
			.field("invoice_bytes", &self.invoice.len())
			.finish_non_exhaustive()
	}
}
