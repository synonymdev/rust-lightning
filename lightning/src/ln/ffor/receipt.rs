//! Monitor observations for importing authenticated historical witness preimages.

use crate::chain::transaction::OutPoint;
use crate::ln::types::ChannelId;
use crate::types::payment::PaymentHash;
use bitcoin::secp256k1::PublicKey;

/// Opaque evidence about one receipt's original monitor, captured before locking the manager.
///
/// Obtain this from [`ChannelMonitor::ffor_witness_receipt_snapshot`] and drop every monitor
/// guard before importing. A known preimage in memory is not proof of completed persistence.
/// The manager also checks its exact current counter and outstanding monitor writes.
///
/// [`ChannelMonitor::ffor_witness_receipt_snapshot`]: crate::chain::channelmonitor::ChannelMonitor::ffor_witness_receipt_snapshot
pub struct FFORWitnessMonitorSnapshot {
	pub(crate) channel_id: ChannelId,
	pub(crate) funding_txo: OutPoint,
	pub(crate) counterparty: PublicKey,
	pub(crate) update_id: u64,
	pub(crate) payment_hash: PaymentHash,
	pub(crate) known_preimage: bool,
}

/// Point-in-time protection of a witness preimage, not payment settlement or receive credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFORWitnessReceiptProgress {
	/// A stock monitor update was submitted, or its persistence is still outstanding.
	/// Process normal monitor completion events, capture a fresh snapshot and retry the import.
	PendingMonitor {
		/// Exact monitor counter at the observation or submitted preimage update.
		monitor_update_id: u64,
	},
	/// The original monitor knows the preimage and the manager has no outstanding writes for it.
	/// This relies on the application's normal [`Watch`] persistence completion contract. It
	/// neither promises an on-chain claim will succeed nor authorizes an invoice or payment event.
	///
	/// [`Watch`]: crate::chain::Watch
	MonitorPersisted {
		/// Exact monitor counter checked under the native peer lock.
		monitor_update_id: u64,
	},
}
