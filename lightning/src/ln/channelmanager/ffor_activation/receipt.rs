//! Historical witness preimages enter only the original native channel monitor.

use super::*;
use crate::ln::ffor::{
	FFORReceiverRecoveryContext, FFORWitnessMonitorSnapshot, FFORWitnessReceipt,
	FFORWitnessReceiptProgress,
};

impl<
		M: Deref,
		T: Deref,
		ES: Deref,
		NS: Deref,
		SP: Deref,
		F: Deref,
		R: Deref,
		MR: Deref,
		L: Deref,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Import an authenticated witness preimage into its original stock channel monitor.
	///
	/// Historical recovery remains available after deadlines, disconnection, conflicting peer
	/// reports and channel removal. The retained native setup, activation and immutable witness
	/// selection must match every receipt term. Neither a witness timestamp nor an application
	/// payment record supplies authority. Missing original monitor state, a changed funding output,
	/// a pending splice or a stale snapshot is refused without changing the channel.
	///
	/// Capture `monitor` with [`ChannelMonitor::ffor_witness_receipt_snapshot`] and release all
	/// monitor guards first. Ownership checks and the update share the native peer lock, including
	/// after force-close. Live unresolved vouchers use the stock claim path; an already failed or
	/// removed voucher receives only preimage protection for possible older on-chain commitments.
	/// No ordinary `PaymentClaimed` event, payment credit or invoice readiness is created here.
	///
	/// A submitted write returns `PendingMonitor` even if persistence completed synchronously.
	/// Process normal monitor events, capture a fresh snapshot and retry. `MonitorPersisted` means
	/// only that the monitor knows this preimage and its native writes have completed according to
	/// the application's [`Watch`] contract. The monitor owns durable idempotence across restart;
	/// callers must retain the authenticated receipt for retries until that observation succeeds.
	/// As with ordinary recovery, [`ChannelManagerReadArgs`] must contain the actual durable
	/// monitors. Encoding an in-memory monitor does not complete an outstanding storage write.
	///
	/// [`ChannelMonitor::ffor_witness_receipt_snapshot`]: crate::chain::channelmonitor::ChannelMonitor::ffor_witness_receipt_snapshot
	/// [`Watch`]: crate::chain::Watch
	pub fn import_ffor_receiver_witness_receipt(
		&self, context: &FFORReceiverRecoveryContext, receipt: &FFORWitnessReceipt,
		monitor: &FFORWitnessMonitorSnapshot,
	) -> Result<FFORWitnessReceiptProgress, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_mutex = per_peer_state
			.get(&context.settlement_node_id())
			.ok_or(FFORCommitmentError::MonitorMismatch)?;
		let mut peer_state_lock = peer_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let channel_id = context.channel_id();
		let counterparty = context.settlement_node_id();
		let funding_txo = context.funding_txo();
		let key = FFORRecoveryKey { channel_id, epoch_id: context.epoch_id() };
		let recovery = self.ffor_recovery.lock().unwrap();
		let current = self.ffor_recovery_context_from_registry(&recovery, &key)?;
		if current.context_digest() != context.context_digest()
			|| current.activation_ack_wire().is_none()
		{
			return Err(FFORReceiverError::InvalidWitnessReceipt);
		}
		let registration =
			recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		let header = receipt.header();
		let body = receipt.body();
		let witness = registration
			.witnesses()
			.iter()
			.find(|witness| witness.witness_node_id() == header.witness)
			.ok_or(FFORReceiverError::InvalidWitnessReceipt)?;
		let index = usize::from(body.slot())
			.checked_sub(1)
			.ok_or(FFORReceiverError::InvalidWitnessReceipt)?;
		let signed = current
			.setup()
			.vouchers()
			.get(index)
			.ok_or(FFORReceiverError::InvalidWitnessReceipt)?;
		let entry = current
			.setup()
			.canonical_book()
			.get(36 + index * 58..36 + (index + 1) * 58)
			.ok_or(FFORReceiverError::InvalidWitnessReceipt)?;
		if header.slot != body.slot()
			|| header.activation_hash != current.activation_hash()
			|| header.mailbox_id != witness.mailbox_id()
			|| header.encryption_public_key != witness.encryption_public_key()
			|| header.terms_hash
				!= Sha256::hash(&[b"ffor/terms".as_slice(), entry].concat()).to_byte_array()
			|| body.epoch_id() != current.epoch_id()
			|| body.payment_hash() != signed.payment_hash
			|| body.amount_msat() != signed.amount_msat
			|| body.voucher_expiry() != signed.expiry
			|| body.settlement_deadline() != current.setup().terms().settlement_deadline
		{
			return Err(FFORReceiverError::InvalidWitnessReceipt);
		}
		let voucher = crate::ln::ffor::FFORVoucher {
			htlc_id: signed.htlc_id,
			payment_hash: PaymentHash(signed.payment_hash),
			amount_msat: signed.amount_msat,
			cltv_expiry: signed.expiry,
		};
		if monitor.channel_id != channel_id
			|| monitor.funding_txo != funding_txo
			|| monitor.counterparty != counterparty
			|| monitor.payment_hash != voucher.payment_hash
		{
			return Err(FFORCommitmentError::MonitorMismatch.into());
		}
		// Registry data is immutable for this historical identity. Drop its lock before the
		// stock completion macro can release the peer lock and run unrelated completion actions.
		drop(recovery);
		let pending = if let Some((funding, updates)) =
			peer_state.in_flight_monitor_updates.get(&channel_id)
		{
			if *funding != funding_txo {
				return Err(FFORCommitmentError::MonitorMismatch.into());
			}
			!updates.is_empty()
		} else {
			false
		};
		let preimage = PaymentPreimage(body.preimage());
		if let Some(channel) = peer_state.channel_by_id.get_mut(&channel_id) {
			let channel = channel.as_funded_mut().ok_or(FFORCommitmentError::MonitorMismatch)?;
			if channel.funding_outpoint() != funding_txo
				|| channel.get_latest_unblocked_monitor_update_id() != monitor.update_id
			{
				return Err(FFORCommitmentError::MonitorMismatch.into());
			}
			let logger = WithChannelContext::from(&self.logger, &channel.context, None);
			let update = channel.ffor_import_receipt_preimage(
				&voucher,
				preimage,
				monitor.known_preimage,
				&&logger,
			)?;
			if let Some(update) = update {
				let update_id = update.update_id;
				handle_new_monitor_update!(
					self,
					funding_txo,
					update,
					peer_state_lock,
					peer_state,
					per_peer_state,
					channel
				);
				return Ok(FFORWitnessReceiptProgress::PendingMonitor {
					monitor_update_id: update_id,
				});
			}
			let pending = pending
				|| channel.is_awaiting_monitor_update()
				|| channel.blocked_monitor_updates_pending() != 0;
			return Ok(receipt_progress(monitor, pending));
		}
		if peer_state.closed_channel_monitor_funding.get(&channel_id) != Some(&funding_txo) {
			return Err(FFORCommitmentError::MonitorMismatch.into());
		}
		let latest = peer_state
			.closed_channel_monitor_update_ids
			.get_mut(&channel_id)
			.ok_or(FFORCommitmentError::MonitorMismatch)?;
		if *latest != monitor.update_id {
			return Err(FFORCommitmentError::MonitorMismatch.into());
		}
		if monitor.known_preimage {
			return Ok(receipt_progress(monitor, pending));
		}
		*latest = latest.checked_add(1).ok_or(FFORCommitmentError::PendingUpdates)?;
		let update_id = *latest;
		let update = ChannelMonitorUpdate {
			update_id,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage: preimage,
				payment_info: None,
			}],
			channel_id: Some(channel_id),
		};
		handle_new_monitor_update!(
			self,
			funding_txo,
			update,
			peer_state_lock,
			peer_state,
			per_peer_state,
			counterparty,
			channel_id,
			POST_CHANNEL_CLOSE
		);
		Ok(FFORWitnessReceiptProgress::PendingMonitor { monitor_update_id: update_id })
	}
}

fn receipt_progress(
	monitor: &FFORWitnessMonitorSnapshot, pending: bool,
) -> FFORWitnessReceiptProgress {
	if pending {
		FFORWitnessReceiptProgress::PendingMonitor { monitor_update_id: monitor.update_id }
	} else {
		FFORWitnessReceiptProgress::MonitorPersisted { monitor_update_id: monitor.update_id }
	}
}

#[cfg(test)]
mod tests;
