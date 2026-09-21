//! Preserve a historical voucher preimage through the stock monitor and claim machinery.

use super::*;

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn ffor_import_receipt_preimage<L: Deref>(
		&mut self, voucher: &FFORVoucher, preimage: PaymentPreimage, monitor_knows_preimage: bool,
		logger: &L,
	) -> Result<Option<ChannelMonitorUpdate>, FFORReceiverError>
	where
		L::Target: Logger,
	{
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		if !book.vouchers.contains(voucher)
			|| !self.context.ffor_owns_preimage(voucher.htlc_id, &preimage)
		{
			return Err(FFORReceiverError::InvalidWitnessReceipt);
		}
		if self.pending_splice.is_some() || self.context.interactive_tx_signing_session.is_some() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let has_drain = book.drain.is_some();
		// A historical receipt can arrive after a failure was already committed. The stock FFOR
		// drain claim hook preserves that outcome while retaining preimage knowledge. A historical
		// terminal book without a drain needs the monitor-only fallback below.
		let htlc =
			self.context.pending_inbound_htlcs.iter().find(|htlc| htlc.htlc_id == voucher.htlc_id);
		if let Some(htlc) = htlc {
			if htlc.payment_hash != voucher.payment_hash
				|| htlc.amount_msat != voucher.amount_msat
				|| htlc.cltv_expiry != voucher.cltv_expiry
			{
				return Err(FFORReceiverError::InvalidWitnessReceipt);
			}
		}
		let committed =
			htlc.map_or(false, |htlc| matches!(htlc.state, InboundHTLCState::Committed));
		if (committed && matches!(self.context.channel_state, ChannelState::ChannelReady(_)))
			|| (has_drain && !committed)
		{
			// A queued failure has not entered a commitment yet. A newly learned preimage wins
			// before its admission, including when a monitor write currently blocks that round.
			self.context.holding_cell_htlc_updates.retain(|update| {
				!matches!(update,
				HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. }
				| HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. }
				if *htlc_id == voucher.htlc_id)
			});
			if let UpdateFulfillCommitFetch::NewClaim { monitor_update, .. } = self
				.get_update_fulfill_htlc_and_commit(voucher.htlc_id, preimage, None, None, logger)
			{
				return Ok(Some(monitor_update));
			}
		}
		if monitor_knows_preimage {
			return Ok(None);
		}
		self.ffor_monitor_only_preimage_update(preimage).map(Some)
	}

	/// Protect a preimage of an archived terminal epoch that this channel's current book no longer
	/// owns. Every voucher of that epoch was already resolved, so no stock claim is possible; only
	/// the original monitor gains the preimage. The manager has matched the epoch, funding output
	/// and witness selection against the archive before calling. A live HTLC of the current epoch
	/// with the same payment hash keeps stock ownership and refuses this path.
	pub(crate) fn ffor_import_historical_receipt_preimage(
		&mut self, voucher: &FFORVoucher, preimage: PaymentPreimage, monitor_knows_preimage: bool,
	) -> Result<Option<ChannelMonitorUpdate>, FFORReceiverError> {
		let hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		if hash != voucher.payment_hash
			|| self
				.context
				.ffor_receiver_book
				.as_ref()
				.map_or(true, |book| book.vouchers.contains(voucher))
		{
			return Err(FFORReceiverError::InvalidWitnessReceipt);
		}
		if self.pending_splice.is_some() || self.context.interactive_tx_signing_session.is_some() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		if self.context.pending_inbound_htlcs.iter().any(|htlc| htlc.payment_hash == hash) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		if monitor_knows_preimage {
			return Ok(None);
		}
		self.ffor_monitor_only_preimage_update(preimage).map(Some)
	}

	fn ffor_monitor_only_preimage_update(
		&mut self, preimage: PaymentPreimage,
	) -> Result<ChannelMonitorUpdate, FFORReceiverError> {
		// Match the stock claim helper's priority insertion: preimage protection must not wait
		// behind a commitment update blocked by another channel or a signer.
		self.context.latest_monitor_update_id = self
			.context
			.latest_monitor_update_id
			.checked_add(1)
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let update_id = self
			.context
			.blocked_monitor_updates
			.first()
			.map_or(self.context.latest_monitor_update_id, |pending| pending.update.update_id);
		for pending in &mut self.context.blocked_monitor_updates {
			pending.update.update_id += 1;
		}
		self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
		Ok(ChannelMonitorUpdate {
			update_id,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage: preimage,
				payment_info: None,
			}],
			channel_id: Some(self.context.channel_id()),
		})
	}
}
