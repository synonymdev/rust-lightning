use super::*;
use crate::ln::ffor::{
	self as verification, FFORCommitmentError, FFORMonitorSnapshot, FFORSettlementParty,
	FFORVoucher, FFORVoucherCommitments,
};

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn ffor_voucher_commitments<L: Deref>(
		&self, settlement_party: FFORSettlementParty, vouchers: &[FFORVoucher],
		monitor: &FFORMonitorSnapshot, logger: &L,
	) -> Result<FFORVoucherCommitments, FFORCommitmentError>
	where
		L::Target: Logger,
	{
		self.check_ffor_synchronized()?;
		verification::validate_vouchers(vouchers)?;
		self.check_ffor_htlc_ids(settlement_party, vouchers)?;
		let context = &self.context;
		if monitor.channel_id != context.channel_id()
			|| Some(monitor.funding_txo) != self.funding.get_funding_txo()
			|| monitor.update_id != context.latest_monitor_update_id
		{
			return Err(FFORCommitmentError::MonitorMismatch);
		}

		let holder_point = self
			.holder_commitment_point
			.current_point()
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let counterparty_point = context
			.counterparty_current_commitment_point
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let holder = context
			.build_commitment_transaction(
				&self.funding,
				self.holder_commitment_point.current_transaction_number(),
				&holder_point,
				true,
				false,
				logger,
			)
			.tx;
		let counterparty = context
			.build_commitment_transaction(
				&self.funding,
				context.counterparty_next_commitment_transaction_number + 1,
				&counterparty_point,
				false,
				true,
				logger,
			)
			.tx;
		let holder_offered = settlement_party == FFORSettlementParty::Holder;
		verification::verify_outputs(&holder, holder_offered, vouchers)?;
		verification::verify_outputs(&counterparty, !holder_offered, vouchers)?;
		if monitor.holder_number != holder.commitment_number()
			|| monitor.holder.commitment_number() != holder.commitment_number()
			|| monitor.holder.trust().built_transaction().transaction
				!= holder.trust().built_transaction().transaction
			|| monitor.holder.trust().txid() != holder.trust().txid()
			|| monitor.holder.nondust_htlcs() != holder.nondust_htlcs()
			|| monitor.counterparty_number != counterparty.commitment_number()
			|| monitor.counterparty_txid != counterparty.trust().txid()
			|| &monitor.counterparty_htlcs != counterparty.nondust_htlcs()
			|| monitor.revoked_through != counterparty.commitment_number() + 1
			|| context.commitment_secrets.get_min_seen_secret() != monitor.revoked_through
		{
			return Err(FFORCommitmentError::MonitorMismatch);
		}
		verification::verify_claim_signatures(
			&holder,
			&monitor.holder,
			&self.funding.channel_transaction_parameters,
		)?;
		Ok(FFORVoucherCommitments {
			holder: verification::commitment_identity(&holder),
			counterparty: verification::commitment_identity(&counterparty),
		})
	}

	fn check_ffor_synchronized(&self) -> Result<(), FFORCommitmentError> {
		let context = &self.context;
		let channel_type = self.funding.get_channel_type();
		if !channel_type.supports_static_remote_key()
			|| !channel_type.supports_anchors_zero_fee_htlc_tx()
			|| channel_type.supports_taproot()
			|| channel_type.supports_anchor_zero_fee_commitments()
		{
			return Err(FFORCommitmentError::UnsupportedChannelType);
		}
		if !context.is_usable() {
			return Err(FFORCommitmentError::ChannelUnavailable);
		}
		if context.is_waiting_on_peer_pending_channel_update()
			|| context.is_monitor_or_signer_pending_channel_update()
			|| !context.holding_cell_htlc_updates.is_empty()
			|| context.holding_cell_update_fee.is_some()
			|| !context.blocked_monitor_updates.is_empty()
			|| context.monitor_pending_revoke_and_ack
			|| context.monitor_pending_commitment_signed
			|| context.interactive_tx_signing_session.is_some()
			|| self.pending_splice.is_some()
			|| matches!(self.quiescent_action, Some(QuiescentAction::Splice(_)))
		{
			return Err(FFORCommitmentError::PendingUpdates);
		}
		Ok(())
	}

	fn check_ffor_htlc_ids(
		&self, settlement_party: FFORSettlementParty, vouchers: &[FFORVoucher],
	) -> Result<(), FFORCommitmentError> {
		let context = &self.context;
		let actual: Vec<FFORVoucher> = match settlement_party {
			FFORSettlementParty::Holder if context.pending_inbound_htlcs.is_empty() => context
				.pending_outbound_htlcs
				.iter()
				.map(|h| FFORVoucher {
					htlc_id: h.htlc_id,
					payment_hash: h.payment_hash,
					amount_msat: h.amount_msat,
					cltv_expiry: h.cltv_expiry,
				})
				.collect(),
			FFORSettlementParty::Counterparty if context.pending_outbound_htlcs.is_empty() => {
				context
					.pending_inbound_htlcs
					.iter()
					.map(|h| FFORVoucher {
						htlc_id: h.htlc_id,
						payment_hash: h.payment_hash,
						amount_msat: h.amount_msat,
						cltv_expiry: h.cltv_expiry,
					})
					.collect()
			},
			_ => return Err(FFORCommitmentError::InvalidVoucherBook),
		};
		if actual.len() != vouchers.len() || actual.iter().any(|htlc| !vouchers.contains(htlc)) {
			return Err(FFORCommitmentError::InvalidVoucherBook);
		}
		Ok(())
	}
}
