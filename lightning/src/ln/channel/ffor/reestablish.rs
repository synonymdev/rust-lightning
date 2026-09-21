//! Frozen Variant D reconnect observations and ordinary commitment proof checks.
//!
//! A peer report is unsigned. It cannot activate, abort, release vouchers or lift the fence.
//! The manager compares the rebuilt identities with its retained activation record before
//! consuming an outcome, then persists the corresponding transition before releasing any wire.

use super::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};

/// An observation on the current authenticated peer connection, never transition authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FFORReestablishOutcome {
	/// The peer reports the exact active epoch. A matching signed acknowledgement is still needed.
	MatchingActive { peer_report: Reestablish },
	/// Setup did not complete. Retain the fence until the manager durably records the abort.
	AbortRequired { peer_report: Option<Reestablish> },
	/// Possibly active evidence conflicts or needs a signed close response. Retain the fence.
	ResolutionRequired { peer_report: Option<Reestablish> },
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn ffor_receiver_reconnect_outcome(&self) -> Option<&FFORReestablishOutcome> {
		self.ffor_reconnect_outcome.as_ref()
	}

	/// Rebuild the frozen commitment pair without acquiring a monitor lock or advancing state.
	/// The manager must compare the result to its authenticated archive under its registry lock.
	/// Original monitor and claim-signature checks remain mandatory at installation and restore.
	pub(crate) fn ffor_frozen_commitments<L: Deref>(
		&self, logger: &L,
	) -> Result<FFORVoucherCommitments, FFORCommitmentError>
	where
		L::Target: Logger,
	{
		if !self.context.is_ffor_frozen() {
			return Err(FFORCommitmentError::ChannelUnavailable);
		}
		self.validate_ffor_fence().map_err(|_| FFORCommitmentError::PendingUpdates)?;
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		verification::validate_vouchers(&book.vouchers)?;
		self.check_ffor_htlc_ids(FFORSettlementParty::Counterparty, &book.vouchers)?;
		let holder_number = self.holder_commitment_point.current_transaction_number();
		let counterparty_number = self
			.context
			.counterparty_next_commitment_transaction_number
			.checked_add(1)
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		if holder_number > INITIAL_COMMITMENT_NUMBER
			|| counterparty_number > INITIAL_COMMITMENT_NUMBER
			|| counterparty_number.checked_add(1)
				!= Some(self.context.commitment_secrets.get_min_seen_secret())
		{
			return Err(FFORCommitmentError::PendingUpdates);
		}
		let holder_point = self
			.holder_commitment_point
			.current_point()
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let counterparty_point = self
			.context
			.counterparty_current_commitment_point
			.ok_or(FFORCommitmentError::PendingUpdates)?;
		let holder = self
			.context
			.build_commitment_transaction(
				&self.funding,
				holder_number,
				&holder_point,
				true,
				false,
				logger,
			)
			.tx;
		let counterparty = self
			.context
			.build_commitment_transaction(
				&self.funding,
				counterparty_number,
				&counterparty_point,
				false,
				true,
				logger,
			)
			.tx;
		verification::verify_outputs(&holder, false, &book.vouchers)?;
		verification::verify_outputs(&counterparty, true, &book.vouchers)?;
		Ok(FFORVoucherCommitments {
			holder: verification::commitment_identity(&holder),
			counterparty: verification::commitment_identity(&counterparty),
		})
	}

	pub(in crate::ln::channel) fn ffor_get_reestablish<L: Deref>(
		&mut self, logger: &L,
	) -> Result<msgs::ChannelReestablish, msgs::WarningMessage>
	where
		L::Target: Logger,
	{
		self.ffor_reconnect_outcome = None;
		let unavailable = || msgs::WarningMessage {
			channel_id: self.context.channel_id(),
			data: FFOR_FROZEN_MESSAGE.to_owned(),
		};
		if !self.context.channel_state.is_peer_disconnected() {
			return Err(unavailable());
		}
		self.ffor_frozen_commitments(logger).map_err(|_| unavailable())?;
		let book = self.context.ffor_receiver_book.as_ref().unwrap();
		let (phase, hash) = self.ffor_receiver_fence().unwrap();
		let (state, activation_hash) = match phase {
			FFORReceiverFencePhase::Activating => (ReportedState::Activating, [0; 32]),
			FFORReceiverFencePhase::Active => (ReportedState::Active, hash),
			FFORReceiverFencePhase::Aborting => (ReportedState::Aborted, [0; 32]),
		};
		let counterparty_next = self.context.counterparty_next_commitment_transaction_number;
		let next_local_commitment_number = INITIAL_COMMITMENT_NUMBER
			.checked_sub(self.holder_commitment_point.next_transaction_number())
			.ok_or_else(unavailable)?;
		let next_remote_commitment_number = INITIAL_COMMITMENT_NUMBER
			.checked_sub(counterparty_next)
			.and_then(|number| number.checked_sub(1))
			.ok_or_else(unavailable)?;
		let secret = if counterparty_next
			.checked_add(1)
			.map_or(false, |number| number < INITIAL_COMMITMENT_NUMBER)
		{
			self.context
				.commitment_secrets
				.get_secret(counterparty_next.checked_add(2).ok_or_else(unavailable)?)
				.ok_or_else(unavailable)?
		} else {
			[0; 32]
		};
		// static_remotekey uses the same valid dummy point as the stock reconnect path.
		let mut point = [2; 33];
		point[1] = 0xff;
		Ok(msgs::ChannelReestablish {
			channel_id: self.context.channel_id(),
			next_local_commitment_number,
			next_remote_commitment_number,
			your_last_per_commitment_secret: secret,
			my_current_per_commitment_point: PublicKey::from_slice(&point).unwrap(),
			next_funding: None,
			my_current_funding_locked: self.maybe_get_my_current_funding_locked(),
			ffor_reestablish: Some(msgs::FFORChannelReestablish::new(Reestablish {
				epoch_id: book.epoch_id,
				state,
				activation_hash,
			})),
		})
	}

	pub(in crate::ln::channel) fn ffor_handle_reestablish<L: Deref>(
		&mut self, msg: &msgs::ChannelReestablish, logger: &L,
	) -> Result<ReestablishResponses, ChannelError>
	where
		L::Target: Logger,
	{
		self.ffor_reconnect_outcome = None;
		self.ffor_frozen_commitments(logger)
			.map_err(|_| ChannelError::WarnAndDisconnect(FFOR_FROZEN_MESSAGE.to_owned()))?;
		let our_commitment = self.validate_reestablish_prefix(msg, logger)?;
		let next_counterparty = INITIAL_COMMITMENT_NUMBER
			- self.context.counterparty_next_commitment_transaction_number;
		if msg.next_local_commitment_number + 1 < next_counterparty
			|| msg.next_local_commitment_number > next_counterparty
		{
			return Err(ChannelError::close(format!("Peer attempted to reestablish frozen channel with an inconsistent remote commitment transaction: {} (received) vs {} (expected)", msg.next_local_commitment_number, next_counterparty)));
		}
		if msg.next_remote_commitment_number != our_commitment
			|| msg.next_local_commitment_number != next_counterparty
		{
			return Err(ChannelError::WarnAndDisconnect("Frozen FFOR commitments require peer state recovery before ordinary retransmission".to_owned()));
		}
		if msg.next_funding.is_some()
			|| msg
				.my_current_funding_locked
				.as_ref()
				.map_or(false, |funding| self.funding.get_funding_txid() != Some(funding.txid))
		{
			return Err(ChannelError::WarnAndDisconnect(
				"Frozen FFOR channel cannot reconcile a different funding transaction".to_owned(),
			));
		}
		let (phase, hash) = self.ffor_receiver_fence().unwrap();
		let epoch = self.context.ffor_receiver_book.as_ref().unwrap().epoch_id;
		let peer_report = msg.ffor_reestablish.as_ref().map(|value| value.report());
		let outcome = if phase == FFORReceiverFencePhase::Aborting {
			FFORReestablishOutcome::AbortRequired { peer_report }
		} else if let Some(report) = peer_report.filter(|report| {
			report.state == ReportedState::Active
				&& report.epoch_id == epoch
				&& report.activation_hash == hash
		}) {
			FFORReestablishOutcome::MatchingActive { peer_report: report }
		} else if phase == FFORReceiverFencePhase::Activating
			&& peer_report.map_or(true, |report| {
				matches!(
					report.state,
					ReportedState::Negotiating
						| ReportedState::VouchersCommitted
						| ReportedState::Activating
						| ReportedState::Aborted
				)
			}) {
			FFORReestablishOutcome::AbortRequired { peer_report }
		} else {
			FFORReestablishOutcome::ResolutionRequired { peer_report }
		};
		self.ffor_reconnect_outcome = Some(outcome);
		self.context.channel_state.clear_peer_disconnected();
		self.mark_response_received();
		Ok(ReestablishResponses {
			channel_ready: None,
			channel_ready_order: ChannelReadyOrder::ChannelReadyFirst,
			raa: None,
			commitment_update: None,
			commitment_order: self.context.resend_order.clone(),
			announcement_sigs: None,
			shutdown_msg: None,
			tx_signatures: None,
			tx_abort: None,
			inferred_splice_locked: None,
		})
	}

	/// Stock BOLT 2 checks performed before reconnect mutates channel state. Variant D uses
	/// these same commitment counter, secret proof and data-loss checks without a carve-out.
	pub(in crate::ln::channel) fn validate_reestablish_prefix<L: Deref>(
		&self, msg: &msgs::ChannelReestablish, logger: &L,
	) -> Result<u64, ChannelError>
	where
		L::Target: Logger,
	{
		if !self.context.channel_state.is_peer_disconnected() {
			// While BOLT 2 doesn't indicate explicitly we should error this channel here, it
			// almost certainly indicates we are going to end up out-of-sync in some way, so we
			// just close here instead of trying to recover.
			return Err(ChannelError::close(
				"Peer sent a loose channel_reestablish not after reconnect".to_owned(),
			));
		}

		// A node:
		//   - if `next_commitment_number` is zero:
		//     - MUST immediately fail the channel and broadcast any relevant latest commitment
		//       transaction.
		if msg.next_local_commitment_number == 0
			|| msg.next_local_commitment_number >= INITIAL_COMMITMENT_NUMBER
			|| msg.next_remote_commitment_number >= INITIAL_COMMITMENT_NUMBER
		{
			return Err(ChannelError::close(
				"Peer sent an invalid channel_reestablish to force close in a non-standard way"
					.to_owned(),
			));
		}

		let our_commitment_transaction =
			INITIAL_COMMITMENT_NUMBER - self.holder_commitment_point.current_transaction_number();
		if msg.next_remote_commitment_number > 0 {
			let expected_point = self.context.holder_signer.as_ref()
				.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - msg.next_remote_commitment_number + 1, &self.context.secp_ctx)
				.expect("TODO: async signing is not yet supported for per commitment points upon channel reestablishment");
			let given_secret = SecretKey::from_slice(&msg.your_last_per_commitment_secret)
				.map_err(|_| {
					ChannelError::close(
						"Peer sent a garbage channel_reestablish with unparseable secret key"
							.to_owned(),
					)
				})?;
			if expected_point != PublicKey::from_secret_key(&self.context.secp_ctx, &given_secret) {
				return Err(ChannelError::close("Peer sent a garbage channel_reestablish with secret key not matching the commitment height provided".to_owned()));
			}
			if msg.next_remote_commitment_number > our_commitment_transaction {
				macro_rules! log_and_panic {
					($err_msg: expr) => {
						log_error!(logger, $err_msg);
						panic!($err_msg);
					};
				}
				log_and_panic!("We have fallen behind - we have received proof that if we broadcast our counterparty is going to claim all our funds.\n\
					This implies you have restarted with lost ChannelMonitor and ChannelManager state, the first of which is a violation of the LDK chain::Watch requirements.\n\
					More specifically, this means you have a bug in your implementation that can cause loss of funds, or you are running with an old backup, which is unsafe.\n\
					If you have restored from an old backup and wish to claim any available funds, you should restart with\n\
					an empty ChannelManager and no ChannelMonitors, reconnect to peer(s), ensure they've force-closed all of your\n\
					previous channels and that the closure transaction(s) have confirmed on-chain,\n\
					then restart with an empty ChannelManager and the latest ChannelMonitors that you do have.");
			}
		}

		// Before we change the state of the channel, we check if the peer is sending a very old
		// commitment transaction number, if yes we send a warning message.
		if msg.next_remote_commitment_number + 1 < our_commitment_transaction {
			return Err(ChannelError::Warn(format!(
				"Peer attempted to reestablish channel with a very old local commitment transaction: {} (received) vs {} (expected)",
				msg.next_remote_commitment_number,
				our_commitment_transaction
			)));
		}

		Ok(our_commitment_transaction)
	}
}

#[cfg(test)]
mod tests;
