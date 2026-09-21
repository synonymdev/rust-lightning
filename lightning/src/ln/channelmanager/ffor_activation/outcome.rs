//! Historical per-voucher cooperative outcomes from a fully completed native drain journal.
//! This getter changes no balances and emits no events. It reports only what stock accounting
//! recorded at irrevocable removal, retained with the Closed proof and the latest completed
//! native write.

use super::*;
use crate::ln::ffor::{FFORReceiverRecoveryContext, FFORVoucherOutcome};
use crate::types::payment::PaymentHash;

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
	/// Report the cooperative outcome of one owned voucher slot after the epoch reached Closed.
	///
	/// The slot is the one-based position in the signed book. The payment hash and amount must
	/// match that exact voucher, and the context must be the current native history for the
	/// epoch. The result is available only after the latest native manager write completed,
	/// including a fresh barrier after restore. Pending drains, force-closed epochs and legacy
	/// records without a journal return None. This is historical accounting, not receive credit
	/// and not permission to notify a payer twice.
	pub fn ffor_receiver_voucher_outcome(
		&self, context: &FFORReceiverRecoveryContext, slot: u16, payment_hash: PaymentHash,
		amount_msat: u64,
	) -> Result<Option<FFORVoucherOutcome>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let current = self.ffor_recovery_context_from_registry(&recovery, &key)?;
		if current.context_digest() != context.context_digest() {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let vouchers = current.setup().vouchers();
		let voucher = usize::from(slot)
			.checked_sub(1)
			.and_then(|index| vouchers.get(index))
			.ok_or(FFORCommitmentError::InvalidVoucherBook)?;
		if voucher.payment_hash != payment_hash.0
			|| voucher.amount_msat != amount_msat
			|| current.funding_txo() != context.funding_txo()
		{
			return Err(FFORCommitmentError::InvalidVoucherBook.into());
		}
		let journal = match recovery
			.get_activation(&key)
			.and_then(|activation| activation.close_record())
			.and_then(|close| close.journal())
		{
			Some(journal) => journal,
			None => return Ok(None),
		};
		let runtime = self.ffor_activation.lock().unwrap();
		let requirement = &runtime.get(&key)?.requirement;
		if !self.ffor_persistence.lock().unwrap().is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(journal.outcome(usize::from(slot) - 1))
	}
}
