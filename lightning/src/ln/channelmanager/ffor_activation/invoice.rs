//! One immutable signed invoice per single-slot epoch, with actual-monitor publication exclusion.

use super::*;
use crate::ln::ffor::invoice::invoice_time;
use crate::ln::ffor::{
	FFORInvoiceIntent, FFORInvoiceMonitorCheck, FFORInvoicePreparation,
	FFORReceiverRecoveryContext, FFORStoredInvoice, FFORWitnessRouteEvidence,
};
use crate::ln::ffor_recovery::invoice::{
	acknowledgements_digest, terms, validate_route, FFORInvoiceRecord,
};
use lightning_invoice::Bolt11Invoice;

struct InvoiceCapture {
	record: FFORInvoiceRecord,
	requirement: FFORPersistenceRequirement,
}

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
	/// Retain one exact invoice for a one-slot, non-hash-chained Variant D epoch.
	///
	/// The signed Init witness restriction must exactly name the registered witnesses, and each
	/// must already have a native durable acknowledgement. The public
	/// W-to-S announcement and update are verified, and the invoice contains exactly W -> S -> R.
	/// Private witness channels without authenticated route evidence are not supported. Amount,
	/// payment hash, settlement fees and the final channel alias are derived from native ownership.
	/// Signing occurs outside native locks, followed by complete revalidation. No invoice bytes are
	/// returned here. A successful reservation is permanent and can never produce a replacement.
	/// New issuance requires the std clock; no_std can restore and inspect historical records.
	pub fn prepare_ffor_receiver_invoice(
		&self, context: &FFORReceiverRecoveryContext, intent: &FFORInvoiceIntent,
		route: &FFORWitnessRouteEvidence,
	) -> Result<FFORInvoicePreparation, FFORReceiverError> {
		let capture = match self.capture_ffor_invoice(context, intent, route)? {
			Ok(existing) => return Ok(existing),
			Err(capture) => capture,
		};
		let mut record = capture.record;
		let registration = self
			.ffor_receiver_witness_registration(context)?
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		let raw = record
			.unsigned(
				context,
				&registration,
				invoice_time()?,
				PaymentSecret(self.entropy_source.get_secure_random_bytes()),
			)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		let signature = self
			.node_signer
			.sign_invoice(&raw, Recipient::Node)
			.map_err(|_| FFORReceiverError::SignerUnavailable)?;
		let signed = raw
			.sign::<_, ()>(|_| Ok(signature))
			.map_err(|_| FFORReceiverError::SignerUnavailable)?;
		record.invoice = Bolt11Invoice::from_signed(signed)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?
			.to_string();
		self.commit_ffor_invoice(context, record, capture.requirement)
	}

	fn capture_ffor_invoice(
		&self, context: &FFORReceiverRecoveryContext, intent: &FFORInvoiceIntent,
		route: &FFORWitnessRouteEvidence,
	) -> Result<Result<FFORInvoicePreparation, InvoiceCapture>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&context.settlement_node_id())
			.ok_or(FFORReceiverError::InvalidInvoice)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(&context.channel_id())
			.and_then(Channel::as_funded)
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		let recovery = self.ffor_recovery.lock().unwrap();
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let current = self.ffor_active_state_locked(channel, &recovery, &key)?;
		let runtime = self.ffor_activation.lock().unwrap();
		let height = self.best_block.read().unwrap();
		Self::validate_ffor_witness_context(context, &current, height.height)?;
		let registration = recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		let acks = recovery.get_witness_acks(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		let acknowledgement_digest = acknowledgements_digest(registration, acks)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		validate_route(context, registration, route, invoice_time()?)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		let requirement = &runtime.get(&key)?.requirement;
		if let Some(existing) = recovery.get_invoice(&key) {
			if !existing.matches_intent(intent, route) {
				return Err(FFORReceiverError::AlreadyRegistered);
			}
			return Ok(Ok(FFORInvoicePreparation {
				invoice_digest: existing.digest(),
				requirement: requirement.clone(),
			}));
		}
		if !self.ffor_persistence.lock().unwrap().is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let (settlement_scid, settlement_cltv) = Self::ffor_invoice_channel_binding(channel)?;
		Ok(Err(InvoiceCapture {
			record: FFORInvoiceRecord {
				context_digest: context.context_digest(),
				acknowledgement_digest,
				created_height: height.height,
				settlement_scid,
				settlement_cltv,
				intent: intent.clone(),
				route: route.clone(),
				invoice: String::new(),
			},
			requirement: requirement.clone(),
		}))
	}

	fn ffor_invoice_channel_binding(
		channel: &FundedChannel<SP>,
	) -> Result<(u64, u16), FFORReceiverError> {
		let scid = channel.get_inbound_scid().ok_or(FFORReceiverError::InvalidInvoice)?;
		let forwarding = channel
			.context
			.counterparty_forwarding_info()
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		if scid == 0 || forwarding.cltv_expiry_delta == 0 {
			return Err(FFORReceiverError::InvalidInvoice);
		}
		Ok((scid, forwarding.cltv_expiry_delta))
	}

	fn ffor_invoice_monitor_check(
		context: &FFORReceiverRecoveryContext, channel: &FundedChannel<SP>,
		record: &FFORInvoiceRecord, height: u32,
	) -> Result<FFORInvoiceMonitorCheck, FFORReceiverError> {
		let init = terms(context).map_err(|_| FFORReceiverError::InvalidInvoice)?;
		let voucher = &context.setup().vouchers()[0];
		Ok(FFORInvoiceMonitorCheck {
			channel_id: context.channel_id(),
			funding_txo: context.funding_txo(),
			settlement: context.settlement_node_id(),
			update_id: channel.context.get_latest_monitor_update_id(),
			commitments: context.commitments(),
			payment_hash: PaymentHash(voucher.payment_hash),
			amount_msat: voucher.amount_msat,
			voucher_expiry: voucher.expiry,
			deadline: init.settlement_deadline,
			manager_height: height,
			invoice_expires_at: record
				.expires_at()
				.map_err(|_| FFORReceiverError::InvalidInvoice)?,
			safety_margin_seconds: record.intent.safety_margin_seconds,
		})
	}

	fn commit_ffor_invoice(
		&self, context: &FFORReceiverRecoveryContext, record: FFORInvoiceRecord,
		captured_requirement: FFORPersistenceRequirement,
	) -> Result<FFORInvoicePreparation, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&context.settlement_node_id())
			.ok_or(FFORReceiverError::InvalidInvoice)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(&context.channel_id())
			.and_then(Channel::as_funded)
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		if channel.context.is_monitor_or_signer_pending_channel_update()
			|| peer
				.in_flight_monitor_updates
				.get(&context.channel_id())
				.map_or(false, |(_, updates)| !updates.is_empty())
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let mut recovery = self.ffor_recovery.lock().unwrap();
		let current = self.ffor_active_state_locked(channel, &recovery, &key)?;
		let mut runtime = self.ffor_activation.lock().unwrap();
		let height = self.best_block.read().unwrap();
		Self::validate_ffor_witness_context(context, &current, height.height)?;
		if Self::ffor_invoice_channel_binding(channel)?
			!= (record.settlement_scid, record.settlement_cltv)
		{
			return Err(FFORReceiverError::InvalidInvoice);
		}
		let registration = recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		let acks = recovery.get_witness_acks(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		record
			.validate(&current, registration, acks)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		validate_route(&current, registration, &record.route, invoice_time()?)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		if let Some(existing) = recovery.get_invoice(&key) {
			if !existing.matches_intent(&record.intent, &record.route) {
				return Err(FFORReceiverError::AlreadyRegistered);
			}
			return Ok(FFORInvoicePreparation {
				invoice_digest: existing.digest(),
				requirement: runtime.get(&key)?.requirement.clone(),
			});
		}
		let mut barrier = self.ffor_persistence.lock().unwrap();
		if runtime.get(&key)?.requirement != captured_requirement
			|| !barrier.is_complete(&captured_requirement)
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let check = Self::ffor_invoice_monitor_check(&current, channel, &record, height.height)?;
		let digest = record.digest();
		let mut upgrade = Some(
			recovery
				.prepare_invoice(&key, record)
				.map_err(|_| FFORReceiverError::RecoveryUnavailable)?,
		);
		let mut result = None;
		self.chain_monitor.validate_and_publish_ffor_invoice(&check, &mut || {
			let permit = upgrade.take().ok_or(())?;
			let requirement = match barrier.request() {
				Ok(requirement) => requirement,
				Err(_) => {
					result = Some(Err(FFORReceiverError::PersistenceUnavailable));
					return Err(());
				},
			};
			permit.commit();
			runtime.record(key, requirement.clone(), false);
			result = Some(Ok(FFORInvoicePreparation { invoice_digest: digest, requirement }));
			Ok(())
		})?;
		result.unwrap_or(Err(FFORReceiverError::InvalidInvoice))
	}

	/// Retrieve the exact persisted invoice only for confirmed application storage or historical
	/// recovery.
	///
	/// The epoch's current manager requirement must be complete, including a fresh barrier after
	/// restore. This historical getter can succeed after close or expiry; it never permits exposure.
	pub fn ffor_receiver_invoice_for_storage(
		&self, context: &FFORReceiverRecoveryContext,
	) -> Result<Option<FFORStoredInvoice>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let current = self.ffor_recovery_context_from_registry(&recovery, &key)?;
		if current.context_digest() != context.context_digest() {
			return Err(FFORReceiverError::InvalidInvoice);
		}
		let record = match recovery.get_invoice(&key) {
			Some(record) => record,
			None => return Ok(None),
		};
		let runtime = self.ffor_activation.lock().unwrap();
		let requirement = &runtime.get(&key)?.requirement;
		if !self.ffor_persistence.lock().unwrap().is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(Some(FFORStoredInvoice {
			context: current,
			invoice: record.invoice.clone(),
			digest: record.digest(),
			intent: record.intent.clone(),
			requirement: requirement.clone(),
		}))
	}

	/// Publish the already confirmed application invoice under current native and monitor locks.
	///
	/// Before calling, a private application owner must successfully persist these exact bytes and
	/// the matching Pending payment, retaining uncertainty across failed writes and restore. The
	/// callback only publishes that preconfirmed response in memory, at most once. It performs no
	/// I/O and acquires no native, monitor, owner or storage locks. Returning Err retains the exact
	/// assignment for retry. Publication never fabricates PaymentClaimed or completed receive credit.
	pub fn release_ffor_receiver_invoice<C>(
		&self, stored: &FFORStoredInvoice, publish: C,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&str) -> Result<(), ()>,
	{
		let _guard = self.total_consistency_lock.read().unwrap();
		let context = &stored.context;
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&context.settlement_node_id())
			.ok_or(FFORReceiverError::InvalidInvoice)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(&context.channel_id())
			.and_then(Channel::as_funded)
			.ok_or(FFORReceiverError::InvalidInvoice)?;
		if channel.context.is_monitor_or_signer_pending_channel_update()
			|| peer
				.in_flight_monitor_updates
				.get(&context.channel_id())
				.map_or(false, |(_, updates)| !updates.is_empty())
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let recovery = self.ffor_recovery.lock().unwrap();
		let current = self.ffor_active_state_locked(channel, &recovery, &key)?;
		let runtime = self.ffor_activation.lock().unwrap();
		let height = self.best_block.read().unwrap();
		Self::validate_ffor_witness_context(context, &current, height.height)?;
		let record = recovery.get_invoice(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		let registration = recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		let acks = recovery.get_witness_acks(&key).ok_or(FFORReceiverError::InvalidInvoice)?;
		record
			.validate(&current, registration, acks)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		validate_route(&current, registration, &record.route, invoice_time()?)
			.map_err(|_| FFORReceiverError::InvalidInvoice)?;
		if record.digest() != stored.digest
			|| record.invoice != stored.invoice
			|| Self::ffor_invoice_channel_binding(channel)?
				!= (record.settlement_scid, record.settlement_cltv)
		{
			return Err(FFORReceiverError::InvalidInvoice);
		}
		let requirement = &runtime.get(&key)?.requirement;
		let barrier = self.ffor_persistence.lock().unwrap();
		if requirement != &stored.requirement || !barrier.is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let check = Self::ffor_invoice_monitor_check(&current, channel, record, height.height)?;
		let mut callback = Some(publish);
		let released = self.chain_monitor.validate_and_publish_ffor_invoice(&check, &mut || {
			callback.take().ok_or(())?(&record.invoice)
		})?;
		Ok(released && callback.is_none())
	}
}

#[cfg(test)]
mod tests;
