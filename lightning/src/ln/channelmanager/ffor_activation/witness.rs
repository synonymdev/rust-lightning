//! Native ownership of compact witness registrations and persistence-gated provisioning.

use super::*;
use crate::ln::ffor::{
	FFORReceiverActiveContext, FFORReceiverRecoveryContext, FFORReceiverWitnessRegistration,
};
use lightning_ffor::witness::{Provision, SignedManifest};

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
	/// Retain the immutable selection of one through four signed witness manifests.
	///
	/// First reserve and durably store the exact manifests and recovery keys in protected
	/// application storage. This method retains compact public evidence only. The supplied
	/// historical context identifies an epoch; actual current Active state, exact commitments,
	/// signed acknowledgement and the live settlement deadline are checked under native locks.
	/// No settlement-peer connection is required. A missing sidecar for an existing registration
	/// must be recovered, never replaced with freshly generated keys.
	///
	/// Exact retries return the current persistence requirement, including while the registration
	/// write is pending. They still require the same current Active state and an unexpired deadline.
	/// A different witness, key or signed manifest cannot replace this registration. Provisioning
	/// remains blocked until persistence completes and a fresh Active context is captured.
	pub fn register_ffor_receiver_witnesses(
		&self, context: &FFORReceiverRecoveryContext, manifests: &[(PublicKey, SignedManifest)],
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&context.settlement_node_id())
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(&context.channel_id())
			.and_then(Channel::as_funded)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
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
		let registration = FFORReceiverWitnessRegistration::from_manifests(&current, manifests)
			.map_err(|_| FFORReceiverError::InvalidWitnessRegistration)?;
		if let Some(existing) = recovery.get_witnesses(&key) {
			if existing != &registration {
				return Err(FFORReceiverError::InvalidWitnessRegistration);
			}
			if recovery.get_witness_acks(&key).is_some() {
				return Ok(runtime.get(&key)?.requirement.clone());
			}
			// A legacy registration must reserve compact ACK capacity before the new authenticated
			// attempt path sends anything. Exact retries cannot skip this checked upgrade.
		}
		// Initial registration cannot convert a merely observed or unpersisted Active phase into
		// authority. Its exact compact evidence and all later close reservations must fit first.
		let mut barrier = self.ffor_persistence.lock().unwrap();
		if !barrier.is_complete(&runtime.get(&key)?.requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let upgrade = recovery
			.prepare_witnesses(&key, registration)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement =
			barrier.request().map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		upgrade.commit();
		runtime.record(key, requirement.clone(), false);
		Ok(requirement)
	}

	/// Inspect immutable historical witness ownership, including after close or channel removal.
	///
	/// The result is not a current-state capability. Applications must compare every selected
	/// witness and exact manifest digest to their confirmed protected records before continuing.
	/// An existing registration with missing application secrets never permits key regeneration.
	pub fn ffor_receiver_witness_registration(
		&self, context: &FFORReceiverRecoveryContext,
	) -> Result<Option<FFORReceiverWitnessRegistration>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?;
		let current = recovery
			.get_activation(&key)
			.ok_or(FFORReceiverError::NotRegistered)?
			.receiver_context(setup)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		if current.context_digest() != context.context_digest() {
			return Err(FFORReceiverError::RecoveryUnavailable);
		}
		Ok(recovery.get_witnesses(&key).cloned())
	}

	/// Release one exact registered Provision while current native authority remains locked.
	///
	/// Capture a fresh Active context after registration persistence. This method checks its
	/// manager instance and latest epoch requirement, the current Active fence and commitment pair,
	/// exact signed manifest, and live settlement deadline. Neither witness acknowledgement nor
	/// invoice readiness follows from success. The settlement peer may be disconnected.
	///
	/// `enqueue` must atomically check its actual authenticated witness connection token and
	/// reserve bounded transport capacity for this exact typed request. It must perform no I/O,
	/// acquire no manager/peer/store locks, and never reenter the manager. No witness peer mutex
	/// is acquired here. `Ok(false)` means callback backpressure; retry the same protected request.
	/// A stale context, changed phase or pending requirement fails before the callback is called.
	pub fn release_ffor_receiver_witness_provision<C>(
		&self, context: &FFORReceiverActiveContext, witness: &PublicKey, provision: &Provision,
		enqueue: C,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&Provision) -> Result<(), ()>,
	{
		let _guard = self.total_consistency_lock.read().unwrap();
		let historical = context.recovery_context();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&historical.settlement_node_id())
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(&historical.channel_id())
			.and_then(Channel::as_funded)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		if channel.context.is_monitor_or_signer_pending_channel_update()
			|| peer
				.in_flight_monitor_updates
				.get(&historical.channel_id())
				.map_or(false, |(_, updates)| !updates.is_empty())
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let key = FFORRecoveryKey {
			channel_id: historical.channel_id(),
			epoch_id: historical.epoch_id(),
		};
		let recovery = self.ffor_recovery.lock().unwrap();
		let current = self.ffor_active_state_locked(channel, &recovery, &key)?;
		let runtime = self.ffor_activation.lock().unwrap();
		let height = self.best_block.read().unwrap();
		Self::validate_ffor_witness_context(historical, &current, height.height)?;
		let registration =
			recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		if !registration.matches_manifest(witness, provision.manifest()) {
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		let requirement = &runtime.get(&key)?.requirement;
		let barrier = self.ffor_persistence.lock().unwrap();
		if requirement != &context.requirement || !barrier.is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(enqueue(provision).is_ok())
	}

	pub(super) fn validate_ffor_witness_context(
		provided: &FFORReceiverRecoveryContext, current: &FFORReceiverRecoveryContext, height: u32,
	) -> Result<(), FFORReceiverError> {
		if provided.context_digest() != current.context_digest()
			|| provided.activation_ack_wire() != current.activation_ack_wire()
			|| height >= current.setup().terms().settlement_deadline
		{
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
