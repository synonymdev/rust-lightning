//! Native sent-request correlation and compact durable witness promises.

use super::*;
use crate::ln::ffor::{
	FFORPeerConnection, FFORReceiverActiveContext, FFORReceiverRecoveryContext,
	FFORReceiverWitnessAcknowledgements, FFORReceiverWitnessRegistration,
	FFORWitnessAcknowledgement, FFORWitnessProvisionAttempt,
};
use bitcoin::hashes::{sha256, Hash};
use lightning_ffor::witness::{Acknowledgement, AcknowledgementResult, Provision};

const MAX_WITNESS_ATTEMPTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptState {
	Staged,
	Sent,
	Refused,
}

pub(super) struct WitnessAttempt {
	handle: FFORWitnessProvisionAttempt,
	state: AttemptState,
}

impl FFORReceiverRuntime {
	pub(in crate::ln::channelmanager) fn invalidate_witness_attempts(&mut self, peer: PublicKey) {
		self.witness_attempts.retain(|attempt| attempt.handle.connection.peer != peer);
	}
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
	/// Bind an exact registered Provision to this manager's authenticated witness connection.
	///
	/// Staging grants no send, ACK or invoice authority. At most 64 attempts and request-ID
	/// tombstones are retained across the manager. Exact retries return the same handle. Reusing
	/// one request ID for different content on the same connection is refused. A witness disconnect
	/// invalidates all its attempts; use a fresh request ID for the same manifest on reconnect.
	/// Registration must have reserved native ACK storage before this path can be used.
	pub fn stage_ffor_receiver_witness_provision(
		&self, context: &FFORReceiverRecoveryContext, connection: &FFORPeerConnection,
		provision: &Provision,
	) -> Result<FFORWitnessProvisionAttempt, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, &connection.peer, Some(connection))?;
		let recovery = self.ffor_recovery.lock().unwrap();
		let (key, registration, _) = self.ffor_ack_registration_locked(&recovery, context)?;
		if !registration.matches_manifest(&connection.peer, provision.manifest()) {
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		let digest = sha256::Hash::hash(&provision.manifest().encode()).to_byte_array();
		let mut runtime = self.ffor_activation.lock().unwrap();
		if let Some(existing) = runtime.witness_attempts.iter().find(|attempt| {
			attempt.handle.connection == *connection
				&& attempt.handle.request_id == provision.request_id()
		}) {
			if existing.handle.key != key
				|| existing.handle.context_digest != context.context_digest()
				|| existing.handle.manifest_digest != digest
				|| existing.state == AttemptState::Refused
			{
				return Err(FFORReceiverError::InvalidWitnessRegistration);
			}
			return Ok(existing.handle.clone());
		}
		if runtime.witness_attempts.len() >= MAX_WITNESS_ATTEMPTS {
			return Err(FFORReceiverError::RecoveryUnavailable);
		}
		let handle = FFORWitnessProvisionAttempt {
			identity: Arc::new(()),
			key,
			context_digest: context.context_digest(),
			connection: connection.clone(),
			request_id: provision.request_id(),
			manifest_digest: digest,
		};
		runtime
			.witness_attempts
			.push(WitnessAttempt { handle: handle.clone(), state: AttemptState::Staged });
		Ok(handle)
	}

	/// Release a staged request while native Active state and the witness generation remain valid.
	///
	/// The callback must atomically check its paired actual witness transport token and enqueue
	/// this exact Provision with bounded capacity. It must perform no I/O and acquire no native,
	/// owner or storage locks. A successful enqueue alone marks this attempt sent. Backpressure
	/// leaves it staged. An already sent exact retry returns true without calling the callback.
	/// The settlement peer need not be connected. This does not authorize invoice exposure.
	pub fn release_ffor_receiver_witness_attempt<C>(
		&self, context: &FFORReceiverActiveContext, attempt: &FFORWitnessProvisionAttempt,
		provision: &Provision, enqueue: C,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&Provision) -> Result<(), ()>,
	{
		let _guard = self.total_consistency_lock.read().unwrap();
		let historical = context.recovery_context();
		// Native generation changes require this map's write lock. Retain the read guard through
		// enqueue, without locking the witness peer while holding the settlement channel.
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
		let recovery = self.ffor_recovery.lock().unwrap();
		let (key, registration, _) = self.ffor_ack_registration_locked(&recovery, historical)?;
		let current = self.ffor_active_state_locked(channel, &recovery, &key)?;
		let height = self.best_block.read().unwrap();
		Self::validate_ffor_witness_context(historical, &current, height.height)?;
		if attempt.key != key
			|| attempt.context_digest != historical.context_digest()
			|| attempt.request_id != provision.request_id()
			|| attempt.manifest_digest
				!= sha256::Hash::hash(&provision.manifest().encode()).to_byte_array()
			|| !registration.matches_manifest(&attempt.connection.peer, provision.manifest())
		{
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		let mut runtime = self.ffor_activation.lock().unwrap();
		let requirement = &runtime.get(&key)?.requirement;
		let barrier = self.ffor_persistence.lock().unwrap();
		if requirement != &context.requirement || !barrier.is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let saved = runtime
			.witness_attempts
			.iter_mut()
			.find(|saved| Arc::ptr_eq(&saved.handle.identity, &attempt.identity))
			.ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		match saved.state {
			AttemptState::Refused => Err(FFORReceiverError::InvalidWitnessRegistration),
			AttemptState::Sent => Ok(true),
			AttemptState::Staged => {
				let sent = enqueue(provision).is_ok();
				if sent {
					saved.state = AttemptState::Sent;
				}
				Ok(sent)
			},
		}
	}

	/// Retain a positive ACK from the current native witness connection and an exact sent attempt.
	///
	/// Call only from authenticated custom-message handling, after the application has durably
	/// retained its own correlated promise. This unsigned wire message is not portable evidence:
	/// caller-created correlation objects cannot replace the actual native session and sent record.
	/// The first native promise for each immutable manifest is retained permanently. Later valid
	/// responses never replace it, even if their request ID or sufficient retention differs.
	/// The returned manager requirement must complete before any later use. This is not readiness.
	pub fn retain_ffor_receiver_witness_ack(
		&self, connection: &FFORPeerConnection, acknowledgement: &Acknowledgement,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, &connection.peer, Some(connection))?;
		let mut recovery = self.ffor_recovery.lock().unwrap();
		let mut runtime = self.ffor_activation.lock().unwrap();
		let saved = runtime
			.witness_attempts
			.iter_mut()
			.find(|saved| {
				saved.handle.connection == *connection
					&& saved.handle.request_id == acknowledgement.request_id()
			})
			.ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		if saved.state != AttemptState::Sent {
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		let retention_until = match acknowledgement.result() {
			AcknowledgementResult::Accepted { witness, retention_until }
				if *witness == connection.peer =>
			{
				*retention_until
			},
			AcknowledgementResult::Refused(_) => {
				saved.state = AttemptState::Refused;
				return Err(FFORReceiverError::InvalidWitnessRegistration);
			},
			_ => return Err(FFORReceiverError::InvalidWitnessRegistration),
		};
		let key = saved.handle.key;
		let registration =
			recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		let witness = registration
			.witnesses()
			.iter()
			.find(|w| w.witness_node_id() == connection.peer)
			.ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		if registration.context_digest() != saved.handle.context_digest
			|| witness.manifest_digest() != saved.handle.manifest_digest
			|| retention_until < witness.retention_until()
		{
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		let existing =
			recovery.get_witness_acks(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?;
		if existing.acknowledgements().iter().any(|ack| ack.witness_node_id() == connection.peer) {
			return Ok(runtime.get(&key)?.requirement.clone());
		}
		let promise = FFORWitnessAcknowledgement {
			witness: connection.peer,
			manifest_digest: saved.handle.manifest_digest,
			request_id: acknowledgement.request_id(),
			retention_until,
		};
		let permit = recovery
			.prepare_witness_ack(&key, promise)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		permit.commit();
		runtime.record(key, requirement.clone(), false);
		Ok(requirement)
	}

	/// Inspect compact historical native ACK evidence, without current durability or readiness.
	/// `None` means no native tracking was reserved; an empty set means no ACK was retained.
	pub fn ffor_receiver_witness_acknowledgements(
		&self, context: &FFORReceiverRecoveryContext,
	) -> Result<Option<FFORReceiverWitnessAcknowledgements>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		self.ffor_validate_ack_context_locked(&recovery, context, &key)?;
		Ok(recovery.get_witness_acks(&key).cloned())
	}

	fn ffor_ack_registration_locked<'a>(
		&self, recovery: &'a FFORRecoveryRegistry, context: &FFORReceiverRecoveryContext,
	) -> Result<
		(
			FFORRecoveryKey,
			&'a FFORReceiverWitnessRegistration,
			&'a FFORReceiverWitnessAcknowledgements,
		),
		FFORReceiverError,
	> {
		let key =
			FFORRecoveryKey { channel_id: context.channel_id(), epoch_id: context.epoch_id() };
		self.ffor_validate_ack_context_locked(recovery, context, &key)?;
		Ok((
			key,
			recovery.get_witnesses(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?,
			recovery.get_witness_acks(&key).ok_or(FFORReceiverError::InvalidWitnessRegistration)?,
		))
	}

	fn ffor_validate_ack_context_locked(
		&self, recovery: &FFORRecoveryRegistry, context: &FFORReceiverRecoveryContext,
		key: &FFORRecoveryKey,
	) -> Result<(), FFORReceiverError> {
		recovery
			.validate_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let setup = recovery.get(key).ok_or(FFORReceiverError::UnknownEpoch)?;
		let current = recovery
			.get_activation(key)
			.ok_or(FFORReceiverError::NotRegistered)?
			.receiver_context(setup)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		if context.context_digest() != current.context_digest()
			|| context.activation_ack_wire() != current.activation_ack_wire()
		{
			return Err(FFORReceiverError::InvalidWitnessRegistration);
		}
		Ok(())
	}
}
