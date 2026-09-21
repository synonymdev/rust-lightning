//! Read-only receiver contexts. No observation releases a message or changes a native phase.

use super::*;
use crate::ln::ffor::context::{FFORReceiverActiveContext, FFORReceiverRecoveryContext};

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
	/// Capture the generation of an already-authenticated native peer connection.
	///
	/// The custom message handler calls this after its native `peer_connected` callback succeeds.
	/// Supply the result with exact incoming bytes to synchronous receiver handling. A transport
	/// queue must retain its own connection token as well; this observation alone cannot authorize
	/// a future queue insertion. Disconnected, rejected and restored peers have no generation.
	pub fn ffor_peer_connection(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<crate::ln::ffor::FFORPeerConnection, FFORReceiverError> {
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		if !peer.is_connected {
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		let generation =
			peer.ffor_connection.as_ref().ok_or(FFORCommitmentError::ChannelUnavailable)?;
		Ok(crate::ln::ffor::FFORPeerConnection {
			peer: *counterparty_node_id,
			generation: Arc::clone(generation),
		})
	}

	/// Return authenticated historical activation evidence, including an archive-only epoch.
	/// This neither requires nor establishes current Active authority or durable readiness.
	pub fn ffor_receiver_recovery_context(
		&self, channel_id: &ChannelId, epoch_id: [u8; 32],
	) -> Result<FFORReceiverRecoveryContext, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		self.ffor_recovery_context_from_registry(
			&recovery,
			&FFORRecoveryKey { channel_id: *channel_id, epoch_id },
		)
	}

	/// List at most 64 retained activation histories for joining protected application records.
	/// Includes terminal histories and removed channels. Missing application keys must never be
	/// interpreted as permission to downgrade or discard the corresponding native epoch.
	pub fn list_ffor_receiver_recovery_contexts(
		&self,
	) -> Result<Vec<FFORReceiverRecoveryContext>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		recovery
			.activation_keys()
			.iter()
			.map(|key| self.ffor_recovery_context_from_registry(&recovery, key))
			.collect()
	}

	pub(super) fn ffor_recovery_context_from_registry(
		&self, recovery: &FFORRecoveryRegistry, key: &FFORRecoveryKey,
	) -> Result<FFORReceiverRecoveryContext, FFORReceiverError> {
		recovery
			.validate_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let setup = recovery.get(key).ok_or(FFORReceiverError::UnknownEpoch)?;
		let activation = recovery.get_activation(key).ok_or(FFORReceiverError::NotRegistered)?;
		activation.receiver_context(setup).map_err(|_| FFORReceiverError::RecoveryUnavailable)
	}

	/// Capture a current durable Active observation without releasing any external work.
	///
	/// The epoch must retain its exact signed acknowledgement and original frozen commitments.
	/// Any retained close intent, pending persistence, or unresolved peer report prevents capture.
	/// Mere disconnection does not revoke a retained Active epoch. The observation may remain valid
	/// after its admission deadline and authorizes neither witness provisioning nor invoices.
	pub fn capture_ffor_receiver_active_context(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
	) -> Result<FFORReceiverActiveContext, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		let channel = peer
			.channel_by_id
			.get(channel_id)
			.and_then(Channel::as_funded)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		self.ffor_active_context_locked(channel, &recovery, &key)
	}

	/// Check whether this manager still has the exact Active state captured in `context`.
	///
	/// This checks manager identity, the latest exact persistence requirement and current native
	/// state. It does not grant authority for a later side effect: another thread may close the
	/// epoch immediately after this call. A future driver must recheck while releasing work.
	/// Every context from an earlier manager instance is invalid after restore, even if the
	/// serialized channel bytes match. Newly captured contexts require new persistence completion.
	pub fn validate_ffor_receiver_active_context(
		&self, context: &FFORReceiverActiveContext,
	) -> Result<(), FFORReceiverError> {
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
		let key = FFORRecoveryKey {
			channel_id: historical.channel_id(),
			epoch_id: historical.epoch_id(),
		};
		let recovery = self.ffor_recovery.lock().unwrap();
		let current = self.ffor_active_context_locked(channel, &recovery, &key)?;
		if current.requirement != context.requirement
			|| current.recovery.context_digest() != historical.context_digest()
			|| current.recovery.activation_ack_wire() != historical.activation_ack_wire()
		{
			return Err(FFORReceiverError::RecoveryUnavailable);
		}
		Ok(())
	}

	pub(in crate::ln::channelmanager) fn ffor_active_context_locked(
		&self, channel: &FundedChannel<SP>, recovery: &FFORRecoveryRegistry, key: &FFORRecoveryKey,
	) -> Result<FFORReceiverActiveContext, FFORReceiverError> {
		let context = self.ffor_active_state_locked(channel, recovery, key)?;
		let runtime = self.ffor_activation.lock().unwrap();
		let requirement = &runtime.get(key)?.requirement;
		if !self.ffor_persistence.lock().unwrap().is_complete(requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(FFORReceiverActiveContext { recovery: context, requirement: requirement.clone() })
	}

	pub(super) fn ffor_active_state_locked(
		&self, channel: &FundedChannel<SP>, recovery: &FFORRecoveryRegistry, key: &FFORRecoveryKey,
	) -> Result<FFORReceiverRecoveryContext, FFORReceiverError> {
		channel
			.ffor_validate_receiver_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let setup = channel
			.ffor_receiver_setup_record()
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
			.ok_or(FFORReceiverError::NotRegistered)?;
		recovery
			.validate_channel_lifecycle(
				&setup,
				channel.ffor_receiver_fence(),
				channel.ffor_receiver_abort_reason(),
				channel.ffor_receiver_drain_binding(),
				channel.ffor_receiver_closed_completion_hash(),
				channel.ffor_receiver_drain_activation_hash(),
			)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let activation = recovery.get_activation(key).ok_or(FFORReceiverError::NotRegistered)?;
		let context = self.ffor_recovery_context_from_registry(recovery, key)?;
		if !activation.is_active()
			|| activation.is_aborted()
			|| activation.close_record().is_some()
			|| channel.ffor_receiver_fence()
				!= Some((FFORReceiverFencePhase::Active, context.activation_hash()))
			|| channel.context.get_counterparty_node_id() != context.settlement_node_id()
			|| channel.ffor_frozen_commitments(&self.logger)? != activation.commitments()
			|| matches!(
				channel.ffor_receiver_reconnect_outcome(),
				Some(FFORReestablishOutcome::ResolutionRequired { .. })
					| Some(FFORReestablishOutcome::AbortRequired { .. })
					| Some(FFORReestablishOutcome::CloseReplayRequired { .. })
			) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		Ok(context)
	}
}

#[cfg(test)]
mod tests;
