//! Private composition of receiver activation, retained evidence and ordered persistence.
//!
//! The experimental driver selects transitions; no observation authorizes invoice exposure.

use super::*;
use crate::ln::channel::{FFORReceiverFencePhase, FFORReestablishOutcome};
use crate::ln::ffor_recovery::{FFORReceiverActivation, FFORRecoveryKey};
use crate::sign::ffor::FFORSigningRequest;
use lightning_ffor::transcript;
use lightning_ffor::wire::{Activate, Message as FFORMessage, Payload};

mod close;
mod context;
mod driver;
mod invoice;
mod receipt;
mod reestablish;
mod witness;
mod witness_ack;

struct RuntimeEntry {
	key: FFORRecoveryKey,
	requirement: FFORPersistenceRequirement,
	may_send_activate: bool,
	request_connection: Option<crate::ln::ffor::FFORPeerConnection>,
	may_send_init: bool,
}

/// Bounded by the retained registry's keys. No bytes or phase authority are copied here.
pub(super) struct FFORReceiverRuntime {
	entries: Vec<RuntimeEntry>,
	witness_attempts: Vec<witness_ack::WitnessAttempt>,
}

impl FFORReceiverRuntime {
	pub(super) fn new() -> Self {
		Self { entries: Vec::new(), witness_attempts: Vec::new() }
	}

	pub(super) fn restored(
		recovery: &FFORRecoveryRegistry, barrier: &mut FFORPersistenceBarrier,
	) -> Result<Self, DecodeError> {
		let mut runtime = Self::new();
		let mut keys = recovery.activation_keys();
		for key in recovery.request_keys() {
			if !keys.contains(&key) {
				keys.push(key);
			}
		}
		if !keys.is_empty() {
			let requirement = barrier.request().map_err(|_| DecodeError::InvalidValue)?;
			for key in keys {
				runtime.record(key, requirement.clone(), false);
			}
		}
		Ok(runtime)
	}

	fn get(&self, key: &FFORRecoveryKey) -> Result<&RuntimeEntry, FFORReceiverError> {
		self.entries
			.iter()
			.find(|entry| entry.key == *key)
			.ok_or(FFORReceiverError::RecoveryUnavailable)
	}

	pub(super) fn record(
		&mut self, key: FFORRecoveryKey, requirement: FFORPersistenceRequirement,
		may_send_activate: bool,
	) {
		let entry = RuntimeEntry {
			key,
			requirement,
			may_send_activate,
			request_connection: None,
			may_send_init: false,
		};
		if let Some(existing) = self.entries.iter_mut().find(|existing| existing.key == key) {
			*existing = entry;
		} else {
			self.entries.push(entry);
		}
	}

	fn sent(&mut self, key: &FFORRecoveryKey) {
		if let Some(entry) = self.entries.iter_mut().find(|entry| entry.key == *key) {
			entry.may_send_activate = false;
		}
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
	/// Derive and sign from the actual quiescent channel. This returns no outbound bytes.
	#[cfg(test)]
	pub(crate) fn prepare_ffor_receiver_activation(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		monitor: &FFORMonitorSnapshot,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		self.prepare_ffor_receiver_activation_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			monitor,
			None,
		)
	}

	pub(crate) fn prepare_ffor_receiver_activation_on_connection(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		monitor: &FFORMonitorSnapshot, connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, counterparty_node_id, connection)?;
		let current_height = self.best_block.read().unwrap().height;
		let channel = peer
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		channel
			.ffor_validate_receiver_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let setup = channel
			.ffor_receiver_setup_record()
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
			.ok_or(FFORReceiverError::NotRegistered)?;
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if authenticated.header().epoch_id != epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let mut recovery = self.ffor_recovery.lock().unwrap();
		if let Some(activation) = recovery.get_activation(&key) {
			let hash = activation
				.activation_hash(&setup)
				.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
			if activation.is_aborted()
				|| activation.is_active()
				|| channel.ffor_receiver_fence() != Some((FFORReceiverFencePhase::Activating, hash))
			{
				return Err(FFORCommitmentError::PendingUpdates.into());
			}
			return Ok(self.ffor_activation.lock().unwrap().get(&key)?.requirement.clone());
		}
		if channel.ffor_receiver_quiescence_status(epoch_id, current_height, &self.logger)?
			!= FFORReceiverQuiescenceStatus::Quiescent
		{
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let commitments = match channel.ffor_receiver_book_status(monitor, &self.logger)? {
			FFORReceiverStatus::Parked { commitments } => commitments,
			_ => return Err(FFORCommitmentError::PendingUpdates.into()),
		};
		let mut message = FFORMessage {
			header: authenticated.header(),
			payload: Payload::Activate(Activate {
				setup_hash: authenticated.setup_hash(),
				book_hash: authenticated.book_hash(),
				commit_hash: transcript::commitment_hash(
					commitments.holder.number,
					&commitments.holder.txid.to_byte_array(),
					commitments.counterparty.number,
					&commitments.counterparty.txid.to_byte_array(),
				),
				epoch_start_height: current_height,
			}),
			extensions: Vec::new(),
			signature: [0; 64],
		};
		let unsigned =
			message.unsigned_wire().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let request = FFORSigningRequest::new(&unsigned)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		message.signature = self
			.node_signer
			.sign_ffor_message(&request)
			.map_err(|_| FFORReceiverError::SignerUnavailable)?
			.serialize_compact();
		let wire = message.encode().map_err(|_| FFORReceiverError::SignerUnavailable)?;
		let activation =
			FFORReceiverActivation::prepare(&setup, &wire, commitments, monitor, current_height)
				.map_err(|_| FFORReceiverError::SignerUnavailable)?;
		let live_height = self.best_block.read().unwrap().height;
		authenticated
			.validate_activation(&message, activation.commitment_hash(), live_height)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let upgrade = recovery
			.prepare_activation(&setup, &activation)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.install_ffor_receiver_activation(
			&activation,
			monitor,
			live_height,
			&self.logger,
		)?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement.clone(), true);
		Ok(requirement)
	}

	/// Enqueue at most once to the original connection after its exact snapshot is durable.
	/// The callback must check its authenticated transport token atomically with queue insertion.
	/// It must not call back into the manager, acquire a monitor, or perform network I/O.
	#[cfg(test)]
	pub(crate) fn release_ffor_receiver_activation<C>(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		enqueue: C,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		self.release_ffor_receiver_activation_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			enqueue,
			None,
		)
	}

	pub(crate) fn release_ffor_receiver_activation_on_connection<C>(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		enqueue: C, connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		let _guard = self.total_consistency_lock.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, counterparty_node_id, connection)?;
		let channel = peer
			.channel_by_id
			.get(channel_id)
			.and_then(Channel::as_funded)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?;
		let activation = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let hash = activation
			.activation_hash(setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let mut runtime = self.ffor_activation.lock().unwrap();
		let entry = runtime.get(&key)?;
		if !entry.may_send_activate
			|| !self.ffor_persistence.lock().unwrap().is_complete(&entry.requirement)
			|| channel.ffor_receiver_fence() != Some((FFORReceiverFencePhase::Activating, hash))
			|| !channel.has_ffor_receiver_quiescence(epoch_id)
		{
			return Ok(false);
		}
		let current_height = self.best_block.read().unwrap().height;
		channel.ffor_receiver_quiescence_status(epoch_id, current_height, &self.logger)?;
		let message = FFORMessage::decode(activation.activate_wire())
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		setup
			.validate_recovery()
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
			.validate_activation(&message, activation.commitment_hash(), current_height)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if enqueue(activation.activate_wire()).is_err() {
			return Ok(false);
		}
		runtime.sent(&key);
		Ok(true)
	}

	/// Retain an exact authenticated S acknowledgement under the same phase and archive authority.
	/// The caller must supply the peer identity from the current authenticated transport callback.
	#[cfg(test)]
	pub(crate) fn accept_ffor_receiver_activation_ack(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		ack_wire: &[u8],
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		self.accept_ffor_receiver_activation_ack_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			ack_wire,
			None,
		)
	}

	pub(crate) fn accept_ffor_receiver_activation_ack_on_connection(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		ack_wire: &[u8], connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, counterparty_node_id, connection)?;
		let channel = peer
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let mut recovery = self.ffor_recovery.lock().unwrap();
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?.clone();
		let previous = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let activation = previous
			.with_ack(&setup, ack_wire)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if previous.is_active() {
			// A byte-identical acknowledgement remains idempotent after close or drain.
			// Check the current lifecycle instead of repeating the earlier phase transition.
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
			return Ok(self.ffor_activation.lock().unwrap().get(&key)?.requirement.clone());
		}
		let upgrade = recovery
			.prepare_activation(&setup, &activation)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.accept_ffor_receiver_activation(&activation)?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement.clone(), false);
		Ok(requirement)
	}

	/// Called under the peer lock before ordinary reconnect can mutate connection state.
	pub(super) fn check_ffor_reconnect_archive(
		&self, channel: &FundedChannel<SP>,
	) -> Result<(), ChannelError> {
		if !channel.context.is_ffor_frozen() && channel.ffor_receiver_drain_binding().is_none() {
			return Ok(());
		}
		let invalid = || {
			ChannelError::WarnAndDisconnect(
				"FFOR reconnect recovery evidence does not match the channel".to_owned(),
			)
		};
		let setup =
			channel.ffor_receiver_setup_record().map_err(|_| invalid())?.ok_or_else(invalid)?;
		let authenticated = setup.validate_recovery().map_err(|_| invalid())?;
		let key = FFORRecoveryKey {
			channel_id: channel.context.channel_id(),
			epoch_id: authenticated.header().epoch_id,
		};
		let recovery = self.ffor_recovery.lock().unwrap();
		recovery
			.validate_channel_lifecycle(
				&setup,
				channel.ffor_receiver_fence(),
				channel.ffor_receiver_abort_reason(),
				channel.ffor_receiver_drain_binding(),
				channel.ffor_receiver_closed_completion_hash(),
				channel.ffor_receiver_drain_activation_hash(),
			)
			.map_err(|_| invalid())?;
		let activation = recovery.get_activation(&key).ok_or_else(invalid)?;
		if activation.is_draining() {
			if !activation.is_closed() {
				channel.validate_ffor_drain().map_err(|_| invalid())?;
			}
			return Ok(());
		}
		if channel.ffor_frozen_commitments(&self.logger).map_err(|_| invalid())?
			!= activation.commitments()
		{
			return Err(invalid());
		}
		Ok(())
	}

	/// An unsigned report can require a durable abort, but cannot itself establish Active.
	pub(super) fn apply_ffor_reconnect_outcome(
		&self, channel: &mut FundedChannel<SP>,
	) -> Result<(), ChannelError> {
		let report = match channel.ffor_receiver_reconnect_outcome() {
			Some(FFORReestablishOutcome::AbortRequired { peer_report }) => *peer_report,
			_ => return Ok(()),
		};
		let invalid = || {
			ChannelError::WarnAndDisconnect("FFOR reconnect abort could not be retained".to_owned())
		};
		let setup =
			channel.ffor_receiver_setup_record().map_err(|_| invalid())?.ok_or_else(invalid)?;
		let authenticated = setup.validate_recovery().map_err(|_| invalid())?;
		let key = FFORRecoveryKey {
			channel_id: channel.context.channel_id(),
			epoch_id: authenticated.header().epoch_id,
		};
		let mut recovery = self.ffor_recovery.lock().unwrap();
		let previous = recovery.get_activation(&key).ok_or_else(invalid)?;
		if previous.is_aborted() {
			return Ok(());
		}
		let aborted = previous.abort_after_reestablish(&setup, report).map_err(|_| invalid())?;
		let upgrade = recovery.prepare_activation(&setup, &aborted).map_err(|_| invalid())?;
		let requirement = self.ffor_persistence.lock().unwrap().request().map_err(|_| invalid())?;
		channel.begin_ffor_receiver_reconnect_abort(&aborted).map_err(|_| invalid())?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement, false);
		Ok(())
	}

	/// Release only a durably recorded pre-active abort. Existing monitor claims remain ahead of failures.
	#[cfg(test)]
	pub(crate) fn release_ffor_receiver_reconnect_abort(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
	) -> Result<bool, FFORReceiverError> {
		self.release_ffor_receiver_reconnect_abort_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			None,
		)
	}

	pub(crate) fn release_ffor_receiver_reconnect_abort_on_connection(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<bool, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(counterparty_node_id)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, counterparty_node_id, connection)?;
		let channel = peer
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?;
		let activation = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		if !activation.is_aborted() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let runtime = self.ffor_activation.lock().unwrap();
		let requirement = &runtime.get(&key)?.requirement;
		if !self.ffor_persistence.lock().unwrap().is_complete(requirement) {
			return Ok(false);
		}
		let hash = activation
			.activation_hash(setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		channel.release_ffor_receiver_reconnect_abort(epoch_id, hash)?;
		channel.ffor_queue_aborted_vouchers(&self.logger);
		Ok(true)
	}
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod drain_tests;
