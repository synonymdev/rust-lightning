//! Private signed close and voucher drain orchestration. Each wire and channel release follows
//! the exact retained transition's persistence requirement; stock monitor writes still gate HTLCs.

use super::*;

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
	fn validate_ffor_close_transition(
		&self, channel: &FundedChannel<SP>, recovery: &FFORRecoveryRegistry,
		allow_close_replay: bool,
	) -> Result<(), FFORReceiverError> {
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
		match channel.ffor_receiver_reconnect_outcome() {
			Some(FFORReestablishOutcome::ResolutionRequired { .. })
			| Some(FFORReestablishOutcome::AbortRequired { .. }) => {
				Err(FFORCommitmentError::PendingUpdates.into())
			},
			Some(FFORReestablishOutcome::CloseReplayRequired { .. }) if !allow_close_replay => {
				Err(FFORCommitmentError::PendingUpdates.into())
			},
			_ => Ok(()),
		}
	}

	/// Sign and retain close intent. Exact retries reuse the existing bytes and barrier.
	#[cfg(test)]
	pub(crate) fn prepare_ffor_receiver_close(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		self.prepare_ffor_receiver_close_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			None,
		)
	}

	pub(crate) fn prepare_ffor_receiver_close_on_connection(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
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
		let mut recovery = self.ffor_recovery.lock().unwrap();
		self.validate_ffor_close_transition(channel, &recovery, true)?;
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?.clone();
		let previous = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let hash = previous
			.activation_hash(&setup)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if previous.is_aborted() || !previous.is_active() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		if previous.close_record().is_some() {
			return Ok(self.ffor_activation.lock().unwrap().get(&key)?.requirement.clone());
		}
		if channel.ffor_receiver_fence() != Some((FFORReceiverFencePhase::Active, hash)) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let mut message = FFORMessage {
			header: setup
				.validate_recovery()
				.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
				.header(),
			payload: Payload::Close(hash),
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
		let next = previous
			.with_close(
				&setup,
				&message.encode().map_err(|_| FFORReceiverError::SignerUnavailable)?,
			)
			.map_err(|_| FFORReceiverError::SignerUnavailable)?;
		let upgrade = recovery
			.prepare_activation(&setup, &next)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement.clone(), false);
		Ok(requirement)
	}

	/// Exact close retransmission is allowed after reconnect. The callback atomically verifies the
	/// current authenticated connection and enqueues a bounded message without manager reentry or I/O.
	#[cfg(test)]
	pub(crate) fn release_ffor_receiver_close<C>(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		enqueue: C,
	) -> Result<bool, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		self.release_ffor_receiver_close_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			enqueue,
			None,
		)
	}

	pub(crate) fn release_ffor_receiver_close_on_connection<C>(
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
		if matches!(
			channel.ffor_receiver_reconnect_outcome(),
			Some(FFORReestablishOutcome::ResolutionRequired { .. })
				| Some(FFORReestablishOutcome::AbortRequired { .. })
		) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let activation = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let close = activation.close_record().ok_or(FFORCommitmentError::PendingUpdates)?;
		if let Some(FFORReestablishOutcome::CloseReplayRequired { peer_report }) =
			channel.ffor_receiver_reconnect_outcome()
		{
			let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?;
			let hash = activation
				.activation_hash(setup)
				.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
			if peer_report.epoch_id != epoch_id
				|| peer_report.activation_hash != hash
				|| peer_report.state != lightning_ffor::reestablish::ReportedState::Active
			{
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			}
		}

		let runtime = self.ffor_activation.lock().unwrap();
		if !channel.context.is_connected()
			|| !self.ffor_persistence.lock().unwrap().is_complete(&runtime.get(&key)?.requirement)
		{
			return Ok(false);
		}
		Ok(enqueue(close.close_wire()).is_ok())
	}

	/// Authenticate an exact settlement response and install the still-disabled channel drain.
	#[cfg(test)]
	pub(crate) fn accept_ffor_receiver_close_ack(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		ack_wire: &[u8],
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		self.accept_ffor_receiver_close_ack_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			ack_wire,
			None,
		)
	}

	pub(crate) fn accept_ffor_receiver_close_ack_on_connection(
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
		self.validate_ffor_close_transition(channel, &recovery, true)?;
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?.clone();
		let previous = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let next = previous
			.with_close_ack(&setup, ack_wire)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		if previous.is_draining() {
			return Ok(self.ffor_activation.lock().unwrap().get(&key)?.requirement.clone());
		}
		let upgrade = recovery
			.prepare_activation(&setup, &next)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.install_ffor_receiver_drain(next.close_record().unwrap())?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement.clone(), false);
		Ok(requirement)
	}

	/// Import every signed preimage before enabling any failure. Repeated calls and restart use
	/// the stock idempotent claim path, whose own monitor persistence gates fulfill wire.
	#[cfg(test)]
	pub(crate) fn release_ffor_receiver_drain(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
	) -> Result<bool, FFORReceiverError> {
		self.release_ffor_receiver_drain_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			None,
		)
	}

	pub(crate) fn release_ffor_receiver_drain_on_connection(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		connection: Option<&crate::ln::ffor::FFORPeerConnection>,
	) -> Result<bool, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let (ack_hash, claims) = {
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
			let recovery = self.ffor_recovery.lock().unwrap();
			self.validate_ffor_close_transition(channel, &recovery, false)?;
			let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?;
			let activation =
				recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
			if activation.is_closed() {
				return Err(FFORCommitmentError::PendingUpdates.into());
			}
			let close = activation.close_record().ok_or(FFORCommitmentError::PendingUpdates)?;
			let ack_hash =
				close.acknowledgement_hash().ok_or(FFORCommitmentError::PendingUpdates)?;
			let runtime = self.ffor_activation.lock().unwrap();
			if !self.ffor_persistence.lock().unwrap().is_complete(&runtime.get(&key)?.requirement) {
				return Ok(false);
			}
			let authenticated =
				setup.validate_recovery().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
			let claims = close
				.preimages()
				.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?
				.into_iter()
				.map(|(slot, preimage)| {
					let voucher = &authenticated.vouchers()[usize::from(slot) - 1];
					(
						HTLCClaimSource {
							counterparty_node_id: *counterparty_node_id,
							funding_txo: channel.funding_outpoint(),
							channel_id: *channel_id,
							htlc_id: voucher.htlc_id,
						},
						preimage,
					)
				})
				.collect::<Vec<_>>();
			(ack_hash, claims)
		};
		for (source, preimage) in claims {
			self.claim_mpp_part(source, preimage, None, None, |_, _| (None, None));
		}
		{
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
			let recovery = self.ffor_recovery.lock().unwrap();
			self.validate_ffor_close_transition(channel, &recovery, false)?;
			let activation =
				recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
			if activation.is_closed()
				|| activation.close_record().and_then(|close| close.acknowledgement_hash())
					!= Some(ack_hash)
			{
				return Err(FFORCommitmentError::PendingUpdates.into());
			}
			let runtime = self.ffor_activation.lock().unwrap();
			if !self.ffor_persistence.lock().unwrap().is_complete(&runtime.get(&key)?.requirement) {
				return Ok(false);
			}
			channel.enable_ffor_receiver_drain(epoch_id, ack_hash)?;
			channel.ffor_queue_draining_vouchers(&self.logger);
			channel.prepare_ffor_receiver_drain_monitor_resume();
		};
		// The stock completion path checks in-flight writes and unblocks only their ordered successors.
		self.channel_monitor_updated(channel_id, None, counterparty_node_id);
		Ok(true)
	}

	/// Capture both empty commitment views and retain Closed before releasing ordinary updates.
	#[cfg(test)]
	pub(crate) fn prepare_ffor_receiver_closed(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
		monitor: &FFORMonitorSnapshot,
	) -> Result<FFORPersistenceRequirement, FFORReceiverError> {
		self.prepare_ffor_receiver_closed_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			monitor,
			None,
		)
	}

	pub(crate) fn prepare_ffor_receiver_closed_on_connection(
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
		let channel = peer
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let mut recovery = self.ffor_recovery.lock().unwrap();
		self.validate_ffor_close_transition(channel, &recovery, false)?;
		let setup = recovery.get(&key).ok_or(FFORReceiverError::UnknownEpoch)?.clone();
		let previous = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		if previous.is_closed() {
			return Ok(self.ffor_activation.lock().unwrap().get(&key)?.requirement.clone());
		}
		let completion = channel.ffor_receiver_drain_completion(monitor, &self.logger)?;
		let next = previous
			.with_closed(&setup, &completion)
			.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		let upgrade = recovery
			.prepare_activation(&setup, &next)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.prepare_ffor_receiver_closed(&completion)?;
		upgrade.commit();
		self.ffor_activation.lock().unwrap().record(key, requirement.clone(), false);
		Ok(requirement)
	}

	#[cfg(test)]
	pub(crate) fn release_ffor_receiver_closed(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, epoch_id: [u8; 32],
	) -> Result<bool, FFORReceiverError> {
		self.release_ffor_receiver_closed_on_connection(
			channel_id,
			counterparty_node_id,
			epoch_id,
			None,
		)
	}

	pub(crate) fn release_ffor_receiver_closed_on_connection(
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
		self.validate_ffor_close_transition(channel, &recovery, false)?;
		let activation = recovery.get_activation(&key).ok_or(FFORReceiverError::NotRegistered)?;
		let close = activation.close_record().ok_or(FFORCommitmentError::PendingUpdates)?;
		let digest = close.completion_hash().ok_or(FFORCommitmentError::PendingUpdates)?;
		let runtime = self.ffor_activation.lock().unwrap();
		if !self.ffor_persistence.lock().unwrap().is_complete(&runtime.get(&key)?.requirement) {
			return Ok(false);
		}
		if channel.ffor_receiver_drain_binding().map(|(_, _, closed)| closed) != Some(true) {
			channel.finish_ffor_receiver_closed(epoch_id, digest)?;
		}
		Ok(true)
	}
}

#[cfg(test)]
mod tests;
