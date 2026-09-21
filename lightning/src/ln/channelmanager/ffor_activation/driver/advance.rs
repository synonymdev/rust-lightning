//! Thin receiver orchestration over the channel's existing lifecycle and persistence authority.

use super::*;

// An ephemeral choice, rechecked by each transition under its own current-generation peer lock.
// It is never serialized, exposed as authority, or used to authorize a later transport enqueue.
enum ReceiverStep {
	Observe(FFORReceiverProgress),
	Setup,
	Quiesce,
	PrepareActivation,
	ReleaseActivation,
	ReleaseAbort,
	ReleaseClose,
	ReleaseDrain,
	PrepareClosed,
	ReleaseClosed,
	Reconnect,
}

enum ReconnectCause<'a> {
	Deadline,
	Abort(&'a FFORMessage),
	CloseAcknowledged(&'a [u8]),
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
	/// Advance one receiver operation chosen exclusively from current native state.
	///
	/// The current native connection generation is checked under every transition lock. Exact Init
	/// and Activate are released at most once on their original connection after persistence. Close
	/// may be replayed when native reconciliation permits it. `enqueue` must atomically check its
	/// paired authenticated transport token and insert into a bounded queue, with no I/O or manager
	/// reentry. `Err(())` preserves exact pending bytes. No progress value authorizes an invoice.
	///
	/// When progress is `NeedsMonitorSnapshot`, capture a fresh monitor snapshot outside manager
	/// locks and call [`Self::advance_ffor_receiver_with_monitor`]. Continue stock events and peer
	/// processing for STFU, commitment rounds, monitor persistence and requested disconnects.
	pub fn advance_ffor_receiver<C>(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, enqueue: C,
	) -> Result<FFORReceiverProgress, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		self.advance_ffor_receiver_inner(id, connection, None, enqueue)
	}

	/// Advance using a fresh opaque monitor snapshot captured before entering native peer locks.
	///
	/// Drop the monitor guard before calling. The channel verifies exact identities and completed
	/// updates again; a stale snapshot cannot start activation or prove Closed. This consumes the
	/// snapshot because the first complete book proof becomes the owned STFU handshake's evidence.
	pub fn advance_ffor_receiver_with_monitor<C>(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, monitor: FFORMonitorSnapshot,
		enqueue: C,
	) -> Result<FFORReceiverProgress, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		self.advance_ffor_receiver_inner(id, connection, Some(monitor), enqueue)
	}

	fn advance_ffor_receiver_inner<C>(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection,
		monitor: Option<FFORMonitorSnapshot>, enqueue: C,
	) -> Result<FFORReceiverProgress, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		let step = self.ffor_receiver_next_step(id, connection, monitor.as_ref())?;
		let peer = &connection.peer;
		match step {
			ReceiverStep::Observe(progress) => Ok(progress),
			ReceiverStep::Setup => self.advance_ffor_receiver_setup(id, connection, enqueue),
			ReceiverStep::Quiesce => {
				self.ffor_driver_request_quiescence(
					id,
					connection,
					monitor.ok_or(FFORCommitmentError::MonitorMismatch)?,
				)?;
				Ok(FFORReceiverProgress::AwaitingPeer)
			},
			ReceiverStep::PrepareActivation => {
				self.prepare_ffor_receiver_activation_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					monitor.as_ref().ok_or(FFORCommitmentError::MonitorMismatch)?,
					Some(connection),
				)?;
				Ok(FFORReceiverProgress::AwaitingPersistence)
			},
			ReceiverStep::ReleaseActivation => {
				let mut refused = false;
				let sent = self.release_ffor_receiver_activation_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					|wire| {
						let result = enqueue(wire);
						refused = result.is_err();
						result
					},
					Some(connection),
				)?;
				Ok(if refused {
					FFORReceiverProgress::Backpressured
				} else if sent {
					FFORReceiverProgress::AwaitingPeer
				} else {
					FFORReceiverProgress::AwaitingPersistence
				})
			},
			ReceiverStep::ReleaseAbort => {
				if self.release_ffor_receiver_reconnect_abort_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					Some(connection),
				)? {
					// The retained request gate still requires its normal fresh-connection release.
					self.advance_ffor_receiver_setup(id, connection, enqueue)
				} else {
					Ok(FFORReceiverProgress::AwaitingPersistence)
				}
			},
			ReceiverStep::ReleaseClose => {
				let mut refused = false;
				let sent = self.release_ffor_receiver_close_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					|wire| {
						let result = enqueue(wire);
						refused = result.is_err();
						result
					},
					Some(connection),
				)?;
				Ok(if refused {
					FFORReceiverProgress::Backpressured
				} else if sent {
					FFORReceiverProgress::AwaitingPeer
				} else {
					FFORReceiverProgress::AwaitingPersistence
				})
			},
			ReceiverStep::ReleaseDrain => {
				if self.release_ffor_receiver_drain_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					Some(connection),
				)? {
					Ok(FFORReceiverProgress::Draining)
				} else {
					Ok(FFORReceiverProgress::AwaitingPersistence)
				}
			},
			ReceiverStep::PrepareClosed => {
				self.prepare_ffor_receiver_closed_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					monitor.as_ref().ok_or(FFORCommitmentError::MonitorMismatch)?,
					Some(connection),
				)?;
				Ok(FFORReceiverProgress::AwaitingPersistence)
			},
			ReceiverStep::ReleaseClosed => {
				if self.release_ffor_receiver_closed_on_connection(
					&id.channel_id,
					peer,
					id.epoch_id,
					Some(connection),
				)? {
					Ok(FFORReceiverProgress::Closed)
				} else {
					Ok(FFORReceiverProgress::AwaitingPersistence)
				}
			},
			ReceiverStep::Reconnect => self
				.ffor_driver_request_reconnect(id, connection, ReconnectCause::Deadline)
				.map(|progress| progress.unwrap_or(FFORReceiverProgress::AwaitingPeer)),
		}
	}

	fn ffor_receiver_next_step(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection,
		monitor: Option<&FFORMonitorSnapshot>,
	) -> Result<ReceiverStep, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, &connection.peer, Some(connection))?;
		let channel = peer
			.channel_by_id
			.get(&id.channel_id)
			.and_then(Channel::as_funded)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let request = channel.ffor_receiver_request().ok_or(FFORReceiverError::NotRegistered)?;
		let message =
			request.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		if message.header.epoch_id != id.epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let key = FFORRecoveryKey { channel_id: id.channel_id, epoch_id: id.epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		if !recovery.contains_request(request) {
			return Err(FFORReceiverError::RecoveryUnavailable);
		}
		let runtime = self.ffor_activation.lock().unwrap();
		let entry = runtime.get(&key)?;
		if !self.ffor_persistence.lock().unwrap().is_complete(&entry.requirement) {
			return Ok(ReceiverStep::Observe(FFORReceiverProgress::AwaitingPersistence));
		}
		let setup = match recovery.get(&key) {
			Some(setup) => setup,
			None => return Ok(ReceiverStep::Setup),
		};
		recovery
			.validate_channel_lifecycle(
				setup,
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
		) {
			return Ok(ReceiverStep::Observe(FFORReceiverProgress::ResolutionRequired));
		}
		if let Some(activation) = recovery.get_activation(&key) {
			if activation.is_aborted() {
				return Ok(ReceiverStep::ReleaseAbort);
			}
			if matches!(
				channel.ffor_receiver_reconnect_outcome(),
				Some(FFORReestablishOutcome::AbortRequired { .. })
			) {
				return Ok(ReceiverStep::Observe(FFORReceiverProgress::ResolutionRequired));
			}
			if matches!(
				channel.ffor_receiver_reconnect_outcome(),
				Some(FFORReestablishOutcome::CloseReplayRequired { .. })
			) {
				return Ok(ReceiverStep::ReleaseClose);
			}
			if activation.is_closed() {
				return Ok(ReceiverStep::ReleaseClosed);
			}
			if activation.is_draining() {
				if !channel.ffor_receiver_drain_enabled() {
					return Ok(ReceiverStep::ReleaseDrain);
				}
				if channel.ffor_receiver_drain_pending() {
					return Ok(ReceiverStep::Observe(FFORReceiverProgress::Draining));
				}
				return Ok(if monitor.is_some() {
					ReceiverStep::PrepareClosed
				} else {
					ReceiverStep::Observe(FFORReceiverProgress::NeedsMonitorSnapshot)
				});
			}
			if activation.close_record().is_some() {
				return Ok(ReceiverStep::ReleaseClose);
			}
			if activation.is_active() {
				// The context helper takes the runtime lock itself. Preserve the peer/archive lock
				// while dropping only the process-local entry guard before its exact proof check.
				drop(runtime);
				self.ffor_active_context_locked(channel, &recovery, &key)?;
				return Ok(ReceiverStep::Observe(FFORReceiverProgress::Active));
			}
			if !entry.may_send_activate && !channel.has_ffor_receiver_quiescence(id.epoch_id) {
				// Reconnect must finish observing the peer, and matching Active must wait for its
				// exact signed ACK even after D. The original STFU connection is bounded below.
				return Ok(ReceiverStep::Observe(FFORReceiverProgress::AwaitingPeer));
			}
			let height = self.best_block.read().unwrap().height;
			let authenticated =
				setup.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
			let activate = FFORMessage::decode(activation.activate_wire())
				.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
			if authenticated
				.validate_activation(&activate, activation.commitment_hash(), height)
				.is_err()
			{
				return Ok(ReceiverStep::Reconnect);
			}
			return Ok(if entry.may_send_activate {
				ReceiverStep::ReleaseActivation
			} else {
				ReceiverStep::Observe(FFORReceiverProgress::AwaitingPeer)
			});
		}
		if channel.ffor_receiver_abort_reason().is_some() {
			return Ok(ReceiverStep::Setup);
		}
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let height = self.best_block.read().unwrap().height;
		if height >= authenticated.terms().settlement_deadline {
			return Ok(ReceiverStep::Reconnect);
		}
		match channel.ffor_receiver_quiescence_status(id.epoch_id, height, &self.logger) {
			Ok(FFORReceiverQuiescenceStatus::Negotiating) => {
				return Ok(ReceiverStep::Observe(FFORReceiverProgress::AwaitingPeer))
			},
			Ok(FFORReceiverQuiescenceStatus::Quiescent) => {
				return Ok(if monitor.is_some() {
					ReceiverStep::PrepareActivation
				} else {
					ReceiverStep::Observe(FFORReceiverProgress::NeedsMonitorSnapshot)
				})
			},
			Err(FFORReceiverError::ChannelState(FFORCommitmentError::ChannelUnavailable)) => {},
			Err(error) => return Err(error),
		}
		let monitor = match monitor {
			Some(monitor) => monitor,
			None => return Ok(ReceiverStep::Observe(FFORReceiverProgress::NeedsMonitorSnapshot)),
		};
		match channel.ffor_receiver_book_status(monitor, &self.logger)? {
			FFORReceiverStatus::Parked { .. } => Ok(ReceiverStep::Quiesce),
			FFORReceiverStatus::Registered { .. } => {
				Ok(ReceiverStep::Observe(FFORReceiverProgress::AwaitingVoucherCommitments))
			},
			FFORReceiverStatus::Aborting { reason } | FFORReceiverStatus::Aborted { reason } => {
				Ok(ReceiverStep::Observe(FFORReceiverProgress::Aborted { reason }))
			},
		}
	}

	fn ffor_driver_request_quiescence(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, monitor: FFORMonitorSnapshot,
	) -> Result<(), FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, &connection.peer, Some(connection))?;
		if !self.init_features().supports_quiescence()
			|| !peer.latest_features.supports_quiescence()
		{
			return Err(FFORCommitmentError::UnsupportedChannelType.into());
		}
		let channel = peer
			.channel_by_id
			.get_mut(&id.channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: id.channel_id, epoch_id: id.epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		if recovery.get_activation(&key).is_some() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let runtime = self.ffor_activation.lock().unwrap();
		if !self.ffor_persistence.lock().unwrap().is_complete(&runtime.get(&key)?.requirement) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let height = self.best_block.read().unwrap().height;
		if let Some(msg) =
			channel.request_ffor_receiver_quiescence(id.epoch_id, monitor, height, &self.logger)?
		{
			peer.pending_msg_events
				.push(MessageSendEvent::SendStfu { node_id: connection.peer, msg });
		}
		Ok(())
	}

	/// Retain a signed close intent for a natively Active epoch. Repeated calls reuse exact bytes.
	/// The close is released only by advance after its current persistence barrier completes.
	pub fn request_ffor_receiver_close(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection,
	) -> Result<FFORReceiverProgress, FFORReceiverError> {
		self.prepare_ffor_receiver_close_on_connection(
			&id.channel_id,
			&connection.peer,
			id.epoch_id,
			Some(connection),
		)?;
		Ok(FFORReceiverProgress::AwaitingPersistence)
	}

	/// Synchronously authenticate exact receiver protocol input on its native peer generation.
	/// Accept installs ownership before subsequent stock add frames can be delivered. Activation
	/// and close acknowledgements enter their native persisted transitions, never a transport-owned
	/// phase. Delayed exact acknowledgements remain historical even after the settlement deadline.
	pub fn handle_ffor_receiver_message(
		&self, connection: &FFORPeerConnection, wire: &[u8],
	) -> Result<FFORReceiverProgress, FFORReceiverError> {
		let message = match FFORMessage::decode(wire) {
			Ok(message) => message,
			Err(_) => return self.handle_ffor_receiver_setup_message(connection, wire),
		};
		let id = FFORReceiverId {
			channel_id: ChannelId(message.header.channel_id),
			epoch_id: message.header.epoch_id,
		};
		let requirement = match message.payload {
			Payload::ActivateAck(_) => self.accept_ffor_receiver_activation_ack_on_connection(
				&id.channel_id,
				&connection.peer,
				id.epoch_id,
				wire,
				Some(connection),
			)?,
			Payload::CloseAck(_) => self.accept_ffor_receiver_close_ack_on_connection(
				&id.channel_id,
				&connection.peer,
				id.epoch_id,
				wire,
				Some(connection),
			)?,
			Payload::Abort(_) => {
				return self.ffor_driver_handle_abort(&id, connection, &message, wire)
			},
			_ => return self.handle_ffor_receiver_setup_message(connection, wire),
		};
		if matches!(message.payload, Payload::CloseAck(_)) {
			if let Some(progress) = self.ffor_driver_request_reconnect(
				&id,
				connection,
				ReconnectCause::CloseAcknowledged(wire),
			)? {
				return Ok(progress);
			}
		}
		Ok(if self.is_ffor_state_persisted(&requirement) {
			FFORReceiverProgress::AwaitingPeer
		} else {
			FFORReceiverProgress::AwaitingPersistence
		})
	}

	fn ffor_driver_handle_abort(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, message: &FFORMessage,
		wire: &[u8],
	) -> Result<FFORReceiverProgress, FFORReceiverError> {
		match self.ffor_driver_request_reconnect(id, connection, ReconnectCause::Abort(message))? {
			Some(progress) => Ok(progress),
			None => self.handle_ffor_receiver_setup_message(connection, wire),
		}
	}

	fn ffor_driver_request_reconnect(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, cause: ReconnectCause<'_>,
	) -> Result<Option<FFORReceiverProgress>, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		self.require_current_ffor_connection(&peer, &connection.peer, Some(connection))?;
		let channel = peer
			.channel_by_id
			.get_mut(&id.channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let key = FFORRecoveryKey { channel_id: id.channel_id, epoch_id: id.epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		let setup = match recovery.get(&key) {
			Some(setup) => setup,
			None if matches!(cause, ReconnectCause::Abort(_)) => return Ok(None),
			None => return Err(FFORReceiverError::UnknownEpoch),
		};
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		if authenticated.header().epoch_id != id.epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		recovery
			.validate_channel_lifecycle(
				setup,
				channel.ffor_receiver_fence(),
				channel.ffor_receiver_abort_reason(),
				channel.ffor_receiver_drain_binding(),
				channel.ffor_receiver_closed_completion_hash(),
				channel.ffor_receiver_drain_activation_hash(),
			)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let activation = recovery.get_activation(&key);
		match cause {
			ReconnectCause::Abort(message) => {
				message
					.verify_signature(&connection.peer)
					.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
				if !matches!(&message.payload, Payload::Abort(abort) if abort.transcript_hash == authenticated.setup_hash())
				{
					return Err(FFORCommitmentError::InvalidVoucherBook.into());
				}
				if activation.map_or(false, |record| record.is_active()) {
					return Err(FFORCommitmentError::PendingUpdates.into());
				}
			},
			ReconnectCause::Deadline => {
				let height = self.best_block.read().unwrap().height;
				if let Some(activation) = activation {
					if activation.is_active() || activation.is_aborted() {
						return Err(FFORCommitmentError::PendingUpdates.into());
					}
					let message = FFORMessage::decode(activation.activate_wire())
						.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
					if authenticated
						.validate_activation(&message, activation.commitment_hash(), height)
						.is_ok()
					{
						return Ok(None);
					}
				} else if height < authenticated.terms().settlement_deadline {
					return Ok(None);
				}
			},
			ReconnectCause::CloseAcknowledged(wire) => {
				let activation = activation.ok_or(FFORReceiverError::NotRegistered)?;
				if activation.close_record().and_then(|close| close.acknowledgement_wire())
					!= Some(wire)
				{
					return Err(FFORCommitmentError::InvalidVoucherBook.into());
				}
				match channel.ffor_receiver_reconnect_outcome() {
					Some(FFORReestablishOutcome::CloseReplayRequired { peer_report })
						if peer_report.epoch_id == id.epoch_id
							&& peer_report.activation_hash
								== activation
									.activation_hash(setup)
									.map_err(|_| FFORReceiverError::RecoveryUnavailable)? => {},
					_ => return Ok(None),
				}
			},
		}
		if recovery.get_activation(&key).is_none() && channel.ffor_receiver_abort_reason().is_none()
		{
			let requirement = self
				.ffor_persistence
				.lock()
				.unwrap()
				.request()
				.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
			channel.abort_ffor_receiver_request(FFORReceiverAbortReason::SetupRejected)?;
			let mut runtime = self.ffor_activation.lock().unwrap();
			let entry = runtime
				.entries
				.iter_mut()
				.find(|entry| entry.key == key)
				.ok_or(FFORReceiverError::RecoveryUnavailable)?;
			entry.requirement = requirement;
			entry.may_send_init = false;
		}
		// A retained activation is never cleared here. The authenticated reestablish report must
		// select the existing native abort or ACK-loss path on the next connection.
		if !peer.pending_msg_events.iter().any(|event| matches!(event, MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::DisconnectPeerWithWarning { msg } } if *node_id == connection.peer && msg.channel_id == id.channel_id)) {
			peer.pending_msg_events.push(MessageSendEvent::HandleError { node_id: connection.peer,
				action: msgs::ErrorAction::DisconnectPeerWithWarning { msg: msgs::WarningMessage { channel_id: id.channel_id, data: "FFOR receiver requires connection reconciliation".to_owned() } } });
		}
		Ok(Some(FFORReceiverProgress::ReconnectRequired))
	}
}
