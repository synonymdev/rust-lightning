//! Operational pre-init admission and synchronous Accept. Native state owns every wire decision.

use super::*;
use crate::ln::ffor::{
	FFORPeerConnection, FFORReceiverAbortReason, FFORReceiverId, FFORReceiverParameters,
	FFORReceiverProgress,
};
use lightning_ffor::wire::Header;

mod advance;

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
	pub(in crate::ln::channelmanager) fn require_current_ffor_connection(
		&self, peer: &PeerState<SP>, node_id: &PublicKey, connection: Option<&FFORPeerConnection>,
	) -> Result<(), FFORReceiverError> {
		// Legacy in-module channel tests exercise private transitions without a transport. Every
		// non-test call must carry actual native connection authority, including crate-internal use.
		#[cfg(not(test))]
		if connection.is_none() {
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		if let Some(connection) = connection {
			if !peer.is_connected || !connection.matches(*node_id, peer.ffor_connection.as_ref()) {
				return Err(FFORCommitmentError::ChannelUnavailable.into());
			}
		}
		Ok(())
	}

	/// Stage receiver-owned interception and exact signed Init before any peer traffic is released.
	///
	/// The supplied connection must be the current authenticated native generation. The channel
	/// must be supported, empty and synchronized. The engine generates the epoch, checks native
	/// limits and reserves bounded storage for the eventual accepted transcript and terminal state.
	/// No bytes are returned. Call `advance_ffor_receiver` after ordered manager persistence.
	/// This experimental facade does not authorize invoices or advertise offline readiness.
	pub fn prepare_ffor_receiver(
		&self, channel_id: &ChannelId, connection: &FFORPeerConnection,
		parameters: FFORReceiverParameters,
	) -> Result<FFORReceiverId, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		if !peer.is_connected || !connection.matches(connection.peer, peer.ffor_connection.as_ref())
		{
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		{
			let recovery = self.ffor_recovery.lock().unwrap();
			if let Some(request) = recovery.find_request(parameters.local_request_id) {
				if !request.matches_intent(*channel_id, connection.peer, &parameters) {
					return Err(FFORReceiverError::AlreadyRegistered);
				}
				let header = request
					.validate_recovery()
					.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
					.header;
				return Ok(FFORReceiverId {
					channel_id: ChannelId(header.channel_id),
					epoch_id: header.epoch_id,
				});
			}
		}
		let channel = peer
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let epoch_id = self.entropy_source.get_secure_random_bytes();
		let mut message = FFORMessage {
			header: Header { channel_id: channel_id.0, epoch_id },
			payload: Payload::Init(parameters.init()?),
			extensions: Vec::new(),
			signature: [0; 64],
		};
		let unsigned =
			message.unsigned_wire().map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
		message.signature = self
			.node_signer
			.sign_ffor_message(
				&FFORSigningRequest::new(&unsigned)
					.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?,
			)
			.map_err(|_| FFORReceiverError::SignerUnavailable)?
			.serialize_compact();
		let wire = message.encode().map_err(|_| FFORReceiverError::SignerUnavailable)?;
		let height = self.best_block.read().unwrap().height;
		let request = channel.prepare_ffor_receiver_request(
			&wire,
			self.our_network_pubkey,
			self.chain_hash,
			height,
			parameters.claim_margin_blocks,
			parameters.local_request_id,
		)?;
		let mut recovery = self.ffor_recovery.lock().unwrap();
		let permit = recovery
			.prepare_request(&request)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.install_ffor_receiver_request(request)?;
		permit.commit();
		let key = FFORRecoveryKey { channel_id: *channel_id, epoch_id };
		let mut runtime = self.ffor_activation.lock().unwrap();
		runtime.record(key, requirement, false);
		let entry = runtime.entries.iter_mut().find(|entry| entry.key == key).unwrap();
		entry.request_connection = Some(connection.clone());
		entry.may_send_init = true;
		Ok(FFORReceiverId { channel_id: *channel_id, epoch_id })
	}

	/// Recover an existing native selector after an ambiguous application retry or restart.
	/// Searches at most 64 retained requests, including removed channels. The result is historical
	/// correlation only; it neither changes a phase nor permits retransmission or invoice exposure.
	pub fn find_ffor_receiver_request(
		&self, local_request_id: [u8; 32],
	) -> Result<Option<FFORReceiverId>, FFORReceiverError> {
		let _guard = self.total_consistency_lock.read().unwrap();
		let recovery = self.ffor_recovery.lock().unwrap();
		recovery
			.validate_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		recovery
			.find_request(local_request_id)
			.map(|request| {
				let header = request
					.validate_recovery()
					.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
					.header;
				Ok(FFORReceiverId {
					channel_id: ChannelId(header.channel_id),
					epoch_id: header.epoch_id,
				})
			})
			.transpose()
	}

	/// Release at most one exact Init after its pre-init gate is durable on the original connection.
	///
	/// `enqueue` must atomically verify its paired authenticated transport generation and insert
	/// these bytes into a bounded queue. It must not perform I/O, acquire a monitor or reenter this
	/// manager. Returning `Err(())` preserves the exact retry; `Ok(())` consumes this one-shot send.
	/// A disconnected or restored negotiation never sends Init again. Accepted setup reports only
	/// voucher-round progress here; activation and invoice readiness are not exposed by this slice.
	fn advance_ffor_receiver_setup<C>(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection, enqueue: C,
	) -> Result<FFORReceiverProgress, FFORReceiverError>
	where
		C: FnOnce(&[u8]) -> Result<(), ()>,
	{
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		if !peer.is_connected || !connection.matches(connection.peer, peer.ffor_connection.as_ref())
		{
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		let channel = peer
			.channel_by_id
			.get_mut(&id.channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let request = channel.ffor_receiver_request().ok_or(FFORReceiverError::NotRegistered)?;
		let init =
			request.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
		if init.header.epoch_id != id.epoch_id {
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let key = FFORRecoveryKey { channel_id: id.channel_id, epoch_id: id.epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		if !recovery.contains_request(request) {
			return Err(FFORReceiverError::RecoveryUnavailable);
		}
		let mut runtime = self.ffor_activation.lock().unwrap();
		let entry = runtime
			.entries
			.iter_mut()
			.find(|entry| entry.key == key)
			.ok_or(FFORReceiverError::RecoveryUnavailable)?;
		if !self.ffor_persistence.lock().unwrap().is_complete(&entry.requirement) {
			return Ok(FFORReceiverProgress::AwaitingPersistence);
		}
		if let Some(reason) = channel.ffor_receiver_abort_reason() {
			if !channel.ffor_receiver_request_gate_released()
				&& entry.request_connection.as_ref() != Some(connection)
			{
				let requirement = self
					.ffor_persistence
					.lock()
					.unwrap()
					.request()
					.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
				channel.release_ffor_receiver_request_gate()?;
				entry.requirement = requirement;
				channel.ffor_queue_aborted_vouchers(&self.logger);
				return Ok(FFORReceiverProgress::AwaitingPersistence);
			}
			return Ok(FFORReceiverProgress::Aborted { reason });
		}
		if channel
			.ffor_receiver_setup_record()
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
			.is_some()
		{
			return Ok(FFORReceiverProgress::AwaitingVoucherCommitments);
		}
		if entry.request_connection.as_ref() != Some(connection) {
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		if !entry.may_send_init {
			return Ok(FFORReceiverProgress::AwaitingPeer);
		}
		channel.ffor_validate_pending_request().map_err(|_| FFORCommitmentError::PendingUpdates)?;
		let deadline = match &init.payload {
			Payload::Init(init) => init.settlement_deadline,
			_ => return Err(FFORReceiverError::RecoveryUnavailable),
		};
		if self.best_block.read().unwrap().height >= deadline {
			let requirement = self
				.ffor_persistence
				.lock()
				.unwrap()
				.request()
				.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
			channel.abort_ffor_receiver_request(FFORReceiverAbortReason::SetupRejected)?;
			entry.requirement = requirement;
			entry.may_send_init = false;
			return Ok(FFORReceiverProgress::AwaitingPersistence);
		}
		if enqueue(channel.ffor_receiver_request().unwrap().init_wire()).is_err() {
			return Ok(FFORReceiverProgress::Backpressured);
		}
		entry.may_send_init = false;
		Ok(FFORReceiverProgress::AwaitingPeer)
	}

	/// Process exact signed peer input synchronously before returning from custom message handling.
	///
	/// Do not hold the transport mutex while calling. PeerManager may next deliver ordinary voucher
	/// add frames on this same connection. A valid Accept installs their exact native identities
	/// before this returns; the accepted manager revision may persist alongside stock monitor work.
	/// A durable pre-init gate already prevents a stale-manager crash from exposing these as normal
	/// payments. A malformed or incompatible setup irreversibly aborts pending requests for this peer.
	/// This bounded facade currently handles Accept and signed pre-accept Abort only.
	fn handle_ffor_receiver_setup_message(
		&self, connection: &FFORPeerConnection, wire: &[u8],
	) -> Result<FFORReceiverProgress, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		if !peer.is_connected || !connection.matches(connection.peer, peer.ffor_connection.as_ref())
		{
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		let message = match FFORMessage::decode(wire) {
			Ok(message) => message,
			Err(_) => {
				self.ffor_reject_pending_requests(&mut peer)?;
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			},
		};
		let channel_id = ChannelId(message.header.channel_id);
		let key = FFORRecoveryKey { channel_id, epoch_id: message.header.epoch_id };
		let result = (|| {
			let channel = peer
				.channel_by_id
				.get_mut(&channel_id)
				.and_then(Channel::as_funded_mut)
				.ok_or(FFORCommitmentError::ChannelUnavailable)?;
			let request =
				channel.ffor_receiver_request().ok_or(FFORReceiverError::NotRegistered)?;
			let init =
				request.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
			if init.header != message.header {
				return Err(FFORReceiverError::UnknownEpoch);
			}
			let mut recovery = self.ffor_recovery.lock().unwrap();
			if !recovery.contains_request(request) {
				return Err(FFORReceiverError::RecoveryUnavailable);
			}
			let mut runtime = self.ffor_activation.lock().unwrap();
			let entry = runtime.get(&key)?;
			if entry.request_connection.as_ref() != Some(connection) || entry.may_send_init {
				return Err(FFORCommitmentError::ChannelUnavailable.into());
			}
			if let Some(reason) = channel.ffor_receiver_abort_reason() {
				return Ok(FFORReceiverProgress::Aborted { reason });
			}
			if let Some(existing) = channel
				.ffor_receiver_setup_record()
				.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
			{
				let setup = existing
					.validate_recovery()
					.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
				if matches!(&message.payload, Payload::Accept(_))
					&& setup.accept().encode().ok().as_deref() == Some(wire)
				{
					return Ok(
						if self.ffor_persistence.lock().unwrap().is_complete(&entry.requirement) {
							FFORReceiverProgress::AwaitingVoucherCommitments
						} else {
							FFORReceiverProgress::AwaitingPersistence
						},
					);
				}
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			}
			if let Payload::Abort(abort) = &message.payload {
				message
					.verify_signature(&connection.peer)
					.map_err(|_| FFORCommitmentError::InvalidVoucherBook)?;
				if abort.transcript_hash != transcript::init_hash(request.init_wire()) {
					return Err(FFORCommitmentError::InvalidVoucherBook.into());
				}
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			}
			if !matches!(message.payload, Payload::Accept(_)) {
				return Err(FFORCommitmentError::InvalidVoucherBook.into());
			}
			let height = self.best_block.read().unwrap().height;
			let setup = channel.prepare_ffor_receiver_accept(wire, height)?;
			let permit = recovery
				.prepare_accept(&setup)
				.map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
			let requirement = self
				.ffor_persistence
				.lock()
				.unwrap()
				.request()
				.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
			channel.install_prepared_ffor_receiver_setup(setup)?;
			permit.commit();
			runtime.record(key, requirement, false);
			let entry = runtime.entries.iter_mut().find(|entry| entry.key == key).unwrap();
			entry.request_connection = Some(connection.clone());
			Ok(FFORReceiverProgress::AwaitingPersistence)
		})();
		if result.is_err() {
			self.ffor_reject_pending_requests(&mut peer)?;
			if let Some(channel) =
				peer.channel_by_id.get_mut(&channel_id).and_then(Channel::as_funded_mut)
			{
				if channel.ffor_receiver_request().is_some()
					&& channel.ffor_receiver_fence().is_none()
					&& channel.ffor_receiver_abort_reason().is_none()
				{
					let requirement = self
						.ffor_persistence
						.lock()
						.unwrap()
						.request()
						.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
					channel.abort_ffor_receiver_request(FFORReceiverAbortReason::SetupRejected)?;
					let mut runtime = self.ffor_activation.lock().unwrap();
					if let Some(entry) =
						runtime.entries.iter_mut().find(|entry| entry.key.channel_id == channel_id)
					{
						entry.requirement = requirement;
						entry.may_send_init = false;
					}
				}
			}
		}
		result
	}

	/// Irreversibly cancel a setup before activation, retaining its interception gate.
	/// After persistence, reconnect and advance again to release the gate for ordinary traffic.
	/// If FFOR already owns an STFU handshake, this queues the required native disconnect warning.
	/// This cannot cancel an activation that may already have reached the peer.
	pub fn cancel_ffor_receiver_setup(
		&self, id: &FFORReceiverId, connection: &FFORPeerConnection,
	) -> Result<FFORReceiverProgress, FFORReceiverError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		let peers = self.per_peer_state.read().unwrap();
		let mut peer = peers
			.get(&connection.peer)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?
			.lock()
			.unwrap();
		if !peer.is_connected || !connection.matches(connection.peer, peer.ffor_connection.as_ref())
		{
			return Err(FFORCommitmentError::ChannelUnavailable.into());
		}
		let channel = peer
			.channel_by_id
			.get_mut(&id.channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or(FFORCommitmentError::ChannelUnavailable)?;
		let request = channel.ffor_receiver_request().ok_or(FFORReceiverError::NotRegistered)?;
		if request
			.validate_recovery()
			.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
			.header
			.epoch_id != id.epoch_id
		{
			return Err(FFORReceiverError::UnknownEpoch);
		}
		let key = FFORRecoveryKey { channel_id: id.channel_id, epoch_id: id.epoch_id };
		let recovery = self.ffor_recovery.lock().unwrap();
		if recovery.get_activation(&key).is_some() || !recovery.contains_request(request) {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let requirement = self
			.ffor_persistence
			.lock()
			.unwrap()
			.request()
			.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
		channel.abort_ffor_receiver_request(FFORReceiverAbortReason::Requested)?;
		let mut runtime = self.ffor_activation.lock().unwrap();
		let entry = runtime
			.entries
			.iter_mut()
			.find(|entry| entry.key == key)
			.ok_or(FFORReceiverError::RecoveryUnavailable)?;
		entry.requirement = requirement;
		entry.may_send_init = false;
		let reconnect = channel.release_ffor_receiver_quiescence();
		channel.ffor_queue_aborted_vouchers(&self.logger);
		if reconnect {
			peer.pending_msg_events.push(MessageSendEvent::HandleError {
				node_id: connection.peer,
				action: msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id: id.channel_id,
						data: "FFOR setup cancellation requires reconnect before voucher drain"
							.to_owned(),
					},
				},
			});
		}
		Ok(FFORReceiverProgress::AwaitingPersistence)
	}

	/// Called under the native peer lock before stock disconnect aborts setup and drops adds.
	pub(in crate::ln::channelmanager) fn ffor_receiver_setup_disconnected(
		&self, peer: &PeerState<SP>,
	) -> bool {
		let mut changed = false;
		let mut runtime = self.ffor_activation.lock().unwrap();
		for channel in peer.channel_by_id.values().filter_map(Channel::as_funded) {
			if channel.ffor_receiver_request().is_none()
				|| channel.ffor_receiver_fence().is_some()
				|| channel.ffor_receiver_request_gate_released()
			{
				continue;
			}
			if let Some(entry) = runtime
				.entries
				.iter_mut()
				.find(|entry| entry.key.channel_id == channel.context.channel_id())
			{
				if let Ok(requirement) = self.ffor_persistence.lock().unwrap().request() {
					entry.requirement = requirement;
					entry.may_send_init = false;
					changed = true;
				}
			}
		}
		changed
	}

	fn ffor_reject_pending_requests(
		&self, peer: &mut PeerState<SP>,
	) -> Result<(), FFORReceiverError> {
		for channel in peer.channel_by_id.values_mut().filter_map(Channel::as_funded_mut) {
			let request = match channel.ffor_receiver_request() {
				Some(request) => request,
				None => continue,
			};
			if channel
				.ffor_receiver_setup_record()
				.map_err(|_| FFORReceiverError::RecoveryUnavailable)?
				.is_some()
			{
				continue;
			}
			let init =
				request.validate_recovery().map_err(|_| FFORReceiverError::RecoveryUnavailable)?;
			let key = FFORRecoveryKey {
				channel_id: ChannelId(init.header.channel_id),
				epoch_id: init.header.epoch_id,
			};
			let requirement = self
				.ffor_persistence
				.lock()
				.unwrap()
				.request()
				.map_err(|_| FFORReceiverError::PersistenceUnavailable)?;
			channel.abort_ffor_receiver_request(FFORReceiverAbortReason::SetupRejected)?;
			let mut runtime = self.ffor_activation.lock().unwrap();
			if let Some(entry) = runtime.entries.iter_mut().find(|entry| entry.key == key) {
				entry.requirement = requirement;
				entry.may_send_init = false;
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
