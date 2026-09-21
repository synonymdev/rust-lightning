//! Release reconnect reports only after the currently retained phase is durable.

use super::*;
use lightning_ffor::reestablish::{Reestablish, ReportedState};

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
	/// Keep the existing per-peer ordering and queue. A blocked reconnect retains the entire
	/// suffix, including stock updates queued after a durable abort releases the channel fence.
	/// Disconnect already clears connection-scoped messages through the ordinary cleanup path.
	pub(in crate::ln::channelmanager) fn drain_ffor_pending_messages(
		&self, peer: &mut PeerState<SP>, output: &mut Vec<MessageSendEvent>,
	) {
		let mut pending = core::mem::take(&mut peer.pending_msg_events).into_iter();
		while let Some(mut event) = pending.next() {
			if let MessageSendEvent::SendChannelReestablish { node_id, msg } = &mut event {
				if let Some(queued) = &msg.ffor_reestablish {
					let channel = match peer
						.channel_by_id
						.get(&msg.channel_id)
						.and_then(Channel::as_funded)
					{
						Some(channel) if peer.is_connected => channel,
						// Force-close or disconnect invalidates the connection's unsent report.
						_ => continue,
					};
					match self.durable_ffor_reestablish(channel, *node_id, queued.report()) {
						Ok(Some(report)) => {
							// Retain the BOLT prefix captured before peer resumption. In particular,
							// a received report may already have caused durable abort and stock drain.
							msg.ffor_reestablish = Some(msgs::FFORChannelReestablish::new(report));
						},
						Ok(None) => {
							peer.pending_msg_events.push(event);
							peer.pending_msg_events.extend(pending);
							return;
						},
						Err(()) => {
							// Do not release other queued channel messages after failed recovery
							// validation. The normal disconnect path will rebuild eligible work.
							output.push(MessageSendEvent::HandleError {
								node_id: *node_id,
								action: msgs::ErrorAction::DisconnectPeerWithWarning {
									msg: msgs::WarningMessage {
										channel_id: msg.channel_id,
										data: "FFOR reconnect recovery evidence does not match the channel".to_owned(),
									},
								},
							});
							return;
						},
					}
				}
			}
			output.push(event);
		}
	}

	/// Called with the peer lock held. Archive and runtime are read together so completion of
	/// an older phase cannot release a newer report. No channel or reconnect observation mutates.
	fn durable_ffor_reestablish(
		&self, channel: &FundedChannel<SP>, peer_id: PublicKey, queued: Reestablish,
	) -> Result<Option<Reestablish>, ()> {
		if channel.context.get_counterparty_node_id() != peer_id {
			return Err(());
		}
		channel
			.ffor_validate_receiver_identity(self.our_network_pubkey, self.chain_hash)
			.map_err(|_| ())?;
		let setup = channel.ffor_receiver_setup_record().map_err(|_| ())?.ok_or(())?;
		let authenticated = setup.validate_recovery().map_err(|_| ())?;
		let key = FFORRecoveryKey {
			channel_id: channel.context.channel_id(),
			epoch_id: authenticated.header().epoch_id,
		};
		if key.epoch_id != queued.epoch_id {
			return Err(());
		}
		let recovery = self.ffor_recovery.lock().unwrap();
		recovery
			.validate_channel_outcome(
				&setup,
				channel.ffor_receiver_fence(),
				channel.ffor_receiver_abort_reason(),
			)
			.map_err(|_| ())?;
		let activation = recovery.get_activation(&key).ok_or(())?;
		if channel.context.is_ffor_frozen()
			&& channel.ffor_frozen_commitments(&self.logger).map_err(|_| ())?
				!= activation.commitments()
		{
			return Err(());
		}
		let runtime = self.ffor_activation.lock().unwrap();
		let entry = runtime.get(&key).map_err(|_| ())?;
		if !self.ffor_persistence.lock().unwrap().is_complete(&entry.requirement) {
			return Ok(None);
		}
		let (state, activation_hash) = if activation.is_aborted() {
			(ReportedState::Aborted, [0; 32])
		} else if activation.is_active() {
			(ReportedState::Active, activation.activation_hash(&setup).map_err(|_| ())?)
		} else {
			(ReportedState::Activating, [0; 32])
		};
		Ok(Some(Reestablish { epoch_id: key.epoch_id, state, activation_hash }))
	}
}
