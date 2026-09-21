use bitcoin::secp256k1::PublicKey;

use super::{Acknowledgement, AcknowledgementResult, Provision, WitnessError};

/// Caller-supplied evidence identifying one authenticated transport connection.
///
/// This crate cannot authenticate a socket. `node_id` must come from the real peer handshake,
/// and `identity` must distinguish connection instances, including reconnects. Never populate
/// either field from acknowledgement bytes. An engine can use its opaque connection token as C.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessConnection<C> {
	/// Node key authenticated by the transport handshake.
	pub node_id: PublicKey,
	/// Caller-owned identity for this particular connection instance.
	pub identity: C,
}

/// One immutable request and the authenticated connection on which its reply is expected.
///
/// Request IDs must not be reused for a different manifest. The caller must persist the signed
/// manifest and recovery keys before sending. A reconnect needs a newly correlated request;
/// re-provision the identical manifest rather than allocating a new mailbox after an uncertain
/// result. This value is deliberately not a durable or ACTIVE state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingProvision<C> {
	provision: Provision,
	connection: WitnessConnection<C>,
}

impl<C> PendingProvision<C> {
	/// Bind the exact request, signed manifest and intended witness connection before sending.
	pub fn new(provision: Provision, connection: WitnessConnection<C>) -> Self {
		Self { provision, connection }
	}

	/// Exact request to persist and send; its manifest cannot be changed through this reference.
	pub fn provision(&self) -> &Provision {
		&self.provision
	}

	/// Expected transport witness and connection generation.
	pub fn connection(&self) -> &WitnessConnection<C> {
		&self.connection
	}
}

impl<C: Clone + Eq> PendingProvision<C> {
	/// Correlate a canonical response with this request and its actual authenticated source.
	///
	/// The ack contains no H_act or manifest hash. Its request ID is meaningful only alongside
	/// this exact retained manifest and connection. A refusal, short retention or mismatch leaves
	/// the pending request unchanged. Even success requires caller persistence before any use.
	pub fn check_acknowledgement(
		&self, acknowledgement: &Acknowledgement, source: &WitnessConnection<C>,
	) -> Result<CheckedAcknowledgement<C>, WitnessError> {
		if acknowledgement.request_id() != self.provision.request_id() {
			return Err(WitnessError::Request);
		}
		if source.identity != self.connection.identity {
			return Err(WitnessError::Connection);
		}
		if source.node_id != self.connection.node_id {
			return Err(WitnessError::Witness);
		}
		let (witness, retention_until) = match acknowledgement.result() {
			AcknowledgementResult::Accepted { witness, retention_until } => {
				(*witness, *retention_until)
			},
			AcknowledgementResult::Refused(_) => return Err(WitnessError::Refused),
		};
		if witness != self.connection.node_id {
			return Err(WitnessError::Witness);
		}
		if retention_until < self.provision.manifest().unsigned().parameters().retention_until {
			return Err(WitnessError::Retention);
		}
		Ok(CheckedAcknowledgement { pending: self.clone(), retention_until })
	}
}

/// Immutable, exactly correlated witness acknowledgement, not proof of invoice readiness.
///
/// Its private fields can only be constructed by successful pending-request checks. The caller
/// must durably associate this result with the engine's current epoch and recheck ACTIVE before
/// exposing anything. A dishonest witness may still fail its storage promise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedAcknowledgement<C> {
	pending: PendingProvision<C>,
	retention_until: u32,
}

impl<C> CheckedAcknowledgement<C> {
	/// The exact request and signed manifest this response acknowledged.
	pub fn provision(&self) -> &Provision {
		self.pending.provision()
	}

	/// The actual expected witness connection that was checked.
	pub fn connection(&self) -> &WitnessConnection<C> {
		self.pending.connection()
	}

	/// Witness retention promise, checked against the full pending manifest requirement.
	pub fn retention_until(&self) -> u32 {
		self.retention_until
	}
}
