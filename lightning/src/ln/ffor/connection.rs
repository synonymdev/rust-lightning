//! Opaque authenticated peer generations for synchronous receiver message handling.

use crate::sync::Arc;
use bitcoin::secp256k1::PublicKey;

/// One authenticated peer connection observed by this channel manager instance.
///
/// Capture this in the custom handler's successful `peer_connected` callback, after the channel
/// manager has processed that same callback. Keep it with the transport's own generation token.
/// The native receiver handler checks this identity under its peer lock before changing state.
/// Cloning preserves a generation; reconnect and manager restore never reuse it. This value has
/// no public constructor or serialized representation and does not attest any FFOR message.
#[derive(Clone, Debug)]
pub struct FFORPeerConnection {
	pub(crate) peer: PublicKey,
	pub(crate) generation: Arc<()>,
}

impl FFORPeerConnection {
	/// The peer identity supplied by the authenticated native connection callback.
	pub fn peer_node_id(&self) -> PublicKey {
		self.peer
	}

	pub(crate) fn matches(&self, peer: PublicKey, generation: Option<&Arc<()>>) -> bool {
		self.peer == peer
			&& generation.map_or(false, |current| Arc::ptr_eq(current, &self.generation))
	}
}

impl PartialEq for FFORPeerConnection {
	fn eq(&self, other: &Self) -> bool {
		self.matches(other.peer, Some(&other.generation))
	}
}
impl Eq for FFORPeerConnection {}
