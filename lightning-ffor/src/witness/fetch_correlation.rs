use alloc::vec::Vec;

use super::{
	AuthenticatedEncryptedRecord, FetchResponse, FetchResult, SignedFetch, SignedManifest,
	WitnessConnection, WitnessError,
};

/// An exact signed fetch and its expected manifest, witness and connection instance.
///
/// Progress is bounded to K pages and retains no accumulated record payloads. Fresh request IDs
/// and nonces are required within this traversal. The caller must also guarantee nonce freshness
/// across restarts/traversals; the witness durably enforces mailbox-wide nonce replay protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingFetch<C> {
	request: SignedFetch,
	manifest: SignedManifest,
	connection: WitnessConnection<C>,
	used: Vec<([u8; 16], [u8; 32])>,
}

impl<C> PendingFetch<C> {
	/// Begin a bounded traversal from slot zero with an already authenticated fetch request.
	/// Noise identity routes the response; only the fetch-key signature authorizes the mailbox.
	pub fn first(
		request: SignedFetch, manifest: SignedManifest, connection: WitnessConnection<C>,
	) -> Result<Self, WitnessError> {
		if request.unsigned().parameters().after_slot.unwrap_or(0) != 0 {
			return Err(WitnessError::Pagination);
		}
		Self::bind(request, manifest, connection, Vec::new())
	}

	/// Exact signed request to send. Request ID uniqueness is a caller-owned transport invariant.
	pub fn request(&self) -> &SignedFetch {
		&self.request
	}
	/// Retained signed manifest that every record must match.
	pub fn manifest(&self) -> &SignedManifest {
		&self.manifest
	}
	/// Expected authenticated response connection; never inferred from record/header bytes.
	pub fn connection(&self) -> &WitnessConnection<C> {
		&self.connection
	}

	fn bind(
		request: SignedFetch, manifest: SignedManifest, connection: WitnessConnection<C>,
		mut used: Vec<([u8; 16], [u8; 32])>,
	) -> Result<Self, WitnessError> {
		let p = request.unsigned().parameters();
		let m = manifest.unsigned().parameters();
		if p.mailbox_id != m.mailbox_id || request.fetch_key() != m.fetch_public_key {
			return Err(WitnessError::Mailbox);
		}
		if used.iter().any(|(id, nonce)| *id == p.request_id || *nonce == p.nonce) {
			return Err(WitnessError::Replay);
		}
		let count = (manifest.unsigned().canonical_book().len() - 36) / 58;
		if used.len() >= count {
			return Err(WitnessError::Pagination);
		}
		used.push((p.request_id, p.nonce));
		Ok(Self { request, manifest, connection, used })
	}
}

impl<C: Clone + Eq> PendingFetch<C> {
	/// Check request, actual source, ascending slots, manifest binding and continuation progress.
	/// A failure never mutates this request or a previously returned page. Successful encrypted
	/// records remain opaque and cannot be credited or submitted as preimages.
	pub fn check_response(
		&self, response: &FetchResponse, source: &WitnessConnection<C>,
	) -> Result<CheckedFetchPage<C>, WitnessError> {
		if response.request_id() != self.request.unsigned().parameters().request_id {
			return Err(WitnessError::Request);
		}
		if source.identity != self.connection.identity {
			return Err(WitnessError::Connection);
		}
		if source.node_id != self.connection.node_id {
			return Err(WitnessError::Witness);
		}
		let (records, next_after_slot) = match response.result() {
			FetchResult::Refused(_) => return Err(WitnessError::Refused),
			FetchResult::Page { records, next_after_slot, .. } => (records, *next_after_slot),
		};
		let count = (self.manifest.unsigned().canonical_book().len() - 36) / 58;
		let mut last = self.request.unsigned().parameters().after_slot.unwrap_or(0);
		let mut checked = Vec::new();
		for record in records {
			if record.header().slot <= last {
				return Err(WitnessError::Pagination);
			}
			last = record.header().slot;
			checked.push(record.clone().authenticate(&self.manifest, self.connection.node_id)?);
		}
		if let Some(next) = next_after_slot {
			if records.is_empty()
				|| next != last
				|| usize::from(next) >= count
				|| self.used.len() >= count
			{
				return Err(WitnessError::Pagination);
			}
		}
		Ok(CheckedFetchPage { pending: self.clone(), records: checked, next_after_slot })
	}
}

/// One exactly correlated page of authenticated opaque records, with bounded continuation.
///
/// The caller retains earlier returned pages even if any subsequent request fails. Guardian
/// attachments and a witness's omission of records are never evidence of an unpaid voucher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedFetchPage<C> {
	pending: PendingFetch<C>,
	records: Vec<AuthenticatedEncryptedRecord>,
	next_after_slot: Option<u16>,
}

impl<C> CheckedFetchPage<C> {
	/// Signed encrypted statements requiring authenticated decryption before payment use.
	pub fn records(&self) -> &[AuthenticatedEncryptedRecord] {
		&self.records
	}
	/// Required exclusive lower slot bound for the next request, or completion if absent.
	pub fn next_after_slot(&self) -> Option<u16> {
		self.next_after_slot
	}
}

impl<C: Clone> CheckedFetchPage<C> {
	/// Correlate a freshly signed continuation without discarding this page's records.
	/// This retains the same authenticated connection. After reconnect, start a fresh traversal
	/// with globally fresh nonces and preserve previously authenticated records independently.
	pub fn next(&self, request: SignedFetch) -> Result<PendingFetch<C>, WitnessError> {
		let after = self.next_after_slot.ok_or(WitnessError::Pagination)?;
		if request.unsigned().parameters().after_slot != Some(after) {
			return Err(WitnessError::Pagination);
		}
		PendingFetch::bind(
			request,
			self.pending.manifest.clone(),
			self.pending.connection.clone(),
			self.pending.used.clone(),
		)
	}
}
