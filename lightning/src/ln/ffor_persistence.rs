//! In-memory completion tracking for FFOR state written with the channel manager.
//!
//! A token must be captured before serialization and completed only after the same ordered
//! persister has durably stored that serialization. It is deliberately unusable after restart.

use crate::sync::Arc;

/// An opaque receipt identifying FFOR state that a forthcoming manager snapshot must include.
///
/// Capture this before encoding the channel manager, then pass it back only after the write
/// succeeds. Capturing or dropping it proves nothing about storage. Tokens cannot be transferred
/// between manager instances, including instances restored from the same serialized bytes.
#[must_use]
pub struct FFORPersistenceToken {
	identity: Arc<()>,
	revision: u64,
}

/// An opaque requirement returned by a protected FFOR channel mutation.
///
/// The requirement can be queried after the manager's persistence callback completes. It is
/// specific to one manager instance and does not assert that a channel remains in the same state.
#[derive(Clone, Debug)]
pub struct FFORPersistenceRequirement {
	identity: Arc<()>,
	revision: u64,
}

impl PartialEq for FFORPersistenceRequirement {
	fn eq(&self, other: &Self) -> bool {
		Arc::ptr_eq(&self.identity, &other.identity) && self.revision == other.revision
	}
}

impl Eq for FFORPersistenceRequirement {}

pub(super) struct FFORPersistenceBarrier {
	identity: Arc<()>,
	requested: u64,
	completed: u64,
}

impl FFORPersistenceBarrier {
	pub(super) fn new() -> Self {
		Self { identity: Arc::new(()), requested: 0, completed: 0 }
	}

	/// Reserve a new revision before changing protected state, while holding manager consistency.
	/// Exhaustion is an error before the state transition, never a wrap to an already durable ID.
	pub(super) fn request(&mut self) -> Result<FFORPersistenceRequirement, ()> {
		self.requested = self.requested.checked_add(1).ok_or(())?;
		Ok(FFORPersistenceRequirement {
			identity: Arc::clone(&self.identity),
			revision: self.requested,
		})
	}

	pub(super) fn capture(&self) -> FFORPersistenceToken {
		FFORPersistenceToken { identity: Arc::clone(&self.identity), revision: self.requested }
	}

	pub(super) fn complete(&mut self, token: FFORPersistenceToken) -> Result<bool, ()> {
		if !Arc::ptr_eq(&self.identity, &token.identity) {
			return Err(());
		}
		// Older completions are idempotent. Storage writes themselves must remain ordered.
		let advanced = token.revision > self.completed;
		self.completed = self.completed.max(token.revision);
		Ok(advanced)
	}

	pub(super) fn is_complete(&self, requirement: &FFORPersistenceRequirement) -> bool {
		Arc::ptr_eq(&self.identity, &requirement.identity)
			&& requirement.revision != 0
			&& requirement.revision <= self.completed
	}

	pub(super) fn needs_persistence(&self) -> bool {
		self.requested > self.completed
	}
}

#[cfg(test)]
mod tests {
	use super::FFORPersistenceBarrier;

	#[test]
	fn ffor_persistence_does_not_release_later_mutations() {
		let mut barrier = FFORPersistenceBarrier::new();
		assert!(!barrier.needs_persistence());
		let first = barrier.request().unwrap();
		let token = barrier.capture();
		let later = barrier.request().unwrap();
		barrier.complete(token).unwrap();
		assert!(barrier.is_complete(&first));
		assert!(!barrier.is_complete(&later));
		assert!(barrier.needs_persistence());
		let token = barrier.capture();
		barrier.complete(token).unwrap();
		assert!(barrier.is_complete(&later));
		assert!(!barrier.needs_persistence());
	}

	#[test]
	fn ffor_persistence_failure_and_cancellation_leave_work_pending() {
		let mut barrier = FFORPersistenceBarrier::new();
		let revision = barrier.request().unwrap();
		drop(barrier.capture());
		assert!(barrier.needs_persistence());
		assert!(!barrier.is_complete(&revision));
		let token = barrier.capture();
		barrier.complete(token).unwrap();
		assert!(barrier.is_complete(&revision));
	}

	#[test]
	fn ffor_persistence_tokens_are_instance_bound_and_cannot_regress() {
		let mut first = FFORPersistenceBarrier::new();
		let mut restored = FFORPersistenceBarrier::new();
		let original = first.request().unwrap();
		let revision = restored.request().unwrap();
		assert!(restored.complete(first.capture()).is_err());
		assert!(!restored.is_complete(&revision));
		assert!(!restored.is_complete(&original));
		let older = restored.capture();
		let newer = restored.request().unwrap();
		let token = restored.capture();
		restored.complete(token).unwrap();
		restored.complete(older).unwrap();
		assert!(restored.is_complete(&newer));
		assert!(!restored.needs_persistence());
	}

	#[test]
	fn ffor_persistence_revision_exhaustion_fails_before_wraparound() {
		let mut barrier = FFORPersistenceBarrier::new();
		barrier.requested = u64::MAX - 1;
		barrier.completed = u64::MAX - 1;
		let last = barrier.request().unwrap();
		assert!(barrier.request().is_err());
		assert!(barrier.needs_persistence());
		assert!(!barrier.is_complete(&last));
	}
}
