//! Bounded pre-init reservations and atomic promotion into accepted setup evidence.

use super::*;
use crate::ln::channel::FFORReceiverRequest;

pub(super) struct PendingRequest {
	pub(super) key: FFORRecoveryKey,
	pub(super) record: FFORReceiverRequest,
	pub(super) encoded_bytes: usize,
}

impl PendingRequest {
	pub(super) fn new(record: FFORReceiverRequest) -> Result<Self, FFORRecoveryError> {
		let message = record.validate_recovery().map_err(|_| FFORRecoveryError::InvalidRecord)?;
		let encoded_bytes = record.serialized_length();
		if encoded_bytes > MAX_SETUP_RECORD_BYTES {
			return Err(FFORRecoveryError::CapacityExceeded);
		}
		Ok(Self {
			key: FFORRecoveryKey {
				channel_id: ChannelId(message.header.channel_id),
				epoch_id: message.header.epoch_id,
			},
			record,
			encoded_bytes,
		})
	}
	pub(super) fn reserved_bytes(&self) -> usize {
		MAX_RECORD_BYTES - self.encoded_bytes
	}
}

pub(crate) struct FFORRequestInsertion<'a> {
	registry: &'a mut FFORRecoveryRegistry,
	entry: PendingRequest,
	header_bytes: usize,
}
impl FFORRequestInsertion<'_> {
	pub(crate) fn commit(self) {
		self.registry.encoded_bytes +=
			self.header_bytes + RECORD_LENGTH_BYTES + self.entry.encoded_bytes;
		self.registry.reserved_transition_bytes += self.entry.reserved_bytes();
		self.registry.pending_requests.push(self.entry);
	}
}

pub(crate) struct FFORRequestPromotion<'a> {
	registry: &'a mut FFORRecoveryRegistry,
	index: usize,
	entry: Entry,
}
impl FFORRequestPromotion<'_> {
	pub(crate) fn commit(self) {
		let pending = self.registry.pending_requests.remove(self.index);
		self.registry.encoded_bytes =
			self.registry.encoded_bytes - pending.encoded_bytes + self.entry.encoded_bytes;
		self.registry.reserved_transition_bytes = self.registry.reserved_transition_bytes
			- pending.reserved_bytes()
			+ self.entry.reserved_transition_bytes();
		self.registry.entries.push(self.entry);
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn find_request(&self, local_request_id: [u8; 32]) -> Option<&FFORReceiverRequest> {
		self.pending_requests
			.iter()
			.map(|entry| &entry.record)
			.chain(self.entries.iter().filter_map(|entry| entry.record.request.as_ref()))
			.find(|request| request.local_request_id() == local_request_id)
	}

	pub(crate) fn request_keys(&self) -> Vec<FFORRecoveryKey> {
		self.pending_requests
			.iter()
			.map(|pending| pending.key)
			.chain(
				self.entries
					.iter()
					.filter(|entry| entry.record.request.is_some())
					.map(|entry| entry.key),
			)
			.collect()
	}
	pub(crate) fn get_request(&self, key: &FFORRecoveryKey) -> Option<&FFORReceiverRequest> {
		self.pending_requests
			.iter()
			.find(|entry| entry.key == *key)
			.map(|entry| &entry.record)
			.or_else(|| {
				self.entries
					.iter()
					.find(|entry| entry.key == *key)
					.and_then(|entry| entry.record.request.as_ref())
			})
	}
	pub(crate) fn contains_request(&self, request: &FFORReceiverRequest) -> bool {
		let message = match request.validate_recovery() {
			Ok(message) => message,
			Err(_) => return false,
		};
		let key = FFORRecoveryKey {
			channel_id: ChannelId(message.header.channel_id),
			epoch_id: message.header.epoch_id,
		};
		self.get_request(&key).map_or(false, |saved| saved.encode() == request.encode())
	}

	pub(crate) fn prepare_request(
		&mut self, request: &FFORReceiverRequest,
	) -> Result<FFORRequestInsertion<'_>, FFORRecoveryError> {
		let pending = PendingRequest::new(request.clone())?;
		if self.find_request(request.local_request_id()).is_some() {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		if self.pending_requests.iter().any(|entry| {
			entry.key.channel_id == pending.key.channel_id
				|| (entry.record.chain_hash() == request.chain_hash()
					&& entry.record.funding_txo() == request.funding_txo())
		}) || self.entries.iter().any(|entry| {
			entry.key.channel_id == pending.key.channel_id
				|| (entry.record.setup.chain_hash() == request.chain_hash()
					&& entry.record.setup.funding_txo() == request.funding_txo())
		}) {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		let header_bytes = if self.version() >= REQUEST_VERSION { 0 } else { 2 };
		self.check_capacity(pending.encoded_bytes + header_bytes, pending.reserved_bytes())?;
		Ok(FFORRequestInsertion { registry: self, entry: pending, header_bytes })
	}

	pub(crate) fn prepare_accept(
		&mut self, setup: &FFORReceiverSetup,
	) -> Result<FFORRequestPromotion<'_>, FFORRecoveryError> {
		let authenticated =
			setup.validate_recovery().map_err(|_| FFORRecoveryError::InvalidRecord)?;
		let key = FFORRecoveryKey {
			channel_id: ChannelId(authenticated.header().channel_id),
			epoch_id: authenticated.header().epoch_id,
		};
		let index = self
			.pending_requests
			.iter()
			.position(|entry| entry.key == key)
			.ok_or(FFORRecoveryError::ConflictingRecord)?;
		let request = &self.pending_requests[index].record;
		if !request.validates_setup(setup) {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		let entry = Entry::new(StoredSetup {
			setup: setup.clone(),
			canonical_book: authenticated.canonical_book().to_vec(),
			activation: None,
			request: Some(request.clone()),
			witnesses: None,
		})?;
		// Both forms were charged the full record allowance before Init. Promotion cannot increase
		// total used plus reserved bytes, and the borrowed permit prevents a conflicting insertion.
		Ok(FFORRequestPromotion { registry: self, index, entry })
	}
}
