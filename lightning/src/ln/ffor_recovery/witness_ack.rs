//! Compact persisted witness promises and reserved capacity for all selected witnesses.

use super::*;
use crate::ln::ffor::{FFORReceiverWitnessAcknowledgements, FFORWitnessAcknowledgement};

// Fixed-width slots charge the full maximum at registration. Filling an ACK cannot grow an
// enclosing TLV prefix or consume storage which another channel has since reserved.
const ACK_SLOT_BYTES: usize = 33 + 32 + 16 + 4;

impl Writeable for FFORReceiverWitnessAcknowledgements {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.context_digest.write(writer)?;
		(self.acknowledgements.len() as u8).write(writer)?;
		for ack in &self.acknowledgements {
			ack.witness.write(writer)?;
			ack.manifest_digest.write(writer)?;
			ack.request_id.write(writer)?;
			ack.retention_until.write(writer)?;
		}
		for _ in self.acknowledgements.len()..4 {
			writer.write_all(&[0; ACK_SLOT_BYTES])?;
		}
		Ok(())
	}
}

impl Readable for FFORReceiverWitnessAcknowledgements {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let context_digest = <[u8; 32]>::read(reader)?;
		let count = u8::read(reader)? as usize;
		if count > 4 {
			return Err(DecodeError::InvalidValue);
		}
		let mut acknowledgements = Vec::with_capacity(count);
		for _ in 0..count {
			acknowledgements.push(FFORWitnessAcknowledgement {
				witness: PublicKey::read(reader)?,
				manifest_digest: <[u8; 32]>::read(reader)?,
				request_id: <[u8; 16]>::read(reader)?,
				retention_until: u32::read(reader)?,
			});
		}
		for _ in count..4 {
			let mut unused = [0; ACK_SLOT_BYTES];
			reader.read_exact(&mut unused)?;
			if unused != [0; ACK_SLOT_BYTES] {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(Self { context_digest, acknowledgements })
	}
}

impl FFORReceiverWitnessAcknowledgements {
	pub(super) fn empty(registration: &FFORReceiverWitnessRegistration) -> Self {
		Self { context_digest: registration.context_digest(), acknowledgements: Vec::new() }
	}

	pub(super) fn validate(
		&self, registration: &FFORReceiverWitnessRegistration,
	) -> Result<(), FFORRecoveryError> {
		if self.context_digest != registration.context_digest()
			|| self.acknowledgements.len() > registration.witnesses().len()
		{
			return Err(FFORRecoveryError::InvalidRecord);
		}
		for (index, ack) in self.acknowledgements.iter().enumerate() {
			let witness = registration
				.witnesses()
				.iter()
				.find(|w| w.witness_node_id() == ack.witness)
				.ok_or(FFORRecoveryError::InvalidRecord)?;
			if witness.manifest_digest() != ack.manifest_digest
				|| ack.retention_until < witness.retention_until()
				|| (index > 0
					&& self.acknowledgements[index - 1].witness.serialize()
						>= ack.witness.serialize())
			{
				return Err(FFORRecoveryError::InvalidRecord);
			}
		}
		Ok(())
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn get_witness_acks(
		&self, key: &FFORRecoveryKey,
	) -> Option<&FFORReceiverWitnessAcknowledgements> {
		self.entries
			.iter()
			.find(|entry| entry.key == *key)
			.and_then(|entry| entry.record.witness_acks.as_ref())
	}

	pub(crate) fn prepare_witness_ack(
		&mut self, key: &FFORRecoveryKey, ack: FFORWitnessAcknowledgement,
	) -> Result<FFORRecoveryUpgrade<'_>, FFORRecoveryError> {
		let index = self
			.entries
			.iter()
			.position(|entry| entry.key == *key)
			.ok_or(FFORRecoveryError::ConflictingRecord)?;
		let previous = &self.entries[index];
		let mut acks =
			previous.record.witness_acks.clone().ok_or(FFORRecoveryError::ConflictingRecord)?;
		if acks.acknowledgements.iter().any(|existing| existing.witness == ack.witness) {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		acks.acknowledgements.push(ack);
		acks.acknowledgements.sort_unstable_by_key(|ack| ack.witness.serialize());
		let entry = Entry::new(StoredSetup {
			setup: previous.record.setup.clone(),
			canonical_book: previous.record.canonical_book.clone(),
			activation: previous.record.activation.clone(),
			request: previous.record.request.clone(),
			witnesses: previous.record.witnesses.clone(),
			witness_acks: Some(acks),
			invoice: previous.record.invoice.clone(),
		})?;
		self.prepare_replacement(index, entry, 0)
	}
}
