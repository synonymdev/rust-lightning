//! Compact immutable manifest evidence, reauthenticated against the retained native context.

use super::*;
use bitcoin::hashes::{sha256, Hash};
use lightning_ffor::wire::Payload;
use lightning_ffor::witness::{ManifestParameters, SignedManifest, UnsignedManifest};

use crate::ln::ffor::{
	FFORReceiverRecoveryContext, FFORReceiverWitnessRegistration, FFORRegisteredWitness,
};

const MAX_WITNESSES: usize = 4;

impl_writeable_tlv_based!(FFORRegisteredWitness, {
	(0, witness, required),
	(2, manifest_digest, required),
	(4, mailbox_id, required),
	(6, fetch_public_key, required),
	(8, encryption_public_key, required),
	(10, retention_until, required),
	(12, minimum_receipts, required),
	(14, signature, required),
});

impl Writeable for FFORReceiverWitnessRegistration {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.context_digest.write(writer)?;
		(self.witnesses.len() as u8).write(writer)?;
		for witness in &self.witnesses {
			witness.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for FFORReceiverWitnessRegistration {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let context_digest = <[u8; 32]>::read(reader)?;
		let count = u8::read(reader)? as usize;
		if count == 0 || count > MAX_WITNESSES {
			return Err(DecodeError::InvalidValue);
		}
		let mut witnesses = Vec::with_capacity(count);
		for _ in 0..count {
			witnesses.push(FFORRegisteredWitness::read(reader)?);
		}
		Ok(Self { context_digest, witnesses })
	}
}

impl FFORReceiverWitnessRegistration {
	pub(crate) fn from_manifests(
		context: &FFORReceiverRecoveryContext, manifests: &[(PublicKey, SignedManifest)],
	) -> Result<Self, DecodeError> {
		if manifests.is_empty() || manifests.len() > MAX_WITNESSES {
			return Err(DecodeError::InvalidValue);
		}
		let mut witnesses = Vec::with_capacity(manifests.len());
		for (witness, manifest) in manifests {
			let p = manifest.unsigned().parameters();
			let entry = FFORRegisteredWitness {
				witness: *witness,
				manifest_digest: sha256::Hash::hash(&manifest.encode()).to_byte_array(),
				mailbox_id: p.mailbox_id,
				fetch_public_key: p.fetch_public_key,
				encryption_public_key: p.encryption_public_key,
				retention_until: p.retention_until,
				minimum_receipts: p.minimum_receipts,
				signature: *manifest.signature(),
			};
			// Reconstruct from native setup, commitment identity and activation height. This also
			// refuses a valid caller-constructed manifest for a different authenticated context.
			if entry.manifest(context)?.encode() != manifest.encode() {
				return Err(DecodeError::InvalidValue);
			}
			witnesses.push(entry);
		}
		witnesses.sort_unstable_by_key(|entry| entry.witness.serialize());
		let registration = Self { context_digest: context.context_digest(), witnesses };
		registration.validate(context)?;
		Ok(registration)
	}

	pub(crate) fn validate(
		&self, context: &FFORReceiverRecoveryContext,
	) -> Result<(), DecodeError> {
		if self.context_digest != context.context_digest()
			|| context.activation_ack_wire().is_none()
			|| self.witnesses.is_empty()
			|| self.witnesses.len() > MAX_WITNESSES
		{
			return Err(DecodeError::InvalidValue);
		}
		let restriction = match &context.setup().init().payload {
			Payload::Init(init) => init.witness_peers.as_ref(),
			_ => return Err(DecodeError::InvalidValue),
		};
		for (index, witness) in self.witnesses.iter().enumerate() {
			if restriction.map_or(false, |peers| !peers.contains(&witness.witness))
				|| witness.fetch_public_key == witness.encryption_public_key
				|| witness.encryption_public_key != self.witnesses[0].encryption_public_key
				|| (index > 0
					&& self.witnesses[index - 1].witness.serialize() >= witness.witness.serialize())
				|| self.witnesses[..index].iter().any(|previous| {
					previous.mailbox_id == witness.mailbox_id
						|| previous.fetch_public_key == witness.fetch_public_key
				}) {
				return Err(DecodeError::InvalidValue);
			}
			witness.manifest(context)?;
		}
		Ok(())
	}

	pub(crate) fn matches_manifest(&self, witness: &PublicKey, manifest: &SignedManifest) -> bool {
		self.witnesses.iter().any(|entry| {
			entry.witness == *witness
				&& entry.manifest_digest == sha256::Hash::hash(&manifest.encode()).to_byte_array()
		})
	}
}

impl FFORRegisteredWitness {
	fn manifest(
		&self, context: &FFORReceiverRecoveryContext,
	) -> Result<SignedManifest, DecodeError> {
		let activation = lightning_ffor::wire::Message::decode(context.activation_wire())
			.map_err(|_| DecodeError::InvalidValue)?;
		let activation = match activation.payload {
			Payload::Activate(activation) => activation,
			_ => return Err(DecodeError::InvalidValue),
		};
		let manifest = UnsignedManifest::new(
			context.setup(),
			ManifestParameters {
				mailbox_id: self.mailbox_id,
				commitment_hash: activation.commit_hash,
				epoch_start_height: activation.epoch_start_height,
				fetch_public_key: self.fetch_public_key,
				encryption_public_key: self.encryption_public_key,
				retention_until: self.retention_until,
				minimum_receipts: self.minimum_receipts,
			},
		)
		.and_then(|unsigned| unsigned.authenticate(self.signature))
		.map_err(|_| DecodeError::InvalidValue)?;
		if manifest.unsigned().activation_hash() != context.activation_hash()
			|| sha256::Hash::hash(&manifest.encode()).to_byte_array() != self.manifest_digest
		{
			return Err(DecodeError::InvalidValue);
		}
		Ok(manifest)
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn get_witnesses(
		&self, key: &FFORRecoveryKey,
	) -> Option<&FFORReceiverWitnessRegistration> {
		self.entries
			.iter()
			.find(|entry| entry.key == *key)
			.and_then(|entry| entry.record.witnesses.as_ref())
	}

	pub(crate) fn prepare_witnesses(
		&mut self, key: &FFORRecoveryKey, witnesses: FFORReceiverWitnessRegistration,
	) -> Result<FFORRecoveryUpgrade<'_>, FFORRecoveryError> {
		let index = self
			.entries
			.iter()
			.position(|entry| entry.key == *key)
			.ok_or(FFORRecoveryError::ConflictingRecord)?;
		let previous = &self.entries[index];
		if previous.record.witnesses.as_ref().map_or(false, |existing| existing != &witnesses) {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		let entry = Entry::new(StoredSetup {
			setup: previous.record.setup.clone(),
			canonical_book: previous.record.canonical_book.clone(),
			activation: previous.record.activation.clone(),
			request: previous.record.request.clone(),
			witness_acks: Some(
				previous
					.record
					.witness_acks
					.clone()
					.unwrap_or_else(|| FFORReceiverWitnessAcknowledgements::empty(&witnesses)),
			),
			witnesses: Some(witnesses),
		})?;
		let header_growth = if self.version() < REQUEST_VERSION { 2 } else { 0 };
		self.prepare_replacement(index, entry, header_growth)
	}
}
