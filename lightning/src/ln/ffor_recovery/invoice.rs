//! Bounded immutable exact invoice assignment and signed public route evidence.

use super::*;
use crate::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use crate::ln::ffor::{FFORInvoiceIntent, FFORReceiverRecoveryContext, FFORWitnessRouteEvidence};
use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate};
use crate::prelude::*;
use crate::routing::gossip::verify_channel_announcement;
use crate::types::payment::PaymentSecret;
use crate::util::ser::LengthReadable;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::Network;
use core::time::Duration;
use lightning_ffor::wire::{Init, Payload};
use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, RawBolt11Invoice};
use lightning_types::routing::{RouteHint, RouteHintHop, RoutingFees};

const MAX_INVOICE_BYTES: usize = 4096;
const MAX_INVOICE_RECORD_BYTES: usize = 8192;
const MAX_DESCRIPTION_BYTES: usize = 639;
const MAX_ANNOUNCEMENT_BYTES: usize = 512;
const MAX_UPDATE_BYTES: usize = 256;

#[derive(Clone)]
pub(crate) struct FFORInvoiceRecord {
	pub(crate) context_digest: [u8; 32],
	pub(crate) acknowledgement_digest: [u8; 32],
	pub(crate) created_height: u32,
	pub(crate) settlement_scid: u64,
	pub(crate) settlement_cltv: u16,
	pub(crate) intent: FFORInvoiceIntent,
	pub(crate) route: FFORWitnessRouteEvidence,
	pub(crate) invoice: String,
}

fn write_bytes<W: Writer>(bytes: &[u8], writer: &mut W) -> Result<(), io::Error> {
	(bytes.len() as u16).write(writer)?;
	writer.write_all(bytes)
}
fn read_bytes<R: io::Read>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, DecodeError> {
	let length = u16::read(reader)? as usize;
	if length > maximum {
		return Err(DecodeError::InvalidValue);
	}
	let mut bytes = vec![0; length];
	reader.read_exact(&mut bytes)?;
	Ok(bytes)
}
impl Writeable for FFORInvoiceRecord {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.context_digest.write(writer)?;
		self.acknowledgement_digest.write(writer)?;
		self.created_height.write(writer)?;
		self.settlement_scid.write(writer)?;
		self.settlement_cltv.write(writer)?;
		self.intent.expiry_seconds.write(writer)?;
		self.intent.safety_margin_seconds.write(writer)?;
		write_bytes(self.intent.description.as_bytes(), writer)?;
		write_bytes(self.invoice.as_bytes(), writer)?;
		write_bytes(&self.route.announcement.encode(), writer)?;
		write_bytes(&self.route.update.encode(), writer)
	}
}
impl Readable for FFORInvoiceRecord {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let context_digest = Readable::read(reader)?;
		let acknowledgement_digest = Readable::read(reader)?;
		let created_height = Readable::read(reader)?;
		let settlement_scid = Readable::read(reader)?;
		let settlement_cltv = Readable::read(reader)?;
		let expiry_seconds = Readable::read(reader)?;
		let safety_margin_seconds = Readable::read(reader)?;
		let description = String::from_utf8(read_bytes(reader, MAX_DESCRIPTION_BYTES)?)
			.map_err(|_| DecodeError::InvalidValue)?;
		let invoice = String::from_utf8(read_bytes(reader, MAX_INVOICE_BYTES)?)
			.map_err(|_| DecodeError::InvalidValue)?;
		let announcement = ChannelAnnouncement::read_from_fixed_length_buffer(
			&mut &read_bytes(reader, MAX_ANNOUNCEMENT_BYTES)?[..],
		)?;
		let update = ChannelUpdate::read_from_fixed_length_buffer(
			&mut &read_bytes(reader, MAX_UPDATE_BYTES)?[..],
		)?;
		Ok(Self {
			context_digest,
			acknowledgement_digest,
			created_height,
			settlement_scid,
			settlement_cltv,
			intent: FFORInvoiceIntent { description, expiry_seconds, safety_margin_seconds },
			route: FFORWitnessRouteEvidence { announcement, update },
			invoice,
		})
	}
}

pub(crate) fn terms(context: &FFORReceiverRecoveryContext) -> Result<&Init, DecodeError> {
	match &context.setup().init().payload {
		Payload::Init(init) if !init.hash_chain && context.setup().vouchers().len() == 1 => {
			Ok(init)
		},
		_ => Err(DecodeError::InvalidValue),
	}
}

pub(crate) fn acknowledgements_digest(
	registration: &FFORReceiverWitnessRegistration, acks: &FFORReceiverWitnessAcknowledgements,
) -> Result<[u8; 32], DecodeError> {
	acks.validate(registration).map_err(|_| DecodeError::InvalidValue)?;
	if acks.acknowledgements().len() != registration.witnesses().len() {
		return Err(DecodeError::InvalidValue);
	}
	let mut bytes = b"ffor/receiver/invoice-ack-set/v1".to_vec();
	bytes.extend_from_slice(&acks.encode());
	Ok(sha256::Hash::hash(&bytes).to_byte_array())
}

pub(crate) fn validate_route(
	context: &FFORReceiverRecoveryContext, registration: &FFORReceiverWitnessRegistration,
	route: &FFORWitnessRouteEvidence, now: u64,
) -> Result<PublicKey, DecodeError> {
	let init = terms(context)?;
	// The signed Init restriction is the honest settlement peer's guard against a payer
	// bypassing the advisory BOLT 11 hint. Every allowed witness must be provisioned and ACKed.
	let allowed = init.witness_peers.as_ref().ok_or(DecodeError::InvalidValue)?;
	if allowed.is_empty()
		|| allowed.len() != registration.witnesses().len()
		|| !registration
			.witnesses()
			.iter()
			.all(|entry| allowed.iter().any(|key| key == &entry.witness_node_id()))
	{
		return Err(DecodeError::InvalidValue);
	}
	let ann = &route.announcement.contents;
	let update = &route.update.contents;
	let witness = if ann.node_id_1.as_slice() == context.settlement_node_id().serialize() {
		PublicKey::from_slice(ann.node_id_2.as_slice()).map_err(|_| DecodeError::InvalidValue)?
	} else if ann.node_id_2.as_slice() == context.settlement_node_id().serialize() {
		PublicKey::from_slice(ann.node_id_1.as_slice()).map_err(|_| DecodeError::InvalidValue)?
	} else {
		return Err(DecodeError::InvalidValue);
	};
	let source = if update.channel_flags & 1 == 0 { ann.node_id_1 } else { ann.node_id_2 };
	let fee = lightning_ffor::amounts::FeePolicy {
		base_msat: init.fee_base_msat,
		proportional_millionths: init.fee_proportional_millionths,
	};
	let gross = fee
		.gross_msat(context.setup().vouchers()[0].amount_msat)
		.map_err(|_| DecodeError::InvalidValue)?;
	if witness == context.receiver_node_id()
		|| witness == context.settlement_node_id()
		|| ann.node_id_1.as_slice() >= ann.node_id_2.as_slice()
		|| !registration.witnesses().iter().any(|entry| entry.witness_node_id() == witness)
		|| source.as_slice() != witness.serialize()
		|| ann.chain_hash != context.chain_hash()
		|| update.chain_hash != context.chain_hash()
		|| ann.short_channel_id == 0
		|| ann.short_channel_id != update.short_channel_id
		|| !ann.excess_data.is_empty()
		|| !update.excess_data.is_empty()
		|| ann.features.requires_unknown_bits()
		|| route.announcement.serialized_length() > MAX_ANNOUNCEMENT_BYTES
		|| route.update.serialized_length() > MAX_UPDATE_BYTES
		|| update.channel_flags & !1 != 0
		|| update.message_flags & !1 != 0
		|| update.cltv_expiry_delta == 0
		|| update.htlc_minimum_msat > gross
		|| update.htlc_maximum_msat < gross
		|| update.htlc_maximum_msat > crate::ln::msgs::MAX_VALUE_MSAT
		|| u64::from(update.timestamp) < now.saturating_sub(14 * 24 * 60 * 60)
		|| u64::from(update.timestamp) > now.saturating_add(24 * 60 * 60)
	{
		return Err(DecodeError::InvalidValue);
	}
	lightning_ffor::amounts::FeePolicy {
		base_msat: update.fee_base_msat,
		proportional_millionths: update.fee_proportional_millionths,
	}
	.gross_msat(gross)
	.map_err(|_| DecodeError::InvalidValue)?;
	let secp = Secp256k1::verification_only();
	verify_channel_announcement(&route.announcement, &secp)
		.map_err(|_| DecodeError::InvalidValue)?;
	let digest = sha256d::Hash::hash(&update.encode()).to_byte_array();
	secp.verify_ecdsa(&Message::from_digest(digest), &route.update.signature, &witness)
		.map_err(|_| DecodeError::InvalidValue)?;
	Ok(witness)
}

impl FFORInvoiceRecord {
	pub(crate) fn digest(&self) -> [u8; 32] {
		sha256::Hash::hash(self.invoice.as_bytes()).to_byte_array()
	}
	pub(crate) fn expires_at(&self) -> Result<u64, DecodeError> {
		let invoice: Bolt11Invoice = self.invoice.parse().map_err(|_| DecodeError::InvalidValue)?;
		invoice
			.duration_since_epoch()
			.as_secs()
			.checked_add(invoice.expiry_time().as_secs())
			.ok_or(DecodeError::InvalidValue)
	}
	pub(crate) fn matches_intent(
		&self, intent: &FFORInvoiceIntent, route: &FFORWitnessRouteEvidence,
	) -> bool {
		self.intent == *intent && self.route == *route
	}
	pub(crate) fn unsigned(
		&self, context: &FFORReceiverRecoveryContext,
		registration: &FFORReceiverWitnessRegistration, timestamp: u64, secret: PaymentSecret,
	) -> Result<RawBolt11Invoice, DecodeError> {
		let init = terms(context)?;
		let voucher = &context.setup().vouchers()[0];
		let witness = validate_route(context, registration, &self.route, timestamp)?;
		let remaining = init
			.settlement_deadline
			.checked_sub(self.created_height)
			.and_then(|blocks| u64::from(blocks).checked_mul(480))
			.and_then(|seconds| seconds.checked_sub(u64::from(self.intent.safety_margin_seconds)))
			.ok_or(DecodeError::InvalidValue)?;
		let expiry = core::cmp::min(u64::from(self.intent.expiry_seconds), remaining);
		if expiry == 0
			|| self.intent.description.len() > MAX_DESCRIPTION_BYTES
			|| self.settlement_scid == 0
			|| self.settlement_cltv == 0
		{
			return Err(DecodeError::InvalidValue);
		}
		let currency =
			Network::from_chain_hash(context.chain_hash()).ok_or(DecodeError::InvalidValue)?.into();
		let update = &self.route.update.contents;
		let hint = RouteHint(vec![
			RouteHintHop {
				src_node_id: witness,
				short_channel_id: update.short_channel_id,
				fees: RoutingFees {
					base_msat: update.fee_base_msat,
					proportional_millionths: update.fee_proportional_millionths,
				},
				cltv_expiry_delta: update.cltv_expiry_delta,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			},
			RouteHintHop {
				src_node_id: context.settlement_node_id(),
				short_channel_id: self.settlement_scid,
				fees: RoutingFees {
					base_msat: init.fee_base_msat,
					proportional_millionths: init.fee_proportional_millionths,
				},
				cltv_expiry_delta: self.settlement_cltv,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			},
		]);
		InvoiceBuilder::new(currency)
			.description(self.intent.description.clone())
			.duration_since_epoch(Duration::from_secs(timestamp))
			.payee_pub_key(context.receiver_node_id())
			.payment_hash(sha256::Hash::from_byte_array(voucher.payment_hash))
			.payment_secret(secret)
			.amount_milli_satoshis(voucher.amount_msat)
			.min_final_cltv_expiry_delta(u64::from(MIN_FINAL_CLTV_EXPIRY_DELTA))
			.expiry_time(Duration::from_secs(expiry))
			.private_route(hint)
			.build_raw()
			.map_err(|_| DecodeError::InvalidValue)
	}
	pub(crate) fn validate(
		&self, context: &FFORReceiverRecoveryContext,
		registration: &FFORReceiverWitnessRegistration, acks: &FFORReceiverWitnessAcknowledgements,
	) -> Result<(), DecodeError> {
		if self.context_digest != context.context_digest()
			|| self.acknowledgement_digest != acknowledgements_digest(registration, acks)?
			|| self.invoice.is_empty()
			|| self.invoice.len() > MAX_INVOICE_BYTES
			|| self.serialized_length() > MAX_INVOICE_RECORD_BYTES
		{
			return Err(DecodeError::InvalidValue);
		}
		let invoice: Bolt11Invoice = self.invoice.parse().map_err(|_| DecodeError::InvalidValue)?;
		let raw = self.unsigned(
			context,
			registration,
			invoice.duration_since_epoch().as_secs(),
			*invoice.payment_secret(),
		)?;
		if *invoice.into_signed_raw().raw_invoice() != raw {
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}
}

impl FFORRecoveryRegistry {
	pub(crate) fn get_invoice(&self, key: &FFORRecoveryKey) -> Option<&FFORInvoiceRecord> {
		self.entries
			.iter()
			.find(|entry| entry.key == *key)
			.and_then(|entry| entry.record.invoice.as_ref())
	}
	pub(crate) fn prepare_invoice(
		&mut self, key: &FFORRecoveryKey, invoice: FFORInvoiceRecord,
	) -> Result<FFORRecoveryUpgrade<'_>, FFORRecoveryError> {
		let index = self
			.entries
			.iter()
			.position(|entry| entry.key == *key)
			.ok_or(FFORRecoveryError::ConflictingRecord)?;
		let previous = &self.entries[index];
		if previous.record.invoice.is_some() {
			return Err(FFORRecoveryError::ConflictingRecord);
		}
		let entry = Entry::new(StoredSetup {
			setup: previous.record.setup.clone(),
			canonical_book: previous.record.canonical_book.clone(),
			activation: previous.record.activation.clone(),
			request: previous.record.request.clone(),
			witnesses: previous.record.witnesses.clone(),
			witness_acks: previous.record.witness_acks.clone(),
			invoice: Some(invoice),
		})?;
		self.prepare_replacement(index, entry, 0)
	}
}

#[cfg(test)]
pub(crate) mod tests;
