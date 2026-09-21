//! Signed setup retained by the channel's experimental receiver parking record.
//!
//! Admission currently supports at most 4096 revealed peer commitments. Longer histories are
//! refused until a bounded native history index exists. A setup remains preactivation evidence
//! with conservative abort on restart. A channel holds one registration at a time; a terminal
//! epoch may be replaced by a later one only through the manager's archive-checked admission.

use super::*;
use bitcoin::locktime::absolute::LOCK_TIME_THRESHOLD;
use lightning_ffor::book::{validate_anchor_book, AnchorChannelLimits};
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::wire::{Message, Payload, MAX_MESSAGE_LEN};

mod request;
pub(crate) use request::FFORReceiverRequest;

// This experimental admission path scans shachain under the channel lock. Older histories
// require a future durable digest index; refuse them before doing unbounded work.
const MAX_SETUP_COMMITMENT_HISTORY: u64 = 4096;

fn checked_history_start(minimum: u64) -> Result<u64, FFORReceiverError> {
	let count = (INITIAL_COMMITMENT_NUMBER + 1).checked_sub(minimum).ok_or_else(invalid_setup)?;
	if count > MAX_SETUP_COMMITMENT_HISTORY {
		return Err(invalid_setup());
	}
	Ok(minimum)
}

/// Admission context is historical evidence, never a replacement for live channel authority.
/// The signed messages retain all optional extensions in their exact canonical wire encoding.
#[derive(Clone)]
pub(crate) struct FFORReceiverSetup {
	init_wire: Vec<u8>,
	accept_wire: Vec<u8>,
	receiver: PublicKey,
	settlement: PublicKey,
	chain_hash: ChainHash,
	funding_txo: OutPoint,
	channel_value_sat: u64,
	receiver_balance_msat: u64,
	feerate_sat_per_kw: u32,
	settlement_is_funder: bool,
	admission_height: u32,
	claim_margin_blocks: u32,
}

impl_writeable_tlv_based!(FFORReceiverSetup, {
	(0, init_wire, required_vec),
	(2, accept_wire, required_vec),
	(4, receiver, required),
	(6, settlement, required),
	(8, chain_hash, required),
	(10, funding_txo, required),
	(12, channel_value_sat, required),
	(14, receiver_balance_msat, required),
	(16, feerate_sat_per_kw, required),
	(18, settlement_is_funder, required),
	(20, admission_height, required),
	(22, claim_margin_blocks, required),
});

fn invalid_setup() -> FFORReceiverError {
	FFORCommitmentError::InvalidVoucherBook.into()
}

impl FFORReceiverSetup {
	fn authenticate(&self) -> Result<AuthenticatedSetup, FFORReceiverError> {
		let init = Message::decode(&self.init_wire).map_err(|_| invalid_setup())?;
		let accept = Message::decode(&self.accept_wire).map_err(|_| invalid_setup())?;
		AuthenticatedSetup::new(&init, &accept, self.receiver, self.settlement)
			.map_err(|_| invalid_setup())
	}

	pub(super) fn validate_book(
		&self, book: &FFORReceiverBook,
	) -> Result<AuthenticatedSetup, FFORReceiverError> {
		let setup = self.validate_record()?;
		if setup.header().epoch_id != book.epoch_id || setup.vouchers().len() != book.vouchers.len()
		{
			return Err(invalid_setup());
		}
		for (signed, parked) in setup.vouchers().iter().zip(&book.vouchers) {
			if signed.htlc_id != parked.htlc_id
				|| signed.payment_hash != parked.payment_hash.0
				|| signed.amount_msat != parked.amount_msat
				|| signed.expiry != parked.cltv_expiry
			{
				return Err(invalid_setup());
			}
		}

		Ok(setup)
	}

	/// Reauthenticate historical signed evidence and its expiry height without claiming current
	/// channel eligibility. Timestamp locktimes are invalid even for fully drained terminal books.
	pub(crate) fn validate_recovery(&self) -> Result<AuthenticatedSetup, DecodeError> {
		self.validate_record().map_err(|_| DecodeError::InvalidValue)
	}

	fn validate_record(&self) -> Result<AuthenticatedSetup, FFORReceiverError> {
		let setup = self.authenticate()?;
		let terms = setup.terms();
		let maximum_balance = self.channel_value_sat.checked_mul(1000).ok_or_else(invalid_setup)?;
		if terms.voucher_expiry >= LOCK_TIME_THRESHOLD
			|| self.receiver_balance_msat > maximum_balance
			|| self.claim_margin_blocks == 0
			|| self.admission_height >= terms.settlement_deadline
			|| terms
				.settlement_deadline
				.checked_add(self.claim_margin_blocks)
				.map_or(true, |expiry| expiry > terms.voucher_expiry)
		{
			return Err(invalid_setup());
		}
		Ok(setup)
	}

	pub(crate) fn receiver(&self) -> PublicKey {
		self.receiver
	}
	pub(crate) fn settlement(&self) -> PublicKey {
		self.settlement
	}
	pub(crate) fn chain_hash(&self) -> ChainHash {
		self.chain_hash
	}
	pub(crate) fn funding_txo(&self) -> OutPoint {
		self.funding_txo
	}
}

impl<SP: Deref> FundedChannel<SP>
where
	SP::Target: SignerProvider,
{
	/// Authenticate a complete setup before any vouchers are offered. Identity, chain and height
	/// arguments are supplied exclusively from the containing manager, under its consistency lock.
	/// This retains no activation acknowledgement and grants no invoice or mutation authority.
	#[cfg(test)]
	pub(crate) fn register_ffor_receiver_setup(
		&mut self, init_wire: &[u8], accept_wire: &[u8], our_node_id: PublicKey,
		chain_hash: ChainHash, current_height: u32, claim_margin_blocks: u32,
	) -> Result<(), FFORReceiverError> {
		let prepared = self.prepare_ffor_receiver_setup(
			init_wire,
			accept_wire,
			our_node_id,
			chain_hash,
			current_height,
			claim_margin_blocks,
		)?;
		self.install_prepared_ffor_receiver_setup(prepared)
	}

	pub(crate) fn prepare_ffor_receiver_setup(
		&self, init_wire: &[u8], accept_wire: &[u8], our_node_id: PublicKey, chain_hash: ChainHash,
		current_height: u32, claim_margin_blocks: u32,
	) -> Result<FFORReceiverSetup, FFORReceiverError> {
		// A terminal previous epoch may be replaced by a different epoch only; the manager
		// verifies its archive record. The same epoch is never registered twice.
		if let Some(previous) = self.ffor_receiver_reusable_epoch()? {
			if Message::decode(init_wire).map_or(true, |init| init.header.epoch_id == previous) {
				return Err(FFORReceiverError::AlreadyRegistered);
			}
		}
		self.check_ffor_synchronized()?;
		if init_wire.len() > MAX_MESSAGE_LEN || accept_wire.len() > MAX_MESSAGE_LEN {
			return Err(invalid_setup());
		}

		let record = FFORReceiverSetup {
			init_wire: init_wire.to_vec(),
			accept_wire: accept_wire.to_vec(),
			receiver: our_node_id,
			settlement: self.context.counterparty_node_id,
			chain_hash,
			funding_txo: self.funding.get_funding_txo().ok_or_else(invalid_setup)?,
			channel_value_sat: self.funding.get_value_satoshis(),
			receiver_balance_msat: self.funding.value_to_self_msat,
			feerate_sat_per_kw: self.context.feerate_per_kw,
			settlement_is_funder: !self.funding.is_outbound(),
			admission_height: current_height,
			claim_margin_blocks,
		};
		let setup = record.authenticate()?;
		if setup.header().channel_id != self.context.channel_id().0 {
			return Err(invalid_setup());
		}
		let accept = match &setup.accept().payload {
			Payload::Accept(accept) => accept,
			_ => return Err(invalid_setup()),
		};
		if accept.s_commitment_number != self.ffor_counterparty_commitment_number()? {
			return Err(invalid_setup());
		}
		let limits = self.ffor_setup_limits(&record)?;
		validate_anchor_book(&setup.terms(), &limits, current_height, claim_margin_blocks)
			.map_err(|_| invalid_setup())?;
		self.ffor_check_revealed_history(setup.vouchers()[0].payment_hash)?;

		if !self.context.is_connected()
			|| !self.context.pending_inbound_htlcs.is_empty()
			|| !self.context.pending_outbound_htlcs.is_empty()
			|| accept.s_htlc_id_base != self.context.next_counterparty_htlc_id
		{
			return Err(invalid_setup());
		}
		Ok(record)
	}

	/// Install immediately after preparing while retaining the same manager and peer locks.
	/// Recheck mutable authority so an internal stale record cannot reserve different state.
	pub(crate) fn install_prepared_ffor_receiver_setup(
		&mut self, record: FFORReceiverSetup,
	) -> Result<(), FFORReceiverError> {
		let setup = record.validate_record()?;
		let accept = match &setup.accept().payload {
			Payload::Accept(accept) => accept,
			_ => return Err(invalid_setup()),
		};
		if record.settlement != self.context.counterparty_node_id
			|| setup.header().channel_id != self.context.channel_id().0
			|| record.funding_txo != self.funding.get_funding_txo().ok_or_else(invalid_setup)?
			|| record.channel_value_sat != self.funding.get_value_satoshis()
			|| record.receiver_balance_msat != self.funding.value_to_self_msat
			|| record.feerate_sat_per_kw != self.context.feerate_per_kw
			|| record.settlement_is_funder == self.funding.is_outbound()
			|| accept.s_commitment_number != self.ffor_counterparty_commitment_number()?
		{
			return Err(invalid_setup());
		}
		self.ffor_check_revealed_history(setup.vouchers()[0].payment_hash)?;
		let limits = self.ffor_setup_limits(&record)?;
		validate_anchor_book(
			&setup.terms(),
			&limits,
			record.admission_height,
			record.claim_margin_blocks,
		)
		.map_err(|_| invalid_setup())?;
		let vouchers: Vec<_> = setup
			.vouchers()
			.iter()
			.map(|voucher| FFORVoucher {
				htlc_id: voucher.htlc_id,
				payment_hash: PaymentHash(voucher.payment_hash),
				amount_msat: voucher.amount_msat,
				cltv_expiry: voucher.expiry,
			})
			.collect();
		let promoting = self.context.ffor_receiver_book.as_ref().map_or(false, |book| {
			book.request.is_some()
				&& book.setup.is_none()
				&& book.abort_reason.is_none()
				&& !book.request_gate_released.unwrap_or(false)
		});
		if promoting {
			let book = self.context.ffor_receiver_book.as_ref().unwrap();
			let request = book.request.as_ref().unwrap();
			if !request.validates_setup(&record) || !book.received.is_empty() {
				return Err(invalid_setup());
			}
			self.check_ffor_synchronized()?;
			self.ffor_validate_request(true).map_err(|_| invalid_setup())?;
			verification::validate_vouchers(&vouchers)?;
			self.context.ffor_receiver_book.as_mut().unwrap().vouchers = vouchers;
		} else if self.context.ffor_receiver_book.is_some() {
			// Only a terminal epoch can be replaced. The manager has already matched it against
			// the archive under the same locks; the channel rechecks its own shape here.
			self.ffor_replace_terminal_book(setup.header().epoch_id, vouchers, None)?;
		} else {
			self.register_ffor_receiver_book(setup.header().epoch_id, &vouchers)?;
		}
		self.context.ffor_receiver_book.as_mut().unwrap().setup = Some(record);
		Ok(())
	}

	fn ffor_check_revealed_history(&self, first_hash: [u8; 32]) -> Result<(), FFORReceiverError> {
		// The bound is checked before iterating any state-derived index range. A future durable
		// digest index can admit busier channels without scanning their complete shachain history.
		let start = checked_history_start(self.context.commitment_secrets.get_min_seen_secret())?;
		for index in start..=INITIAL_COMMITMENT_NUMBER {
			if self
				.context
				.commitment_secrets
				.get_secret(index)
				.map_or(false, |secret| Sha256::hash(&secret).to_byte_array() == first_hash)
			{
				return Err(invalid_setup());
			}
		}
		Ok(())
	}

	fn ffor_counterparty_commitment_number(&self) -> Result<u64, FFORReceiverError> {
		let current = self
			.context
			.counterparty_next_commitment_transaction_number
			.checked_add(1)
			.ok_or_else(invalid_setup)?;
		INITIAL_COMMITMENT_NUMBER.checked_sub(current).ok_or_else(invalid_setup)
	}

	fn ffor_setup_limits(
		&self, record: &FFORReceiverSetup,
	) -> Result<AnchorChannelLimits, FFORReceiverError> {
		let settlement_balance_msat = record
			.channel_value_sat
			.checked_mul(1000)
			.and_then(|total| total.checked_sub(record.receiver_balance_msat))
			.ok_or_else(invalid_setup)?;
		Ok(AnchorChannelLimits {
			max_accepted_htlcs: self.context.holder_max_accepted_htlcs,
			max_in_flight_msat: self.context.holder_max_htlc_value_in_flight_msat,
			htlc_minimum_msat: self.context.holder_htlc_minimum_msat,
			receiver_dust_sat: self.context.holder_dust_limit_satoshis,
			settlement_dust_sat: self.context.counterparty_dust_limit_satoshis,
			settlement_balance_msat,
			receiver_balance_msat: record.receiver_balance_msat,
			settlement_reserve_sat: self.funding.holder_selected_channel_reserve_satoshis,
			receiver_reserve_sat: self
				.funding
				.counterparty_selected_channel_reserve_satoshis
				.ok_or_else(invalid_setup)?,
			settlement_is_funder: record.settlement_is_funder,
			feerate_sat_per_kw: record.feerate_sat_per_kw,
		})
	}

	/// Check n0 again once the stock voucher round has revealed it. Never derive or expose it
	/// outside this channel, and do not accept caller-provided revocation evidence.
	pub(super) fn ffor_revealed_secret_matches(&self) -> Result<bool, FFORReceiverError> {
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) if book.abort_reason.is_none() => book,
			_ => return Ok(false),
		};
		let record = match book.setup.as_ref() {
			Some(record) => record,
			None => return Ok(false),
		};
		let setup = record.validate_book(book)?;
		let number = match &setup.accept().payload {
			Payload::Accept(accept) => accept.s_commitment_number,
			_ => return Err(invalid_setup()),
		};
		let index = INITIAL_COMMITMENT_NUMBER.checked_sub(number).ok_or_else(invalid_setup)?;
		if index < self.context.commitment_secrets.get_min_seen_secret() {
			return Ok(false);
		}
		let secret = self.context.commitment_secrets.get_secret(index).ok_or_else(invalid_setup)?;
		Ok(Sha256::hash(&secret).to_byte_array() == setup.vouchers()[0].payment_hash)
	}

	pub(super) fn ffor_abort_revealed_secret_reuse(&mut self) {
		if self.ffor_revealed_secret_matches().unwrap_or(true) {
			if let Some(book) = self.context.ffor_receiver_book.as_mut() {
				book.abort(FFORReceiverAbortReason::CommitmentSecretReused);
			}
		}
	}

	/// Export a validated immutable setup for the containing manager's retained evidence registry.
	pub(crate) fn ffor_receiver_setup_record(
		&self,
	) -> Result<Option<FFORReceiverSetup>, DecodeError> {
		self.ffor_validate_receiver_setup()?;
		Ok(self.context.ffor_receiver_book.as_ref().and_then(|book| book.setup.clone()))
	}

	/// Rebind the saved receiver and network to the manager restoring this channel.
	pub(crate) fn ffor_validate_receiver_identity(
		&self, our_node_id: PublicKey, chain_hash: ChainHash,
	) -> Result<(), DecodeError> {
		if let Some(request) = self.ffor_receiver_request() {
			if request.receiver() != our_node_id || request.chain_hash() != chain_hash {
				return Err(DecodeError::InvalidValue);
			}
		}
		if let Some(record) =
			self.context.ffor_receiver_book.as_ref().and_then(|book| book.setup.as_ref())
		{
			if record.receiver != our_node_id || record.chain_hash != chain_hash {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(())
	}

	/// Validate before the reader converts a live setup into an aborted restart record.
	pub(in crate::ln::channel) fn ffor_restored(&mut self) -> Result<(), DecodeError> {
		self.ffor_validate_receiver_setup()?;
		self.validate_ffor_fence()?;
		if self.ffor_receiver_drain_binding().is_some() {
			self.validate_ffor_drain()?;
		}
		if let Some(book) = self.context.ffor_receiver_book.as_mut() {
			book.abort(FFORReceiverAbortReason::Restarted);
		}
		Ok(())
	}

	pub(crate) fn ffor_validate_receiver_setup(&self) -> Result<(), DecodeError> {
		self.ffor_validate_request(false)?;
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) => book,
			None => return Ok(()),
		};
		let record = match book.setup.as_ref() {
			Some(record) => record,
			None => return Ok(()),
		};
		let setup = record.validate_book(book).map_err(|_| DecodeError::InvalidValue)?;
		if record.settlement != self.context.counterparty_node_id
			|| setup.header().channel_id != self.context.channel_id().0
		{
			return Err(DecodeError::InvalidValue);
		}
		let pending = self.context.pending_inbound_htlcs.iter().any(|htlc| book.owns(htlc.htlc_id));
		if (book.abort_reason.is_none() && !book.is_closed()) || pending {
			let channel_type = self.funding.get_channel_type();
			if record.funding_txo
				!= self.funding.get_funding_txo().ok_or(DecodeError::InvalidValue)?
				|| record.channel_value_sat != self.funding.get_value_satoshis()
				|| record.settlement_is_funder == self.funding.is_outbound()
				|| !channel_type.supports_static_remote_key()
				|| !channel_type.supports_anchors_zero_fee_htlc_tx()
				|| channel_type.supports_taproot()
				|| channel_type.supports_anchor_zero_fee_commitments()
			{
				return Err(DecodeError::InvalidValue);
			}
			let accept = match &setup.accept().payload {
				Payload::Accept(accept) => accept,
				_ => return Err(DecodeError::InvalidValue),
			};
			if accept.s_commitment_number
				> self
					.ffor_counterparty_commitment_number()
					.map_err(|_| DecodeError::InvalidValue)?
				|| accept.s_htlc_id_base > self.context.next_counterparty_htlc_id
			{
				return Err(DecodeError::InvalidValue);
			}
			let limits = self.ffor_setup_limits(record).map_err(|_| DecodeError::InvalidValue)?;
			validate_anchor_book(
				&setup.terms(),
				&limits,
				record.admission_height,
				record.claim_margin_blocks,
			)
			.map_err(|_| DecodeError::InvalidValue)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::messages as ffor_setup_test_messages;
