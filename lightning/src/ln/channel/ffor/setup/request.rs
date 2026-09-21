//! Immutable pre-init admission evidence. This gate must be durable before Init can leave.

use super::*;
use lightning_ffor::amounts::FeePolicy;
use lightning_ffor::book::BookTerms;

#[derive(Clone)]
pub(crate) struct FFORReceiverRequest {
	init_wire: Vec<u8>,
	local_request_id: [u8; 32],
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
	counterparty_commitment_number: u64,
	incoming_htlc_id: u64,
}

impl_writeable_tlv_based!(FFORReceiverRequest, {
	(0, init_wire, required_vec), (2, receiver, required), (4, settlement, required),
	(6, chain_hash, required), (8, funding_txo, required), (10, channel_value_sat, required),
	(12, receiver_balance_msat, required), (14, feerate_sat_per_kw, required),
	(16, settlement_is_funder, required), (18, admission_height, required),
	(20, claim_margin_blocks, required), (22, counterparty_commitment_number, required),
	(24, incoming_htlc_id, required),
	(26, local_request_id, required),
});

impl FFORReceiverRequest {
	pub(crate) fn validate_recovery(&self) -> Result<Message, DecodeError> {
		let message = Message::decode(&self.init_wire).map_err(|_| DecodeError::InvalidValue)?;
		message.verify_signature(&self.receiver).map_err(|_| DecodeError::InvalidValue)?;
		let terms = match &message.payload {
			Payload::Init(init) => Self::terms(init),
			_ => return Err(DecodeError::InvalidValue),
		};
		if self.receiver == self.settlement
			|| self.claim_margin_blocks == 0
			|| self.counterparty_commitment_number > INITIAL_COMMITMENT_NUMBER
			|| self.incoming_htlc_id.checked_add(terms.amounts_msat.len() as u64).is_none()
			|| self
				.channel_value_sat
				.checked_mul(1000)
				.map_or(true, |total| self.receiver_balance_msat > total)
			|| self.admission_height >= terms.settlement_deadline
			|| terms.voucher_expiry >= LOCK_TIME_THRESHOLD
			|| terms
				.settlement_deadline
				.checked_add(self.claim_margin_blocks)
				.map_or(true, |height| height > terms.voucher_expiry)
		{
			return Err(DecodeError::InvalidValue);
		}
		Ok(message)
	}

	fn terms(init: &lightning_ffor::wire::Init) -> BookTerms {
		BookTerms {
			amounts_msat: init.amounts_msat.clone(),
			budget_msat: init.budget_msat,
			minimum_payment_msat: init.min_payment_msat,
			fees: FeePolicy {
				base_msat: init.fee_base_msat,
				proportional_millionths: init.fee_proportional_millionths,
			},
			settlement_deadline: init.settlement_deadline,
			voucher_expiry: init.voucher_expiry,
		}
	}

	fn setup(&self, accept_wire: &[u8]) -> FFORReceiverSetup {
		FFORReceiverSetup {
			init_wire: self.init_wire.clone(),
			accept_wire: accept_wire.to_vec(),
			receiver: self.receiver,
			settlement: self.settlement,
			chain_hash: self.chain_hash,
			funding_txo: self.funding_txo,
			channel_value_sat: self.channel_value_sat,
			receiver_balance_msat: self.receiver_balance_msat,
			feerate_sat_per_kw: self.feerate_sat_per_kw,
			settlement_is_funder: self.settlement_is_funder,
			admission_height: self.admission_height,
			claim_margin_blocks: self.claim_margin_blocks,
		}
	}

	pub(crate) fn validates_setup(&self, setup: &FFORReceiverSetup) -> bool {
		self.validate_recovery().is_ok()
			&& self.setup(&setup.accept_wire).encode() == setup.encode()
			&& setup.validate_recovery().map_or(false, |authenticated| {
				match &authenticated.accept().payload {
					Payload::Accept(accept) => {
						accept.s_commitment_number == self.counterparty_commitment_number
							&& accept.s_htlc_id_base == self.incoming_htlc_id
					},
					_ => false,
				}
			})
	}
	pub(crate) fn local_request_id(&self) -> [u8; 32] {
		self.local_request_id
	}
	pub(crate) fn matches_intent(
		&self, channel_id: ChannelId, peer: PublicKey,
		parameters: &crate::ln::ffor::FFORReceiverParameters,
	) -> bool {
		let message = match self.validate_recovery() {
			Ok(message) => message,
			Err(_) => return false,
		};
		self.settlement == peer
			&& message.header.channel_id == channel_id.0
			&& self.local_request_id == parameters.local_request_id
			&& self.claim_margin_blocks == parameters.claim_margin_blocks
			&& parameters.init().map_or(false, |init| message.payload == Payload::Init(init))
	}
	pub(crate) fn init_wire(&self) -> &[u8] {
		&self.init_wire
	}
	pub(crate) fn receiver(&self) -> PublicKey {
		self.receiver
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
	pub(crate) fn prepare_ffor_receiver_request(
		&self, init_wire: &[u8], receiver: PublicKey, chain_hash: ChainHash, current_height: u32,
		claim_margin_blocks: u32, local_request_id: [u8; 32],
	) -> Result<FFORReceiverRequest, FFORReceiverError> {
		if self.context.ffor_receiver_book.is_some() {
			return Err(FFORReceiverError::AlreadyRegistered);
		}
		self.check_ffor_synchronized()?;
		if !self.context.is_connected()
			|| !self.context.pending_inbound_htlcs.is_empty()
			|| !self.context.pending_outbound_htlcs.is_empty()
		{
			return Err(invalid_setup());
		}
		let request = FFORReceiverRequest {
			init_wire: init_wire.to_vec(),
			local_request_id,
			receiver,
			settlement: self.context.counterparty_node_id,
			chain_hash,
			funding_txo: self.funding.get_funding_txo().ok_or_else(invalid_setup)?,
			channel_value_sat: self.funding.get_value_satoshis(),
			receiver_balance_msat: self.funding.value_to_self_msat,
			feerate_sat_per_kw: self.context.feerate_per_kw,
			settlement_is_funder: !self.funding.is_outbound(),
			admission_height: current_height,
			claim_margin_blocks,
			counterparty_commitment_number: self.ffor_counterparty_commitment_number()?,
			incoming_htlc_id: self.context.next_counterparty_htlc_id,
		};
		let message = request.validate_recovery().map_err(|_| invalid_setup())?;
		if message.header.channel_id != self.context.channel_id().0 {
			return Err(invalid_setup());
		}
		let terms = match &message.payload {
			Payload::Init(init) => FFORReceiverRequest::terms(init),
			_ => return Err(invalid_setup()),
		};
		validate_anchor_book(
			&terms,
			&self.ffor_setup_limits(&request.setup(&[]))?,
			current_height,
			claim_margin_blocks,
		)
		.map_err(|_| invalid_setup())?;
		checked_history_start(self.context.commitment_secrets.get_min_seen_secret())?;
		Ok(request)
	}

	pub(crate) fn install_ffor_receiver_request(
		&mut self, request: FFORReceiverRequest,
	) -> Result<(), FFORReceiverError> {
		let current = self.prepare_ffor_receiver_request(
			&request.init_wire,
			request.receiver,
			request.chain_hash,
			request.admission_height,
			request.claim_margin_blocks,
			request.local_request_id,
		)?;
		if current.encode() != request.encode() {
			return Err(invalid_setup());
		}
		let epoch_id = request.validate_recovery().map_err(|_| invalid_setup())?.header.epoch_id;
		self.context.ffor_receiver_book = Some(FFORReceiverBook {
			epoch_id,
			vouchers: Vec::new(),
			received: Vec::new(),
			abort_reason: None,
			setup: None,
			fence: None,
			drain: None,
			request: Some(request),
			request_gate_released: None,
		});
		Ok(())
	}

	pub(crate) fn ffor_validate_pending_request(&self) -> Result<(), DecodeError> {
		self.check_ffor_synchronized().map_err(|_| DecodeError::InvalidValue)?;
		self.ffor_validate_request(true)
	}

	pub(crate) fn abort_ffor_receiver_request(
		&mut self, reason: FFORReceiverAbortReason,
	) -> Result<(), FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		if book.request.is_none() || book.fence.is_some() || book.is_closed() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		book.abort(reason);
		Ok(())
	}

	pub(crate) fn release_ffor_receiver_request_gate(&mut self) -> Result<bool, FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_mut().ok_or(FFORReceiverError::NotRegistered)?;
		if book.request.is_none() || book.abort_reason.is_none() || book.fence.is_some() {
			return Err(FFORCommitmentError::PendingUpdates.into());
		}
		let changed = !book.request_gate_released.unwrap_or(false);
		book.request_gate_released = Some(true);
		Ok(changed)
	}

	pub(crate) fn ffor_receiver_request_gate_released(&self) -> bool {
		self.context
			.ffor_receiver_book
			.as_ref()
			.map_or(false, |book| book.request_gate_released.unwrap_or(false))
	}

	pub(crate) fn ffor_receiver_request(&self) -> Option<&FFORReceiverRequest> {
		self.context.ffor_receiver_book.as_ref().and_then(|book| book.request.as_ref())
	}

	pub(crate) fn prepare_ffor_receiver_accept(
		&self, accept_wire: &[u8], height: u32,
	) -> Result<FFORReceiverSetup, FFORReceiverError> {
		let book =
			self.context.ffor_receiver_book.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		let request = book.request.as_ref().ok_or(FFORReceiverError::NotRegistered)?;
		if book.abort_reason.is_some()
			|| book.setup.is_some()
			|| !book.received.is_empty()
			|| book.request_gate_released.unwrap_or(false)
		{
			return Err(invalid_setup());
		}
		self.check_ffor_synchronized()?;
		let setup = request.setup(accept_wire);
		let authenticated = setup.validate_record()?;
		if height >= authenticated.terms().settlement_deadline {
			return Err(invalid_setup());
		}
		let accept = match &authenticated.accept().payload {
			Payload::Accept(accept) => accept,
			_ => return Err(invalid_setup()),
		};
		if accept.s_commitment_number != request.counterparty_commitment_number
			|| accept.s_htlc_id_base != request.incoming_htlc_id
		{
			return Err(invalid_setup());
		}
		self.ffor_validate_request(true).map_err(|_| invalid_setup())?;
		Ok(setup)
	}

	pub(super) fn ffor_validate_request(&self, current: bool) -> Result<(), DecodeError> {
		let book = match self.context.ffor_receiver_book.as_ref() {
			Some(book) => book,
			None => return Ok(()),
		};
		let request = match book.request.as_ref() {
			Some(request) => request,
			None => return Ok(()),
		};
		let message = request.validate_recovery()?;
		if message.header.channel_id != self.context.channel_id().0
			|| message.header.epoch_id != book.epoch_id
			|| request.settlement != self.context.counterparty_node_id
		{
			return Err(DecodeError::InvalidValue);
		}
		if let Some(setup) = book.setup.as_ref() {
			if !request.validates_setup(setup)
				|| (book.request_gate_released.unwrap_or(false)
					&& (book.abort_reason.is_none() || book.fence.is_some()))
			{
				return Err(DecodeError::InvalidValue);
			}
			return Ok(());
		}
		if !book.vouchers.is_empty()
			|| book.fence.is_some()
			|| book.drain.is_some()
			|| (book.request_gate_released.unwrap_or(false) && book.abort_reason.is_none())
		{
			return Err(DecodeError::InvalidValue);
		}
		let owned = self.context.pending_inbound_htlcs.iter().any(|htlc| book.owns(htlc.htlc_id));
		if current || !book.request_gate_released.unwrap_or(false) || owned {
			if request.funding_txo
				!= self.funding.get_funding_txo().ok_or(DecodeError::InvalidValue)?
				|| request.channel_value_sat != self.funding.get_value_satoshis()
				|| request.settlement_is_funder == self.funding.is_outbound()
			{
				return Err(DecodeError::InvalidValue);
			}
		}
		if current || !book.request_gate_released.unwrap_or(false) || owned {
			let channel_type = self.funding.get_channel_type();
			if !channel_type.supports_static_remote_key()
				|| !channel_type.supports_anchors_zero_fee_htlc_tx()
				|| channel_type.supports_taproot()
				|| channel_type.supports_anchor_zero_fee_commitments()
			{
				return Err(DecodeError::InvalidValue);
			}
			let terms = match &message.payload {
				Payload::Init(init) => FFORReceiverRequest::terms(init),
				_ => return Err(DecodeError::InvalidValue),
			};
			let limits = self
				.ffor_setup_limits(&request.setup(&[]))
				.map_err(|_| DecodeError::InvalidValue)?;
			validate_anchor_book(
				&terms,
				&limits,
				request.admission_height,
				request.claim_margin_blocks,
			)
			.map_err(|_| DecodeError::InvalidValue)?;
		}
		if current
			&& (request.receiver_balance_msat != self.funding.value_to_self_msat
				|| request.feerate_sat_per_kw != self.context.feerate_per_kw
				|| request.counterparty_commitment_number
					!= self
						.ffor_counterparty_commitment_number()
						.map_err(|_| DecodeError::InvalidValue)?
				|| request.incoming_htlc_id != self.context.next_counterparty_htlc_id
				|| !self.context.pending_inbound_htlcs.is_empty()
				|| !self.context.pending_outbound_htlcs.is_empty())
		{
			return Err(DecodeError::InvalidValue);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
