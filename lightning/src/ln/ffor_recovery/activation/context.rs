//! Authenticated projection of retained activation evidence into public historical observations.

use super::*;
use crate::ln::ffor::context::{FFORReceiverRecoveryContext, FFORReceiverRecoveryContextData};

impl FFORReceiverActivation {
	pub(crate) fn receiver_context(
		&self, setup: &FFORReceiverSetup,
	) -> Result<FFORReceiverRecoveryContext, DecodeError> {
		let authenticated = setup.validate_recovery()?;
		let hash = self.validate(&authenticated)?;
		Ok(FFORReceiverRecoveryContext::from_authenticated(
			FFORReceiverRecoveryContextData {
				setup: authenticated,
				chain_hash: setup.chain_hash(),
				receiver: setup.receiver(),
				settlement: setup.settlement(),
				funding_txo: setup.funding_txo(),
				activate_wire: self.activate_wire.clone(),
				activation_hash: hash,
				ack_wire: self.ack_wire.clone(),
				commitments: self.commitments(),
				monitor_update_id: self.monitor_update_id,
				preparation_height: self.preparation_height,
				destination_script: self.destination_script.clone(),
			},
			&setup.encode(),
		))
	}
}
