#![no_main]

use bitcoin::secp256k1::PublicKey;
use libfuzzer_sys::fuzz_target;
use lightning_ffor::setup::AuthenticatedSetup;
use lightning_ffor::wire::Message;
use lightning_ffor::witness::{Acknowledgement, Provision, SignedManifest, MAX_MESSAGE_LEN};

fuzz_target!(|data: &[u8]| {
	if let Ok(ack) = Acknowledgement::decode(data) {
		assert_eq!(ack.encode(), data);
	}
	// Public signed setup plus candidate, so the receiver-specific manifest decoder is exercised
	// without a private key or a second independent canonical-book implementation.
	if data.len() < 4 || data.len() > 3 * MAX_MESSAGE_LEN + 4 {
		return;
	}
	let init_length = usize::from(u16::from_be_bytes([data[0], data[1]]));
	let accept_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
	let Some(init) = data.get(4..4 + init_length) else {
		return;
	};
	let Some(accept) = data.get(4 + init_length..4 + init_length + accept_length) else {
		return;
	};
	let Some(candidate) = data.get(4 + init_length + accept_length..) else {
		return;
	};
	let (Ok(init), Ok(accept)) = (Message::decode(init), Message::decode(accept)) else {
		return;
	};
	let receiver = PublicKey::from_slice(&[
		3, 159, 202, 127, 129, 87, 170, 118, 135, 8, 137, 79, 253, 146, 85, 15, 233, 112, 237, 209,
		133, 38, 165, 249, 54, 88, 62, 163, 181, 77, 171, 50, 40,
	])
	.unwrap();
	let settlement = PublicKey::from_slice(&[
		2, 8, 123, 125, 27, 71, 137, 23, 15, 110, 55, 79, 10, 14, 88, 161, 183, 168, 153, 227, 73,
		41, 121, 83, 20, 171, 105, 100, 230, 150, 9, 233, 192,
	])
	.unwrap();
	let Ok(setup) = AuthenticatedSetup::new(&init, &accept, receiver, settlement) else {
		return;
	};
	if let Ok(manifest) = SignedManifest::decode(candidate, &setup) {
		assert_eq!(manifest.encode(), candidate);
	}
	if let Ok(provision) = Provision::decode(candidate, &setup) {
		assert_eq!(provision.encode(), candidate);
	}
});
