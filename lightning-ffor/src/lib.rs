//! Pure primitives for the draft FFOR Variant D protocol.
//!
//! These primitives do not implement a receiver or settlement peer. In particular, successful
//! arithmetic, signature verification or transcript construction is not proof of channel
//! commitments, durable activation, or readiness to expose an offline invoice.
//!
//! The channel engine must retain sole ownership of commitment transitions and signing keys.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod amounts;
pub mod book;
pub mod reestablish;
pub mod setup;
pub mod transcript;
pub mod wire;
