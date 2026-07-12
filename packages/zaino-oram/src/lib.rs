//! Research foundations for Zaino's host-oblivious private-query service.
//!
//! This crate currently provides fixed data shapes, a deterministic trace
//! model, and a mock store. It does not yet contain a real ORAM, encryption,
//! persistence, attestation, or network service and makes no production
//! privacy claim.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "foundation APIs stay private until the zainod-oram consumer lands"
    )
)]

mod engine;
mod envelope;
mod profile;
mod records;
mod store;
