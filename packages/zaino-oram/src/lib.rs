//! Research foundations for Zaino's host-oblivious private-query service.
//!
//! This crate currently provides fixed data shapes, a deterministic trace
//! model, and a mock store. An optional pinned `rostl` adapter is an
//! offline-only compile/behavior experiment; it does not supply production
//! recovery or persistence. The crate has no production encryption,
//! attestation, or network service and makes no production privacy claim.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "foundation APIs stay private until the zainod-oram consumer lands"
    )
)]

mod continuation_token;
mod corpus;
mod engine;
mod envelope;
mod profile;
mod records;
#[cfg(feature = "rostl-experimental")]
mod rostl_adapter;
mod sizing;
mod store;
mod trace;
#[cfg(feature = "corpus-zaino")]
mod zaino_corpus;

#[cfg(feature = "corpus-zaino")]
pub use zaino_corpus::{
    MainnetCorpusError, MainnetCorpusModel, MainnetCorpusReport, MainnetCorpusScanner,
};
