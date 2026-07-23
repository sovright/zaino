//! Research foundations for Zaino's host-oblivious private-query service.
//!
//! This crate currently provides fixed data shapes, a crate-internal
//! protected inner-envelope contract, a crate-internal XChaCha20-Poly1305
//! primitive, deterministic trace and exclusive two-table command models, and
//! fake stores. An optional pinned `rostl` adapter is an offline-only
//! compile/behavior experiment; it does not supply production recovery or
//! persistence. The crate has no production key/nonce lifecycle, attestation,
//! or network service and makes no production privacy claim.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "foundation APIs stay private until the zainod-oram consumer lands"
    )
)]

#[cfg(feature = "corpus-zaino")]
mod canonical_chain;
#[cfg(feature = "corpus-zaino")]
mod checkpoint;
mod continuation_token;
mod corpus;
mod engine;
mod envelope;
#[cfg(feature = "corpus-zaino")]
mod full_map_saturation;
mod inner_codec;
mod layout;
#[cfg(feature = "corpus-zaino")]
mod process_memory;
mod profile;
#[cfg(feature = "corpus-zaino")]
mod projection;
#[cfg(feature = "corpus-zaino")]
mod projection_owner;
mod protection;
#[cfg(feature = "corpus-zaino")]
mod qualification;
mod recent_snapshot;
mod records;
mod sizing;
mod store;
#[cfg(feature = "corpus-zaino")]
mod stress_qualification;
#[cfg(feature = "corpus-zaino")]
mod target_load;
mod trace;
mod xchacha20;
#[cfg(feature = "corpus-zaino")]
mod zaino_corpus;
#[cfg(all(test, feature = "corpus-zaino"))]
mod zaino_fixtures;

#[cfg(feature = "corpus-zaino")]
pub use full_map_saturation::{
    run_typed_worker_full_map_saturation, TypedWorkerFullMapSaturationError,
    TypedWorkerFullMapSaturationProfile, TypedWorkerFullMapSaturationReport,
};
#[cfg(feature = "corpus-zaino")]
pub use projection_owner::{
    TypedWorkerColdRebuildError, TypedWorkerColdRebuildProfile, TypedWorkerColdRebuildReport,
    TypedWorkerColdRebuildSession,
};
#[cfg(feature = "corpus-zaino")]
pub use qualification::{
    run_typed_worker_qualification, TypedWorkerQualificationError, TypedWorkerQualificationReport,
};
#[cfg(feature = "corpus-zaino")]
pub use stress_qualification::{
    run_typed_worker_stress_qualification, TypedWorkerStressProfile,
    TypedWorkerStressQualificationError, TypedWorkerStressQualificationReport,
};
#[cfg(feature = "corpus-zaino")]
pub use target_load::{
    run_typed_worker_target_load, TypedWorkerTargetLoadError, TypedWorkerTargetLoadProfile,
    TypedWorkerTargetLoadReport,
};
#[cfg(feature = "corpus-zaino")]
pub use zaino_corpus::{
    MainnetCorpusCheckpoint, MainnetCorpusError, MainnetCorpusMeasurement, MainnetCorpusScanner,
    MainnetSizingModel, MainnetSizingQualification,
};
