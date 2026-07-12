# Changelog

All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Initial dependency-free research foundation: fixed transparent-UTXO records,
  fixed envelopes, exact compiled privacy-profile shapes, a bounded plaintext
  mock store, modeled logical store-call schedules, and equivalence tests. No
  equal-physical-work claim is made.
- Aggregate-only corpus accumulation and checked capacity sizing tied to an
  exact 72-byte append-only persistent event record.
- An optional canonical `IndexedBlock` adapter with genesis/continuity/checkpoint
  validation and identifier-free reports.
- A fixed continuation-token codec with injected protection and atomic replay
  interfaces.
- A Linux-x86_64-only volatile `rostl` experiment pinned at `8c3a12d2`; other
  targets reject construction and no production obliviousness claim is made.
- A bounded single-owner worker for the volatile candidate, with nonblocking
  admission, serialized reads and inserts, deterministic shutdown draining,
  terminal fault latching, dropped-reply/send-failure handling, and
  aggregate-only lifecycle telemetry.
- Exact immutable 38-byte address-directory and 82-byte one-event page
  candidates with canonical dummy encodings, named persistence conversions,
  standard-address validation, redacted diagnostics, and `Pod`/`Cmov` proofs.
- A pure const-generic two-table layout model with canonical address-key
  derivation, secret-seeded keyed probes, power-of-two capacity/admission
  validation, complete fixed-array collision/corruption scans, requested-event
  owner binding, and opaque immutable insertion plans. Backend integration,
  atomic mutation, content authentication, full-capacity sizing, and physical
  trace claims remain out of scope.

### Changed

### Deprecated

### Removed

### Fixed
