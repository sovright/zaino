# Changelog

All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Initial dependency-free research foundation: fixed transparent-UTXO records,
  fixed envelopes, exact compiled privacy-profile shapes, a bounded plaintext
  mock store, modeled logical store-call schedules, and equivalence tests. No
  equal-physical-work claim is made.
- Initial aggregate-only corpus accumulation and page-oriented capacity model
  tied to an exact 72-byte append-only persistent event record.
- An optional canonical `IndexedBlock` adapter with genesis/continuity/checkpoint
  validation and identifier-free reports.
- A fixed continuation-token codec with injected protection and atomic replay
  interfaces.
- A crate-internal, versioned private request/response codec with a
  complete-budget-derived profile identifier, checkpoint and session binding,
  optional opaque continuation field, canonical result slots, checked
  profile-capacity coupling, direction separation, and an injected
  whole-envelope protection interface. Profile/session/direction are explicit
  protection context. A non-cryptographic deterministic fixture pins exact
  request/response digests, rejects one single-bit mutation at every envelope
  offset, and exercises protected noncanonical fields. No production AEAD,
  nonce lifecycle or physical fixed-work claim is supplied.
- A module-private listener-free runtime adapter that validates opaque tokens
  before engine use, performs one real-or-cover replay operation and token
  issue per completed protected round after server-material acquisition, scans
  the complete store domain, paginates with absolute logical store-slot cursors,
  and records an ordered ten-phase logical schedule. Token failures collapse to
  a protected fixed
  `InvalidContinuation` response after the same modeled work when no
  higher-priority store or projection-readiness failure applies. Token
  protection binds the checkpoint and codec session; every replay path models
  one lookup and one write-back, with cover writes isolated from the real-token
  namespace. Test profiles bind the runtime schedule version, replay budget,
  and continuation lifetime into their ID; all protectors, clock/nonces,
  replay storage, and stores remain injected research fixtures rather than
  production implementations.
- A Linux-x86_64-only volatile `rostl` experiment pinned at `8c3a12d2`; other
  targets reject construction and no production obliviousness claim is made.
- Separate typed `rostl` stores for the exact 38-byte directory and 82-byte
  event-page records, plus a private Linux-only offline constructor that places
  both stores behind the exclusive business-command worker for native proof and
  the crate-internal offline projection owner. Healthy misses and
  duplicates share one read/remap plus one write-or-insert/remap schedule;
  `Cmov` selection preserves the prior logical bytes on duplicate, and
  uncertain upstream outcomes fail the store closed. Native Linux execution,
  authentication, persistence, recovery, and physical-trace claims remain out
  of scope.
- A bounded single-owner worker for the exact two-table command core, with
  nonblocking admission of whole history-read/append commands, deterministic
  shutdown draining, terminal fault latching, uniform append-ticket-abandonment
  fault latching, and identifier-free internal queue/lifecycle/outcome counters
  with no export-policy claim.
- A private generic finalized-event/checkpoint coordinator that fully stages
  canonical validation, transparent event extraction, spend-owner resolution,
  capacity checks, and an ordered standard-event batch before its first sink
  call. It commits the cloned plaintext projection checkpoint only after every
  synchronous sink append succeeds and drops/fails closed on staging, sink, or
  finish failure. This is an offline ordering model, not backend block
  atomicity, authenticated persistence, or recovery.
- A private `corpus-zaino` event-sink implementation on the owning atomic
  worker. It rejects nonstandard events before admission, derives P2PKH/P2SH
  addresses through the existing business conversion, submits only the whole
  append command, consumes the reply synchronously, and collapses worker
  failures to an identifier-free sink error.
- A crate-internal offline projection owner that rejects network, schema, key
  epoch, directory admission, event admission, or per-address bound mismatches
  before backend allocation; owns the coordinator and worker without exposing
  table handles or snapshots; and consumes shutdown into coarse stopped or
  failed-closed outcomes. Portable fake-backed tests cover complete build,
  finish, shutdown, and mutate-then-fail retry prohibition; a Linux x86_64 test
  drives the same owner over the exact typed `rostl` stores.
- Exact immutable 38-byte address-directory and 82-byte one-event page
  candidates with canonical dummy encodings, named persistence conversions,
  standard-address validation, redacted diagnostics, and `Pod`/`Cmov` proofs.
- A pure const-generic two-table layout model with canonical address-key
  derivation, secret-seeded keyed probes, power-of-two capacity/admission
  validation, complete fixed-array collision/corruption scans, requested-event
  owner binding, and opaque immutable insertion plans. Backend integration,
  atomic mutation, content authentication, and physical trace claims remain out
  of scope.
- A checked two-table capacity model that shares layout allocation validation,
  charges every allocated 38/82-byte cell and both full position-map domains,
  and reports independent directory, event, hot-address, modeled-memory, and
  combined modeled fit flags. Backend expansion and position-map width remain
  uncalibrated research inputs rather than measured RSS evidence.
- A module-private synchronous two-table command core that owns distinct typed
  fake backend handles, validates their public capacity shape before use, scans
  the full directory plus every bounded event ordinal on successful preflights,
  derives the append ordinal from a contiguous owned-backend history, obtains
  admission counts from those backends, and preflights both immutable inserts
  without executor-command interleaving. Any uncertain or partial mutation
  terminal-latches the candidate for discard. The private owner composes this
  core and worker with the projection and real `rostl` adapter, but makes no
  authenticated block-atomicity, persistence, or physical-obliviousness claim.

### Changed

- Replace the obsolete occupied-page corpus estimate and version-1 report with
  fixed directory/event allocation inputs and the version-2 aggregate schema.
- Replace the incompatible raw-key/raw-record `rostl`-adapter worker with a
  portable business-command worker that consumes the exclusive two-table
  executor and exposes no storage-operation bypass.

### Deprecated

### Removed

### Fixed
