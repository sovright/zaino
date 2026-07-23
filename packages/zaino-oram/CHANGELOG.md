# Changelog

All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Profile ID v5 and authenticated fixed-width replay-entry format v2
  (`ZORJENT2`) for fresh replay-journal provisioning. Each persisted real
  continuation claim is one typed value containing its opaque replay key and a
  nonzero, one-based ceiling expiry-bucket ordinal. The current head remains
  version two and all record widths remain unchanged. V4 state is neither
  migrated nor dual-accepted, and a later incompatible persisted replay
  successor requires another profile identity. This is authenticated metadata,
  not a trusted-time provider, expiry/eligibility decision, maintenance
  watermark, deletion, count reduction, compaction, reclamation, or
  garbage-collection implementation. Request claims remain unexpired and
  capacity remains lifetime cumulative.
- ADR 0009's production gate for one opaque, rollback-resistant runtime
  security-state owner spanning key/projection epochs, sessions and distinct
  role keys, request/server nonce ownership, trusted time, real-or-cover replay
  durability, external freshness, lifecycle rotation, and release-time
  currentness. The ADR defines required invariants and fail-closed
  qualification evidence requirements; it does not select or implement a
  provider.
- Private opaque XChaCha20-Poly1305 dependency composition for the listener-free
  runtime. An end-to-end test rejects a wrong request key before material or
  replay work, then exercises real encrypted request/response pagination,
  token-tamper rejection, a valid continuation claim, and replay rejection with
  the same complete modeled trace. The composition retains deterministic
  material and counting replay fixtures; it is not a production key/session,
  nonce, clock, replay, owner, or service bundle.
- Crate-internal XChaCha20-Poly1305 request-envelope, response-envelope, and
  continuation-token protectors backed by separately owned, zeroized 256-bit
  role-key objects. Distinct canonical associated-data domains authenticate all
  existing profile, direction, session, and checkpoint context. A fixed vector
  was cross-checked against Go's independent `x/crypto/chacha20poly1305` v0.47.0
  implementation; tests also reject nonce, ciphertext, tag, associated-data,
  context, direction, and key changes without exposing plaintext. The direct
  dependency stays on the workspace-compatible RustCrypto 0.10.1 line, whose
  upstream project reports an NCC Group audit; this integration still requires
  independent cryptographic review. Version 0.11 currently conflicts with the
  prerelease `crypto-common` version pinned by the Zcash dependency graph. This
  slice does not select or expose service key establishment, derivation,
  provisioning, rotation, nonce generation, trusted time, durable replay,
  KMS/TDX ownership, or a public runtime factory.
- A listener-free response-release gate inside the private process-lifetime
  owner. One non-`Clone` permit keeps a completed response outstanding; while
  it is held, later handle, refresh, and explicit shutdown attempts reject
  before mutating owner or runtime state. Dropping the permit reopens the gate
  unless it is already closed; a successful stop or owner drop closes it
  permanently. The finalized-runtime pending round carries a narrow
  first-release witness over its expected epoch identity, opaque capture, and
  shared currentness observer. It atomically enters checking, re-observes and compares the source,
  then authorizes the byte borrow; mismatch, observation failure, or owner
  closure fails closed. Unpolled drop performs no observation, and the witness
  retains no serving lease or finalized store. Once refresh has retired the
  active epoch, cancellation never restores it. This is an internal ownership,
  exclusion, and late-release contract only: it is not a service, listener,
  transport-write, response-body, or currentness-at-write proof, and the
  canonical source may advance immediately after the check. It establishes no
  FIFO, queue, wait, deadline, drain, or underlying-worker shutdown behavior;
  tests exercise the exact helper delegated to by the owner rather than a
  successfully refreshed ready-owner lifecycle; a public owner factory and
  private protobuf/body integration remain open.
- A default-off crate-internal process-lifetime owner for the exact recent-chain
  refresh controller and one stable private-query runtime state. It retires the
  active epoch before capture, refreshes from the committed checkpoint of the
  supplied exact finalized store, pins the controller-published epoch, and
  derives the protected runtime checkpoint only from that store-bound lease
  identity. Epoch replacement preserves the injected envelope/token protectors,
  replay guard, material source, codec session binding, compiled profile, and
  monotonic fail-closed health. Failed refresh, pinning, or epoch construction
  leaves no active epoch and never falls back to the retired one. Its logical
  stop is idempotent. This is not an enforced process singleton or service
  caller, and it does not establish concurrent admission, FIFO/queue/overload or
  draining behavior, a transport-write guard, clean underlying-worker shutdown,
  persistence, authenticated provenance, production cryptography, trusted time,
  nonce uniqueness, durable replay, physical or timing obliviousness, TDX,
  target-load, or mainnet readiness.
- A default-off crate-internal exact-lease runtime factory. It consumes one
  already-pinned serving-epoch lease specialized to
  `FinalizedProjectionServingStore`, derives all six protected
  `PrivateQueryCheckpoint` fields from the lease identity, and constructs the
  existing listener-free `PrivateQueryRuntime` without accepting an independent
  checkpoint, store, or currentness observer. The process-lifetime owner above
  now uses the same exact-lease activation seam after pinning from its owned
  controller; the standalone factory still does not enforce unique
  construction, query-level concurrency, service lifecycle, or transport-write
  completion.
- A private Ready-only finalized serving-store adapter. Consuming an
  `OfflineProjectionOwner` now transfers its exact `AtomicWorker` into a
  non-cloneable read-only facade, derives the finalized serving identity within
  the owner boundary, and rejects Building or failed-closed owners while
  shutting their workers down. Each successful in-profile `AddressKey`/slot
  read, absent a backend or worker failure, performs a complete fixed-profile
  directory and padded event-history command, validates and folds the full
  append-only history into dense creation-order live UTXOs, and uses no
  cross-call cache or query-derived fallback. Decreasing event heights and
  events above the owner-bound committed checkpoint fail closed. This is a
  concrete logical adapter for the existing serving-epoch contract and is
  consumed through the exact-lease runtime path by the process-lifetime owner
  above. It still has no service caller and establishes neither persistence nor
  physical or timing obliviousness, production cryptography, TDX, target-load,
  or mainnet readiness.
- A private generation-bound serving-epoch contract. The refresh controller
  invalidates before its sole await, validates a coherent transparent-projection
  capture, activates the owner-generated recent generation, and publishes one
  serving-epoch `Arc` last. The epoch binds an owner-issued finalized store with
  matching identity, the exact recent generation, the opaque NFS revision, and
  a query-independent currentness capability. A separately tested
  listener-free runtime contract accepts the same lease shape, derives its
  finalized store and currentness observer from that lease, completes and
  protects the fixed-work response, and then discards it on a failed final
  observation or double currentness check. The exact-lease factory above now
  provides a non-test construction path after a caller has already pinned the
  epoch. The process-lifetime owner above now supplies the private
  controller-to-runtime pinning and replacement path. There remains no enforced
  process singleton, service or listener caller, or transport-write guard. The
  concrete private adapter above supersedes only the then-current lack of an
  implementation.
- The default-off `corpus-zaino` integration now has a private conversion
  candidate that consumes one `CanonicalRecentChainSnapshot` and an immutable,
  identity-pinned finalized-outpoint classifier. It preserves dense
  standard-event slots in canonical order and tracks nonstandard states without
  treating them as ordinary address events, and the candidate remains
  generation-free. The private single-writer publication owner remains the sole
  generation authority: it accepts a candidate only through its current
  outstanding ticket, requires exact finalized and recent-tip metadata, and
  moves the candidate's slots into `FrozenRecentSnapshot`. Direct raw-slot
  activation is test-only. This entry records the earlier conversion-only
  slice: at that head, begin-update-before-conversion was a control-flow
  obligation and no refresh controller or serving epoch enforced it. The
  private controller and serving-epoch contracts above supersede those
  then-current implementation limitations, but not the lack of non-test
  composition, durability, authenticated provenance, production cryptography,
  TDX, or mainnet evidence.
- Frozen recent snapshots now bind an in-memory monotonic generation, exact
  finalized identity, recent tip height/hash, and the internally computed
  fixed-slot commitment into one lineage digest. The listener-free runtime
  recomputes that binding after every complete scan and continuation query
  binding v2 rejects a token from any other lineage even when its transparent
  slot contents are identical. A private single-writer publication model clears
  the active generation before refresh, admits only the opaque outstanding
  build ticket, retains immutable leases, and supports a final
  current-generation check. Its tests cover advances, same-height and
  shortening reorgs, stale tickets, failed builds, finalized rollback, and
  generation overflow. A replacement owner must roll the durable projection
  epoch because its in-memory generation restarts at one. This entry records
  the earlier snapshot-owner contract, which then had no runtime consumer or
  serving epoch. The private serving-epoch and runtime contracts above
  supersede that implementation-status limitation; they still do not
  authenticate tip or slot provenance, durably prevent rollback, establish a
  non-test composition path, or provide physical, TDX, mainnet, or
  production-readiness evidence.
- Profile ID v3 now binds padded input slots, a distinct recent-snapshot scan
  budget, a fixed timeout bucket, and the explicit single-worker FIFO
  execution/queue/reject-at-capacity policy. The allocation-free recorder
  separately validates sequential recent-snapshot scan ordinals while keeping
  forbidden query-derived source calls at zero. The listener-free runtime now
  executes a nonzero, profile-bound, ordinal-only full scan over a concrete
  runtime-owned `FrozenRecentSnapshot<N>`, merges its create/spend changes before
  pagination, and addresses the finalized store plus recent snapshot through
  one combined cursor domain. The frozen type computes its fixed-slot content
  commitment internally rather than accepting a generic source-reported digest;
  fault and post-construction corruption hooks exist only under `#[cfg(test)]`
  and are absent from the production API. The commitment is bound into the
  continuation query digest, and every round completes the scan before
  rechecking both exact checkpoint identity and recomputed content commitment.
  Malformed same-outpoint sequences, owner mismatches against finalized outputs,
  and duplicate creates fail closed as protected `ProjectionNotReady` only after
  the full modeled work, while query-derived source calls remain zero. This is
  logical mock evidence only: the commitment is not an authenticated
  canonical/live Zaino snapshot root, and the slice does not supply live NFS
  acquisition, canonical or reorg-safe snapshot publication, physical
  obliviousness, allocator or timing equivalence, TDX, mainnet, or target-load
  evidence.
- A crate-internal recovery foundation for the volatile projection worker: a
  fixed 160-byte public manifest payload plus 32-byte authenticator binds
  monotonic publication and predecessor digests, projection identity/epoch,
  finalized checkpoint, event count, deterministic semantic event-log root,
  and an explicit rebuild-required durability mode. Immutable
  content-addressed publication,
  a non-authoritative atomic `CURRENT` hint, an injected digest-bound external
  freshness witness, strict decoding, directory/file checks, and four
  deterministic crash failpoints reject rollback, corruption, equivocation,
  and incomplete publication. The projection publishes after all worker
  mutations and commits in-memory state last; restart creates a fresh worker,
  rolls the projection epoch, and replays genesis-forward. Portable and
  Linux-x86_64-gated typed-worker tests prove deterministic rebuild/root
  equivalence. This does not persist or resume ROSTL tables, position maps,
  stash state, or query-induced mutations, and supplies no production key or
  freshness-witness owner or measured RTO.
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
  the complete finalized-store and runtime-owned frozen-snapshot domains,
  paginates with absolute logical cursors in their combined domain, and records
  an ordered ten-phase logical schedule. Token failures collapse to a
  protected fixed `InvalidContinuation` response after the same modeled work
  when no higher-priority store or projection-readiness failure applies. Token
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
- A listener-free typed-worker qualification entry point that drives one fixed
  nine-command read/append/replay scenario through the real Linux x86_64
  `rostl` worker and returns only deterministic correctness totals plus
  identifier-free aggregate worker counters. It does not measure latency, RSS,
  stash behavior, physical access traces, persistence, TDX behavior, mainnet
  capacity, or any runtime-service property, and its report marks source,
  lockfile, toolchain, binary, and execution-attestation binding as absent.
- A separate fixed `SmokeV1` typed-worker stress qualification with 64
  deterministic mixed read, unique-append, and exact-replay operations across
  four modeled addresses, periodic and final reference-model verification, a
  nonterminal cross-address rejection probe, and a second worker that checks an
  accepted limit-exceeding append returns `FailedClosed`, latches terminal
  state, and rejects later commands at admission. Its report exposes no raw
  modeled address, event, seed, or per-operation result and explicitly records
  that CI smoke correctness is not target-load, billion-operation,
  latency/RSS/stash/queue-load, physical-trace, persistence/recovery, TDX, or
  mainnet-gate evidence; it has no node-year failure bound and is not
  source/lockfile/toolchain/binary-bound or execution-attested. A portable
  in-memory execution of both exact worker scenarios pins the fixed layout seed
  to a probe-set-viable choice before native CI.
- A distinct deterministic `FullMapSaturationV1` typed-worker qualification
  that uses independent workers to reach the directory-admission and
  event-admission bounds exactly, verifies the complete admitted histories and
  replay behavior, and requires the next boundary-crossing append to fail
  closed and latch terminal state. Its separate aggregate report records the
  remaining physical-capacity reserve and explicitly does not claim physical
  exhaustion, random or adversarial target-load behavior, benchmark results,
  persistence/recovery, target CPU/TDX qualification, or mainnet readiness.
- A separate source-bound `BuilderFoundationV1` typed-worker target-load
  foundation for generic Linux x86_64 builders. It consumes the exact
  capture-bound sizing model within a fixed research envelope: power-of-two
  directory capacity 64..=512 with admission at least 48, power-of-two event
  capacity 128..=4096 with admission at least 96, 3..=64 events per address,
  four probes per table, and queue capacity one. Warmup reserves 16 directory
  and 48 event admission slots; the deterministic shuffled measured phase then
  runs 160 hot reads, 48 reads from the resident non-hot warmup set (the fixed
  `cold` class), 32 unique hot appends, and 16 unique cold appends, filling both
  logical admission limits. Its aggregate report records
  reference-model correctness, logical occupied-probe collisions,
  typed-worker call latency, mixed-phase wall-clock completion rates,
  process-wide Linux RSS plus process-lifetime HWM, and clean-shutdown
  queue/lifecycle counters. Queue contention
  remains unmeasured, and backend stash state plus physical access traces are
  explicitly `backend-unobservable`. This bounded 256-command profile is not
  target CPU/TDX, persistence/recovery, `10^9`-operation, full-mainnet,
  attestation, physical-obliviousness, or mainnet-readiness evidence.
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
- Read-only sizing-model accessors for the directory/event capacities,
  admission limits, and per-address event limit consumed by the companion
  sizing-input validation command. They expose explicit model inputs, not
  measurements, and do not run a worker or establish load, performance,
  hardware, or mainnet evidence.
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
