# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `zaino-oram`: add a module-private replay-component construction and
  verification foundation for the outer security-state snapshot. A versioned,
  domain-separated composite security-component digest currently commits the
  replay-journal component digest. Initial provisioning is explicit; its
  restart-verification seam
  accepts only an exact match between the outer snapshot and the current replay
  state, and any mismatch fails closed. A journal latched indeterminate cannot
  supply component state. Live successor construction requires the caller to
  retain the pre-advance replay digest and reads the real post-advance digest
  from a ready concrete journal. Supplying the same authoritative journal
  instance and an allowed commit count remains a coordinator obligation, so the
  binding never infers transition direction or repairs either component
  automatically. This is a construction and reconciliation foundation, not
  coordinated witness advancement or an atomic combined transaction.
  Profile ID v4 now binds total committed replay-transaction capacity, public
  trusted-time expiry-bucket width, and proactive fixed garbage-collection
  interval. Journal/coordinator construction derives the persisted transaction
  bound from the compiled profile, and outer-sequence exhaustion is rejected
  before replay commit. No non-test runtime or security-owner caller can
  construct and coordinate both private stores in this slice; owner integration,
  maintenance execution, production protector/nonce/time/key ownership, and
  rollback, TDX, and access-oblivious qualification remain deferred.
- `zaino-oram`: add a crate-private crash-durable local replay-journal
  foundation for the atomic request plus real-or-cover continuation contract.
  Version-two current-state and version-one immutable-entry records have exact
  fixed sizes and keep the compiled profile ID, replay identities, lane tags,
  counters, and chain state inside a context-bound sealed-record boundary; this
  slice supplies only a
  deterministic test protector. The next sequence candidate is synchronized
  before `current.bin`, which remains the sole local commit marker; committed
  entries are then immutable. Restart reads only the exact authoritative
  sequence range and never opens the next candidate, while every retry replaces
  that non-authoritative candidate without inspecting its contents. Real commit
  phases and focused synchronous tests cover semantic duplicates, the one
  public transaction bound, authentication, exact-size reads, restart,
  candidate overwrite, direct-component path rejection, and crash prefixes.
  The store implements the existing replay-guard seam but is not wired into the
  runtime. At this earlier journal-only step, its transaction bound was not yet
  profile-derived, and there is no
  production protector/key/nonce owner, coordinated external freshness-witness
  advancement, rollback resistance, nonce or trusted-time journal,
  single-writer process lock, access-oblivious memory or persistence, listener
  integration, or production qualification claim. Until witness integration,
  an absent `current.bin` opens as empty and cannot distinguish first
  initialization from loss of a previously committed marker.
- `zaino-oram`: add a crate-private witness-bound security-state persistence
  foundation. One fixed-width, versioned snapshot binds stable service,
  protocol, owner, key, projection, profile, session, and security-epoch
  identity to opaque serving and component-state digests. Mutations stage and
  synchronize the local snapshot before advancing an injected exact
  sequence-and-digest freshness witness; startup accepts only an exact
  local/witness match, and post-replace or witness ambiguity fails closed.
  Version-one transitions keep service/protocol/profile identity stable,
  prevent owner/key/projection epoch regression, and require a new owner
  generation plus new session/security bindings for any identity rotation.
  Crash-boundary tests cover staged-but-unpublished state, a durable local
  advance without witness authority, rejected witness advancement, and an
  advance-then-error reconciliation. This foundation supplies no concrete
  witness, runtime/owner construction path, coordinated replay-journal and
  witness advancement, trusted-time or nonce journal, key owner, rollback
  deployment evidence, or production privacy claim.
- `zaino-oram`: add a crate-private, fixture-only runtime security contract
  API. Canonical versioned identities separate authenticated request-nonce
  replay from continuation replay, while one atomic in-memory seam completes
  both the request lane and its real-or-cover continuation lane. Distinct
  non-`Clone` round-material reservation and replay-commit authorities are
  retained through response construction and validated together under an
  opaque in-process security epoch at release; unavailable or retired state
  fails closed. This does not change profile ID v3 or the existing ten-phase
  logical schedule, and it supplies no production durable replay, trusted
  clock, nonce ledger, key management, rollback resistance, TDX, listener,
  transport-write, or peer-delivery evidence.
- `zaino-oram` / `zainod-oram`: make one internal, profile-bound, non-`Clone`
  `ActiveSecurityLease` the sole owner of runtime security state, with full raw
  security-bundle fixture assembly restricted to `#[cfg(test)]`. `zaino-oram`
  exports only the lifetime-safe `FixedEnvelopeRuntime`,
  `PendingFixedEnvelope`, and `PrivateQueryUnavailable` facade, which
  `zainod-oram` consumes without extracting detached response bytes. The
  concrete runtime owner remains private and has no public constructor or
  factory. A production protector/replay/material-provider bundle, generated
  route/listener, durable replay, trusted clock, nonce ledger, key management,
  rollback resistance, TDX, and transport evidence remain open. Profile ID v3
  and the ten-phase logical schedule are unchanged.
- `zaino-oram` / `zaino-state`: add a private generation-bound serving-epoch
  contract. The refresh controller invalidates publication before its sole
  await, validates one coherent transparent-projection capture, activates the
  owner-generated recent generation, and publishes one serving-epoch `Arc`
  last. That epoch binds an owner-issued finalized store whose identity must
  match, the exact recent generation, the opaque NFS revision, and a
  query-independent currentness capability. A separately tested listener-free
  runtime contract accepts the same lease shape, derives both its finalized
  store and currentness observer from it, completes the fixed-work response,
  and then fails closed if the final observation or double currentness check
  fails. These are separately tested compatible private contracts: there is no
  non-test controller-to-runtime composition path, process-wide service owner,
  production finalized-store implementation or caller, listener, or
  transport-write guard. This slice therefore makes no production service,
  physical-obliviousness, TDX, target-load, or mainnet claim.
- `zaino-state`: add a crate-private, ORAM-agnostic transparent-projection input
  that joins one immutable canonical recent-chain snapshot to finalized
  outpoint classifications at its exact retained height/hash seam. The
  finalized materializer deduplicates requests and executes metadata,
  checkpoint, creator, spender, reverse-index, and verified forward-row reads
  in one LMDB read transaction; checksum, row-length, Merkle-root, location,
  spend-input, and ordering mismatches fail closed rather than becoming
  `NeverSeen`. Acquisition reads only the already-published NFS value and never
  falls through to the validator. At the time of this staged chain-data slice,
  projection/key-epoch ownership and whole-serving-epoch freshness binding were
  follow-on work. The private controller and lease contracts described above
  supersede that then-current implementation limitation; production ownership,
  retry policy, ORAM persistence, physical obliviousness, TDX, target-load, and
  mainnet evidence remain open.
- `zaino-oram`: the default-off `corpus-zaino` path now contains a private
  conversion candidate that consumes a `CanonicalRecentChainSnapshot` together
  with an immutable, identity-pinned finalized-outpoint classifier. It preserves
  dense standard-event slots in canonical order while tracking nonstandard
  states separately and remains generation-free. The private single-writer
  publication owner is the sole generation authority: through its current
  outstanding ticket it requires exact candidate finalized and recent-tip
  metadata, then moves the candidate's slots into `FrozenRecentSnapshot`. Direct
  raw-slot activation is test-only. This entry records the earlier
  conversion-only slice: at that head, begin-update-before-conversion remained
  a control-flow obligation and no refresh controller or serving epoch enforced
  it. The private controller and serving-epoch contracts described above
  supersede those then-current controller/runtime limitations, but not the lack
  of non-test composition, durability, authenticated provenance, production
  cryptography, TDX, or mainnet evidence.
- `zaino-state`: add a synchronous immutable-snapshot API that verifies an
  exact finalized height/hash seam and returns only canonical recent
  `IndexedBlock`s above it, oldest-to-newest. The API checks structural
  consistency of the retained seam payload, declared tip, contiguous height
  map, block identities, and parent links while excluding side branches and
  structurally preventing DB or validator fallback. It value-binds a
  caller-supplied checkpoint to one immutable NFS snapshot rather than
  atomically capturing finalized storage with NFS. At that slice, production
  finalized-outpoint resolution, live DB/NFS acquisition, runtime wiring, and
  serving-epoch publication remained open. The current private controller/lease
  contracts build on this seam, but still provide no non-test composition path
  or production service publication.
- `zaino-oram`: frozen recent snapshots now bind an in-memory monotonic
  generation, exact finalized identity, recent tip height/hash, and the
  internally computed fixed-slot commitment into one lineage digest. The
  listener-free runtime recomputes that binding after every complete scan and
  continuation query binding v2 rejects a token from any other lineage even
  when its transparent slot contents are identical. A private single-writer
  publication model clears the active generation before a refresh, admits only
  the opaque outstanding build ticket, retains immutable leases, and supports a
  final current-generation check. Its tests cover advances, same-height and
  shortening reorgs, stale tickets, failed builds, finalized rollback, and
  generation overflow. A replacement owner must roll the durable projection
  epoch because its in-memory generation restarts at one. This entry records
  the earlier snapshot-owner contract, which then had no runtime consumer or
  serving epoch. The private serving-epoch and runtime contracts above
  supersede that implementation-status limitation; they still do not
  authenticate tip or slot provenance, durably prevent rollback, establish a
  non-test composition path, or provide physical, TDX, mainnet, or
  production-readiness evidence.
- `zaino-oram`: profile ID v3 now binds padded input slots, a distinct
  recent-snapshot scan budget, timeout bucket, and explicit single-worker FIFO
  execution/queue/reject-at-capacity policy. The logical recorder validates
  ordered recent-snapshot scan ordinals separately from forbidden
  query-derived source calls. The listener-free runtime now executes a nonzero,
  profile-bound, ordinal-only full scan over a concrete runtime-owned
  `FrozenRecentSnapshot<N>` and merges its create/spend changes before
  paginating across one combined finalized-plus-recent cursor domain. The
  frozen type computes its fixed-slot content commitment internally rather than
  accepting a generic source-reported digest; fault and post-construction
  corruption hooks exist only under `#[cfg(test)]` and are absent from the
  production API. The commitment is bound into the continuation query digest,
  and every round completes the scan before rechecking both exact checkpoint
  identity and recomputed content commitment. Malformed same-outpoint
  sequences, owner mismatches against finalized outputs, and duplicate creates
  fail closed as protected `ProjectionNotReady` only after the full modeled
  work, while query-derived source calls remain zero. This is logical mock
  evidence only: the commitment is not an authenticated canonical/live Zaino
  snapshot root, and the slice does not supply live NFS acquisition, canonical
  or reorg-safe snapshot publication, physical obliviousness, allocator or
  timing equivalence, TDX, mainnet, or target-load evidence.
- `zaino-oram`: a crate-internal authenticated public-manifest and volatile
  rebuild foundation now binds publication lineage, projection identity/epoch,
  finalized checkpoint, event count, and a deterministic semantic event-log
  root to a fixed-width keyed-MAC record plus an injected digest-bound external
  freshness witness. Content-addressed publication, a non-authoritative atomic
  hint, crash-boundary failpoints, and restart tests fail closed on stale,
  corrupt, equivocating, or incomplete public state. Restart always allocates a
  fresh worker and replays genesis-forward under a new projection epoch; the
  underlying ROSTL tables, position maps, stash, and read mutations remain
  volatile, with no production witness/key integration or measured RTO.
- `zaino-oram`: a non-published, dependency-free research foundation for
  private transparent-UTXO queries, including fixed records and envelopes,
  exact compiled profile shapes, a bounded plaintext mock store, and tests for
  equal logical store-call schedules. This slice does not claim equal physical
  work. ADR-0007 defines the privacy boundary and keeps the experimental runtime
  outside the publishable Zaino dependency graph.
- `zaino-oram`: initial aggregate corpus/page-capacity models, a fixed
  continuation-token contract, an exact 72-byte append-only event candidate,
  and a pinned volatile `rostl` feasibility adapter. These remain offline
  research components and do not establish a production host-obliviousness
  claim.
- `zaino-oram`: a crate-internal fixed request/response codec now binds a
  complete-budget-derived profile ID, checkpoint, session, query, opaque
  continuation field, protected outcome, and canonical result slots inside one
  direction-separated fixed envelope. Profile/session/direction are supplied
  as protection context, checked layout arithmetic rejects impossible shapes,
  and exact digest/canonicality tests cover the whole envelope. The injected
  deterministic protector is a non-cryptographic test fixture only; there is
  no production AEAD, nonce lifecycle, listener, or physical fixed-work claim.
- `zaino-oram`: a private listener-free runtime adapter now composes canonical
  request decode, one server-material acquisition, real-or-cover token open and
  replay access, complete finalized-store and runtime-owned frozen-snapshot
  scans, fixed result normalization, one real-or-cover token issue, and
  protected response encode into a versioned ten-phase logical trace. Absolute
  cursors in the combined finalized-plus-recent domain paginate without skips or
  duplicates; invalid, expired, mismatched, and replayed tokens complete the
  same modeled schedule and return one protected `InvalidContinuation` shape
  when no higher-priority store or projection-readiness failure applies.
  Token protection binds the checkpoint and codec session, and each completed
  protected round after server-material acquisition models one replay lookup
  plus write-back without cover writes entering the real-token namespace.
  The profile ID now binds the phase schedule and continuation lifetime. This
  is deterministic logical-model evidence only, not production AEAD, trusted
  time/nonces, transport, timing, physical ORAM, or TDX evidence.
- `zaino-state`: a reusable transparent create/spend event-extraction seam for
  ORAM-agnostic projection consumers.
- `zaino-oram` / `zaino-state`: a default-off offline shadow fixture compares
  the plaintext projection with ordinary-source UTXO results for every standard
  address observed at one identical immutable regtest-vector checkpoint. The
  supporting `zaino-state` surface exists only under `test_dependencies`.
- `zaino-oram`: the exclusive two-table command core now has a bounded,
  single-owner worker that admits only whole history-read/append commands,
  drains accepted FIFO work on shutdown, fails not-yet-entered work without
  touching the executor after a terminal fault, and keeps internal telemetry
  identifier-free. Export cadence and suppression remain unset. The old raw
  read/insert worker surface is removed.
- `zaino-oram`: exact immutable protected-table candidates now encode a
  38-byte directory cell and an 82-byte one-event page with canonical dummies,
  named persistence conversions, and `Pod`/`Cmov` proofs. Linux-only table
  allocation and an offline worker constructor now bind separate exact typed
  `rostl` stores; projection/service ownership remains separate work.
- CI: a path-scoped Ubuntu 24.04 x86_64 lane with immutable action pins runs
  locked strict Clippy and the complete all-feature `zaino-oram` suite with the
  pinned Rust/nextest tools against the native volatile `rostl` backend. This
  is generic functional validation, not target-capacity,
  physical-obliviousness, persistence, performance, or TDX evidence.
- `zaino-oram`: a pure two-table layout model now derives canonical
  network/schema-separated address keys, generates distinct keyed fixed probes,
  validates complete directory/event probe arrays, and prepares opaque
  immutable inserts only after a clean scan. A private command worker now binds
  the plan to exact typed stores offline; it is not a projection-owner,
  content-authentication, or physical-obliviousness claim.
- `zaino-oram` / `zainod-oram`: the aggregate capacity model and corpus CLI now
  charge full allocated 38-byte directory and 82-byte event tables plus both
  complete position-map domains. Version-2 reports separate admission,
  hot-address, modeled-memory, and combined modeled fit with explicit negative
  evidence markers; backend expansion remains an uncalibrated research
  assumption rather than measured RSS evidence.
- `zaino-oram` / `zainod-oram`: add a source-bound
  `BuilderFoundationV1` target-load foundation for generic Linux x86_64
  builders. It consumes validated capture and sizing artifacts inside a fixed
  64..=512-directory/128..=4096-event envelope, reserves 16 directory and 48
  event admission slots during warmup, then measures exactly 256 shuffled
  single-caller commands: 160 hot reads, 48 reads from the resident non-hot
  warmup set (the fixed `cold` class), 32 unique hot appends, and 16 unique cold
  appends. The distinct read-back-verified artifact records typed-worker call
  latency, mixed-phase wall-clock completion rates, process-wide RSS plus the
  process-lifetime HWM, clean-shutdown lifecycle counters, and logical probe collisions,
  while marking queue contention unmeasured and stash/physical access
  `backend-unobservable`. This is research-only generic-builder evidence, not
  target hardware/TDX, persistence/recovery, `10^9` operations, full-mainnet,
  attestation, physical-obliviousness, or mainnet-readiness qualification.
- `zaino-oram`: a module-private synchronous command core now owns two typed
  fake table handles, validates their public capacity shape, performs a full
  directory plus bounded-history successful preflight, derives the next
  ordinal from owned-backend state, and terminal-latches after uncertain or
  partial writes. Generic native CI exercises the corresponding exact typed
  `rostl` executor behind the business worker; projection ownership,
  persistence, crash recovery, target load, and physical-trace integration
  remain follow-up work.
- `zainod-oram`: a non-published, listener-free one-shot runner that scans one
  fixed mainnet tip using an NFS snapshot and chain-continuity validation into
  identifier-free corpus aggregates.

### Changed
- `zaino-state`: `FetchService` and `StateService` are merged into a single
  generic `NodeBackedIndexerService<Source>` (module
  `zaino_state::indexer::node_backed_indexer`; the former `backends` module is
  gone). The validator connection is now selected at runtime rather than by type:
  `NodeBackedIndexerServiceConfig { common, connection }` carries a
  `ValidatorConnectionType` of either `Rpc` (JSON-RPC, formerly `Fetch`) or
  `Direct(DirectConnectionConfig)` (Zebra `ReadStateService`, formerly `State`).
  The per-backend `Fetch/StateServiceConfig`, `Fetch/StateServiceError`, and
  `BackendConfig` types are replaced by `NodeBackedIndexerServiceConfig`,
  `NodeBackedIndexerServiceError`, and `ValidatorConnectionType`.
- **Breaking** — config: `zainod.toml`'s `backend` selector is renamed
  `state` → `direct` and `fetch` → `rpc`. The legacy `"state"` / `"fetch"`
  values are still accepted as aliases, so existing config files keep working.
- `zaino-state`: the `ChainIndex` trait is split into `ChainIndex` (the
  wallet-essential core: chain/tx/address/mempool access) and a
  `ChainIndexRpcExt: ChainIndex` extension (compact-block serving, subtree
  roots, and the block-explorer / mining / node-passthrough RPCs). The split is
  a provisional first pass to be refined into finer capability traits later.
- `zaino-state`: all remaining backend-split RPC functionality has moved out of
  the `FetchService` (`JsonRpSeeConnector`) and `StateService`
  (`ReadStateService`) backends and into `BlockchainSource` /
  `ChainIndex`. Both backends now resolve every fetch through their `ChainIndex`
  indexer — building responses from Zaino's own indexed state where possible and
  delegating to the `ValidatorConnector` (`BlockchainSource`) only for
  validator-only or passthrough data. Validator connection/syncer spawning also
  moves into `ValidatorConnector::spawn_fetch` / `spawn_state`, so each
  service/subscriber now holds only `{ indexer, data, config }`. This readies
  the two backends for their eventual merge into a single
  `ValidatorBackedIndexerService`. No behaviour change.
- TLS: zaino now installs rustls's **aws-lc-rs** CryptoProvider as its
  preferred process-level default (was ring) and enables rustls's
  `prefer-post-quantum` feature, so the X25519MLKEM768 hybrid key exchange
  leads zaino's outbound handshakes (ADR-0006). Installation remains
  first-install-wins: an embedder that installs a provider before zaino
  keeps its choice.

### Deprecated
- Classical TLS key exchange (X25519, SECP256R1, SECP384R1) is deprecated:
  still offered and accepted for wallet compatibility, slated for refusal
  once major wallet stacks negotiate hybrid key exchange (ADR-0006).
- **Breaking** — config: `storage.database.sync_write_batch_bytes` (bytes) is
  renamed to `sync_write_batch_size` and given in **GiB** (default raised from
  4 GiB to 32 GiB); this budget now also bounds the txout-set accumulator
  rebuild's per-shard memory. New `storage.database.sync_checkpoint_interval`
  (seconds, default 300) makes the bulk-sync flush interval configurable (was a
  fixed 60s).

### Fixed
- `zaino-state`: finalised-database startup now classifies exact supported
  schema versions and rejects incomplete, unknown, or newer V1 metadata before
  constructing the request router. Existing databases must match a known
  version/hash pair and contain that version's required named tables before any
  create-on-open call can mutate the environment; the current version also
  requires an empty migration status. Each completed migration now records the
  canonical hash for its target version, keeping crash-resume admission valid.
  Builds with experimental transparent address history reject historical
  migrations until a correct address-history backfill exists. Cross-process
  admission uses one
  process-lifetime exclusive lease scoped to each network namespace, preventing
  concurrent normal Zaino writers from opening the same LMDB environment.
  Failed or panicked migrations close read and write routing while retaining
  ownership until the router is dropped; shutdown waits for its owned migration
  task before closing the backends. Data-only LMDB restores are still discovered
  and migrated. The lock sidecars are operational coordination state, not
  database tables or a schema revision; the migration-only target-version helper
  applies the same fail-closed rule. The first rollout requires a quiescent
  cutover because older binaries do not honor the lease. This changes no schema
  bytes or version.
- Zaino no longer OOM-crashes during the txout-set accumulator rebuild when it
  reaches mainnet chain tip on memory-constrained hosts; the rebuild auto-shards
  its in-memory spent set to fit the configured `sync_write_batch_size` budget.

## [0.4.1] - 2026-06-18
- Bump zaino-proto 0.1.2 → 0.1.3 and zainod 0.4.0 → 0.4.1 to work around
  a yanked 0.1.2 slot on crates.io. No code changes.

## [0.4.0] - 2026-06-17
- NU6.2 network upgrade is now supported: activation-height configuration
  (`zaino-common`) and Zebra RPC response parsing (`zaino-fetch`) recognise
  NU6.2.
- [943] Zallet regtest fixes
- [1065] Move functionality to BlockChainSource: t-address rpcs
- `gettxoutsetinfo` is now served indexer-side. Both `FetchService` and
  `StateService` compute the response from Zaino's own UTXO-set accumulator
  (finalised state + non-finalised state) instead of forwarding to the backing
  validator.

### Added
- `storage.database.sync_write_batch_bytes` config (default 4 GiB) tunes the
  finalised-state bulk-sync / migration write-batch size.
- `zainod` gains an `allow_unencrypted_public_json_rpc_bind` build feature that
  lifts the new private-only JSON-RPC bind restriction for trusted
  private-network deployments (logs a `WARN` on startup when enabled).
- `zaino-state::chain_index::source::BlockchainSource` and
  `zaino-state::chain_index::ChainIndex` now expose transparent-address query
  methods for deltas, balances, txids, and UTXOs.
- `ChainIndex::get_tx_out_set_info` — combines the finalised
  `FinalisedTxOutSetInfoAccumulator` with the non-finalised state to produce
  the full `GetTxOutSetInfoResponse`.
- Optional ("ephemeral") finalised state: `zainod` gains an
  `ephemeral_finalised_state` config option (default `false`) that runs Zaino
  without a persistent finalised-state database, serving finalised reads from
  the backing validator via an ephemeral passthrough.
- `ChainIndex::get_outpoint_spenders` — resolves, for each transparent
  outpoint, the txid that spent it on the best chain (or `None` if unspent),
  with a `ChainScope` selecting finalised-only or full-chain search.
### Changed
- Finalised-state sync and the v1.1.0 -> v1.2.0 migration are substantially
  faster on large/mainnet caches. The txout-set accumulator is built in bulk at
  the tip instead of per block (removing an unbounded fan-out of random reads),
  block validation is off the write path, and the random-keyed `spent` /
  `txid_location` indexes are written in sorted batches — together removing the
  random-fault stall around sandblast height. See the `zaino-state` changelog for
  details; tune the write-batch size with `storage.database.sync_write_batch_bytes`.
- Finalised-state sync and version migrations are now background, non-blocking
  operations: large syncs and migrations run while an ephemeral passthrough
  serves finalised reads, so startup and serving are no longer blocked on
  persistence. Internally the finalised-state facade `ZainoDB` was renamed
  `FinalisedState` and its backing `DbBackend`/`db` module became
  `FinalisedSource`/`finalised_source` (now covering an ephemeral passthrough,
  not only databases). Bumps the finalised DB version to v1.2.1 (metadata-only).
- The `zainod` JSON-RPC server now refuses to bind to public or unspecified
  (`0.0.0.0` / `::`) addresses by default; `check_config` enforces the same
  private/loopback rule already applied to gRPC. The unencrypted JSON-RPC
  interface is intended for loopback or trusted private networks only (Z-02 /
  Zellic #48480).
- `get_address_utxos` now bounds the number of addresses fanned out per request,
  preventing an unbounded multi-address query from amplifying backend load
  (#974).
- Integration tests now use `corez`, with Zcash, Zebra, and Zingo dependencies
  updated to releases and companion branches that no longer depend on the
  yanked `core2` crate.
- Integration tests now follow the companion Zingo corez migration branches and
  use `zcash_client_backend` 0.22, with deprecated nullifier-range client calls
  allowed locally until they are replaced.
- `JsonRpSeeConnector::get_tree_state` now returns a `GetTreestateResponse`
  whose `sapling` and `orchard` fields are optional. In regtest mode, these
  fields may be omitted when the corresponding network upgrade activation
  height is not configured.
### Removed
### Deprecated
### Fixed
- Finalised-state DB v1.2.0 migration no longer appears to hang on large caches.
  A reverse transaction-id index (`txid_location`) makes previous-output
  resolution an O(log n) lookup instead of a full table scan, removing a
  near-quadratic cost in both the migration backfill and the clean-sync write
  path. The v1.1.0 -> v1.2.0 migration is now a re-entrant two-stage backfill
  with progress logging, and caches built by 0.4.0-alpha.1 self-heal on open.
- Nullifiers-only compact blocks (`compact_block_to_nullifiers`) no longer leak
  transparent `vin` / `vout`, restoring lightwalletd compact-block parity
  (#1067).

## [0.3.1] - 2026-05-25

Re-release of 0.3.0 to publish the `zainod` binary's container image under the
new `zainod` Docker Hub repository alongside the legacy `zaino` repository
(#1133, #1134). No functional changes to any crate since 0.3.0.

## [0.3.0] - 2026-05-22

### Added
- Transparent-address queries on the `zaino-state` `ChainIndex` trait —
  `get_address_balance`, `get_address_deltas`, `get_address_txids`,
  `get_address_utxos` (#1065) — plus block lookups (#1000) and subtree-root
  reporting (#853).
- `zaino-state` shared `CommonBackendConfig` payload carrying an
  `indexer_version` field, and a `DonationAddress` type (#1008).
- `zainodlib::config::ZainodConfig` gains an optional `donation_address` field;
  0.2.0 TOML configs continue to load (the field defaults to absent) (#1008).
- `z_validateaddress` JSON-RPC passthrough across `zaino-fetch` and the
  `zaino-serve` `ZcashIndexerRpc` trait, shipped pre-deprecated (#389).
- `zaino-common` `logging` module — the initial structured-logging surface for
  the Zaino crates (#888).
- `zaino-proto` Cargo features `heavy` (default) and `grpc_proxy_server`; build
  wiring moved to `tonic-prost` / `tonic-prost-build` 0.14.

### Changed
- **Breaking** — the `ChainIndex` (`zaino-state`) and `ZcashIndexerRpc`
  (`zaino-serve`) traits gain required methods with no default body, so
  downstream implementers must add them; adding `donation_address` to
  `ZainodConfig` is likewise breaking for struct-literal construction (#1008).
- `LightdInfo.version` now reports the running `zainod` binary version rather
  than the `zaino-state` library version (#1061).

### Fixed
- Restart path no longer crashes when the validator's readiness signal arrives
  before the indexer's status is observed (#962).

## [0.2.0] - 2026-03-25
- [808] Adopt lightclient-protocol v0.4.0

### Added
### Changed
- zaino-proto now references v0.4.0 files
- `zaino_fetch::jsonrpsee::response::ErrorsTimestamp` no longer supports a String
  variant.
### Removed

### Deprecated
- `zaino-fetch::chain:to_compact` in favor of `to_compact_tx` which takes an
  optional height and a `PoolTypeFilter` (see zaino-proto changes)
- `zaino_fetch::FullTransaction::to_compact` deprecated in favor of `to_compact_tx` which includes
  an optional for index to explicitly specify that the transaction is in the mempool and has no
  index and `Vec<PoolType>` to filter pool types according to the transparent data changes of
  lightclient-protocol v0.4.0
- `zaino_fetch::chain::Block::to_compact` deprecated in favor of `to_compact_block` allowing callers
  to specify `PoolTypeFilter` to filter pools that are included into the compact block according to
  lightclient-protocol v0.4.0
- `zaino_fetch::chain::Transaction::to_compact` deprecated in favor of `to_compact_tx` allowing callers
  to specify `PoolTypFilter` to filter pools that are included into the compact transaction according
  to lightclient-protocol v0.4.0.

---

This file tracks **Zaino workspace** releases only. Two related histories live
elsewhere:

- The lightwallet / `walletrpc` **protocol** changelog (proto-definition version
  history, v0.1.0 → v0.4.0) is at
  `packages/zaino-proto/lightwallet-protocol/CHANGELOG.md`.
- The `zaino-proto` **Rust crate** changelog is at
  `packages/zaino-proto/CHANGELOG.md`.
