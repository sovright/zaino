# ORAM Phase 0/1 feasibility report with Phase 2 offline evidence

- Date: 2026-07-14
- Evaluated recovery code head: `feat/oram-recovery-foundation` at
  `c53a06f18f37f83810ed68488b060f02e4fc85b8`, stacked on exact target-load
  head `79d54a0059a0daa6bb59cea945e8a1d0da6a84ed`.
  The target-load branch is itself stacked on exact full-map-saturation head
  `a169da2b6edfb44b87f5f66c0e1fcd93aa02514a`.
  The `SmokeV1` parent at `17356db0` passed strict all-target/all-feature Clippy
  for both research crates plus the 204-test `zaino-oram` and 39-test
  `zainod-oram` suites in native run `29250757780` (job `86818420630`).
- The load-foundation Rust source snapshot matched the dedicated GCP builder
  byte-for-byte and passed the same strict native gates: 204 `zaino-oram`
  tests and 44 `zainod-oram` tests. Exact source hashes are recorded below.
- The five Rust sources changed by the full-map-saturation slice also matched
  the dedicated builder byte-for-byte. Combined strict native Clippy passed;
  all 210 `zaino-oram` and 53 `zainod-oram` tests passed, including both real
  typed-backend boundary cases and the native three-file runner publication.
  Exact source hashes and nextest run IDs are recorded below.
- The recovery code head passed strict local feature-on/feature-off gates and
  234 portable tests. An exact detached copy on the dedicated GCP builder
  passed strict native Clippy, 244 tests including the Linux-only typed-ROSTL
  restart/rebuild path, and warning-denied rustdoc. Exact commands and the
  native nextest run ID are recorded below.
- Upstream baseline: [`zingolabs/zaino@c94ae247`](https://github.com/zingolabs/zaino/commit/c94ae247de7286fd3337e313559bb3d62bdcbd5d)
- Foundation commit: `bd601cf3028efc65a82484070f3d504af5107f4d`
- Design authority: [ADR-0007](../adr/0007-private-query-service-and-leakage-model.md)
- Delivery plan: [ORAM-enabled Zaino plan](oram-enabled-zaino-plan.md)
- Design seed: [TEE-backed Zaino/lightwalletd sketch](https://gist.github.com/zmanian/61f6b2b1afad08729356d5f226fdfbb3)

## Decision

**Current decision: NO-GO for private-server integration, deployment, or any
mainnet/host-oblivious privacy claim.**

**Offline research may continue** in the non-published `zaino-oram` package.
The implemented work is useful evidence for API shape, fixed records, aggregate
corpus accounting, logical schedules, bounded generic-builder measurement
plumbing, and an authenticated public projection-manifest/rebuild contract
around a pinned upstream experiment. It does not establish equal physical work,
production encryption, durable ORAM state, a measured recovery-time objective,
TDX isolation, attestation, wire-shape equivalence, or mainnet capacity.

This is a gate decision, not a conclusion that ORAM is infeasible. Server work
must remain closed until the Phase 0 blockers in this report have measured,
reviewable results and the decision is revisited.

## Evidence boundary

The evaluated worktree implements:

- the accepted threat model and dedicated-service decision in ADR-0007;
- a non-published `zaino-oram` research crate that is outside the workspace's
  default members;
- fixed transparent UTXO shapes and named persistence-boundary conversions;
- an exact 72-byte append-only `PersistentUtxoEvent` byte representation with
  named finalized create/spend constructors, storage-boundary state validation,
  and adjacent round-trip/rejection tests;
- exact immutable 38-byte `PersistentAddressDirectory` and 82-byte one-event
  `PersistentAddressEventPage` candidates that carry full address/directory and
  event-ordinal identity, require standard-address events, encode canonical
  dummies, use named persistence conversions, and satisfy `Pod`/`Cmov`;
- a private pure two-table layout model that derives golden
  network/schema-separated P2PKH/P2SH address keys, binds one secret seed and
  generation to both table geometries, produces distinct odd-step keyed probes
  over power-of-two capacities, scans complete const-generic observation
  arrays, validates collision placement and requested event ownership, and
  prepares opaque immutable inserts only after a clean full scan;
- a module-private synchronous two-table command core that validates the owned
  fake backends' public capacity shape before use, completes the directory plus
  every bounded event-ordinal scan on successful preflights, rejects
  noncontiguous histories, derives the next ordinal from owned-backend
  observations, obtains admission counts from those backends, and preflights
  both insertions before its first write;
- a portable bounded worker that moves that exact command core onto one thread,
  admits only whole history-read/append business commands, has no raw key or
  persistent-record surface, drains accepted FIFO work, and rejects commands
  that have not yet entered the executor without executor I/O after a terminal
  fault;
- compile-time `bytemuck::Pod` and `rostl_primitives::traits::Cmov` checks when
  `rostl-experimental` is enabled;
- fixed Rust envelope and result-page shapes plus a test-only compiled profile
  with a canonical 16-byte identifier derived from every authoritative budget
  dimension;
- a crate-internal versioned inner request/response codec that binds the
  compiled profile, direction, fixed public-chain/projection checkpoint,
  prepared query, optional fixed continuation field, session binding,
  protected outcome, `has_more`, and canonical fixed result slots. It uses
  checked layout arithmetic, rejects the former impossible 128-byte/two-slot
  codec shape, binds version/profile/session/direction as protection context,
  rejects one single-bit mutation at every nonce/body/tag byte offset with a
  non-cryptographic fixture, and pins exact 512-byte test-envelope digests;
- an allocation-free logical trace recorder bound to the only supported
  read-only unary query-store profile shape: configured sequential reads, zero
  query-store writes/allocations/source calls, one replay lookup and write-back,
  one request/response application envelope, fixed application bytes, one
  public completion shape, and a versioned ordered ten-phase runtime schedule;
- a bounded plaintext mock and equal complete modeled traces across selected
  hit, miss, filtered, full, cap-hit, early/late, invalid-domain, and
  injected-store-failure cases;
- a fixed 128-byte continuation-token format with injected protection and
  replay-guard interfaces whose associated data binds checkpoint and codec
  session, plus tamper, expiry, binding, reserved-byte, replay, and guard-failure
  tests;
- a module-private listener-free runtime adapter that acquires its clock and
  output nonces before any real token claim, performs one real-or-cover token
  open, replay access, and token issue per completed protected round after that
  material acquisition, scans every configured store slot, paginates by
  absolute store-slot ordinal, preserves absolute expiry, and protects semantic
  token failures as one
  fixed `InvalidContinuation` response after the complete modeled schedule when
  no higher-priority store or projection-readiness failure applies;
- a redacted transparent-event extraction seam from `IndexedBlock`;
- shared feature-gated address-history write/delete consumers of that seam,
  including legacy nonstandard-key preservation;
- a legacy `CompactTxStreamer` schema golden pinned to the upstream baseline's
  service name, ordered RPC signatures, and normalized proto fingerprint;
- an aggregate-only corpus measurement whose joint event/live/peak address-state
  histogram, derived marginals, and compiled record widths are independent of
  the separately applied two-table sizing model. The model shares layout
  capacity/admission validation, charges every allocated
  38/82-byte cell and both complete position-map domains, and reports separate
  directory, event, hot-address, modeled-memory, and combined modeled fit flags;
- a Zaino corpus adapter that validates a nonempty genesis-forward chain,
  contiguous heights, parent hashes, and the network-bound canonical genesis before
  emitting a public final checkpoint;
- one shared, staged canonical-chain cursor used by both corpus scanning and a
  plaintext offline finalized-projection oracle;
- a bounded fixture oracle that tracks every seen/live outpoint (including
  nonstandard outputs), appends standard-address create/spend events,
  reconstructs exact standard UTXOs, stages whole blocks before checkpoint
  publication, latches identifier-free failed-closed faults, and models fresh
  rebuild, forward replay, and network/schema/key/checkpoint reconciliation;
- a private generic finalized-event coordinator that reuses the same staged
  canonical validation, extraction, capacity, and plaintext spend-owner
  resolver, collects the complete ordered standard-event batch before its first
  sink call, and commits cloned state/cursor plus the in-memory checkpoint only
  after every synchronous sink append succeeds;
- a private `corpus-zaino` implementation of that sink boundary for the owning
  business-command worker. It derives the standard address through the existing
  business conversion, rejects nonstandard events before admission, submits a
  whole append command, consumes its reply before success, and coarsens worker
  outcomes to identifier-free sink failures;
- a crate-internal offline projection owner that rejects network, schema, key
  epoch, directory admission, event admission, and per-address event-bound
  mismatches before allocation; exclusively owns the coordinator and worker;
  exposes only coarse building/ready/failed-closed state and consuming shutdown;
  and never exposes a raw table handle or worker snapshot;
- a crate-internal fixed-width public projection manifest authenticated with a
  keyed BLAKE2s MAC. Immutable content-addressed publication binds monotonic
  sequence/predecessor digests, projection identity and per-rebuild epoch,
  finalized height/hash, event count, and a deterministic semantic event-log
  root. An injected external freshness witness advances the exact
  sequence/digest pair; `CURRENT` remains a non-authoritative hint;
- deterministic publication failpoints before/after the immutable-manifest,
  hint, and witness boundaries; strict restart classification rejects stale,
  corrupt, torn, or equivocating state, requires a fresh genesis-forward worker
  rebuild, and remains unready when freshness evidence is missing or invalid;
- a default-off static shadow fixture that compares that oracle with ordinary
  Zaino `BlockchainSource::get_address_utxos` results for every standard
  address observed through the same immutable regtest-vector tip, plus an
  absent address, with both sides bound to the identical height and hash;
- a non-published, listener-free `zainod-oram corpus capture` runner that binds
  the scanner to canonical mainnet genesis, uses one indexed non-finalized
  snapshot, optionally verifies an explicit public height/hash checkpoint,
  streams `IndexedBlock` values without retaining them, accepts no sizing
  input, and atomically publishes revalidated JSON, text, and minimal-provenance
  files into a new directory;
- a fully offline `zainod-oram corpus size` command that requires the complete
  validated capture directory plus eleven explicit model inputs, binds input
  reads to one directory handle, rejects symlink/non-regular or oversized
  entries, recomputes the qualification from the captured measurement, binds
  input/model/result digests and checkpoint provenance, and atomically
  publishes typed JSON, exact text, and provenance through one opened parent
  directory without loading config, contacting a node, or starting a listener;
- a read-only `corpus validate-sizing` command that reopens an existing sizing
  directory alongside its separately validated source capture, repeats bounded
  no-follow artifact validation, and requires exact source-bound recomputation
  before reporting the typed input digests and model table shape. It creates no
  artifact, accepts no runtime/workload tuning, and instantiates no ORAM
  backend, store, or worker;
- a listener-free typed-worker qualification entry point that executes one
  fixed nine-command scenario through the real Linux x86_64 worker: empty reads,
  three inserted events, one exact replay, independent histories, and clean
  shutdown. Its successful report contains only deterministic correctness
  totals and identifier-free aggregate queue/lifecycle/outcome counters;
- a default-off `typed-qualification` feature exposing
  `zainod-oram qualification run`. The command accepts only an output directory
  and atomically publishes the typed report as exactly three read-back-verified
  JSON, text, and digest-bound provenance files. It loads no node configuration,
  contacts no node, and starts no listener. The digest binds the compact typed
  JSON report into provenance; staged read-back separately checks the text
  rendering. The bundle is unsigned and self-reported;
- a separate fixed `SmokeV1` typed-worker stress qualification that executes a
  deterministic 64-step mix of reads, unique appends, and exact replays across
  four modeled addresses, checks every result against a bounded reference
  model, performs periodic and final sweeps, verifies a nonterminal
  cross-address command rejection, and uses a second constrained worker to
  check that an accepted second unique append exceeds the event limit, returns
  `FailedClosed`, and latches terminal state. One later read and append are
  rejected at admission, and shutdown returns the expected stopped, faulted
  snapshot. Its CLI accepts no numeric workload/backend knobs. Its distinct
  three-file artifact contains fixed public schema/profile/backend/shape
  metadata, aggregate counters/digests/flags/snapshots, and unsigned
  target-label provenance, with no raw modeled address/event/seed fields or
  per-operation results;
- a separate `FullMapSaturationV1` typed-worker qualification with independent
  workers for the directory-admission and event-admission boundaries. The
  directory case reaches 6/6 logical directory admission with 6/12 event
  admission; the event case reaches 12/12 logical event admission with 4/6
  directory admission. Each case verifies fixed-width histories, exact
  replays, absent reads, and a healthy cross-address rejection before the next
  append fails closed and latches terminal state. Its separate aggregate
  report records physical reserve and explicitly marks physical exhaustion,
  random/adversarial target load, performance, recovery, target hardware/TDX,
  and mainnet qualification absent;
- a separate source-bound `BuilderFoundationV1` typed-worker target-load
  foundation for generic Linux x86_64 builders. The runner reopens a complete
  capture and sizing bundle, requires exact source-bound sizing recomputation,
  and consumes that model's table capacities, admission limits, and per-address
  event bound only inside a fixed builder envelope: power-of-two directory
  capacity 64..=512 with admission at least 48, power-of-two event capacity
  128..=4096 with admission at least 96, 3..=64 events per address, four probes
  per table, and queue capacity one. Warmup reserves 16 directory and 48 event
  admission slots. Its deterministic shuffled measured phase executes exactly
  256 blocking commands: 160 hot reads, 48 reads from the resident non-hot
  warmup set (the fixed `cold` class), 32 unique hot appends, and 16 unique cold
  appends. It fills both logical admission limits,
  checks each result against a bounded reference model, and validates a logical
  occupied-probe collision schedule;
- target-load evidence fields for typed-worker call latency, nearest-rank
  percentiles, mixed-phase wall-clock completion rates, process-wide Linux
  `/proc/self/status` RSS samples plus process-lifetime `VmHWM`, and clean-shutdown aggregate
  queue/lifecycle counters. Queue contention is explicitly unmeasured, while
  stash current/peak state and physical access traces are explicitly
  `backend-unobservable`. The separate Linux-x86_64-only three-file artifact is
  unsigned and self-reported. Publication rejects output nested under either
  validated source and rebinds staged read-back to both inputs;
- separate pinned, volatile `rostl` tables for the exact 38-byte directory and
  82-byte event-page records. Their private offline Linux-x86_64 constructor
  creates distinct `CircuitORAM` and recursive-position-map instances and
  places the resulting exact two-table executor behind the business-command
  worker. The private offline owner consumes that constructor, but has no
  runtime or service caller;
- a path-scoped Ubuntu 24.04 x86_64 CI lane with immutable action pins that
  uses the repository's Rust 1.96.0 toolchain and cargo-nextest 0.9.140, runs
  locked strict all-feature/all-target Clippy, and executes the complete
  all-feature `zaino-oram` suite against the native `rostl` backend and the
  listener-free `zainod-oram` runner. Exact `SmokeV1` head `17356db0` passed the
  204-test `zaino-oram` and 39-test `zainod-oram` suites in native run
  `29250757780` (job `86818420630`); its Linux-only qualification tests
  exercised the real typed backend;
- a production-used portable unique-insert helper whose healthy missing and
  duplicate cases both perform read/remap followed by
  write-or-insert/remap. `Cmov` selects the candidate on a miss and the exact
  prior bytes on a duplicate; result disagreement, impossible occupancy, or a
  caught upstream panic terminal-latches the affected table;
- a bounded single-owner command worker that admits at most a fixed public queue
  depth in the research range 1..=4096 without fallback, owns the exclusive
  two-table executor, drains accepted FIFO work before shutdown/join, latches
  terminal executor faults and full-call panics, counts every unconsumed reply
  ticket in one aggregate, and additionally terminal-latches every append-ticket
  abandonment with the same coarse fault. A command already in flight when a
  late abandonment latches may finish its backend call, but its reply fails
  closed and later commands do not enter the executor.

The following statements are **not** established by that evidence:

- the previously reviewed native `rostl` evidence uses small 8/16-entry table
  tests on generic Ubuntu 24.04 x86_64. The target-load foundation permits only
  its bounded 64..=512 directory and 128..=4096 event builder envelope. Neither
  is the intended CPU, TDX platform, accepted release profile, full-mainnet
  capacity, or final workload;
- the 72-byte record has not been benchmarked at mainnet capacity;
- no production privacy profile or accepted profile constants exist;
- no mainnet corpus report, target-TDX RSS or latency result, stash result,
  target-load queue-contention result, assembly result, or physical trace result
  exists. `BuilderFoundationV1` measures process-wide RSS plus process-lifetime
  HWM, typed-worker call latency, mixed-phase completion rates, and lifecycle
  counters only on a generic builder;
  it exposes neither backend stash state nor physical accesses and is not
  target-hardware or physical-obliviousness evidence;
- the logical trace tests do not measure or prove equal instructions, branches,
  allocator activity, memory/page accesses, timing, transport frames, or
  packets;
- the continuation and inner-envelope protectors used by tests are not selected
  production AEADs. The inner-envelope protector is a non-cryptographic
  deterministic integrity fixture, and nonce generation has no production
  owner;
- codec/runtime tests prove exact/canonical bytes, protection-interface
  plumbing, and equality of a source-level logical decode/token/replay/
  full-store/issuance/encode phase schedule. They do not prove cryptographic
  authentication or equal instructions, branches, allocator activity,
  memory/page accesses, timing, transport frames, or packets. The runtime's
  clock, nonce source, replay guard, protectors, and store are research
  fixtures with no production lifecycle;
- no private protobuf, gRPC adapter, NFS merge, attestation provider, TLS
  identity, readiness path, or private-service lifecycle exists;
  `zainod-oram` contains only listener-free corpus capture, offline sizing, and
  the fixed typed-worker correctness qualification;
- no durable ORAM backend, production freshness-witness/key owner, atomic
  coupling between public publication and ROSTL buckets/position maps/stash,
  measured full-corpus rebuild path, or recovery-time objective exists. The
  public manifest foundation detects rollback/corruption only when its injected
  external witness and authentication key are correctly owned;
- the typed qualification neither persists worker state nor connects it to the
  logical private-query runtime, a network listener, mainnet data, or TDX. Its
  nine commands establish only deterministic typed-worker semantics; they do
  not establish latency, RSS, a physical access trace, crash consistency, or a
  host-oblivious service;
- the qualification artifact does not bind a source revision, lockfile,
  toolchain, binary, CI run, or execution attestation. Trusted CI provenance or
  a later signed/attested mechanism must establish those facts;
- the finalized-event coordinator's private sink seam is implemented by the
  business-command worker and a crate-internal offline owner composes them with
  the typed `rostl` constructor after exact identity/admission validation. A
  failure can leave a partial event prefix in the discarded sink candidate
  while the prior in-memory checkpoint remains unadvanced. There is no rollback
  or automatic retry, and no runtime or service calls the owner;
- the portable worker mechanics remain primarily covered by the deterministic
  fake-backed executor. Generic Linux CI additionally constructs the exact
  typed `rostl` stores, preserves directory/event duplicates without aliasing,
  exercises a full-store duplicate, runs append/read/shutdown through the real
  executor behind the business worker, and checks synthetic caught-panic
  fail-closed behavior. The private owner and coordinator can now consume an
  injected authenticated public-manifest publisher and exercise restart/rebuild
  in portable and Linux-gated tests, but no production key/witness owner,
  durable ROSTL state, query engine, or service lifecycle exists;
- worker queue depth is observable load leakage, caught panics still invoke the
  process-wide panic hook (including connector/backend, projection-sink, and
  discarded-sink destructor panics), so real panic payloads must be
  identifier-free and a controlled boundary is still missing. Candidate
  records are not zeroized, and a volatile mutation
  that fails before acknowledgement has no exactly-once retry claim;
  an unexpected outer worker-loop panic reports the active accepted command as
  indeterminate, forbids automatic retry, and requires volatile-state discard
  plus reconciliation or rebuild from an authoritative checkpoint;
- fixed-probe derivation and logical binding now have a portable synchronous
  connector plus a business-command worker. The private offline Linux-only
  constructor moves two separately constructed typed ORAM/map pairs into that
  worker, and generic native Linux CI executes its small 8/16-entry table
  tests. The private offline owner has no runtime caller, authenticated composite
  two-ORAM commit, crash-atomic commit, seed generation/persistence/rotation
  protocol, or selected production probe/load constants;
- full-capacity logical arithmetic now exists, but its flat position-map width
  and backend expansion are uncalibrated operator inputs. It does not model the
  pinned backend's tree blocks, recursive maps, stash, initialization
  temporaries, allocator/runtime working set, or measured RSS;
- the pure planner's vacancy witness and admission input remain caller-supplied
  model values; the connector obtains counts from its owned fake-backed table
  interfaces, but has no authenticated real-backend state. The injected probe
  seed and keyed-hash state are not zeroized or memory-locked;
- the pure model validates a requested directory key/physical slot and a
  requested event tuple/script owner, but the 38/82-byte records contain no MAC,
  generation tag, rollback defense, or full-content authentication. An unrelated
  event collision cannot be associated with its directory without additional
  protected reads or a wider authenticated record;
- const-generic full-array scans establish source-level logical work only, not
  equal instructions, branches, allocation, memory/page access, or timing;
- a canonical address-cell dummy is versioned `[1, 0, ...]`; an all-zero
  `Default`/`Zeroable` value is invalid scratch storage that may only be ignored
  after a definitive backend miss, never deserialized or preinserted; only a
  sparse-table miss is free, while a found canonical dummy is corruption;
- a healthy duplicate still physically remaps and rewrites through the pinned
  backend, but `Cmov` selection supplies the exact prior bytes, so the
  logical record and wrapper-owned occupancy are preserved. This fixed
  two-access property is covered portably against the production helper and is
  exercised against the Linux-native backend in generic CI. An indeterminate
  write still requires discard before reconciliation or rebuild.
  The direct table remains ready after a definite duplicate, while the enclosing
  executor treats any insertion error as terminal because preflight should have
  excluded that duplicate;
- terminal occupancy-invariant rejection may stop after the first read/remap;
  the equal two-access claim covers only healthy missing/duplicate insertion,
  not corrupt state or upstream failure behavior;
- the offline projection uses ordinary cloned Rust maps/vectors: it is not an
  ORAM, authenticated root, durable transaction, or allocator-failure boundary;
- `TransparentBlockEvent::Spent` carries only a previous outpoint, so the
  coordinator still relies on the plaintext live-output resolver to recover
  address/value ownership. A protected owner index or audited resolved
  finalization feed remains open;
- static fixture parity is not live-backend shadow parity, finalised-database
  parity, reorg/seam coverage, a source-call trace, or mainnet evidence;
- dependency licensing is not cleared for the intended distribution.

## Gate scorecard

### Phase 0 — feasibility

| Deliverable or gate | State | Evidence | Required before reconsideration |
|---|---|---|---|
| Recorded fork baseline | Pass | Branch merge-base is `c94ae247`; fork remote is `sovright/zaino` | Keep the baseline/current rebases recorded |
| Threat model and architecture ADR | Pass for research | ADR-0007 is accepted for the research fork | Security and client teams must still accept final constants and claim |
| Explicit leakage matrix | Draft in this report | Categories are enumerated below | Assign fixed budgets, owners, tests, and formal acceptance |
| Aggregate corpus implementation | Partial | Identifier-free measurement, mainnet-only capture runner, fixed indexed snapshot, explicit checkpoint verification, semantic and digest read-back validation, atomic three-file publication, nonempty fixture, same-block spend, standard/nonstandard accounting | Execute the runner and produce a reproducible full-mainnet artifact |
| Mainnet counts/distributions and growth | Missing | No mainnet output artifact exists | Measure distinct standard scripts, lifetime events, live/peak UTXOs, hot tails, script classes, record sizes, and selected growth horizon |
| Exact candidate record | Partial pass | 72-byte event, 38-byte directory, and 82-byte one-event page byte-array records; named conversions; canonical dummies; standard-event validation; `Pod`/`Cmov`; generic native Linux CI constructs separate real 38/82-byte backend monomorphizations and exercises both | Measure the target-capacity profile on the selected CPU/TDX platform |
| Fixed-probe table layout | Partial real integration | Canonical standard-address key vectors, one-generation keyed directory/event probes, power-of-two capacity/admission checks, full-array placement/duplicate/dummy/owner validation, opaque insert preparation, a complete bounded-history preflight, and a bounded worker with no raw storage bypass. A private offline owner validates exact projection/layout identity and admission limits before composing the coordinator and worker; generic native Linux CI runs 8/16-entry typed stores and the worker-owned exact executor | Add authenticated generation ownership and crash-safe commit/rebuild; select measured capacities/probe counts and trace the backend on target hardware |
| Full-capacity logical sizing | Partial pass | Version-2 reports bind compiled 38/82-byte cells to shared directory/event allocation validation, charge both full table and position-map domains, keep modeled bytes fixed across occupancy/growth, and expose load/admission/hot-address/modeled-memory flags plus explicit negative evidence markers. Offline `corpus size` consumes a complete validated capture, recomputes every row, and atomically binds measurement/model/result digests. Read-only `corpus validate-sizing` can reopen the existing bundles and require the same source-bound recomputation without emitting another artifact | Calibrate the actual ORAM tree, recursive maps, stash, allocator, initialization peak, and runtime working set on target hardware; select an accepted mainnet profile |
| Compiler pin | Pass | Repository pins Rust 1.96.0 | Pin release flags, LLVM behavior, and reproducible Linux build inputs |
| CPU/target/TDX pin | Partial target-class gate | An Ubuntu 24.04 x86_64 CI lane with immutable action pins executes the real adapter; the hosted image, CPU generation, TDX instance, firmware/TCB, DOIT, and memory remain unset | Select CPU generations, exact target/release flags, TDX instance, firmware/TCB policy, DOIT policy, and memory limit |
| Pinned ORAM dependency | Partial | `rostl` alpha9 at `8c3a12d2...` is in `Cargo.lock` | Resolve API/failure/recovery concerns and decide upstream, fork, or replacement |
| Dependency/license inventory | Blocked | Manifest declarations recorded below; `rostl` checkout has no root license text | Obtain authoritative license files/confirmation and complete automated transitive audit |
| Random full-map experiments | Partial builder foundation | Fixed `SmokeV1` covers a 64-step mixed workload, while separate `FullMapSaturationV1` workers exercise exact logical admission failures. Source-bound `BuilderFoundationV1` adds a deterministic shuffled 256-command hot/cold read/unique-append workload that fills both sizing-derived logical admission limits inside a fixed builder envelope and requires logical occupied-probe collisions. It is neither random/adversarial physical full-map load nor a long-run benchmark | Run mixed random reads/inserts and adversarial collisions at measured full-mainnet target capacity/load; keep that result schema separate from all deterministic profiles |
| Memory/RSS gate | Partial builder instrumentation; target gate missing | `BuilderFoundationV1` samples process-wide `VmRSS` before spawn, after spawn, after warmup, and after the measured phase, plus process-lifetime `VmHWM`, on Linux x86_64. The HWM includes driver/runtime memory predating the run. This is whole-process generic-builder evidence, not backend-only memory or intended-TDX headroom | Measure peak RSS, initialization pressure, page faults, and swapping on intended TDX hardware with at least 30% headroom |
| Latency/stash/queue gate | Partial builder instrumentation; target gate missing | `BuilderFoundationV1` records synchronous typed-worker call latency and mixed-phase wall-clock completion rates with a single caller and queue capacity one. Synthetic input preparation and verification are outside command latency but inside the phase wall; per-class rates are not isolated throughput. It also records clean-shutdown lifecycle/queue counters, while queue contention is unmeasured and stash/physical access is backend-unobservable | Record target-hardware latency distribution, sustained QPS, stash pressure, loaded queue depth, update contention, and failure behavior |
| Assembly/compiler-preservation experiment | Missing | No release assembly or instruction trace | Resolve the concern tracked by [`rostl` issue #8](https://github.com/obliviouslabs/rostl/issues/8) for the pinned binary/toolchain |
| Failure probability | Missing | No long-run or analytical bound | Address [`rostl` issue #24](https://github.com/obliviouslabs/rostl/issues/24) and document node-year risk |
| Typed capacity/stash/queue failure | Partial | Local validation is typed; the research worker has nonblocking bounded admission, a typed identifier-free `QueueFull`, no fallback, and terminal backend/panic latching. `SmokeV1` checks the per-address limit. Separate `FullMapSaturationV1` workers reach the directory and event admission bounds independently, fail closed on the next append, and latch terminal state. `BuilderFoundationV1` reaches both source-sized admission limits in one healthy run and requires a clean stopped snapshot, but its single caller does not load the queue and the backend exposes no stash telemetry | Replace panic-based upstream boundaries, type stash exhaustion, and prove capacity/stash/queue behavior under native target load |
| Persistence/recovery/RTO | Partial public-manifest foundation; production gate blocked | Fixed authenticated manifests, exact digest-bound external freshness transitions, deterministic crash-boundary tests, and fresh-worker genesis replay establish a fail-closed public publication/rebuild contract. The candidate ROSTL adapter remains volatile; no production witness/key owner, composite ORAM-state commit, full-corpus timing, or RTO exists | Wire production key/freshness ownership and either implement authenticated atomic ORAM persistence or measure a target-hardware cold rebuild and publish an accepted RTO |
| Go/no-go stakeholder acceptance | Missing | No accepted numeric profile or client contract | Security, operator, and client teams approve the exact leakage budget |

Phase 0 does not pass. Mainnet capacity, hardware memory, physical behavior,
recovery, and licensing are independent blockers; satisfying only one does not
open the server gate.

### Phase 1 — deterministic contract

| Deliverable or acceptance condition | State | Evidence or gap |
|---|---|---|
| Business and persistent records | Partial pass | Fixed UTXO and 72-byte event types exist with named conversions and adjacent tests; finalized create/spend states are enforced, and an in-memory offline checkpoint/projection model exists; persistent page/directory/checkpoint representations remain incomplete |
| Fixed envelope codec | Partial pass | A crate-internal versioned codec binds direction, derived profile ID, fixed checkpoint, prepared query, opaque optional token, session binding, outcome/`has_more`, and canonical fixed result slots inside one exact envelope. Version/profile/session/direction are explicit protection context. Checked arithmetic rejects undersized shapes; a non-cryptographic deterministic fixture rejects one single-bit mutation at every byte offset, reseals malformed plaintext to exercise protected canonical rejection, and pins exact request/response digests. All pre-runtime decode failures map to one external failure class. There is no production AEAD/nonce owner or protobuf framing |
| Compiled profile table | Partial pass | Test profiles derive their 16-byte ID from query-store reads, zero query-store writes/allocations/source calls, one replay lookup/write-back, one request/response application frame, fixed bytes, unary completion, response slots, cover rounds, runtime schedule version/count, and continuation lifetime; regression tests prove every selectable authoritative dimension changes the ID while the diagnostic label does not. Padded multi-input limits, NFS work, concurrency, and approved production profile entries are absent |
| Continuation tokens | Partial pass for the logical model | The fixed token is opened and semantically validated before engine use; full checkpoint plus codec-session bytes are protector context, cursors are bounded absolute store ordinals, expiry does not slide, and valid uses are atomically claimed through the injected guard. Invalid/expired/mismatched/replayed tokens become one protected all-dummy outcome after the same modeled schedule when no higher-priority store or projection-readiness failure applies. Initial/invalid paths write back to a dedicated non-durable cover slot without mutating the real-token namespace, and every completed protected round after server-material acquisition issues one real-or-cover token. No reviewed AEAD, trusted clock/nonce lifecycle, durable replay store, service integration, or instruction/memory/timing result exists |
| Deterministic mock store | Pass for logical modeling | Bounded plaintext mock rejects duplicate/out-of-range/capacity errors |
| Logical store trace | Pass for the offline model | Allocation-free recorder validates sequential query-store reads, zero query-store writes/allocations/source calls, one replay lookup/write-back, modeled application frames/bytes, completion, and the exact ordered ten-phase decode/token/replay/read/issue/encode schedule across secret and protected-error cases; NFS, physical, allocator, instruction, timing, and transport dimensions remain outside this evidence |
| Failure completion schedule | Partial pass | Every injected mock read failure still completes all configured logical reads; physical failure behavior is not equivalent or measured |
| Independent private proto | Missing | No `zainod-oram/proto` or `zaino.private.v1` generation exists |
| Private service adapter | Missing | A listener-free module-private runtime adapter exists, but no private proto, gRPC service, transport, or real outer-status equivalence test exists |
| Frame/byte/completion equivalence | Partial model | Every offline round models one fixed request and response application envelope, equal bytes, and unary completion; this is explicitly not protobuf, HTTP/2, TLS, packet-capture, or outer-status evidence |
| NFS/source-call equivalence | Partial model | The engine has no source dependency and validates zero query-derived source calls; no NFS scan or integrated validator/LMDB/raw-transaction instrumentation exists |
| Legacy golden/parity tests | Partial pass | A committed schema golden pins the upstream `CompactTxStreamer` service name, all 20 ordered RPC signatures, and normalized proto fingerprint; existing write/delete consumers retain nonstandard behavior; static ordinary-source versus offline-oracle UTXO parity is committed, while live direct/RPC and finalised-database parity remain open |
| Token fixed-work equivalence | Partial pass for logical schedule | Initial, valid, tampered, expired, query-mismatched, replayed, and guard-unavailable paths perform one modeled token open, replay lookup/write-back, complete store scan, token issue, response encode, fixed frames/bytes, and completion. This is not instruction/allocation/memory/page/timing or production-crypto equivalence |
| Test runtime discipline | Pass in this slice | Synchronous cases use `#[test]`; the shadow fixture's two tests alone use current-thread `#[tokio::test]` because they await the ordinary `BlockchainSource` query |

Phase 1 is a useful skeleton, not an accepted private contract.

### Phase 2 — offline projection and static shadow parity

| Deliverable or acceptance condition | State | Evidence or gap |
|---|---|---|
| Pinned real-ORAM adapter | Partial generic-native evidence | Separate volatile 38-byte directory and 82-byte event-page `rostl` tables execute on Ubuntu 24.04 x86_64 CI with immutable action pins and construct the exact worker-owned executor. Small 8/16-entry table tests cover duplicate preservation/non-aliasing, full-store duplicate access, worker append/read/shutdown, and synthetic caught-panic latching. This is not target hardware, load, physical-trace, or persistence evidence |
| Append-only event-page or audited upsert design | Partial typed connector | Exact immutable directory and one-event cells avoid tail-page/directory upsert; the keyed planner validates full probe sets, and a module-private synchronous connector scans every bounded ordinal, derives a contiguous next ordinal, reads owned-backend admission counts, and preflights a new directory plus event before writing. A bounded worker owns this core and exposes only whole business commands. The private offline owner composes its projection sink with the coordinator and typed `rostl` constructor. Authenticated contents, crash atomicity, target-load execution, and measured whole-history cost remain open |
| Deterministic finalized projection | Pass for fixtures | Genesis-forward `IndexedBlock` fixtures cover multiple outputs, repeated addresses, same-block and cross-block spends, empty results, nonstandard spend resolution, duplicate-after-spend rejection, and identical rebuild state. The coordinator emits the existing three-block fixture's exact seven standard events in extraction order and performs zero sink writes for its nonstandard-only final block |
| Staged mutation and fail-closed state | Pass for portable owner integration | Whole blocks apply to a cloned candidate before the first sink call; a late invalid event produces zero calls. A fake backend's sixth event insertion mutates then fails, drops both candidate tables exactly once, preserves only the prior height-0 cursor/checkpoint, rejects retry without later I/O, and shuts down failed closed. This is not backend rollback or block atomicity |
| Checkpoint/replay/rebuild policy | Partial authenticated public-manifest model | Opaque cursor candidates prevent forged/stale in-process commits; explicit network/schema/key targets distinguish finish, forward replay, and rebuild. A fixed authenticated manifest binds lineage, identity, per-rebuild epoch, finalized checkpoint, count, and semantic event-log root; an exact digest-bound external witness is freshness authority, while deterministic failpoints cover every publication boundary. The coordinator publishes after sink success and commits cloned in-memory state last. The manifest does not durably or atomically couple ROSTL buckets, position maps, stash, or read mutations |
| Single mutation worker and backend telemetry | Partial typed integration | A portable std-thread worker exclusively owns the exact two-table executor, validates a 1..=4096 research queue bound before allocation, bounds accepted-not-started whole business commands with a `sync_channel`, drains FIFO admissions before shutdown/join, removes raw read/insert bypasses, and separates lifecycle from terminal fault health. Its identifier-free counters are internal and not approved for export. The private owner validates exact network/schema/key-epoch and admission compatibility before allocation, owns the coordinator plus worker, and joins it on consuming shutdown without exporting snapshots. Generic native Linux CI binds the real typed stores to that owner and completes the full three-block/seven-event lifecycle. There is no stash metric, runtime projection lifecycle, or fixed-cadence suppression policy |
| Volatile rebuild path | Partial pass | Portable and Linux-x86_64-gated typed-worker tests shut down, classify the authenticated prior manifest, allocate a fresh worker under a new projection epoch, replay genesis-forward, and reproduce the same semantic event-log root/checkpoint while advancing publication lineage. No production owner, full-corpus runtime, target-hardware timing, or RTO is measured |
| Shadow comparison with ordinary Zaino | Pass for one static fixture checkpoint | A default-off test independently obtains ordinary UTXOs from `MockchainSource::get_address_utxos` over Zebra full blocks and projection UTXOs from `IndexedBlock` transparent events; it compares every standard address observed through immutable regtest-vector height 200 plus an absent address, at the same height/hash. Live direct/RPC, finalised-database, mainnet, and reorg shadow modes remain missing |
| Zero query-derived source calls | Pass for current type boundary | The query engine has no validator/LMDB/raw-transaction dependency; this is not yet an integrated readiness or call-trace result |
| Long-run failure bound | Missing | No target-load mixed-operation soak or node-year analysis exists |

Phase 2 now has a deterministic plaintext oracle, one static ordinary-source
parity result, a portable finalized-event/checkpoint ordering coordinator, a
private synchronous adapter from its sink seam to the business worker, and a
private offline owner that composes the typed volatile ORAM worker path after
exact configuration validation. There is no runtime ORAM-backed projection or
live shadow mode.

## Leakage matrix

This is the current working matrix. “Permitted” means intentionally public in
ADR-0007. “Must hide” means the value must not distinguish secret cases within
one accepted profile. Exact numeric budgets remain unset, so the matrix is not
yet stakeholder-approved.

| Host-visible surface or value | Classification | Intended rule | Current evidence | Current gate |
|---|---|---|---|---|
| Queried address/script | Must hide | Never appears outside the protected workload or in host-keyed storage access | Sensitive Rust `Debug` output is redacted; no private transport or TDX exists | Open |
| Queried txid/outpoint | Must hide | No logs, errors, source calls, tokens, or physical locations expose it | Event/corpus debug output is redacted; query service is absent | Open |
| Continuation cursor/query digest/nonce | Must hide | Fixed authenticated encryption and no visible remaining count | The listener-free runtime validates a fixed 128-byte token, uses bounded absolute store-slot cursors, preserves expiry, and keeps token/query/replay diagnostics redacted; protectors and replay storage remain injected test interfaces | Open: production crypto/key/nonce/replay lifecycle missing |
| Hit versus miss | Must hide | Same work, outer status, bytes, frames, and completion | Equal complete listener-free logical runtime traces, full store schedules, fixed application bytes/frames, and one protected response class are tested | Open: physical, transport, timing, and real outer-status equivalence missing |
| Invalid-domain versus valid query | Must hide after authenticated decode | Full profile work and protected outcome | Listener-free runtime tests complete the same ordered logical trace, full store schedule, fixed envelope bytes/frames, and protected outcome | Open: instruction/memory/timing and real wire/transport behavior not measured |
| Store failure versus ordinary outcome | Must hide per completed-query policy and fail readiness safely | Uniform outer behavior; detailed fault remains internal | Every mock failure ordinal completes the same modeled trace. The native backend has only coarse local fail-closed tests; its internal worker reply still distinguishes success, rejection, and failed-closed state and is not service-integrated | Open: target-load readiness and service-level equivalence missing |
| Exact result count | Must hide | Fixed response slots and encrypted dummy occupancy | The runtime always normalizes and protects the complete configured slot array and performs a real-or-cover token issue; deterministic fixtures canonically encode dummy/real occupancy | Open: no production encryption or transport/physical evidence |
| Last real page / `has_more` | Must hide | Fixed page and cover-round behavior | The listener-free runtime owns absolute store-slot pagination, preserves expiry, emits a fixed token only for `ResultBudgetExceeded`, and still issues/discards one cover token on terminal/error pages. Client cover-round execution is absent | Open |
| Client continuation count | Permitted only for weak profiles | Strong profile requires fixed cover rounds | No client or service exists | Unset budget |
| Logical ORAM key | Must hide | No query-derived host address or fallback | Mock receives the key; this is explicitly plaintext test code | Open |
| Physical ORAM location/path | Must hide | Secret cases must be indistinguishable under accepted trace test | Pinned adapter executes functionally on generic Linux x86_64 CI; no physical trace was captured | Open |
| Worker queue depth, in-flight state, and aggregate counters | Permitted operational load only | Fixed public capacity and fixed-schema aggregates; never identifiers, command/result kinds, hit/miss, or per-command timing | The internal snapshot separates queue/lifecycle, completion/failure, admission-rejection, and reply-delivery counters. They are identifier-free but are not approved for export; no fixed-cadence aggregation or suppression policy exists | Open: budget and fixed-interval export policy unset; no native-load trace |
| Address-directory lookup | Must hide | Directory and event-page lookup both protected | A module-private synchronous connector, bounded business-command worker, and private offline projection owner combine exact directory/page encodings, shared full-capacity sizing, keyed fixed-probe binding, and exact identity/admission validation; generic native CI executes the real typed stores and exact worker behind that boundary | Open: no runtime caller, content authentication, crash-safe commit, target-capacity run, or measured physical trace |
| Query-derived allocation | Must hide | Fixed allocation/work budget | Offline recorder validates zero explicit modeled query allocations | Open: allocator/page/instruction measurement absent |
| Validator, LMDB, raw-transaction, or backfill calls | Must hide | Zero private-keyed source calls after readiness | Engine has no source dependency and validates zero modeled source calls | Open: no integrated source instrumentation or readiness proof |
| NFS scan work | Must hide | Complete profile-fixed scan on every query | No NFS merge implementation | Open |
| Request/response application bytes | Fixed public class | Exactly the attested profile size | The listener-free profile/runtime trace binds equal fixed application-envelope bytes; the inner codec rejects undersized compiled shapes and emits one exact protected envelope in each direction | Open: no production AEAD, protobuf/TLS, transport trace, or packet capture |
| Frame count and completion shape | Fixed public class | Same across protected outcomes | Offline trace models one request, one response, and unary completion | Open: no network or outer-status evidence |
| Method class | Permitted only if contract exposes separate methods | Preferred single `QueryPage` hides it | No proto exists | Decision retained, unimplemented |
| Request arrival and connection duration | Permitted | Declared traffic-analysis leakage | No service exists | Not applicable yet |
| Client IP/network metadata | Permitted | Outside initial claim | No service exists | Not applicable yet |
| Service/schema/profile ID | Permitted | Bound into attestation and publicly versioned | The inner codec carries a fixed test-only format version and a canonical 16-byte ID derived from the complete logical budget; there is no approved profile table, private schema, or attestation | Open |
| Coarse network/chain epoch/height/hash/sync lag | Permitted | Public checkpoint and freshness policy | Corpus report plus offline oracle bind network, height/hash, schema, and key epoch with replay/rebuild decisions | Partial; authoritative live feed and serving policy absent |
| Database capacity and projected growth | Permitted | Aggregate only, never identifier-bearing | Aggregate report types and redacted debug exist | Partial; no mainnet artifact |
| Aggregate QPS/queue/health | Permitted within allowlist | No outcome/cardinality labels | An internal snapshot exists; no service metrics exporter or fixed-cadence aggregation/suppression policy exists | Open |
| Logs, errors, traces, metric labels | Must exclude private values/outcomes | Allowlisted aggregate/public fields only | New sensitive types use redacted debug; no end-to-end log audit | Open |
| CPU instructions/branches/timing | Must not distinguish secret cases above accepted threshold | Pinned release build, assembly review, classifier/trace gate | Not measured | Blocker |
| Page faults, memory addresses, allocations | Must not distinguish secret cases above accepted threshold | Release-binary physical trace gate | Not measured | Blocker |
| Persistent storage traffic and rollback | Must hide keys and detect stale/corrupt state | Authenticated atomic state and freshness/checkpoint policy | Public manifest integrity/freshness and volatile rebuild classification are modeled with an injected exact digest-bound witness; ORAM state and its traffic remain volatile/unqualified | Blocker |
| Denial of service, delay, drop, reordering | Out of scope for confidentiality | Detect integrity/freshness failures and fail closed; cannot prevent DoS | Research adapter has a local failed-closed latch only | Open integrity/recovery work |
| Power, thermal, frequency, speculative and undocumented CPU channels | Out of scope for first claim | State exclusion explicitly and avoid broader wording | Documented in plan/ADR | Must remain excluded |

## Toolchain, target, and dependency inventory

### Compiler and execution targets

| Item | Pin or observed value | Status |
|---|---|---|
| Zaino Rust toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)`, LLVM 22.1.2 | Pinned by `rust-toolchain.toml` |
| Local verification host | `aarch64-apple-darwin` | Portable/model tests only |
| Native CI verification host | Ubuntu 24.04, Linux kernel `6.17.0-1018-azure`, x86_64 | Generic hosted-runner execution only; not target CPU/TDX qualification |
| Dedicated native builder | GCP Ubuntu 24.04, Linux kernel `6.17.0-1020-gcp`, x86_64 Intel family 6/model 85 under KVM, 16 vCPU, 62 GiB RAM | Cache-preserving developer gate only; not an immutable CI image, target CPU, TDX instance, or attested build |
| Canonical-toolchain targets | The local Rust 1.96.0 installation has `aarch64-apple-darwin`; the pinned CI toolchain and dedicated builder execute natively on x86_64 Linux | Portable local, generic native CI, and dedicated native-builder evidence recorded separately |
| Auxiliary stable-toolchain targets | Rust 1.96.1 has `x86_64-unknown-linux-gnu` installed | Supported adapter path cross-checks, but does not execute |
| Candidate ORAM target | Linux x86_64, as enforced by the real adapter `cfg` | Target class executes in generic CI; intended CPU/TDX target remains unselected |
| CPU generation and feature policy | Not selected | Blocker |
| DOIT enablement/self-check policy | Not selected or tested | Blocker |
| TDX platform/instance/memory | Not selected | Blocker |
| Firmware, microcode, TCB and quote policy | Not selected | Blocker |
| Release flags and reproducible image | Not pinned | Blocker for assembly/attestation evidence |

Successful compilation of `rostl-experimental` on macOS aarch64 proves only
that the trait-level candidate and unsupported-platform stub compile. It does
not qualify the architecture's conditional-move implementation or exercise
`CircuitORAM`. The generic native CI run exercises `CircuitORAM` at small
8/16-entry table capacities, but does not qualify target-capacity physical
behavior, target CPU features, or TDX isolation.

### Dependencies and licensing

| Component | Exact selection | Role | Observed license evidence | Status |
|---|---|---|---|---|
| Zaino baseline | `c94ae247de7286fd3337e313559bb3d62bdcbd5d` | Authoritative fork base | Root Apache-2.0 license file | Recorded |
| `zaino-oram` | Local `0.1.0`, `publish = false` | Research model and candidate adapter | Workspace Apache-2.0 | Research only |
| `zainod-oram` | Local `0.1.0`, `publish = false` | Listener-free one-shot mainnet corpus capture and fully offline logical sizing with atomic artifact publication, plus read-only sizing-input validation | Workspace Apache-2.0 | Offline research only |
| `zaino-state` | Local/version `0.3.1`, optional, no default features | Indexed-block corpus adapter | Workspace Apache-2.0 | Enabled only by `corpus-zaino` |
| `bytemuck` | `1.25.1`, derive/min-const-generics | Exact `Pod` record proof | Manifest: `Zlib OR Apache-2.0 OR MIT` | No identified direct blocker |
| `bytemuck_derive` | `1.11.0` | Derive transitive | Manifest: `Zlib OR Apache-2.0 OR MIT` | No identified direct blocker |
| `rostl-oram` | `0.1.0-alpha9`, [`8c3a12d2...`](https://github.com/obliviouslabs/rostl/commit/8c3a12d2febf17b024f2e949428b3bc526d74172) | Volatile candidate Circuit ORAM | Workspace manifest: `MIT OR Apache-2.0`; no root `LICENSE`/`COPYING` file found in pinned checkout | Distribution blocker pending authoritative text/confirmation |
| `rostl-primitives` | Same alpha/version/commit | `Cmov` trait and primitives | Same inherited manifest declaration; same missing root license text | Distribution blocker |
| `rostl-sort` | Same alpha/version/commit, transitive | `rostl-oram` transitive | Same inherited manifest declaration; same missing root license text | Distribution blocker |
| `assume` | `0.5.0`, transitive | `rostl` primitive support | Manifest: `MIT OR Apache-2.0` | Include in final automated audit |
| `static_assertions` | `1.1.0`, transitive | `rostl` compile-time checks | Manifest: `MIT OR Apache-2.0` | Include in final automated audit |
| `rand` family | Direct optional `rand 0.9.4` plus locked transitives | Uniform experimental remap-position sampling and upstream randomness | `rand` manifest: `MIT OR Apache-2.0` | Entropy source remains subject to TDX review; full transitive audit still required |
| `rostl-datastructures` | Assessed at the same commit; not linked | Possible map layer | Same manifest family; macOS build is blocked by Linux-specific affinity code | Excluded from current dependency graph |
| [`oblivious_node`](https://github.com/obliviouslabs/oblivious_node/commit/d00718dfdfd38dd50ec2e315e35ab54f25cd5067) | Reference only | Architecture/TDX precedent | Not a dependency and not cleared for redistribution here | Do not copy or ship |
| TDX runtime and quote verifier | None selected | Attestation and TLS binding | No approved dependency inventory; the reference verifier boundary noted in the plan remains license-sensitive | Blocker before TDX integration |

The table is an engineering inventory, not legal advice. The final gate needs
an automated license/SBOM review of the exact release closure plus authoritative
license texts for git dependencies. A manifest string alone is insufficient for
the intended redistribution decision.

## Verification evidence

Commands below were run through 2026-07-13 against the evaluated worktree or
the explicitly named predecessor head.

| Command | Result | Interpretation |
|---|---|---|
| `git merge-base HEAD upstream/dev` | `c94ae247de7286fd3337e313559bb3d62bdcbd5d` | Recorded upstream baseline |
| `rustc --version --verbose` | Rust 1.96.0, LLVM 22.1.2, `aarch64-apple-darwin` | Compiler/host pin confirmed |
| `rust-analyzer --version` | Rust Analyzer 1.96.0 (`ac68faa2`) | Installed from the pinned toolchain for semantic code intelligence |
| `cargo nextest --version` | `cargo-nextest 0.9.140` | Repository-native test runner installed for the single workspace |
| [`ORAM - Native Linux` run 29224873175, job 86736864252](https://github.com/sovright/zaino/actions/runs/29224873175/job/86736864252) environment | Ubuntu 24.04 x86_64, Rust 1.96.0, cargo-nextest 0.9.140; pass in 20m02s for capture parent head `bd4554bf` | Immutable action pins, locked dependency resolution, and exact tool versions establish a repeatable generic native CI gate; the hosted image is not a reproducible release, target-CPU, or TDX build |
| Dedicated native builder environment | Ubuntu 24.04 x86_64, Linux `6.17.0-1020-gcp`, Intel family 6/model 85 under KVM, 16 vCPU/62 GiB, Rust 1.96.0, cargo-nextest 0.9.140 | Records the cache-preserving developer gate used for the load-foundation and full-map-saturation snapshots; it is neither GitHub CI nor release/TDX attestation evidence |
| `shasum -a 256 packages/zaino-oram/src/zaino_corpus.rs packages/zainod-oram/src/corpus_artifact.rs packages/zainod-oram/src/main.rs` | `faf8b488ca25234e9a803d955f751a821d639dca405cf7b80c8000c98e443fd9`, `5c2e9790e8905fef42cf0eb5df349515d147e8d234df0f83918d769c6b0ca12e`, `5edeba5532780a0660e2cd2641900dda8dd8fb56ad6c7b2b76a732eb8dc202c2` | The three changed Rust sources matched the builder byte-for-byte before the final native gates; later evidence-only edits do not alter them |
| `sha256sum packages/zaino-oram/src/{lib.rs,stress_qualification.rs,full_map_saturation.rs} packages/zainod-oram/src/{main.rs,full_map_saturation_artifact.rs}` | `4293c61182de046a78bfd8b7acbfc22267c4227bfda3c76ac7bf12d454ee3675`, `61a6adf1f585f9038b59f15bc28f7db51f6b971d23e009d9f0fab63aa6687fe9`, `1f923a323e9372d6eb1ec64939ea9b07673a47dab35709094387d07c4e4fe280`, `616b3144d3cdb01b040ef45574a6a517117c40517686186415c8047f82277915`, `8ced4a39f7cfcdbca80766224cb242035f1fb37299c1879b88cf4312c26fd760` | All five full-map-saturation Rust sources matched the builder byte-for-byte before the final native Clippy and nextest gates |
| `cargo clippy -p zaino-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass in capture-head native Linux CI | The complete capture-head all-feature/all-target ORAM graph is warning-free on the supported OS/architecture with the pinned compiler |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 161 passed, 0 skipped at capture parent head `bd4554bf` | Executes the complete generic Linux x86_64 suite, including the real typed-store projection-owner lifecycle and capture measurement model; this is functional small-table evidence, not a benchmark or hardware qualification |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 164 passed, 0 skipped at sizing code head `19392f36`; run `29227379947`, job `86744258243`, nextest run `47169b5c-3aff-46de-a237-a3300a726db1` | Executes the complete sizing-branch suite on Ubuntu 24.04.4 x86_64 with Rust 1.96.0 and cargo-nextest 0.9.140, including the real typed `rostl` stores. This remains functional small-table evidence, not mainnet, benchmark, TDX, capacity, or side-channel qualification |
| Native `cargo clippy -p zaino-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass at sizing code head `19392f36`; run `29227379947`, job `86744258243` | Warning-denied native Linux lint covers every sizing/corpus feature combination before the native tests |
| [`ORAM - Native Linux` run 29219929129](https://github.com/sovright/zaino/actions/runs/29219929129) | Historical parent evidence: 157 passed, 0 skipped at owner code head `d71a4031` | Records the first complete native projection-owner lifecycle before the capture slice |
| `rustup target list --installed` | Local pinned 1.96.0: `aarch64-apple-darwin` | Local target inventory only; the native CI evidence is recorded above |
| `rustup +stable target list --installed` | Includes `x86_64-unknown-linux-gnu`; stable is Rust 1.96.1 | Enables a compile-only supported-path check, not execution evidence |
| `cargo tree -p zaino-oram --features rostl-experimental --edges normal` | Resolved `rostl` alpha9 to pinned commit `8c3a12d2...` | Dependency pin confirmed |
| `cargo check -p zaino-oram --all-targets --no-default-features` | Pass | Portable research model compiles |
| `cargo check -p zaino-oram --all-targets --features corpus-zaino` | Pass | Optional Zaino corpus adapter compiles |
| `cargo check -p zaino-oram --lib --features shadow-parity` | Pass | The production library graph compiles without exposing the test fixture API; `cargo tree --edges normal` contains no `test_dependencies` feature |
| `cargo check -p zaino-oram --all-targets --features rostl-experimental` | Pass on macOS aarch64 | Exact record constraints, portable production insertion helper, and unsupported-target path compile; this local command does not execute the real ORAM path |
| `cargo nextest run -p zaino-oram --no-default-features --status-level fail` | 144 passed | Fixed models, integrated token/runtime semantics, protected inner-codec shape/canonicality, ordered complete logical traces, absolute-cursor pagination, exact records, keyed layout, full-capacity arithmetic, exclusive two-table preflight, and all business-command worker tests pass without optional features |
| `cargo nextest run -p zaino-oram --features corpus-zaino --status-level fail` | 194 passed | Adds canonical-cursor hardening, measured/sizing separation, deterministic measurement JSON and semantic rejection, source-bound sizing recomputation, corpus provenance/retry, deterministic projection/coordinator/owner coverage, exact seven-event sink ordering, failure/panic containment, projection-to-worker adapter tests, owner lifecycle/configuration/fail-closed cases, typed qualification, typed worker-error seam tests, and portable `SmokeV1` plan/report/negative-evidence plus exact in-memory worker/probe-set checks |
| `cargo nextest run -p zaino-oram --features rostl-experimental --status-level fail` | 150 passed | Adds directory/page `Pod`/`Cmov` semantics, power-of-two capacity rejection, equal healthy miss/duplicate two-access schedules against the production helper, found-parity/occupancy rejection, and exact typed unsupported-host construction rejection |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 194 passed on native Ubuntu 24.04 x86_64 at `d65a999f`; run `29244273040`, job `86797325618` | Combined inner codec/runtime, keyed layout, two-table command, structurally validated and source-bound sizing model/result serialization, ordered trace, exact record, token, corpus/provenance, offline projection/coordinator/owner, static ordinary-source shadow parity, business-command worker suite, portable typed-`rostl` suite, and the fixed qualification. Its Linux-only qualification test exercised the real backend. This is small-table generic-host correctness evidence, not target-load or hardware qualification |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 204 passed, 0 skipped on native Ubuntu 24.04 x86_64 at exact `SmokeV1` head `17356db0`; run `29250757780`, job `86818420630` | Adds the typed command-error seam, deterministic 64-step `SmokeV1` plan/reference/report validation, exact worker execution of both scenarios through the real typed backend, healthy-rejection and terminal-fault semantics, and explicit negative-evidence checks. This is small-table generic-host correctness evidence, not target-load, benchmark, hardware, or mainnet qualification |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 201 passed, 0 skipped locally on macOS aarch64 in the load-foundation worktree | Rechecks the complete portable model and the unsupported-host typed-backend branch after adding the consumed sizing-model accessors. The three additional real-backend tests remain Linux-only; this is not native backend evidence |
| `cargo nextest run -p zaino-state --features test_dependencies shadow_parity::tests::fixture_binds_ordinary_cases_to_the_exact_static_checkpoint --status-level fail` | 1 passed | The feature-gated ordinary fixture binds its full block prefix and address cases to immutable regtest-vector height/hash 200 |
| `cargo nextest run -p zaino-proto --test compact_tx_streamer_legacy_golden --status-level fail` | 1 passed | Pins the upstream-baseline legacy service name, ordered RPC surface, and normalized proto schema fingerprint |
| `cargo nextest run -p zainod-oram --locked --no-tests fail --status-level fail` | 29 passed, 0 skipped locally on macOS aarch64 in the load-foundation worktree | Adds the read-only `validate-sizing` CLI contract and dispatch, matched input loading, source-bound semantic recomputation, exact digest/model-shape reporting inputs, byte-for-byte input preservation, and on-disk schema/provenance/file-type/size/tamper rejection to the existing capture/size suite |
| `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 29 passed on native Ubuntu 24.04 x86_64 at `d65a999f`; run `29244273040`, job `86797325618` | Adds the fixed-only qualification CLI contract, typed report/provenance tamper rejection, exact three-file read-back publication, and a canonical qualification-artifact digest while the library qualification executes the real backend. This remains unsigned generic-host runner/artifact evidence |
| `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 39 passed, 0 skipped on native Ubuntu 24.04 x86_64 at exact `SmokeV1` head `17356db0`; run `29250757780`, job `86818420630` | Adds the fixed-only `smoke-v1` CLI contract, distinct stress wrapper/provenance schemas, canonical digest, semantic/tamper/overclaim rejection, fail-before-publication behavior, and supported-host publication while the library test exercises the real backend. This remains unsigned generic-host runner/artifact correctness evidence |
| `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 44 passed, 0 skipped locally on macOS aarch64 in the load-foundation worktree | Rechecks the complete capture, sizing, qualification, and `SmokeV1` runner/artifact surface with the new read-only sizing-input command. The typed backend remains unavailable on this host; the separate native-builder result is recorded below |
| `cargo clippy -p zaino-oram -p zainod-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass locally in the load-foundation worktree | Both changed crates and every feature/target surface are warning-free, and the changed production paths contain no disallowed `unwrap` |
| `cargo clippy -p zaino-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass in 2m44s on the dedicated native builder for the checksum-pinned load-foundation source | The complete all-feature/all-target library graph, including the real Linux backend, is warning-free with no disallowed production `unwrap`; this is a developer gate, not GitHub CI or attestation evidence |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 204 passed, 0 skipped on the dedicated native builder; nextest run `32ca6b43-652e-4f82-a902-5886ea6dfa73` | Executes the Linux-only real-backend tests with the consumed sizing-model accessors; the accessors add no tests, so the native total remains 204 |
| `cargo clippy -p zainod-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass in 1.10s on the warm dedicated native builder for the final checksum-pinned source | The new sizing loader, CLI consumer, strengthened read-only test, and every optional daemon surface are warning-free with no disallowed production `unwrap` |
| `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 44 passed, 0 skipped on the dedicated native builder; final nextest run `4edd5788-7950-4aa9-8891-2a2f9d6224e3` | Executes the full daemon artifact/runner suite plus the read-only sizing-input validation command on native Linux; this remains correctness evidence, not load, benchmark, mainnet, TDX, or side-channel qualification |
| `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 207 passed, 0 skipped locally on macOS aarch64 after the boundary-condition schema review; nextest run `a9529889-0814-417b-8ffa-90e1aa7de961` | Adds portable report/schema/negative-evidence validation and independent fake-backed directory/event admission-boundary execution. The real typed backend remains host-gated locally |
| `cargo nextest run -p zainod-oram --locked --no-tests fail --status-level fail` | 29 passed, 0 skipped locally on macOS aarch64; nextest run `b1c0beb7-2a36-437b-99c8-8834f245aa7d` | Rechecks the feature-off daemon surface; the new qualification remains default-off |
| `cargo check -p zainod-oram --features typed-qualification --tests --locked` | Pass locally on the final fixture | The complete feature-gated daemon production and test surface typechecks after binding the native-derived canonical digest |
| `cargo clippy -p zainod-oram --features typed-qualification --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass locally on the final fixture | The changed daemon surface is warning-free and contains no disallowed production `unwrap` |
| Local `cargo nextest run -p zainod-oram --all-features --locked full_map_saturation --no-tests fail --status-level fail` | Environment-blocked during final macOS arm64 linking before test execution | The local cache emitted stale/mixed native object warnings and undefined LLVM symbols; the exact checksum-matched clean Linux builder passed the focused 9-test and complete 53-test suites below |
| Native focused `cargo nextest run -p zaino-oram --all-features --locked full_map_saturation --no-tests fail --status-level fail` | 6 passed, 0 skipped; nextest run `23af3e69-3543-4d8f-9935-20d4a8d12132` | Executes both independent cases through the real typed `rostl` worker and revalidates the distinct report, exact occupancy/reserve, one-hot boundary conditions, aggregate digests, and negative evidence |
| Native focused `cargo nextest run -p zainod-oram --all-features --locked full_map_saturation --no-tests fail --status-level fail` | 9 passed, 0 skipped; nextest run `a70a270e-4e23-4895-aee4-f7351edea019` | Executes CLI dispatch plus canonical digest, tamper/overclaim rejection, provenance binding, exact three-file publication, staged read-back, and target gating |
| Native `cargo clippy -p zaino-oram -p zainod-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass in 2m12s on the exact checksum-matched full-map-saturation source | Both complete research crate surfaces are warning-free and contain no disallowed production `unwrap` |
| Native `cargo nextest run -p zaino-oram --all-features --locked --no-tests fail --status-level fail` | 210 passed, 0 skipped; nextest run `9373bae3-f743-4a56-b792-0d3ccc8d056b` | Rechecks the complete library suite and adds the Linux-only real-backend full-map-saturation runner. This is small-table deterministic correctness, not physical-capacity or target-load evidence |
| Native `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 53 passed, 0 skipped; nextest run `b4c22e6b-5f2c-4ae8-8dda-69201e256219` | Rechecks every daemon runner/artifact path, including native full-map publication and dispatch; the bundle remains unsigned and non-attested |
| Local `cargo nextest run -p zaino-oram --features corpus-zaino --status-level fail` at recovery code head `c53a06f1` | 234 passed, 0 skipped; nextest run `ae2fca52-788b-48e5-b69e-9823b10d84b6` | Covers fixed manifest encoding/MAC/freshness, crash-boundary failpoints, rollback/equivocation/corruption rejection, deterministic semantic roots, and portable fresh-worker restart/rebuild. This is not native ROSTL, full-corpus, or RTO evidence |
| Native `cargo clippy -p zaino-oram --features "corpus-zaino rostl-experimental" --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` at exact recovery code head `c53a06f1` | Pass on the dedicated generic Linux x86_64 builder with Rust 1.96.0 | Covers the complete changed library graph plus the real typed ROSTL path; this is a developer gate, not target-CPU, TDX, or attestation evidence |
| Native `cargo nextest run -p zaino-oram --features "corpus-zaino rostl-experimental" --locked --status-level fail` at exact recovery code head `c53a06f1` | 244 passed, 0 skipped; nextest run `ad8e8dda-6f63-4aba-8c66-7cc8313676ab` | Adds Linux-only typed-ROSTL shutdown, authenticated-manifest restart classification, fresh-worker genesis replay under a new projection epoch, and semantic-root/checkpoint equivalence. This is generic-host correctness, not durable ROSTL state or measured RTO evidence |
| Native `RUSTDOCFLAGS='-D warnings' cargo doc -p zaino-oram --features "corpus-zaino rostl-experimental" --no-deps --locked` at exact recovery code head `c53a06f1` | Pass on the dedicated generic Linux x86_64 builder | The recovery contract and feature-complete library documentation are warning-free |
| Native `zainod-oram qualification stress --profile full-map-saturation-v1 --output-dir <NEW_DIR>` | Pass; canonical wrapper BLAKE2s-256 `2dfbd24e45662e6f112ab7c738dd780c0916d253636a47b739e15425e0932854` | Publishes exactly `full-map-saturation.json`, `full-map-saturation.txt`, and digest-bound `provenance.json`; this synthetic artifact validates runner plumbing only and is not a benchmark or hardware/mainnet result |
| `cargo +stable clippy -p zaino-oram --lib --no-default-features --features rostl-experimental --target x86_64-unknown-linux-gnu --no-deps -- -D warnings -D clippy::unwrap_used` | Pass with local Rust 1.96.1 | Compile-only precursor for the exact directory/event stores, fixed two-access insertion path, and private offline worker constructor; the exact pinned native CI run above supersedes its execution limitation |
| `cargo +stable check -p zaino-oram --all-targets --no-default-features --features rostl-experimental --target x86_64-unknown-linux-gnu` | Environment-blocked before local Linux test checking | The macOS host lacks `x86_64-linux-gnu-gcc`/`g++`, required by transitive native dev dependencies including `aws-lc-sys`, `lmdb-sys`, and `libzcash_script`; the pinned native CI run now covers this host limitation |
| `cargo +stable clippy -p zaino-oram --lib --all-features --target x86_64-unknown-linux-gnu --no-deps -- -D warnings -D clippy::unwrap_used` | Environment-blocked in local transitive native builds | Combined Linux `corpus-zaino` plus `rostl-experimental` checking requires the missing cross C/C++ toolchain for `aws-lc-sys`, `ring`, `lz4-sys`, `lmdb-sys`, and `libzcash_script`; pinned native CI now passes the stricter all-target equivalent |
| `cargo nextest run -p zaino-state transparent_events --no-default-features --status-level fail` | 4 passed | Event ordering, coinbase skip, script handling, overflow errors, and redaction |
| `cargo nextest run -p zaino-state --no-default-features --status-level fail` | 218 passed, 1 skipped | Process isolation avoids the tracing-subscriber collision seen under the legacy in-process runner; the complete no-default unit suite is green |
| `cargo clippy -p zaino-oram --all-targets --all-features --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass at exact `SmokeV1` head `17356db0`; native run `29250757780`, job `86818420630` | Focused all-feature/all-target native lint is warning-free and the affected crate has no disallowed production `unwrap` use |
| `cargo clippy -p zaino-state --lib --features test_dependencies --no-deps -- -D warnings` | Pass | The feature-gated cross-crate fixture seam is warning-free without widening the normal production feature set |
| `cargo clippy -p zaino-state --lib --features test_dependencies --no-deps -- -D warnings -D clippy::unwrap_used` | Existing-tree failure | Reports four pre-existing production `unwrap` calls outside this slice (`node_backed_indexer.rs`, `finalised_state/entry.rs`, and `mempool.rs`); the changed production/test-support paths contain none |
| `cargo clippy -p zaino-proto --test compact_tx_streamer_legacy_golden -- -D warnings` | Pass | Legacy schema golden is warning-free |
| `cargo clippy -p zainod-oram --all-targets --no-deps -- -D warnings -D clippy::unwrap_used` | Pass | Capture runner and artifact publisher are warning-free and contain no production unwraps; unrelated workspace dependencies are excluded from this package-local lint |
| `cargo clippy -p zainod-oram --all-features --all-targets --no-deps --locked -- -D warnings -D clippy::unwrap_used` | Pass at exact `SmokeV1` head `17356db0`; native run `29250757780`, job `86818420630` | The default-off qualification CLI/artifact path is warning-free and contains no production unwraps in the native gate |
| `cargo check --workspace --all-targets --no-default-features --locked` | Pass locally in the full-map-saturation worktree | Every workspace member, including the new non-default runner, compiles without default features |
| `RUSTDOCFLAGS='-D warnings' cargo doc -p zaino-oram --no-deps --all-features` | Pass | The research models, shadow seam, and private worker document cleanly |
| `cargo fmt --all -- --check` | Pass | Rust formatting is clean |
| `rust-analyzer diagnostics .` | Exit 0; expected weak inactive-`cfg` diagnostics only on the changed surfaces | The single workspace resolves and analyzes the new profile/report/runner/artifact symbols; no semantic error is reported |
| Rust Analyzer semantic search of the concrete typed backend | Two `access_position`, one `read`, and one `write_or_insert` call site | The implementation has one independently remapped read path and one independently remapped write-or-insert path; the production helper invokes both for healthy miss and duplicate cases |
| Rust Analyzer references for projection `stage_block`, `commit_staged`, and sink `append_and_wait` | Stage and commit each have the plaintext-oracle and coordinator call sites; sink append-and-wait has one production coordinator call and a private `AtomicWorker` implementation | The coordinator reuses the existing staging/commit implementation, and the owning worker provides the only production sink adapter without exposing a raw handle |
| `git diff --check -- docs/notes/oram-phase0-1-feasibility-report.md` | Pass | Report has no whitespace errors |
| Exact `lint-boundary-conversions` task body from `tools/makefiles/lints.toml` | Pass; the `makers` wrapper is not installed locally | No forbidden persistence- or wire-boundary `From`/`TryFrom` implementation exists; CI should still run the canonical wrapper |

The five Linux-x86_64-only `#[test]` functions included in the 161-test
capture-head native run are
`exact_typed_stores_preserve_duplicate_values_and_do_not_alias`,
`full_store_duplicate_still_completes_both_accesses`,
`exact_typed_executor_runs_behind_the_business_worker`, and
`synthetic_caught_panic_latches_and_blocks_later_access`, and
`linux_rostl_owner_builds_finishes_and_shuts_down`. The two unsupported-host
constructor rejections that run on macOS are excluded on Linux, so that
capture-head native total was three higher than the 158-test macOS total at
the same capture head. The sizing code head adds three cross-platform tests and
its 164-test native total is reported separately in the table above. The later
typed-qualification head has the exact 194-test native total reported above;
exact `SmokeV1` head `17356db0` has its completed 204-test `zaino-oram` and
39-test `zainod-oram` native totals reported above. The load-foundation
worktree's local 201-test `zaino-oram`, 29-test default `zainod-oram`, and
44-test all-feature `zainod-oram` totals are reported separately. The
full-map-saturation worktree has 207 portable library tests and 29 default
daemon tests locally; its exact checksum-matched native-builder totals are 210
and 53. GitHub CI remains the merge gate and the builder run is not target-load
or attestation evidence.

Two broader `zaino-state` gates remain baseline-blocked outside this slice.
Warning-denied Clippy with `clippy::unwrap_used` reports four existing
production unwraps in `node_backed_indexer.rs`, `finalised_state/entry.rs`, and
`mempool.rs`. Warning-denied `zaino-state` rustdoc stops on two private
`OPERATIONAL_NFS_DEPTH` links and one stale `BlockCacheConfig` link. The
complete no-default `zaino-state` suite now passes under `cargo nextest`, and
warning-denied `zaino-oram` rustdoc passes with all features.

These are compile/unit-model results. They are not benchmark, mainnet, TDX,
network, recovery, or side-channel results.

## Mainnet corpus and capacity blocker

The scanner core now has useful safety properties: it requires a nonempty
height-zero start, validates the network-bound canonical genesis hash and null
genesis parent, checks contiguous heights and parent hashes, resolves spends
from a genesis-forward live-output map, and returns an aggregate measurement
bound to a public network/final height/hash checkpoint. Its returned measurement
retains no address, transaction, or outpoint identifiers. Growth, table,
backend-expansion, and memory assumptions are applied only after measurement and
can be changed without rescanning.

It is not yet a mainnet measurement:

- the public `ChainIndex::get_indexed_block_by_height` point source and
  `zainod-oram corpus capture` runner are implemented, including fixed-snapshot
  checkpoint verification and atomic read-back-verified publication, but the
  runner has not been executed against a full mainnet checkpoint and no output
  artifact exists;
- no mainnet checkpoint, counts, histogram, hot-address tail, or growth output
  is checked in or otherwise attached to this branch;
- exact identities are available only for standard P2PKH/P2SH scripts;
  nonstandard compact outputs are counted by class without inventing a false
  address identity;
- the separate sizing model charges every compiled 38-byte directory and
  82-byte event cell across the full configured table capacities plus both full
  position-map domains; projected occupancy affects only explicit
  load/admission/hot-address flags, never allocated bytes;
- the position-map entry width and backend expansion remain uncalibrated
  operator assumptions. The model does not calculate the pinned backend's
  actual tree blocks, recursive map levels, stash, initialization temporaries,
  allocator overhead, or runtime working set, and admission fit is not a bound
  on fixed-probe insertion success or collision probability;
- proportional growth currently multiplies address counts within existing
  histogram buckets; it does not forecast a worsening hot-address tail;
- no growth horizon or target TDX memory size has been approved.

Therefore `fits_modeled_memory` and `fits_modeled_constraints` are model results
only. Neither may be used as the 30%-RSS go/no-go result. Those projections are
not part of the captured measurement artifact; the offline `corpus size`
command recomputes them from explicit assumptions into a separate artifact.
No full-mainnet sizing artifact has been produced yet.
The load-foundation slice adds a read-only `corpus validate-sizing` command that
reopens and revalidates those existing capture and sizing inputs and requires
the same source-bound recomputation. It emits no additional artifact, accepts no
runtime or workload tuning, instantiates no ORAM backend, store, or worker, and
supplies no load measurement, performance result, hardware result, or mainnet
result.

## RSS, benchmark, stash, and queue blockers

No target hardware benchmark has been run. The fixed 64-step `SmokeV1` mixed
scenario and the independent `FullMapSaturationV1` logical admission-boundary
cases are deterministic correctness and failure-semantics exercises. The latter
retains physical capacity in both tables.

`BuilderFoundationV1` is the next bounded measurement foundation. It consumes
the separately validated capture and sizing artifacts rather than accepting
capacity or workload knobs at the command line. Within its fixed builder
envelope, warmup stops 16 directory slots and 48 event slots below the supplied
admission limits. The measured phase then shuffles exactly 160 hot reads, 48
reads from the resident non-hot warmup set (the fixed `cold` class), 32 unique
hot appends, and 16 unique cold appends; those 256
commands fill both logical admission limits. The report binds the source
digests and deterministic schedule/final-state digests, checks a logical
occupied-probe collision schedule, measures synchronous typed-worker call
latency and mixed-phase wall-clock completion rates, samples whole-process RSS
and process-lifetime HWM, and
requires clean aggregate shutdown counters. Because the current backend does
not expose them, stash current/peak state and physical access traces are
reported as `backend-unobservable`; the single-caller run also makes no queue
contention claim.

The exact listener-free invocation is:

```text
zainod-oram qualification target-load \
  --profile builder-foundation-v1 \
  --capture-dir <CAPTURE_DIR> \
  --sizing-dir <SIZING_DIR> \
  --output-dir <NEW_DIR>
```

The command publishes only on Linux x86_64. A successful run on the dedicated
GCP/Linux builder remains generic-builder, single-caller research evidence. It
does not establish target CPU/TDX behavior, full-mainnet capacity, durable
persistence/recovery, a `10^9`-operation failure bound, signed or attested
execution, backend physical-obliviousness, or mainnet readiness. Required
evidence still includes:

1. a full mainnet build at an explicit public checkpoint and growth horizon;
2. random full-map mixed reads/inserts, adversarial collision patterns, and
   realistic update/query interleaving;
3. p50/p95/p99/p999 latency, throughput, queueing, and update contention;
4. peak RSS, allocator overhead, page-fault behavior, and confirmation of no
   host swapping on the intended TDX instance;
5. at least 30% measured RSS headroom at target capacity;
6. stash and position-map pressure plus typed capacity/queue/stash failures;
7. long-run failure evidence and a documented probability bound rather than an
   assumption.

The typed `rostl` tables and business-command worker remain intentionally
unsuitable for such a claim. The stores are volatile, do not implement the
engine's `ObliviousStore`, expose no upstream stash metric, and have not run on
the intended target. The private offline Linux constructor creates separate
exact directory/event ORAM and position-map instances and moves their executor
into the worker. Prior functional tests cover small 8/16-entry tables on
generic Ubuntu 24.04 x86_64; the bounded builder profile does not change that
host qualification boundary. The private projection owner consumes that
constructor, but has no runtime/service caller. The
tables, synchronous executor, and outer worker boundary catch panics and latch
coarse failed-closed state, but Rust's process-wide panic hook still runs and
this is not recovery. Upstream open work includes Circuit ORAM stash recovery
([#13](https://github.com/obliviouslabs/rostl/issues/13)) and map queue recovery
([#32](https://github.com/obliviouslabs/rostl/issues/32)).

## Assembly and trace blocker

No release-binary assembly or physical trace experiment exists. Before a
privacy claim, the exact Linux x86_64 release artifact must be examined under
the pinned compiler and target CPU policy for contrasting secret cases. At
minimum, record and compare:

- relevant instructions and secret-dependent branches;
- memory addresses, page accesses/page faults, and allocations;
- ORAM physical storage paths and operation counts;
- wall-clock distributions under controlled load;
- application frames, bytes, completion shape, logs, and metric output;
- DOIT state and results on every supported CPU generation.

This work must explicitly address the compiler-preservation concern in
[`rostl` issue #8](https://github.com/obliviouslabs/rostl/issues/8). TDX
attestation would bind a binary and configuration; it would not prove that the
binary is semantically oblivious.

## Persistence, recovery, and rollback blocker

The selected upstream experiment has no production persistence contract for
the Circuit ORAM state used here. Reads mutate the ORAM, so data buckets,
position maps, stash state, key epoch, and checkpoint publication cannot be
snapshotted independently without risking corruption or stale mappings.

The recovery foundation now implements the public-manifest half of the
contract. A fixed manifest is authenticated with a keyed MAC and stored as an
immutable content-addressed file; it binds its predecessor, a monotonic
publication sequence, network/schema/key identity, a per-rebuild projection
epoch, finalized height/hash, event count, and a deterministic semantic
event-log root. An injected external witness compares and advances the exact
sequence/digest pair. The `CURRENT` file is only an atomic repairable hint and
is never freshness authority. Four deterministic failpoints exercise crashes
before immutable commit, after immutable commit, after the hint, and after the
witness. Restart loads only the witness-selected authenticated manifest and
then requires a fresh worker to replay the public stream from genesis under a
new projection epoch; missing, stale, corrupt, torn, or equivocating evidence
stays unready. Tests cover portable fake workers and the Linux-x86_64 typed
ROSTL path.

This does not make the ORAM durable. No implementation or measurement currently
provides:

- authenticated atomic advancement of ROSTL data buckets, position maps,
  stash, query-induced mutations, and the public manifest as one transaction;
- production ownership, rollback guarantees, provisioning, or rotation for the
  manifest authentication key and external freshness witness;
- a durable external-memory backend or resumable ROSTL worker;
- integration with authoritative live finalised state or a service readiness
  lifecycle;
- a full-corpus target-hardware cold-rebuild measurement and declared RTO;
- key-rotation or schema-migration recovery; or
- recovery-directory hardening beyond the current trusted, exclusive-writer
  boundary and final-component file/directory checks.

`catch_unwind` plus a public manifest is not a durable ORAM recovery protocol.
Until one of the persistence options in the delivery plan is implemented and
tested—or a measured cold rebuild meets the accepted RTO—the private endpoint
must not exist, or must remain unready in a later offline prototype.

## Work allowed under the NO-GO

The following work remains in scope because it reduces uncertainty without
exposing a private server:

1. execute `zainod-oram corpus capture` at an explicit public mainnet checkpoint
   and publish only its identifier-free, digest-bound artifact;
2. produce and review the full-mainnet distribution and calibrated sizing
   artifact;
3. execute the fixed source-bound `BuilderFoundationV1` profile on the generic
   Linux x86_64 builder, retain its three-file artifact, and extend that gate
   toward a reproducible release artifact without calling either result a
   target-hardware or privacy qualification;
4. select target CPU/TDX instances and measure random full-map performance,
   stash/queue behavior, RSS, swapping, and rebuild time;
5. extend the logical trace into release-binary source, allocator, physical
   storage, instruction/memory/page, and real transport-frame instrumentation;
6. implement production key/freshness-witness ownership and either obtain typed
   durable upstream recovery behavior or qualify the authenticated
   genesis-forward rebuild protocol against a declared target-hardware RTO;
7. resolve git-dependency and TDX/verifier licensing with an exact SBOM;
8. extend the completed logical token/runtime phase model into private schema,
   real source/NFS, transport, allocator, instruction/memory/page, timing, and
   outer-status evidence without opening a production listener prematurely;
   retain the legacy schema golden;
9. obtain independent security review of the evidence and then revisit this
   decision.

## Conditions to change the decision

Changing from NO-GO requires all of the following, not a subset:

- a reproducible full-mainnet aggregate report at a public checkpoint;
- approved growth and profile constants derived from that report;
- measured target-TDX capacity with at least 30% RSS headroom and no swapping;
- target-load latency/stash/queue/failure results with typed fail-closed
  behavior;
- reviewed assembly and physical trace evidence for the pinned release binary;
- a credible authenticated persistence/recovery design and measured RTO;
- resolved licenses for the exact distribution closure;
- an accepted leakage matrix and client cover-round contract;
- completion of the Phase 1 fixed-work/wire/source/legacy parity evidence; and
- a written review that explicitly authorizes the next integration phase.

Until then, the accurate description is: **experimental offline ORAM research
for a possible Zaino private-query subsystem**.
