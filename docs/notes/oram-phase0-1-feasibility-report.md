# ORAM Phase 0/1 feasibility report with Phase 2 offline evidence

- Date: 2026-07-13
- Evaluated branch: `feat/oram-stress-qualification`, stacked on
  `feat/oram-typed-qualification`; capture parent head `bd4554bf` has final
  native evidence in run `29224873175`, sizing code head `19392f36` has native
  evidence in run `29227379947` (job `86744258243`), and typed-qualification
  head `d65a999f` has native evidence in run `29244273040` (job
  `86797325618`). Exact-head native stress evidence remains pending.
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
corpus accounting, logical schedules, and a pinned upstream experiment. It does
not establish equal physical work, production encryption, durable ORAM state,
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
- separate pinned, volatile `rostl` tables for the exact 38-byte directory and
  82-byte event-page records. Their private offline Linux-x86_64 constructor
  creates distinct `CircuitORAM` and recursive-position-map instances and
  places the resulting exact two-table executor behind the business-command
  worker. The private offline owner consumes that constructor, but has no
  runtime or service caller;
- a path-scoped Ubuntu 24.04 x86_64 CI lane with immutable action pins that
  uses the repository's Rust 1.96.0 toolchain and cargo-nextest 0.9.140, runs
  locked strict all-feature/all-target Clippy, and executes the complete
  all-feature `zaino-oram` suite against the native `rostl` backend. The typed
  qualification slice extends that lane to the listener-free `zainod-oram`
  runner as well. Typed-qualification head `d65a999f` passed the 194-test
  `zaino-oram` and 29-test `zainod-oram` suites in native run
  `29244273040` (job `86797325618`); their Linux-only qualification tests
  exercised the real typed backend. Exact-head stress-slice evidence is still
  pending;
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

- `rostl` has executed only in small 8/16-entry table tests on a generic
  GitHub-hosted Ubuntu 24.04 x86_64 VM. That is not the intended CPU, TDX
  platform, release profile, capacity, or workload;
- the 72-byte record has not been benchmarked at mainnet capacity;
- no production privacy profile or accepted profile constants exist;
- no mainnet corpus report, TDX RSS result, latency result, stash result,
  target-load queue result, assembly result, or physical trace result exists.
  The fixed scenario's aggregate worker counters are correctness telemetry, not
  performance or physical-obliviousness evidence;
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
- no durable ORAM/checkpoint implementation, rollback defense, crash recovery,
  measured rebuild path, or recovery-time objective exists;
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
  fail-closed behavior. The private owner and coordinator now consume that
  constructor, but they are not connected to a durable checkpoint publisher,
  query engine, or service lifecycle;
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
| Full-capacity logical sizing | Partial pass | Version-2 reports bind compiled 38/82-byte cells to shared directory/event allocation validation, charge both full table and position-map domains, keep modeled bytes fixed across occupancy/growth, and expose load/admission/hot-address/modeled-memory flags plus explicit negative evidence markers. Offline `corpus size` consumes a complete validated capture, recomputes every row, and atomically binds measurement/model/result digests | Calibrate the actual ORAM tree, recursive maps, stash, allocator, initialization peak, and runtime working set on target hardware; select an accepted mainnet profile |
| Compiler pin | Pass | Repository pins Rust 1.96.0 | Pin release flags, LLVM behavior, and reproducible Linux build inputs |
| CPU/target/TDX pin | Partial target-class gate | An Ubuntu 24.04 x86_64 CI lane with immutable action pins executes the real adapter; the hosted image, CPU generation, TDX instance, firmware/TCB, DOIT, and memory remain unset | Select CPU generations, exact target/release flags, TDX instance, firmware/TCB policy, DOIT policy, and memory limit |
| Pinned ORAM dependency | Partial | `rostl` alpha9 at `8c3a12d2...` is in `Cargo.lock` | Resolve API/failure/recovery concerns and decide upstream, fork, or replacement |
| Dependency/license inventory | Blocked | Manifest declarations recorded below; `rostl` checkout has no root license text | Obtain authoritative license files/confirmation and complete automated transitive audit |
| Random full-map experiments | Missing (adjacent deterministic CI smoke only) | Fixed `SmokeV1` executes a 64-step mix of reads, unique appends, and exact replays across four modeled addresses with reference-model checks and aggregate digests. This small-table generic-host correctness scenario is neither random nor full-map load and is not a benchmark | Run mixed random reads/inserts at measured target capacity/load; avoid repeated key-zero microbenchmarks and keep the result schema separate from `SmokeV1` |
| Memory/RSS gate | Missing | Sizing code is a logical model only | Measure peak RSS on intended TDX hardware with at least 30% headroom and no host swapping |
| Latency/stash/queue gate | Missing | No target-hardware measurements | Record latency distribution, sustained QPS, stash pressure, queue depth, update contention, and failure behavior |
| Assembly/compiler-preservation experiment | Missing | No release assembly or instruction trace | Resolve the concern tracked by [`rostl` issue #8](https://github.com/obliviouslabs/rostl/issues/8) for the pinned binary/toolchain |
| Failure probability | Missing | No long-run or analytical bound | Address [`rostl` issue #24](https://github.com/obliviouslabs/rostl/issues/24) and document node-year risk |
| Typed capacity/stash/queue failure | Partial | Local validation is typed; the research worker has nonblocking bounded admission, a typed identifier-free `QueueFull`, no fallback, and terminal backend/panic latching. `SmokeV1` separately checks a healthy command rejection, then accepts a unique append that exceeds the per-address limit, returns `FailedClosed`, latches terminal state, and rejects two later commands at admission; it does not load the queue or observe a stash | Replace panic-based upstream boundaries, type stash exhaustion, and prove capacity/stash/queue behavior under native target load |
| Persistence/recovery/RTO | Blocked | Candidate adapter is deliberately volatile and is not an `ObliviousStore` backend | Design authenticated atomic persistence or measure a cold rebuild and publish an RTO |
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
| Checkpoint/replay/rebuild policy | Partial publication-last model | Opaque cursor candidates prevent forged/stale in-process commits; explicit network/schema/key targets distinguish finish, forward replay, and rebuild; failed replay/replacement leaves the old ready plaintext oracle usable. The coordinator assigns its cloned cursor/state checkpoint only after all synchronous event calls succeed, but the checkpoint has no authenticated root or durable/atomic coupling to sink state |
| Single mutation worker and backend telemetry | Partial typed integration | A portable std-thread worker exclusively owns the exact two-table executor, validates a 1..=4096 research queue bound before allocation, bounds accepted-not-started whole business commands with a `sync_channel`, drains FIFO admissions before shutdown/join, removes raw read/insert bypasses, and separates lifecycle from terminal fault health. Its identifier-free counters are internal and not approved for export. The private owner validates exact network/schema/key-epoch and admission compatibility before allocation, owns the coordinator plus worker, and joins it on consuming shutdown without exporting snapshots. Generic native Linux CI binds the real typed stores to that owner and completes the full three-block/seven-event lifecycle. There is no stash metric, runtime projection lifecycle, or fixed-cadence suppression policy |
| Volatile rebuild path | Partial pass | Fresh rebuild and clone-ready forward replay are deterministic in fixtures; no full-corpus runtime or RTO is measured |
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
| Persistent storage traffic and rollback | Must hide keys and detect stale/corrupt state | Authenticated atomic state and freshness/checkpoint policy | No persistence | Blocker |
| Denial of service, delay, drop, reordering | Out of scope for confidentiality | Detect integrity/freshness failures and fail closed; cannot prevent DoS | Research adapter has a local failed-closed latch only | Open integrity/recovery work |
| Power, thermal, frequency, speculative and undocumented CPU channels | Out of scope for first claim | State exclusion explicitly and avoid broader wording | Documented in plan/ADR | Must remain excluded |

## Toolchain, target, and dependency inventory

### Compiler and execution targets

| Item | Pin or observed value | Status |
|---|---|---|
| Zaino Rust toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)`, LLVM 22.1.2 | Pinned by `rust-toolchain.toml` |
| Local verification host | `aarch64-apple-darwin` | Portable/model tests only |
| Native CI verification host | Ubuntu 24.04, Linux kernel `6.17.0-1018-azure`, x86_64 | Generic hosted-runner execution only; not target CPU/TDX qualification |
| Canonical-toolchain targets | The local Rust 1.96.0 installation has `aarch64-apple-darwin`; the pinned CI toolchain executes natively on x86_64 Linux | Both portable local and generic native CI evidence recorded |
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
| `zainod-oram` | Local `0.1.0`, `publish = false` | Listener-free one-shot mainnet corpus capture plus fully offline logical sizing, both with atomic artifact publication | Workspace Apache-2.0 | Offline research only |
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

Commands below were run through 2026-07-13 against the evaluated worktree.

| Command | Result | Interpretation |
|---|---|---|
| `git merge-base HEAD upstream/dev` | `c94ae247de7286fd3337e313559bb3d62bdcbd5d` | Recorded upstream baseline |
| `rustc --version --verbose` | Rust 1.96.0, LLVM 22.1.2, `aarch64-apple-darwin` | Compiler/host pin confirmed |
| `rust-analyzer --version` | Rust Analyzer 1.96.0 (`ac68faa2`) | Installed from the pinned toolchain for semantic code intelligence |
| `cargo nextest --version` | `cargo-nextest 0.9.140` | Repository-native test runner installed for the single workspace |
| [`ORAM - Native Linux` run 29224873175, job 86736864252](https://github.com/sovright/zaino/actions/runs/29224873175/job/86736864252) environment | Ubuntu 24.04 x86_64, Rust 1.96.0, cargo-nextest 0.9.140; pass in 20m02s for capture parent head `bd4554bf` | Immutable action pins, locked dependency resolution, and exact tool versions establish a repeatable generic native CI gate; the hosted image is not a reproducible release, target-CPU, or TDX build |
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
| `cargo nextest run -p zaino-oram --all-features --status-level fail` | 201 passed locally on macOS aarch64 at the stress worktree | Adds the typed command-error seam, deterministic 64-step `SmokeV1` plan/reference/report validation, exact in-memory probe-set execution of both worker scenarios, healthy-rejection and terminal-fault semantics, and explicit negative-evidence checks. This host executes the typed-backend-unavailable branch; exact-head native execution is pending |
| `cargo nextest run -p zaino-state --features test_dependencies shadow_parity::tests::fixture_binds_ordinary_cases_to_the_exact_static_checkpoint --status-level fail` | 1 passed | The feature-gated ordinary fixture binds its full block prefix and address cases to immutable regtest-vector height/hash 200 |
| `cargo nextest run -p zaino-proto --test compact_tx_streamer_legacy_golden --status-level fail` | 1 passed | Pins the upstream-baseline legacy service name, ordered RPC surface, and normalized proto schema fingerprint |
| `cargo nextest run -p zainod-oram --status-level fail` | 24 passed | Nested capture/size CLI, synchronous offline sizing execution, paired checkpoint and snapshot selection, required model inputs, golden canonical model/qualification digests, dirfd-bound regular-file and byte-limit enforcement, exact three-file publication, atomic concurrent-output refusal, ambiguous-rename inode resolution, source lineage and typed tamper rejection, read-back validation, post-commit parent synchronization, and synchronized staging cleanup |
| `cargo nextest run -p zainod-oram --all-features --locked --no-tests fail --status-level fail` | 29 passed on native Ubuntu 24.04 x86_64 at `d65a999f`; run `29244273040`, job `86797325618` | Adds the fixed-only qualification CLI contract, typed report/provenance tamper rejection, exact three-file read-back publication, and a canonical qualification-artifact digest while the library qualification executes the real backend. This remains unsigned generic-host runner/artifact evidence |
| `cargo nextest run -p zainod-oram --all-features --status-level fail` | 39 passed locally on macOS aarch64 at the stress worktree | Adds the fixed-only `smoke-v1` CLI contract, distinct stress wrapper/provenance schemas, canonical digest, semantic/tamper/overclaim rejection, and fail-before-publication behavior. Supported-host exact publication and real-backend execution remain native-CI gates |
| `cargo +stable clippy -p zaino-oram --lib --no-default-features --features rostl-experimental --target x86_64-unknown-linux-gnu --no-deps -- -D warnings -D clippy::unwrap_used` | Pass with local Rust 1.96.1 | Compile-only precursor for the exact directory/event stores, fixed two-access insertion path, and private offline worker constructor; the exact pinned native CI run above supersedes its execution limitation |
| `cargo +stable check -p zaino-oram --all-targets --no-default-features --features rostl-experimental --target x86_64-unknown-linux-gnu` | Environment-blocked before local Linux test checking | The macOS host lacks `x86_64-linux-gnu-gcc`/`g++`, required by transitive native dev dependencies including `aws-lc-sys`, `lmdb-sys`, and `libzcash_script`; the pinned native CI run now covers this host limitation |
| `cargo +stable clippy -p zaino-oram --lib --all-features --target x86_64-unknown-linux-gnu --no-deps -- -D warnings -D clippy::unwrap_used` | Environment-blocked in local transitive native builds | Combined Linux `corpus-zaino` plus `rostl-experimental` checking requires the missing cross C/C++ toolchain for `aws-lc-sys`, `ring`, `lz4-sys`, `lmdb-sys`, and `libzcash_script`; pinned native CI now passes the stricter all-target equivalent |
| `cargo nextest run -p zaino-state transparent_events --no-default-features --status-level fail` | 4 passed | Event ordering, coinbase skip, script handling, overflow errors, and redaction |
| `cargo nextest run -p zaino-state --no-default-features --status-level fail` | 218 passed, 1 skipped | Process isolation avoids the tracing-subscriber collision seen under the legacy in-process runner; the complete no-default unit suite is green |
| `cargo clippy -p zaino-oram --all-targets --all-features --no-deps -- -D warnings -D clippy::unwrap_used` | Pass | Focused all-feature lint is warning-free and the affected crate has no disallowed `unwrap` use |
| `cargo clippy -p zaino-state --lib --features test_dependencies --no-deps -- -D warnings` | Pass | The feature-gated cross-crate fixture seam is warning-free without widening the normal production feature set |
| `cargo clippy -p zaino-state --lib --features test_dependencies --no-deps -- -D warnings -D clippy::unwrap_used` | Existing-tree failure | Reports four pre-existing production `unwrap` calls outside this slice (`node_backed_indexer.rs`, `finalised_state/entry.rs`, and `mempool.rs`); the changed production/test-support paths contain none |
| `cargo clippy -p zaino-proto --test compact_tx_streamer_legacy_golden -- -D warnings` | Pass | Legacy schema golden is warning-free |
| `cargo clippy -p zainod-oram --all-targets --no-deps -- -D warnings -D clippy::unwrap_used` | Pass | Capture runner and artifact publisher are warning-free and contain no production unwraps; unrelated workspace dependencies are excluded from this package-local lint |
| `cargo clippy -p zainod-oram --all-features --all-targets --no-deps -- -D warnings -D clippy::unwrap_used` | Pass | The default-off qualification CLI/artifact path is warning-free and contains no production unwraps on the portable host; native CI is required for the real backend branch |
| `cargo check --workspace --all-targets --no-default-features` | Pass | Every workspace member, including the new non-default runner, compiles without default features |
| `RUSTDOCFLAGS='-D warnings' cargo doc -p zaino-oram --no-deps --all-features` | Pass | The research models, shadow seam, and private worker document cleanly |
| `cargo fmt --all -- --check` | Pass | Rust formatting is clean |
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
the stress-slice total will be recorded only after its workflow completes.

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

## RSS, benchmark, stash, and queue blockers

No target hardware benchmark has been run. The fixed 64-step `SmokeV1` mixed
scenario is a deterministic CI correctness and failure-semantics exercise; it
does not satisfy the target-load/full-map experiment below. Required evidence
still includes:

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
into the worker. Its small 8/16-entry table functional tests pass on generic
Ubuntu 24.04 x86_64 CI. The private projection owner consumes that constructor,
but has no runtime/service caller. The
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

No implementation or measurement currently provides:

- authenticated atomic advancement of ORAM state and public checkpoint/root;
- rollback/freshness detection against a hostile host;
- crash/failpoint recovery at every mutation/checkpoint boundary;
- a durable external-memory backend;
- deterministic startup comparison with authoritative finalised state;
- a measured cold rebuild path and declared RTO;
- key rotation or migration recovery.

`catch_unwind` around an offline experiment is not a recovery protocol. Until
one of the persistence options in the delivery plan is implemented and tested,
the private endpoint must not exist, or must remain unready in a later offline
prototype.

## Work allowed under the NO-GO

The following work remains in scope because it reduces uncertainty without
exposing a private server:

1. execute `zainod-oram corpus capture` at an explicit public mainnet checkpoint
   and publish only its identifier-free, digest-bound artifact;
2. produce and review the full-mainnet distribution and calibrated sizing
   artifact;
3. extend the pinned generic Linux x86_64 CI gate into a reproducible release
   artifact and target-capacity run without calling that a privacy
   qualification;
4. select target CPU/TDX instances and measure random full-map performance,
   stash/queue behavior, RSS, swapping, and rebuild time;
5. extend the logical trace into release-binary source, allocator, physical
   storage, instruction/memory/page, and real transport-frame instrumentation;
6. design or obtain typed upstream failure/recovery behavior and an
   authenticated persistence/checkpoint protocol;
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
