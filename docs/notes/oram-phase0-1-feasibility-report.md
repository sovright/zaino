# ORAM Phase 0/1 feasibility report

- Date: 2026-07-12
- Branch: `feat/oram-private-foundation`
- Upstream baseline: [`zingolabs/zaino@c94ae247`](https://github.com/zingolabs/zaino/commit/c94ae247de7286fd3337e313559bb3d62bdcbd5d)
- Foundation commit: `6bf50bdaada0491b423d999b4911cd5900c28d9a`
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
- compile-time `bytemuck::Pod` and `rostl_primitives::traits::Cmov` checks when
  `rostl-experimental` is enabled;
- fixed Rust envelope and result-page shapes plus a test-only compiled profile;
- an allocation-free logical trace recorder bound to the only supported
  read-only unary profile shape: configured sequential reads, zero modeled
  writes/allocations/source calls, one request/response application envelope,
  fixed application bytes, and one public completion shape;
- a bounded plaintext mock and equal complete modeled traces across selected
  hit, miss, filtered, full, cap-hit, early/late, invalid-domain, and
  injected-store-failure cases;
- a fixed 128-byte continuation-token format with injected protection and
  replay-guard interfaces, plus tamper, expiry, binding, reserved-byte, replay,
  and guard-failure tests;
- a redacted transparent-event extraction seam from `IndexedBlock`;
- shared feature-gated address-history write/delete consumers of that seam,
  including legacy nonstandard-key preservation;
- a legacy `CompactTxStreamer` schema golden pinned to the upstream baseline's
  service name, ordered RPC signatures, and normalized proto fingerprint;
- an aggregate-only corpus accumulator and sizing model;
- a Zaino corpus adapter that validates a nonempty genesis-forward chain,
  contiguous heights, parent hashes, and the network-bound canonical genesis before
  emitting a public final checkpoint;
- a non-published, listener-free `zainod-oram corpus` runner that binds the
  scanner to canonical mainnet genesis, captures a fixed public tip, streams
  `IndexedBlock` values without retaining them, and requires every sizing input;
- a pinned, volatile `rostl` candidate adapter that is compiled only into real
  operations on Linux x86_64 and returns `UnsupportedPlatform` elsewhere.

The following statements are **not** established by that evidence:

- `rostl` has not been executed here on Linux x86_64; the current host runs only
  the unsupported-platform path;
- the 72-byte record has not been benchmarked at mainnet capacity;
- no production privacy profile or accepted profile constants exist;
- no mainnet corpus report, TDX RSS result, latency result, stash result, queue
  result, assembly result, or physical trace result exists;
- the logical trace tests do not measure or prove equal instructions, branches,
  allocator activity, memory/page accesses, timing, transport frames, or
  packets;
- the continuation protector used by tests is not a selected production AEAD;
- no private protobuf, gRPC adapter, NFS merge, attestation provider, TLS
  identity, readiness path, or private-service lifecycle exists;
  `zainod-oram` currently contains only the offline corpus runner;
- no durable ORAM/checkpoint implementation, rollback defense, crash recovery,
  measured rebuild path, or recovery-time objective exists;
- dependency licensing is not cleared for the intended distribution.

## Gate scorecard

### Phase 0 — feasibility

| Deliverable or gate | State | Evidence | Required before reconsideration |
|---|---|---|---|
| Recorded fork baseline | Pass | Branch merge-base is `c94ae247`; fork remote is `sovright/zaino` | Keep the baseline/current rebases recorded |
| Threat model and architecture ADR | Pass for research | ADR-0007 is accepted for the research fork | Security and client teams must still accept final constants and claim |
| Explicit leakage matrix | Draft in this report | Categories are enumerated below | Assign fixed budgets, owners, tests, and formal acceptance |
| Aggregate corpus implementation | Partial | Identifier-free accumulator, mainnet-only one-shot runner, provenance validation, nonempty fixture, same-block spend, standard/nonstandard accounting | Execute the runner and produce a reproducible full-mainnet report |
| Mainnet counts/distributions and growth | Missing | No mainnet output artifact exists | Measure distinct standard scripts, lifetime events, live/peak UTXOs, hot tails, script classes, record sizes, and selected growth horizon |
| Exact candidate record | Partial pass | 72-byte byte-array record; named conversions; `Pod`/`Cmov` compile-time test | Exercise it through actual pinned ORAM operations on Linux x86_64 and review semantics |
| Compiler pin | Pass | Repository pins Rust 1.96.0 | Pin release flags, LLVM behavior, and reproducible Linux build inputs |
| CPU/target/TDX pin | Missing | Code gates real adapter operations to Linux x86_64; only macOS aarch64 is installed locally | Select CPU generations, target triple, TDX instance, firmware/TCB policy, DOIT policy, and memory limit |
| Pinned ORAM dependency | Partial | `rostl` alpha9 at `8c3a12d2...` is in `Cargo.lock` | Resolve API/failure/recovery concerns and decide upstream, fork, or replacement |
| Dependency/license inventory | Blocked | Manifest declarations recorded below; `rostl` checkout has no root license text | Obtain authoritative license files/confirmation and complete automated transitive audit |
| Random full-map experiments | Missing | No benchmark or result artifact | Run mixed random reads/inserts at target load; avoid repeated key-zero microbenchmarks |
| Memory/RSS gate | Missing | Sizing code is a logical model only | Measure peak RSS on intended TDX hardware with at least 30% headroom and no host swapping |
| Latency/stash/queue gate | Missing | No target-hardware measurements | Record latency distribution, sustained QPS, stash pressure, queue depth, update contention, and failure behavior |
| Assembly/compiler-preservation experiment | Missing | No release assembly or instruction trace | Resolve the concern tracked by [`rostl` issue #8](https://github.com/obliviouslabs/rostl/issues/8) for the pinned binary/toolchain |
| Failure probability | Missing | No long-run or analytical bound | Address [`rostl` issue #24](https://github.com/obliviouslabs/rostl/issues/24) and document node-year risk |
| Typed capacity/stash/queue failure | Partial | Local validation is typed; upstream panics are caught by the research adapter and latch a failed-closed state | Replace panic-based upstream boundaries, type stash/queue exhaustion, and prove no leaky fallback |
| Persistence/recovery/RTO | Blocked | Candidate adapter is deliberately volatile and is not an `ObliviousStore` backend | Design authenticated atomic persistence or measure a cold rebuild and publish an RTO |
| Go/no-go stakeholder acceptance | Missing | No accepted numeric profile or client contract | Security, operator, and client teams approve the exact leakage budget |

Phase 0 does not pass. Mainnet capacity, hardware memory, physical behavior,
recovery, and licensing are independent blockers; satisfying only one does not
open the server gate.

### Phase 1 — deterministic contract

| Deliverable or acceptance condition | State | Evidence or gap |
|---|---|---|
| Business and persistent records | Partial pass | Fixed UTXO and 72-byte event types exist with named conversions and adjacent tests; finalized create/spend state combinations are enforced at construction and persistent decode, while projection/page/directory/checkpoint types remain incomplete |
| Fixed envelope codec | Partial | Exact Rust byte-array length is tested; there is no encrypted inner codec or protobuf framing |
| Compiled profile table | Partial pass | Test profile binds reads, zero logical writes/allocations/source calls, one request/response application frame, fixed bytes, unary completion, response slots, envelope bytes, and cover rounds; padded inner inputs, NFS work, timeout, concurrency, and a production profile ID are absent |
| Continuation tokens | Partial | Fixed format and semantic rejection tests exist; nonce generation is still caller-supplied, and no reviewed AEAD, key lifecycle, service integration, or fixed-work timing/trace result exists |
| Deterministic mock store | Pass for logical modeling | Bounded plaintext mock rejects duplicate/out-of-range/capacity errors |
| Logical store trace | Pass for the offline model | Allocation-free recorder validates sequential reads, zero modeled writes/allocations/source calls, modeled application frames/bytes, and completion across selected secret/error cases; NFS and physical/runtime dimensions remain outside this evidence |
| Failure completion schedule | Partial pass | Every injected mock read failure still completes all configured logical reads; physical failure behavior is not equivalent or measured |
| Independent private proto | Missing | No `zainod-oram/proto` or `zaino.private.v1` generation exists |
| Private service adapter | Missing | No service or outer-status equivalence test exists |
| Frame/byte/completion equivalence | Partial model | Every offline round models one fixed request and response application envelope, equal bytes, and unary completion; this is explicitly not protobuf, HTTP/2, TLS, packet-capture, or outer-status evidence |
| NFS/source-call equivalence | Partial model | The engine has no source dependency and validates zero query-derived source calls; no NFS scan or integrated validator/LMDB/raw-transaction instrumentation exists |
| Legacy golden/parity tests | Partial pass | A committed schema golden pins the upstream `CompactTxStreamer` service name, all 20 ordered RPC signatures, and normalized proto fingerprint; existing write/delete consumers retain nonstandard behavior, but complete result-state parity still awaits the offline projection oracle |
| Token fixed-work equivalence | Missing | Rejection semantics are tested, but instruction/allocation/timing and full query-shape equivalence are not |
| Test runtime discipline | Pass in this slice | New tests are synchronous `#[test]` cases |

Phase 1 is a useful skeleton, not an accepted private contract.

## Leakage matrix

This is the current working matrix. “Permitted” means intentionally public in
ADR-0007. “Must hide” means the value must not distinguish secret cases within
one accepted profile. Exact numeric budgets remain unset, so the matrix is not
yet stakeholder-approved.

| Host-visible surface or value | Classification | Intended rule | Current evidence | Current gate |
|---|---|---|---|---|
| Queried address/script | Must hide | Never appears outside the protected workload or in host-keyed storage access | Sensitive Rust `Debug` output is redacted; no private transport or TDX exists | Open |
| Queried txid/outpoint | Must hide | No logs, errors, source calls, tokens, or physical locations expose it | Event/corpus debug output is redacted; query service is absent | Open |
| Continuation cursor/query digest/nonce | Must hide | Fixed authenticated encryption and no visible remaining count | Fixed 128-byte token and redacted debug exist; protector is only an interface with a test implementation | Open |
| Hit versus miss | Must hide | Same work, outer status, bytes, frames, and completion | Equal complete offline logical traces are tested | Open: physical, transport, and outer-status equivalence missing |
| Invalid-domain versus valid query | Must hide after authenticated decode | Full profile work and protected outcome | Mock engine completes the same modeled trace and protects the outcome | Open: decode/token/wire timing not traced |
| Store failure versus ordinary outcome | Must hide per completed-query policy and fail readiness safely | Uniform outer behavior; detailed fault remains internal | Every mock failure ordinal completes the same modeled trace | Open: real ORAM/readiness/service behavior missing |
| Exact result count | Must hide | Fixed response slots and encrypted dummy occupancy | Fixed result-page shape exists | Open: no encrypted wire result |
| Last real page / `has_more` | Must hide | Fixed page and cover-round behavior | Cover-round integer exists only in a test profile | Open |
| Client continuation count | Permitted only for weak profiles | Strong profile requires fixed cover rounds | No client or service exists | Unset budget |
| Logical ORAM key | Must hide | No query-derived host address or fallback | Mock receives the key; this is explicitly plaintext test code | Open |
| Physical ORAM location/path | Must hide | Secret cases must be indistinguishable under accepted trace test | Pinned adapter compiles; no Linux/x86 physical trace was captured | Open |
| Address-directory lookup | Must hide | Directory and event-page lookup both protected | Sizing model counts both logical position-map domains | Open: no implemented directory ORAM |
| Query-derived allocation | Must hide | Fixed allocation/work budget | Offline recorder validates zero explicit modeled query allocations | Open: allocator/page/instruction measurement absent |
| Validator, LMDB, raw-transaction, or backfill calls | Must hide | Zero private-keyed source calls after readiness | Engine has no source dependency and validates zero modeled source calls | Open: no integrated source instrumentation or readiness proof |
| NFS scan work | Must hide | Complete profile-fixed scan on every query | No NFS merge implementation | Open |
| Request/response application bytes | Fixed public class | Exactly the attested profile size | Offline profile/trace bind equal fixed application-envelope bytes | Open: no inner codec, protobuf/TLS, or packet capture |
| Frame count and completion shape | Fixed public class | Same across protected outcomes | Offline trace models one request, one response, and unary completion | Open: no network or outer-status evidence |
| Method class | Permitted only if contract exposes separate methods | Preferred single `QueryPage` hides it | No proto exists | Decision retained, unimplemented |
| Request arrival and connection duration | Permitted | Declared traffic-analysis leakage | No service exists | Not applicable yet |
| Client IP/network metadata | Permitted | Outside initial claim | No service exists | Not applicable yet |
| Service/schema/profile ID | Permitted | Bound into attestation and publicly versioned | Test label only; no attestation | Open |
| Coarse network/chain epoch/height/hash/sync lag | Permitted | Public checkpoint and freshness policy | Corpus report records network and final height/hash | Partial; serving policy absent |
| Database capacity and projected growth | Permitted | Aggregate only, never identifier-bearing | Aggregate report types and redacted debug exist | Partial; no mainnet artifact |
| Aggregate QPS/queue/health | Permitted within allowlist | No outcome/cardinality labels | No metrics implementation | Open |
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
| Canonical-toolchain targets | Rust 1.96.0 has `aarch64-apple-darwin` installed | Exact pinned Linux target was not executed here |
| Auxiliary stable-toolchain targets | Rust 1.96.1 has `x86_64-unknown-linux-gnu` installed | Supported adapter path cross-checks, but does not execute |
| Candidate ORAM target | Linux x86_64, as enforced by the real adapter `cfg` | Target class selected and cross-compiled; no native target run yet |
| CPU generation and feature policy | Not selected | Blocker |
| DOIT enablement/self-check policy | Not selected or tested | Blocker |
| TDX platform/instance/memory | Not selected | Blocker |
| Firmware, microcode, TCB and quote policy | Not selected | Blocker |
| Release flags and reproducible image | Not pinned | Blocker for assembly/attestation evidence |

Successful compilation of `rostl-experimental` on macOS aarch64 proves only
that the trait-level candidate and unsupported-platform stub compile. It does
not qualify the architecture's conditional-move implementation or exercise
`CircuitORAM`.

### Dependencies and licensing

| Component | Exact selection | Role | Observed license evidence | Status |
|---|---|---|---|---|
| Zaino baseline | `c94ae247de7286fd3337e313559bb3d62bdcbd5d` | Authoritative fork base | Root Apache-2.0 license file | Recorded |
| `zaino-oram` | Local `0.1.0`, `publish = false` | Research model and candidate adapter | Workspace Apache-2.0 | Research only |
| `zainod-oram` | Local `0.1.0`, `publish = false` | Listener-free one-shot mainnet corpus runner | Workspace Apache-2.0 | Offline research only |
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

Commands below were run on 2026-07-12 against the evaluated worktree.

| Command | Result | Interpretation |
|---|---|---|
| `git merge-base HEAD upstream/dev` | `c94ae247de7286fd3337e313559bb3d62bdcbd5d` | Recorded upstream baseline |
| `rustc --version --verbose` | Rust 1.96.0, LLVM 22.1.2, `aarch64-apple-darwin` | Compiler/host pin confirmed |
| `rustup target list --installed` | Pinned 1.96.0: `aarch64-apple-darwin` | Exact pinned Linux target was not exercised |
| `rustup +stable target list --installed` | Includes `x86_64-unknown-linux-gnu`; stable is Rust 1.96.1 | Enables a compile-only supported-path check, not execution evidence |
| `cargo tree -p zaino-oram --features rostl-experimental --edges normal` | Resolved `rostl` alpha9 to pinned commit `8c3a12d2...` | Dependency pin confirmed |
| `cargo check -p zaino-oram --all-targets --no-default-features` | Pass | Portable research model compiles |
| `cargo check -p zaino-oram --all-targets --features corpus-zaino` | Pass | Optional Zaino corpus adapter compiles |
| `cargo check -p zaino-oram --all-targets --features rostl-experimental` | Pass on macOS aarch64 | Trait proof and unsupported-target path compile; real ORAM path not executed |
| `cargo test -p zaino-oram --all-targets --no-default-features` | 53 passed | Fixed models, token semantics, complete logical traces, event-state validation, records, sizing, and aggregate core |
| `cargo test -p zaino-oram --all-targets --features corpus-zaino` | 60 passed | Adds canonical/nonempty Zaino fixture, network/genesis binding, incremental scanning, poisoning, and provenance coverage |
| `cargo test -p zaino-oram --all-targets --features rostl-experimental` | 55 passed | Adds `Pod`/`Cmov` proof and expected `UnsupportedPlatform`; Linux round-trip test was cfg-excluded |
| `cargo test -p zaino-oram --all-targets --all-features` | 62 passed | Combined trace, record, token, corpus/provenance, and unsupported-host adapter suite |
| `cargo test -p zaino-proto --test compact_tx_streamer_legacy_golden` | 1 passed | Pins the upstream-baseline legacy service name, ordered RPC surface, and normalized proto schema fingerprint |
| `cargo test -p zainod-oram --all-targets` | 2 passed | CLI requires explicit model inputs and rejects a zero progress interval |
| `cargo +stable clippy -p zaino-oram --lib --no-default-features --features rostl-experimental --target x86_64-unknown-linux-gnu -- -D warnings` | Pass with Rust 1.96.1 | Linux x86_64 adapter code compiles strictly; it was not linked or executed and is not the exact pinned compiler |
| `cargo test -p zaino-state transparent_events --lib --no-default-features` | 4 passed | Event ordering, coinbase skip, script handling, overflow errors, and redaction |
| `cargo clippy -p zaino-oram --all-targets --all-features -- -D warnings` | Pass | Focused all-feature lint is clean on the local host |
| `cargo clippy -p zaino-proto --test compact_tx_streamer_legacy_golden -- -D warnings` | Pass | Legacy schema golden is warning-free |
| `cargo clippy -p zainod-oram --all-targets -- -D warnings` | Pass | Listener-free runner lint is clean |
| `cargo check --workspace --all-targets --no-default-features` | Pass | Every workspace member, including the new non-default runner, compiles without default features |
| `RUSTDOCFLAGS='-D warnings' cargo doc -p zaino-oram --no-deps --all-features` | Pass | New private trace and record APIs document cleanly |
| `cargo fmt --all -- --check` | Pass | Rust formatting is clean |
| `git diff --check -- docs/notes/oram-phase0-1-feasibility-report.md` | Pass | Report has no whitespace errors |
| `makers lint-boundary-conversions` | Canonical task unavailable because `makers` is not installed; its four forbidden-pattern classes were scanned directly with `rg` and returned no hits | Re-run the canonical task in CI/tooling-enabled environment |

These are compile/unit-model results. They are not benchmark, mainnet, TDX,
network, recovery, or side-channel results.

## Mainnet corpus and capacity blocker

The scanner core now has useful safety properties: it requires a nonempty
height-zero start, validates the network-bound canonical genesis hash and null genesis
parent, checks contiguous heights and parent hashes, resolves spends from a
genesis-forward live-output map, and returns an aggregate report bound to a
public network/final height/hash checkpoint. Its returned report retains no
address, transaction, or outpoint identifiers.

It is not yet a mainnet measurement:

- the public `ChainIndex::get_indexed_block_by_height` point source and
  `zainod-oram corpus` runner are implemented, but the runner has not been
  executed against a full mainnet checkpoint and no output artifact exists;
- no mainnet checkpoint, counts, histogram, hot-address tail, or growth output
  is checked in or otherwise attached to this branch;
- exact identities are available only for standard P2PKH/P2SH scripts;
  nonstandard compact outputs are counted by class without inventing a false
  address identity;
- the sizing model reserves fixed page slots and accounts for both directory
  and page position-map entries, but its backend expansion, directory/page
  constants, ORAM tree load, stash, recursive maps, allocator overhead, and
  runtime working set are not calibrated to a real backend;
- no growth horizon or target TDX memory size has been approved.

Therefore `fits_memory` is a model result only. It must not be used as the
30%-RSS go/no-go result.

## RSS, benchmark, stash, and queue blockers

No target hardware benchmark has been run. Required evidence still includes:

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

The current `RostlCandidateStore` is intentionally unsuitable for such a
claim. It is volatile, does not implement the engine's `ObliviousStore`, catches
upstream panics only to latch a local failed-closed state, and has not run on
the intended target. Upstream open work includes Circuit ORAM stash recovery
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

1. execute the non-published aggregate corpus runner at a public mainnet
   checkpoint and publish only its identifier-free output;
2. produce and review the full-mainnet distribution and calibrated sizing
   artifact;
3. establish a reproducible Linux x86_64 build and execute the pinned candidate
   there without calling that a privacy qualification;
4. select target CPU/TDX instances and measure random full-map performance,
   stash/queue behavior, RSS, swapping, and rebuild time;
5. extend the logical trace into release-binary source, allocator, physical
   storage, instruction/memory/page, and real transport-frame instrumentation;
6. design or obtain typed upstream failure/recovery behavior and an
   authenticated persistence/checkpoint protocol;
7. resolve git-dependency and TDX/verifier licensing with an exact SBOM;
8. complete the Phase 1 inner codec and fixed-work token/runtime parity without
   opening a network listener; retain the new legacy schema golden;
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
