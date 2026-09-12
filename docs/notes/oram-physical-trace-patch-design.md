# Physical ROSTL trace patch design

Status: implementation design for review. No fork, instrumentation code, trace
result, accepted image, or physical-privacy result exists yet.

This design is based on Zaino integration commit `5b7daaea` and upstream ROSTL
revision `8c3a12d2febf17b024f2e949428b3bc526d74172`. It implements the trusted
backend-diagnostic half of the
[operator-observation protocol](oram-operator-observation-protocol.md). It does
not provide a host-visible TDX page sensor and cannot replace one.

## Source and license boundary

`packages/zaino-oram/Cargo.toml` pins `rostl-oram` and `rostl-primitives` to the
revision above; `Cargo.lock` resolves both to that exact commit. The upstream
workspace declares `MIT OR Apache-2.0` in its root `Cargo.toml`, inherited by
`crates/oram/Cargo.toml`. The checked-out commit contains no `LICENSE*`,
`COPYING*`, or `NOTICE*` file. The manifest declaration is useful provenance,
but is not the canonical license-text closure needed to redistribute a fork.
Before publishing or distributing patched source or binaries, obtain the
canonical MIT and Apache-2.0 texts and any required notices from upstream and
record their hashes. Until then, a local implementation branch is research-only
and must not be treated as clearing the existing license gate.

The implementation pins a Sovright fork commit derived directly from
`8c3a12d2...`; it never tracks a branch or tag. The fork commit and its tree,
patch, license texts, Cargo lock entry, compiler, target, and build command are
part of each diagnostic artifact manifest.

## Build separation: instrumentation is not a Cargo feature

Do **not** add `physical-trace`, `diagnostics`, or an equivalent Cargo feature
to `zaino-oram`, `zainod-oram`, or the patched ROSTL crate. Native research CI
builds `zainod-oram --all-features`; any such feature would silently compile
instrumentation into that release-shaped research binary. The current
accepted-workload builder at
`deploy/tdx/accepted-guest-spike/build-workload-inner.sh` builds only
`tdx-evidence-agent`, so it contains no ROSTL runtime at all. That absence does
not prove a future ORAM-serving accepted candidate is uninstrumented; its build
must gain the explicit refusal below before it includes Zaino ORAM code.

Use an excluded standalone Cargo workspace plus a registered custom
configuration name instead. The proposed layout is:

```text
tools/oram-trace-workbench/
  Cargo.toml                 # contains its own [workspace]
  Cargo.lock                 # separate lock
  src/main.rs
```

Add `tools/oram-trace-workbench` to the root workspace `exclude` list. Its
manifest path-depends on `../../packages/zaino-oram` with the explicit minimum
existing features required by the actual production-query owner, established
with compiler/LSP evidence. That is expected to include `rostl-experimental`
and may include `corpus-zaino` for the mainnet runtime; it must not use
`--all-features` or enable a dependency fallback. It scopes a Cargo source patch for the exact
ROSTL Git source to the pinned Sovright trace fork and exact fork revision.
Because this manifest is a separate workspace, its `[patch]` and lockfile do
not alter or feature-unify with the root workspace. Adding the exclusion does
change the root `Cargo.toml`; the root `Cargo.lock`, original `rostl-oram`
source pin, and ordinary dependency graph must remain unchanged. Verify this
with `cargo metadata` from both manifests and byte-compare the root lock before
and after the diagnostic build.

The separately compiled path dependency uses this registered custom
configuration name:

```text
zaino_oram_physical_trace_v1
```

Both patched ROSTL and the narrow Zaino adapter compile trace fields and calls
only under `#[cfg(zaino_oram_physical_trace_v1)]`. Register the name with
Cargo/rustc's `check-cfg` lint, without giving it a default or mapping any Cargo
feature to it. Under that cfg only, `zaino-oram` exposes one narrow diagnostic
entry point that owns sink creation and runs the real typed query; it does not
export the sink, raw stores, or mutable worker. This entry point is absent from
ordinary and accepted crate metadata. The standalone runner calls only that
entry point.

The only supported enabling path is a dedicated, reviewed
research wrapper, for example:

```text
tools/scripts/build-oram-physical-trace-v1.sh
```

The wrapper must invoke `cargo` with
`--manifest-path tools/oram-trace-workbench/Cargo.toml --locked`, use a clean
target directory, fixed compiler/target and
`RUSTFLAGS='--cfg zaino_oram_physical_trace_v1'`, build the explicitly named
research runner, and emit a manifest with the command and source/binary hashes.
It must refuse ambient `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTC`,
`RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, target-specific rustflags, Cargo
aliases, and a nonempty output directory before setting its own value. It uses
an explicit empty Cargo home/config plus the frozen offline source closure and
records every effective rustc invocation. The runner and output
are named `oram-physical-trace-v1`; they are never installed into the guest
rootfs or workload closure.

The existing native research builder keeps its `zainod-oram --all-features`
coverage without treating that artifact as accepted. When an ORAM-serving
accepted-candidate builder replaces the current evidence-agent-only workload,
it must independently reject trace cfg injection and inspect rustc invocation
and build metadata for `zaino_oram_physical_trace_v1`. A negative build test
proves:

1. root-workspace ordinary and `--all-features` builds
   retain the original upstream ROSTL source and contain no trace
   symbols or trace-schema domain string;
2. the dedicated wrapper contains both and is labeled diagnostic;
3. a future ORAM-serving accepted-candidate builder refuses the cfg before
   rustc by verifying its closed Cargo configuration, environment, compiler,
   wrappers, target configuration, build scripts, source closure, and captured
   rustc invocations. Trace symbol/domain absence in its output is a secondary
   check;
   the current evidence-agent-only build is recorded as out of scope rather
   than used as this negative control;
4. the workbench lock resolves only the exact fork while the root lock remains
   byte-identical and resolves only the original revision;
5. diagnostic and accepted binary digests differ and cannot share an
   attestation allowlist entry. Digest inequality is only identification, not
   proof of isolation; the source graph, effective flags, and captured compiler
   metadata carry that claim;
6. the actual uninstrumented candidate passes its existing fresh native codegen
   guards after cfg registration and adapter changes. Inactive cfg blocks do not
   imply byte-identical machine code, so no such equivalence is claimed.

This is a source/build separation, not a claim that dead instrumentation is
harmless. Only the uninstrumented build may enter a future accepted-image
measurement policy.

## Minimal trace API

The patched dependency owns a small no-std-shaped module with private fields.
It must not depend on logging, serialization, allocation, wall clocks, thread
locals, I/O, or Zaino types.

```rust
pub trait PhysicalTraceSink {
    fn record(&mut self, event: PhysicalTraceEvent) -> Result<(), TraceFull>;
}

#[repr(C)]
pub struct PhysicalTraceEvent {
    sequence: u64,
    table: u8,
    component: u8,
    level: u8,
    operation: u8,
    phase: u8,
    direction: u8,
    depth: u8,
    reserved: [u8; 1],
    bucket_index: u64,
    work_count: u64,
}
```

The actual visibility begins private and widens only as compilation requires.
No event contains a query key, value, record bytes, address type, result,
found/miss flag, source identifier, TLS/session value, or raw application
request. `bucket_index` is meaningful only for tree-path events;
`work_count` is meaningful only for fixed linear/stash scan events. Unused
fields are zero and validated as zero. Integers have a canonical little-endian
file encoding independent of Rust struct padding; the in-memory `repr(C)` is
not itself the file format.

Closed enums:

- `table`: directory or event; any future table/topology requires a schema
  version rather than reusing a value;
- `component`: top data ORAM, position-map linear level, position-map recursive
  ORAM;
- `operation`: read/remap, write-or-insert/remap, position-map update;
- `phase`: selected path, selected-path writeback, deterministic eviction 0,
  deterministic eviction 1, linear scan, stash scan;
- `direction`: read, write, scan.

`level` is zero for the top data ORAM and linear map and is one-based from the
linear-map-facing recursive level toward the data ORAM. For each logical table
operation, events are ordered: position-map linear read/scan/write, recursive
levels in ascending level order (each complete selected path then eviction 0
then eviction 1), then the top data ORAM selected path, selected-path writeback,
eviction 0, and eviction 1. Within a path, depth ascends root to leaf; read
precedes scan/eviction work and writeback. Tree events carry every
`(depth, bucket_index)` in that order. Eviction read and write paths use the
same eviction phase and distinct directions. Scan events carry the public fixed
number of examined entries. The `(table, component, level, operation, phase,
direction, sequence)` tuple prevents identical bucket indices in different
stores or recursion levels from aliasing.

## Buffer and failure contract

The exclusive ROSTL worker owns one fixed-capacity
`Box<[MaybeUninit<Event>]>`, allocated before entering the measured query. It
passes an exclusive `&mut sink` plus explicit table/operation context through
one table operation and its nested position-map/data-ORAM calls, then releases
that borrow before the other table can run. Neither table stores a second
mutable reference. Shared mutable globals, thread-local state, interior-mutability
locks, and callback registries are forbidden fallbacks. The sink contains only
the fixed slice, next index, expected capacity, and a latched failure bit.
`record` performs a checked bounds test and one fixed-size write. Fixed scan
work is counted with a checked increment at every actual linear/stash loop-body
visit and emitted only after the loop; it is never inferred from a declared
capacity before or after the loop. It never allocates, formats,
hashes, locks, calls the clock, or performs I/O.

The required event capacity is computed before execution solely from the
public profile, table capacities/heights, fixed query schedule, ROSTL constants,
recursive-map geometry, and fixed eviction count. Checked arithmetic failure or
an unsupported geometry refuses the run. Overflow latches `TraceFull`; every
later call stays failed. The adapter propagates the failure at the next trace
boundary and the query becomes a failed trial. A path event recorded before a
bucket access means `attempted`; only normal return from every nested operation
and the typed query emits a separate complete marker. A panic or terminal
backend failure therefore cannot turn attempted events into a successful
complete trace. A short final count, overflow,
sequence gap, unknown enum, nonzero reserved/unused field, or trailing byte
refuses trace comparison. Partial buffers do not enter successful comparisons,
but their trial identity, failure phase, observed count, overflow state, and
censoring remain mandatory experiment outcomes. They cannot be discarded or
selectively rerun; secret-correlated truncation is negative evidence.

After the complete measured region, outside the sink, the runner serializes the
canonical fixed-width header and events and hashes them. The header commits:

- domain `ZAINO-ROSTL-PHYSICAL-TRACE-V1` and schema version 1;
- source, dependency-tree, compiler, runner, and uninstrumented-reference
  binary digests;
- public profile/table geometry and calculated/actual event counts;
- boot/run/sample identifiers and explicit `trusted_guest_diagnostic=true`;
- overflow/short/truncation status and trace digest.

Bucket traces remain private diagnostic artifacts because they reveal the
random physical schedule and can assist correlation.

## Exact hook locations

Patch the fork at the point where it has complete information:

1. `HeapTree<Bucket<V>>::read_path` and `write_path`: record every computed
   `get_index(depth, path)` before touching the bucket.
2. `CircuitORAM::read`, `write_or_insert`, and `update`: set operation and
   selected-path phase, record fixed stash work, and label each of the two
   `perform_deterministic_evictions` rounds. Do not infer rounds later from
   `evict_counter`.
3. `RecursivePositionMap::access_position`: label its fixed linear-map read and
   write and place each recursive `CircuitORAM::update` under its exact level.
   This cannot be reconstructed at the current Zaino wrapper because these
   fields and random positions are private upstream.
4. `RostlTable` in
   `packages/zaino-oram/src/layout/atomic_store/worker/rostl.rs`: accept the sink
   only through custom-cfg operation methods. The exclusive worker retains
   ownership and lends it sequentially to the directory or event table, which
   threads the borrow into its position map and data ORAM and returns it before
   the next command step. Surface a typed terminal trace failure. The ordinary constructor and
   trait implementations remain byte-for-byte source-equivalent outside cfg
   blocks.
5. The research runner invokes the real typed private-query schedule and drains
   the trace after completion. It cannot call raw table operations as a
   substitute for the runtime query path.

## Completeness and negative gates

Small-capacity deterministic tests use a fixed injectable test RNG stream and
an independent oracle outside the patched implementation. The oracle freezes
the current backend's least-significant path-bit convention: for zero-based
depth `d`, `level_offset = (1 << d) - 1` and
`bucket_index = level_offset + (path & level_offset)`. It consumes the known RNG
positions and independently models recursive geometry and eviction-counter
progression to require exact ordered events for:

- selected read/writeback and both deterministic eviction rounds;
- top data ORAM, linear position map, and every recursive level;
- fixed full stash/linear scans and complete typed-query table/work order;
- present/absent and early/late logical cases with equal schema and event count;
- two consecutive operations, proving eviction-counter progression is captured.

Format tests reject unknown enums/versions, sequence gaps, nonzero reserved or
unused fields, short records, trailing bytes, and broken header/count/digest
integrity. Integrity detects byte modification; it does not prove semantic
truth. Independent-oracle tests reject an omitted, duplicated, reordered, or
altered but freshly rehashed event and an incorrect table/component/level/
phase/direction/bucket/work count. A deliberately broken hook must fail the
oracle rather than yielding a plausible shorter trace. Production traces
without a known RNG oracle claim format integrity and completeness against the
source-bound event-count model only; their self-computed digest does not
semantically authenticate each event.

The diagnostic Linux gate runs the real typed ROSTL worker and query runtime,
then compares public work/event counts across secret cases. It also records the
instrumented/uninstrumented timing difference as overhead, without using the
instrumented timing as operator evidence.

## Claim boundary and next decision

This patch can be implemented and tested before the custom guest boots. Passing
it establishes that a trusted diagnostic build captured its algorithmic ROSTL
bucket-index schedule completely under the declared schema. It does not show
guest virtual pages, guest physical pages, host memory-controller traffic,
cache lines, paging, or what a curious GCP operator can observe.

Outside-operator trials use the uninstrumented, independently attested accepted
candidate and separately registered network, storage, source, resource, and
administrative sensors. If no authorized C3 host page/address sensor exists,
the memory/page surface remains unresolved. The diagnostic fork must not cause
that missing channel to be marked safe, and neither its binary nor its trace
may populate an accepted-image policy.
