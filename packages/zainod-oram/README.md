# zainod-oram

`zainod-oram` is a non-published application package for Zaino ORAM research.
It is not part of the workspace's default members.

## Listener-free private service boundary

The default-off `private-service` feature compiles an independent
`zaino.private.v1` protobuf contract owned by this package. Its only method is
`PrivateCompactTxStreamer.QueryPage`; both directions carry one non-empty
`FixedEnvelope.bytes` field whose decoded length must exactly match the selected
compile-time profile:

```console
cargo check -p zainod-oram --features private-service
```

When `protoc` is available, the build script regenerates and formats a temporary
copy, then fails if it differs from the committed Rust source. Refreshing after
an intentional schema change requires the pinned toolchain's `rustfmt` and the
explicit update mode:

```console
ZAINO_UPDATE_PRIVATE_PROTO=1 cargo check -p zainod-oram --features private-service
```

Builds without `protoc` consume the same committed source, so ordinary and
native-builder checks do not depend on an ambient compiler and never select a
different generated contract.

The same feature adds a crate-private synchronous, listener-free adapter over
the small `zaino-oram` `FixedEnvelopeRuntime`, `PendingFixedEnvelope`, and
`PrivateQueryUnavailable` facade. It validates the protobuf boundary through
named `try_from_wire` / `to_wire` methods, maps boundary and runtime failures to
one redacted adapter error, and retains the non-`Clone` pending response without
extracting detached response bytes.

A crate-private custom Tonic codec and body adapter consumes that pending value
only when the outbound body is first polled. That poll performs the pending
value's fallible release-time currentness check before borrowing its fixed
bytes. A successful check encodes one exact fixed-envelope protobuf DATA frame
and releases the pending value after encoding. A stale or unavailable response
emits no DATA and is collapsed to one static `Unavailable` trailer shape. If
the body is dropped before it is polled, the pending value is released without
a currentness check or response-byte borrow.

The concrete `zaino-oram` runtime owner remains private, with no public
constructor or factory, so this package currently exercises the shared facade
with mock implementations only. The generated Tonic service trait is
deliberately not implemented; it fixes the response type to the generated
protobuf message and cannot carry this pending value. A generated route and
listener, production protector/replay/material providers, durable replay,
trusted clock and nonce ledger, key management, rollback protection, TLS/TDX,
package/profile-specific message limits, real-owner integration, and
transport-write or peer-delivery evidence remain open. Currentness at first
body poll is not currentness at the later transport-write boundary.

## Release-bound deterministic-build receipt

From a completely clean checkout at an exact full source revision, the
workbench can build and publish the fixed ORAM release product with Podman:

```console
CONTAINER_ENGINE=podman cargo run --locked --release --manifest-path tools/workbench/Cargo.toml --bin build-deterministic -- --product zainod-oram
```

The ORAM path accepts no forwarded container arguments. It archives the exact
HEAD into a detached build context and performs two no-cache builds from that
same source archive. Both builds use target `x86_64-unknown-linux-musl`, profile
`release`, feature `typed-qualification`, and the fixed deterministic build
flags. Their output files must have distinct inodes and identical bytes before
the first binary creates a receipt and the second binary verifies it.

Receipt creation checks that the archive's embedded source revision matches
the requested revision and that its `Cargo.lock`, `rust-toolchain.toml`, and
`Dockerfile.deterministic` bytes exactly match the separately hashed build
inputs. The staged release is read back and verified before it is atomically
published without replacing an existing destination. A successful run creates:

- `build/oram-release/zainod-oram`
- `build/oram-release/release-receipt.json`

The published binary can reverify its canonical receipt and its own executable
identity:

```console
./build/oram-release/zainod-oram release verify-receipt \
  --receipt build/oram-release/release-receipt.json
```

The receipt is self-reported procedure, local-integrity, and binary-identity
evidence only. It is unsigned and provides no execution attestation,
source-derivation attestation, physical-access trace, TDX result, mainnet
result, or claim that the two same-source builds were independently executed.

## Gate 2 paired insertion timing

The `typed-qualification` feature also builds a separate synchronous binary for
the dynamic half of the insertion-path experiment. Run it on Linux x86_64 under
`taskset`; it refuses to start unless `/proc/self/status` confirms exactly one
allowed CPU, Linux scheduler statistics are enabled, and the declared load
policy admits the initial host state:

```console
cargo build -p zainod-oram --features typed-qualification \
  --bin zainod-oram-timing --release
taskset -c 3 target/release/zainod-oram-timing \
  --mode hit-miss \
  --directory-capacity <POWER_OF_TWO> \
  --directory-occupancy <RECORDS_BELOW_CAPACITY> \
  --event-capacity <POWER_OF_TWO> \
  --event-occupancy <RECORDS_BELOW_CAPACITY> \
  --mean-bound-nanos <PREDECLARED_NANOSECONDS> \
  --cdf-distance-bound <PREDECLARED_0_TO_1_BOUND> \
  --max-load-average-1m <LOAD> \
  --max-competing-processes <COUNT> \
  --max-runqueue-wait-ratio <PREDECLARED_0_TO_1_RATIO> \
  --seed <SEED> \
  --output <NEW_JSON_FILE>
```

`--mode hit-miss` is the default and measures the actual existing-key versus
absent-key insertion paths. The same supported driver also runs the two null
controls; use a distinct new output path for every invocation:

```console
taskset -c 3 target/release/zainod-oram-timing \
  --mode forced-hit \
  --directory-capacity <POWER_OF_TWO> \
  --directory-occupancy <RECORDS_BELOW_CAPACITY> \
  --event-capacity <POWER_OF_TWO> \
  --event-occupancy <RECORDS_BELOW_CAPACITY> \
  --mean-bound-nanos <PREDECLARED_NANOSECONDS> \
  --cdf-distance-bound <PREDECLARED_0_TO_1_BOUND> \
  --max-load-average-1m <LOAD> \
  --max-competing-processes <COUNT> \
  --max-runqueue-wait-ratio <PREDECLARED_0_TO_1_RATIO> \
  --seed <SEED> \
  --output <NEW_FORCED_HIT_JSON_FILE>
taskset -c 3 target/release/zainod-oram-timing \
  --mode forced-miss \
  --directory-capacity <POWER_OF_TWO> \
  --directory-occupancy <RECORDS_BELOW_CAPACITY> \
  --event-capacity <POWER_OF_TWO> \
  --event-occupancy <RECORDS_BELOW_CAPACITY> \
  --mean-bound-nanos <PREDECLARED_NANOSECONDS> \
  --cdf-distance-bound <PREDECLARED_0_TO_1_BOUND> \
  --max-load-average-1m <LOAD> \
  --max-competing-processes <COUNT> \
  --max-runqueue-wait-ratio <PREDECLARED_0_TO_1_RATIO> \
  --seed <SEED> \
  --output <NEW_FORCED_MISS_JSON_FILE>
```

`forced-hit` executes the existing-key insertion for both schedule labels;
`forced-miss` executes the absent-key insertion for both labels. They retain the
same balanced AB/BA schedule, fresh equal-occupancy tables, warm-up, scheduler
admission, statistics, and atomic artifact publication as `hit-miss`. Their
reported hit/miss-named statistics compare the two schedule labels, not two
different operations. One invocation always measures both the directory and
event record kinds in its selected mode.

Set `kernel.sched_schedstats=1` before the run if the host has disabled that
accounting. The driver reads the control before, between, and after the two
record-kind experiments and fails closed if it is unavailable or disabled.

One invocation measures both fixed-record monomorphizations. Each uses 50
discarded warm-up pairs followed by exactly 500 measured pairs against fresh,
equal-occupancy tables, with an exactly balanced seed-shuffled AB/BA order.
The single atomically renamed, no-replace JSON file records both raw timing
vectors, plans, predeclared bounds, classifier AUC, the nominal family-wise 95%
paired-mean bootstrap intervals and permutation diagnostic, empirical CDF
distance, and its distribution-free joint family-wise 95% upper confidence
limits. The statistical gate evaluates the pooled sample, both AB/BA order
strata, and both first/second measurement positions, preventing order or
cache-period effects from cancelling into a pass. The file also records CPU
and quiescence observations before, between, and after the two experiments.
The `zaino-oram-insert-timing-v2` artifact records the selected mode and
separate booleans for all three quiescence decisions, affinity stability,
scheduler-stat continuity, both per-record scheduler decisions, and the
combined environment decision. Its `mode` value is `hit_miss`, `forced_hit`,
or `forced_miss`.
Scheduler counters bracket every timed insertion. Run-queue wait is divided by
the narrower measured wall-clock interval, so scheduler work at either procfs
bracket can only make admission more conservative; both aggregate and
worst-measurement ratios must meet the declared bound.
The declared quiescence policy must admit all three snapshots. The caller must
therefore choose its predeclared load-average bound with the CPU-bound driver's
own contribution in mind. A post-start quiescence failure, CPU-affinity drift,
disabled scheduler accounting, or excess run-queue waiting makes
`declared_criteria_satisfied` false after preserving the negative artifact.

The CDF gate detects threshold-visible distribution shapes that the mean can
miss. AUC remains a diagnostic with no universal pass threshold; the
predeclared paired-mean and CDF bounds remain the gate. Neither result is
evidence against arbitrary nonlinear classifiers, memory/page traces, PMU
traces, allocator behavior, or other host side channels. Bounds and host
thresholds are caller-selected, so
`declared_criteria_satisfied` means exactly that and is not by itself a Gate 2
qualification. The output is self-reported and is not signed, source-bound, or
execution-attested.

## Typed-worker correctness qualification

The default-off `typed-qualification` feature exposes one fixed, listener-free
correctness exercise for the real volatile typed `rostl` worker. It is
available only on Linux x86_64:

```console
cargo run -p zainod-oram --features typed-qualification -- \
  qualification run --output-dir <NEW_DIR>
```

The command accepts no node configuration or workload knobs. It executes nine
synchronous business commands against fixed 8-slot directory and 16-slot event
tables: empty reads, three inserted events across two addresses, one observed
exact replay, one two-event history, independent histories, and a final empty
read. It then requires clean worker shutdown with nine accepted/completed
commands, no failures or rejections, and queue high-water one. No address,
transaction, event, or probe seed is emitted.

The output uses the same synchronized sibling staging and atomic no-replace
publication path as corpus artifacts. Staged files are bounded, opened without
following links, parsed, semantically revalidated, and compared with the
in-memory report before publication. The directory contains:

- `qualification.json`: the
  `zaino-oram-typed-worker-qualification-v1` typed report wrapper.
- `qualification.txt`: the exact identifier-free text rendering.
- `provenance.json`: the
  `zaino-oram-typed-worker-qualification-provenance-v1` runner version,
  Linux/x86_64 target labels, and lowercase BLAKE2s-256 digest of the compact
  typed qualification wrapper.

The provenance digest binds the compact typed JSON wrapper. Publication also
checks the text rendering against that report, but neither mechanism is a
signature or execution attestation. The report explicitly records that it is
not bound to a source revision, lockfile digest, toolchain, binary identity, CI
run, or attestation. Trusted CI logs or later signed provenance must establish
who ran which binary. The command is also not a benchmark: it records no
latency, RSS, stash, physical access trace, persistence, TDX, mainnet-capacity,
or runtime-service result. Unsupported hosts fail before creating the output
directory.

## Typed-worker stress smoke qualification

The same default-off feature exposes a separate fixed mixed-workload smoke
profile:

```console
cargo run -p zainod-oram --features typed-qualification -- \
  qualification stress --profile smoke-v1 --output-dir <NEW_DIR>
```

`SmokeV1` is named and immutable at the command boundary: the CLI accepts no
operation count, seed, capacity, admission, queue, or backend configuration.
It runs 64 deterministically derived read, unique-append, and exact-replay
steps across four modeled addresses on one healthy worker, verifies results
against a bounded reference model after every command and at a fixed cadence,
then checks every modeled address plus two absent addresses. It also checks
that a cross-address append is rejected without faulting the healthy worker.
A separate deliberately constrained worker checks that an accepted second
unique append exceeds the public per-address event limit, returns
`FailedClosed`, and latches terminal state. One later read and append are
rejected at admission, and shutdown returns the expected stopped, faulted
aggregate snapshot.

Publication uses the same bounded, no-follow, synchronized sibling-staging and
atomic no-replace path as the correctness qualification, but writes distinct
`stress-qualification.json`, `stress-qualification.txt`, and `provenance.json`
files. The JSON schema is
`zaino-oram-typed-worker-stress-qualification-v1`; provenance uses
`zaino-oram-typed-worker-stress-qualification-provenance-v1` and binds the
compact typed report digest. The artifact contains fixed public
schema/profile/backend/shape metadata, aggregate counts, schedule and
final-state digests, correctness/fault summaries, evidence flags, and
identifier-free worker snapshots; provenance adds unsigned runner-version and
OS/architecture labels plus the report digest. It contains no raw modeled
address/event/seed fields or per-operation results. The digests deliberately
commit to the deterministic synthetic schedule and final state.

A successful run yields generic Linux x86_64 CI-smoke evidence only. At exact
`SmokeV1` head `17356db0`, native run `29250757780` (job `86818420630`) passed
strict all-target, all-feature Clippy for both research crates plus all 204
`zaino-oram` and 39 `zainod-oram` tests; the Linux-only qualification tests
exercised the real typed backend. This remains correctness evidence only. The
report records no latency, throughput, RSS, allocator/page-fault behavior,
stash pressure, queue behavior under load, physical access trace,
persistence/recovery result, target CPU/TDX result, mainnet result, or
billion-operation reliability result. It is not
source/lockfile/toolchain/binary-bound or execution-attested and supplies no
node-year failure bound or mainnet-gate result. Unsupported hosts fail before
creating the output directory.

## Typed-worker admitted-map saturation qualification

The `typed-qualification` feature also exposes a separate deterministic
admitted-map boundary profile:

```console
cargo run -p zainod-oram --features typed-qualification -- \
  qualification stress --profile full-map-saturation-v1 \
  --output-dir <NEW_DIR>
```

`FullMapSaturationV1` uses two independent workers so one terminal fault cannot
mask the other case. The directory-boundary case admits six addresses with one
event each into the fixed 8-slot/6-admitted directory and 16-slot/12-admitted
event tables, verifies histories, replay behavior, absent reads, and
cross-address rejection, then requires a seventh-address append to return
`FailedClosed` and latch terminal state. The event-boundary case admits three
events for each of four addresses, verifies the same invariants at 12 admitted
events while directory admission remains below its bound, then requires a
thirteenth unique event on an existing address to fail closed and latch.

Publication uses the same bounded, no-follow, synchronized sibling-staging and
atomic no-replace path, but writes a distinct `full-map-saturation.json`,
`full-map-saturation.txt`, and `provenance.json` bundle. The report schema is
`zaino-oram-full-map-saturation-v1`; provenance uses
`zaino-oram-full-map-saturation-provenance-v1` and binds the compact typed
wrapper digest. The aggregate report records exact logical occupancy, admission
bounds, physical-capacity reserve, deterministic schedule and final-state digests,
one-hot pre-fault boundary conditions, and identifier-free worker snapshots.

This profile proves deterministic correctness at both logical admitted-map
boundaries. It deliberately leaves physical capacity unreached and is not a
random or adversarial target-load experiment, benchmark, latency/RSS/stash or
queue-load measurement, billion-operation soak, persistence/recovery test,
physical-trace experiment, target CPU/TDX or attestation result, mainnet sizing
result, or mainnet gate.
The bundle is unsigned and self-reported; it binds no source revision, lockfile,
toolchain, release binary, or execution attestation.

## Source-bound fresh-worker rebuild qualification

The `typed-qualification` feature exposes a listener-free mainnet rebuild
foundation for a fresh volatile typed worker:

```console
cargo run -p zainod-oram --features typed-qualification -- \
  qualification cold-rebuild \
  --profile source-bound-builder-v1 \
  --config <MAINNET_ZAINOD_TOML> \
  --capture-dir <CAPTURE_DIR> \
  --sizing-dir <SIZING_DIR> \
  --declared-rebuild-budget-seconds <SECONDS> \
  --output-dir <NEW_DIR> \
  --progress-interval <BLOCKS>
```

The runner revalidates the complete capture and sizing lineage, opens one fixed
non-finalized mainnet snapshot, and verifies the capture checkpoint height and
hash against that source before allocating the worker. It then streams the same
genesis-forward `IndexedBlock` sequence into both a fresh corpus scanner and the
fresh typed projection owner. Readiness is accepted only if the recomputed
measurement exactly equals the loaded capture, the worker reaches the exact
checkpoint, the semantic publication is available, and the worker shuts down
cleanly. A source, scanner, worker, memory-sampling, or validation failure drops
the identifier-bearing scanner state, shuts down the candidate worker, and
publishes no output.

The declared budget has a deliberately narrow boundary: it starts immediately
before worker allocation and ends after source-measurement equality and typed
worker readiness are validated. Source-service startup, snapshot selection and
checkpoint preverification happen before this timer. Shutdown and total
lifecycle time are recorded separately and cannot change the budget result.
When the validated rebuild misses the budget, the command first publishes the
valid negative artifact and then exits unsuccessfully.

The new output directory contains `cold-rebuild.json`, `cold-rebuild.txt`, and
`provenance.json`. The typed JSON binds the capture and sizing digests, declared
budget, fresh-worker report, and source snapshot evidence: backend kind, fixed
snapshot mode, serviceable height, preverified checkpoint, and the explicit
`uncontrolled` source-cache mode. Provenance binds the compact typed wrapper to
the runner version and Linux x86_64 target labels. Staged files are bounded,
read back, semantically revalidated against both input directories, and
atomically published without replacing an existing output.

This is fresh-worker replay evidence on the executing host, not a full-service
recovery-time objective or a controlled cold-cache benchmark. It does not
establish durable ORAM state, authenticated state restoration, production key
or freshness ownership, target hardware or TDX behavior, physical access-trace
obliviousness, attestation, signed provenance, full-mainnet feasibility, or
mainnet readiness.

## Corpus capture

`corpus capture` produces an identifier-free measurement of the transparent
mainnet corpus. It accepts no growth, table-capacity, memory-expansion, TDX, or
other sizing assumptions.

The command starts `NodeBackedIndexerService` directly without starting a gRPC,
JSON-RPC, metrics, or private-service listener. It requires an indexed
non-finalized snapshot and rejects the finalized-state-still-syncing fallback.
Non-finalized reads use that fixed snapshot; older finalized blocks come from
the service's append-only finalized source. With no checkpoint arguments, the
scan ends at the snapshot's serviceable tip. Alternatively,
`--target-height` and `--target-hash` may be supplied together to select an
earlier checkpoint; the RPC-order hash is verified against the indexed
canonical block before the scan begins. The scanner then verifies genesis,
height, parent-hash, and final checkpoint continuity while retaining no blocks
in the runner.

Block fetching is sequential by default. Operators may explicitly set
`--fetch-concurrency` from 1 through 32 to keep a bounded number of indexed
block reads in flight. Fetches may complete out of order, but the runner always
feeds them to the canonical scanner in ascending height order, so this knob
does not change the measurement or its digest. The bound limits transient
full-block memory and validator work-queue pressure.

`--output-dir` must name a new directory. The command builds the artifact in a
temporary sibling directory and atomically renames it into place only after all
files validate, so it never merges with or overwrites an existing capture. The
directory contains:

- `measurement.json`: the versioned machine-readable aggregate measurement.
- `measurement.txt`: a human-readable rendering of the same measurement.
- `provenance.json`: minimal public capture provenance: schema and runner
  version; backend kind (`direct` or `rpc`); snapshot mode
  (`non-finalized-state`); checkpoint selection (`serviceable-tip` or
  `explicit-checkpoint`); serviceable and verified checkpoint heights; verified
  checkpoint hash; and `measurement_blake2s256`.

`measurement_blake2s256` is 64 lowercase hexadecimal characters encoding
BLAKE2s-256 over the exact compact JSON bytes of the typed
`zaino-oram-mainnet-measurement-v1` measurement wrapper. Pretty-printed
`measurement.json` and `measurement.txt` are not digest inputs; read-back
verification deserializes the measurement and reconstructs the compact typed
bytes before recomputing the digest.

This command is a listener-free research capture tool, not an ORAM-backed Zaino
service. It does not start a private query API, exercise ORAM access paths, or
qualify TDX deployment, measured RSS, backend expansion, insertion success, or
physical-obliviousness.

Run `cargo run -p zainod-oram -- corpus capture --help` for the complete input
set.

## Corpus sizing

`corpus size` consumes the complete three-file capture directory, revalidates
its schema, measurement semantics, text rendering, checkpoint, provenance, and
canonical digest, then applies one explicit model without loading Zainod
configuration, connecting to a validator, rescanning the chain, or starting a
listener. The input directory remains bound to one opened handle; every entry
must be a regular file opened with no symlink following, and JSON/text reads
have explicit byte limits. All eleven model inputs are required and have no
defaults:

```console
cargo run -p zainod-oram -- corpus size \
  --input-dir <CAPTURE_DIR> \
  --output-dir <NEW_DIR> \
  --growth-horizon-years <YEARS> \
  --annual-growth-bps <BPS> \
  --directory-capacity <SLOTS> \
  --directory-admission-limit <RECORDS> \
  --event-capacity <SLOTS> \
  --event-admission-limit <RECORDS> \
  --max-events-per-address <EVENTS> \
  --position-map-entry-bytes <BYTES> \
  --backend-expansion-bps <BPS> \
  --tdx-memory-bytes <BYTES> \
  --required-headroom-bps <BPS>
```

The output must be a new directory outside the input capture. It is staged,
synchronized, typed-read-back validated, and committed with the same atomic
no-replace rename used by capture. The parent directory is synchronized after
that commit. If this final sync fails, the command reports that the complete
artifact is visible but crash durability is uncertain; it never removes the
published artifact as rollback. If a filesystem reports a rename error after
possibly committing it, recovery compares the held staging inode with both
directory names: confirmed commits are preserved, confirmed non-commits are
cleaned and synchronized, and indeterminate state is reported without deleting
either name. The directory contains:

- `qualification.json`: a `zaino-oram-mainnet-sizing-v1` wrapper containing the
  input measurement digest and the validated model, compiled record widths,
  negative evidence markers, and projection rows. Potentially wider `u128`
  load-basis-point values use canonical decimal strings.
- `qualification.txt`: the exact human-readable rendering of the typed result.
- `provenance.json`: `zaino-oram-sizing-provenance-v1` provenance containing
  the runner version and target OS/architecture, verified checkpoint, and
  canonical BLAKE2s-256 digests of the input measurement wrapper, sizing model,
  and sizing qualification wrapper.

The sizing model and qualification digests use compact typed JSON in declared
field order. Neither pretty-printed `qualification.json` nor
`qualification.txt` is hashed; typed read-back reconstructs the compact bytes
before verifying every digest. Structural qualification validation checks its
internal arithmetic; artifact validation additionally recomputes the complete
qualification from the captured measurement and requires exact equality.

The read-only validation command reopens an already-published sizing directory
alongside its separately validated source capture:

```console
cargo run -p zainod-oram -- corpus validate-sizing \
  --capture-dir <CAPTURE_DIR> \
  --sizing-dir <SIZING_DIR>
```

It repeats the bounded no-follow checks, requires the recomputed qualification
and capture binding to match, and prints the two canonical input digests plus
the validated directory/event capacity, admission, and per-address model
inputs. It accepts no output, node configuration, workload, queue, or backend
arguments and creates no artifact. Logical allocation constraints are
revalidated, but no ORAM backend, store, or worker is instantiated; the command
supplies no load, performance, hardware, or mainnet result.

For `corpus size`, the qualification can successfully report false directory, event,
hot-address, memory, or combined fit flags; those are model results, not command
failures. Malformed input, invalid model parameters, checked-arithmetic
overflow, lineage mismatch, digest or text drift, an existing destination, or
any partial-publication condition fails closed.

This is deterministic logical sizing only. `backend_expansion_bps`,
`tdx_memory_bytes`, and `required_headroom_bps` are operator assumptions. The
result explicitly records `insertion_bound=false`,
`backend_calibrated=false`, and `rss_measured=false`; it does not qualify an
actual ORAM insertion bound, backend expansion, process RSS, target CPU/TDX
deployment, load behavior, or physical obliviousness.

Run `cargo run -p zainod-oram -- corpus size --help` and
`cargo run -p zainod-oram -- corpus validate-sizing --help` for validation
details.
