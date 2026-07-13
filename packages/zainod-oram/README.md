# zainod-oram

`zainod-oram` is a non-published application package for Zaino ORAM research.
It is not part of the workspace's default members.

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

A successful run yields generic Linux x86_64 CI-smoke evidence only. Exact-head
native `SmokeV1` execution evidence is pending. The report records no latency,
throughput, RSS, allocator/page-fault behavior, stash pressure, queue behavior
under load, physical access trace, persistence/recovery result, target CPU/TDX
result, or billion-operation reliability result. It is not
source/lockfile/toolchain/binary-bound or execution-attested and supplies no
node-year failure bound or mainnet-gate result. Unsupported hosts fail before
creating the output directory.

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

The qualification can successfully report false directory, event,
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

Run `cargo run -p zainod-oram -- corpus size --help` for validation details.
