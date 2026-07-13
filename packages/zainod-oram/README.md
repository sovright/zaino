# zainod-oram

`zainod-oram` is a non-published application package for Zaino ORAM research.
It is not part of the workspace's default members.

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
