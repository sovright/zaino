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

This command is an offline research capture tool, not an ORAM-backed Zaino
service. It does not start a private query API, exercise ORAM access paths, or
qualify TDX deployment, measured RSS, backend expansion, insertion success, or
physical-obliviousness. The next PR will add offline `corpus size`, which will
consume a captured measurement and apply explicit sizing assumptions without
rescanning the chain.

Run `cargo run -p zainod-oram -- corpus capture --help` for the complete input
set.
