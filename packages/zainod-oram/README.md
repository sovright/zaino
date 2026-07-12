# zainod-oram

`zainod-oram` is a non-published application package for Zaino ORAM research.
It is not part of the workspace's default members.

The current `corpus` command starts `NodeBackedIndexerService` directly without
starting any gRPC, JSON-RPC, metrics, or private-service listener. It captures
one non-finalised-state snapshot and fixed public tip, reads indexed blocks
from genesis through that tip, and verifies genesis, height, and parent-hash
continuity while incrementally producing an identifier-free aggregate report.
Finalised reads come from the service's append-only finalised source; blocks
are not retained by the runner.

All growth and logical-sizing inputs are required explicitly. The version-2
report takes fixed directory/event capacities and admission limits, charges the
compiled 38/82-byte cells across both complete tables, and emits independent
directory, event, hot-address, modeled-memory, and combined modeled-constraint
flags. The position-map width and backend expansion are uncalibrated operator
assumptions;
`fits_modeled_constraints` is not measured RSS, an insertion-success bound, or a
TDX qualification. The machine-readable report also states
`insertion_bound=false`, `backend_calibrated=false`, and `rss_measured=false`.
See `docs/notes/oram-phase0-1-feasibility-report.md` for the remaining gates.

Run `cargo run -p zainod-oram -- corpus --help` for the reproducible input set.
