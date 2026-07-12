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

All growth and logical-sizing inputs are required explicitly. The resulting
`fits_memory` field is a model result, not a measured RSS or TDX qualification.
See `docs/notes/oram-phase0-1-feasibility-report.md` for the remaining gates.

Run `cargo run -p zainod-oram -- corpus --help` for the reproducible input set.
