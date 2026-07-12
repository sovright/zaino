# zaino-oram

`zaino-oram` is the internal research library for Zaino's proposed
host-oblivious private-query service.

The current research foundation contains deterministic models plus an optional
offline dependency experiment:

- fixed transparent-UTXO, 72-byte append-only event, and envelope shapes;
- immutable 38-byte protected-directory and 82-byte one-event page candidates;
- a private, pure two-table planner with network/schema-separated address keys,
  keyed fixed probes, fixed-array scan validation, and opaque insertion plans;
- a module-private synchronous command core that owns distinct directory and
  event fake-backend handles, validates their public capacity shape before
  use, and models one full-history append preflight without executor-command
  interleaving;
- compiled privacy-profile validation;
- an internal store interface and bounded plaintext mock implementation;
- exact logical store-call schedules and schedule-equivalence tests;
- an aggregate-only corpus accumulator, checked full-capacity two-table sizing
  model, and optional adapter for canonical `zaino-state::IndexedBlock` streams;
- a bounded plaintext finalized-projection oracle plus a default-off
  `shadow-parity` fixture that compares every observed standard address with
  ordinary-source results at one identical immutable vector checkpoint;
- a fixed continuation-token codec with injected protection/replay interfaces;
- `rostl-experimental`, pinned to `8c3a12d2`, which compile-checks the fixed
  event as `Pod`/`Cmov` and exposes an offline volatile adapter only on Linux
  x86_64. A bounded single-owner worker serializes both reads and inserts,
  rejects queue saturation without fallback, drains accepted work before
  joining, rejects queue capacities outside the research bound of 1..=4096,
  and reports identifier-free aggregate lifecycle counters. Other targets fail
  real-worker construction explicitly while still testing the worker mechanics
  against a deterministic fake backend.

It does **not** contain production encryption, durable ORAM persistence, TDX
attestation, protobufs, or a network listener, and it makes no production
privacy claim. The listener-free `zainod-oram corpus` runner can feed canonical
mainnet blocks into the core, but no full-mainnet measurement artifact exists
yet. Static fixture parity is not live-backend, finalised-database, reorg, or
mainnet shadow evidence. Upstream `rostl` panic/recovery, persistence,
side-channel, and licensing gates remain unresolved.
The worker is not connected to the projection or query engine, and its queue
metrics expose aggregate load. Panics caught by either the worker or synchronous
connector still invoke Rust's process-wide panic hook, so future real backend
panic payloads must be identifier-free and a panic-free or controlled boundary
remains a production requirement. Candidate records are not zeroized, and
accepted volatile mutations have no durable acknowledgement or retry guarantee.
An unexpected worker-loop panic can make the active accepted command's outcome
indeterminate. Automatic retry is forbidden: discard the volatile candidate and
reconcile or rebuild it from an authoritative checkpoint first.
The one-event page is the deliberately inefficient append-only compatibility
baseline: filling a multi-event tail page would require an upsert, while the
current candidate overwrites before reporting a duplicate. Immutability and
unique-key allocation are therefore preconditions, not properties enforced by
the adapter: duplicate insertion is destructive, is not an idempotency probe,
and requires discarding the entire candidate store. An indeterminate write has
the same discard-and-reconcile requirement.

The record shapes are not authenticated, but the pure layout model now checks
their logical placement before use. It derives canonical address keys from the
network, schema, standard script class, and full 20-byte hash; binds both sparse
tables to one secret-seeded generation; uses an odd-step keyed BLAKE2s probe
sequence over power-of-two capacities; and consumes fixed arrays so every
configured probe is inspected before a result or immutable insertion plan is
returned. A different identity in a candidate slot is a valid collision only
when its stored identity owns that physical probe. Exact directory matches bind
their full key and physical slot. Exact event matches bind directory slot plus
ordinal and must derive the same address key from the event script.

This remains a logical model, not a real ORAM backend or authenticator.
The module-private synchronous connector obtains occupancy from its owned typed
fake backends, scans the directory and every bounded event ordinal on successful
preflights, validates a contiguous history, derives the next ordinal, and
preflights both insertions before its first write. A possible partial or
uncertain mutation terminal-latches the connector as unusable, pending owner
discard and rebuild. Its unaliased fake handles model no executor-command
interleaving; they do not prove non-aliasing for a future real backend. This is
not crash atomicity, persistence, rollback, or a physical obliviousness claim.
The connector is not wired to the existing worker, projection, query engine,
or `rostl` adapter.

Cross-table script ownership is checked for the requested event, but an
unrelated event collision cannot be associated with its directory without more
protected reads or a wider authenticated record. The 38/82-byte formats
contain no MAC,
generation tag, content authentication, or rollback protection. The injected
seed and keyed-hash state are not zeroized or memory-locked, and no seed
generation, persistence, or rotation lifecycle exists. Source-level fixed
scanning is not proof of equal instructions, branches, allocations, memory/page
accesses, or timing. The pure planner still accepts caller-supplied vacancy and
occupancy model inputs; the module-private connector closes only
executor-command TOCTOU in its unaliased fake model. The current `rostl` worker
still exposes separate raw read and insert commands and is not a safe
integration surface, so integrating the two requires replacing that raw
command surface in a later slice.

The canonical dummy encoding is versioned `[1, 0, ...]`; all-zero `Default` or
`Zeroable` storage is invalid and may only be an ignored scratch buffer after a
definitive backend miss. In a sparse table, only a backend miss is free: finding
a canonical dummy is corruption, not reusable capacity, and pre-inserting
dummies would turn later real inserts into destructive duplicates. The differing
record sizes are safe only in distinct typed stores; a future unified padded
value needs an authenticated kind tag.
Slots, ordinals, occupancy, and nested event fields remain sensitive and must
not enter logs, errors, or metrics. No real composite two-ORAM store, worker
connector, or seed persistence/rotation protocol is implemented. The
logical sizing model charges every allocated 38-byte directory cell, every
allocated 82-byte event cell, and position-map entries for both full capacity
domains; occupancy changes admission/load flags but never reduces modeled
bytes. Its flat position-map width and backend expansion remain uncalibrated
operator assumptions. They do not model the pinned backend's tree blocks,
recursive maps, stash, initialization temporaries, allocator/runtime working
set, or measured RSS. `fits_modeled_constraints` therefore combines only
configured count limits with the uncalibrated memory model; it is not proof of
insertion success, collision probability, TDX fit, or 30% RSS headroom. The
version-2 report carries `insertion_bound=false`, `backend_calibrated=false`,
and `rss_measured=false` alongside those booleans.
The schedule model does not establish equal instruction, memory, allocation,
page, timing, or packet behavior.
Those components remain gated by ADR-0007 and the feasibility criteria in
`docs/notes/oram-enabled-zaino-plan.md`.
