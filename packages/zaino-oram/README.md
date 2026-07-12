# zaino-oram

`zaino-oram` is the internal research library for Zaino's proposed
host-oblivious private-query service.

The current research foundation contains deterministic models plus an optional
offline dependency experiment:

- fixed transparent-UTXO, 72-byte append-only event, and envelope shapes;
- immutable 38-byte protected-directory and 82-byte one-event page candidates;
- compiled privacy-profile validation;
- an internal store interface and bounded plaintext mock implementation;
- exact logical store-call schedules and schedule-equivalence tests;
- an aggregate-only corpus accumulator, checked memory-sizing model, and
  optional adapter for canonical `zaino-state::IndexedBlock` streams;
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
metrics expose aggregate load. Caught panics still invoke Rust's process-wide
panic hook; candidate records are not zeroized, and accepted volatile mutations
have no durable acknowledgement or retry guarantee. An unexpected worker-loop
panic can make the active accepted command's outcome indeterminate. Automatic
retry is forbidden: discard the volatile candidate and reconcile or rebuild it
from an authoritative checkpoint first.
The one-event page is the deliberately inefficient append-only compatibility
baseline: filling a multi-event tail page would require an upsert, while the
current candidate overwrites before reporting a duplicate. Immutability and
unique-key allocation are therefore preconditions, not properties enforced by
the adapter: duplicate insertion is destructive, is not an idempotency probe,
and requires discarding the entire candidate store. An indeterminate write has
the same discard-and-reconcile requirement.

These are self-described record shapes, not an authenticated layout. The future
layout must validate a directory cell's stored slot and address key against its
logical read key, validate an event cell's stored directory slot and ordinal,
and prove that the event script class/hash belongs to the referenced address.
The canonical dummy encoding is versioned `[1, 0, ...]`; all-zero `Default` or
`Zeroable` storage is invalid and may only be an ignored scratch buffer after a
definitive backend miss. In a sparse table, only a backend miss is free: finding
a canonical dummy is corruption, not reusable capacity, and pre-inserting
dummies would turn later real inserts into destructive duplicates. The differing
record sizes are safe only in distinct typed stores; a future unified padded
value needs an authenticated kind tag.
Slots, ordinals, occupancy, and nested event fields remain sensitive and must
not enter logs, errors, or metrics. No protected table allocator, fixed-probe
lookup, composite backend, or page-capacity sizing claim is implemented yet.
The schedule model does not establish equal instruction, memory, allocation,
page, timing, or packet behavior.
Those components remain gated by ADR-0007 and the feasibility criteria in
`docs/notes/oram-enabled-zaino-plan.md`.
