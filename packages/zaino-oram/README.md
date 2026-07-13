# zaino-oram

`zaino-oram` is the internal research library for Zaino's proposed
host-oblivious private-query service.

The current research foundation contains deterministic models plus an optional
offline dependency experiment:

- fixed transparent-UTXO, 72-byte append-only event, and envelope shapes;
- immutable 38-byte protected-directory and 82-byte one-event page candidates;
- a private, pure two-table planner with network/schema-separated address keys,
  keyed fixed probes, fixed-array scan validation, and opaque insertion plans;
- a module-private synchronous command core that owns distinct typed directory
  and event handles, validates their public capacity shape before use, and
  models one full-history append preflight without executor-command
  interleaving;
- a bounded single-owner worker that moves that exact command core onto one
  thread and admits only whole `read_history` and `append` business commands,
  with no raw probe, key, record, read, or insert surface;
- fixed listener-free typed-worker correctness and `SmokeV1` stress
  qualifications. The latter performs a deterministic 64-step mixed workload
  with reference-model verification, checks a healthy command rejection, and
  exercises a separate terminal event-limit fault. Its report contains fixed
  public scenario/profile/backend/shape metadata plus aggregate counts, digests,
  flags, and worker snapshots, with no raw modeled identifiers, seed, or
  per-operation results. A portable in-memory run executes both exact worker
  scenarios and rejects fixed-seed probe-set exhaustion before native CI. It is
  CI-smoke correctness evidence, not target-load, benchmark, billion-operation,
  physical-trace, recovery, TDX, or mainnet evidence;
- compiled privacy-profile validation;
- a crate-internal versioned request/response codec that seals one
  complete-budget-derived profile ID, fixed checkpoint, prepared query,
  optional opaque 128-byte continuation field, session binding, protected
  outcome, and exact result slots into a single compile-time envelope. Checked
  layout arithmetic rejects profile/page shapes that cannot fit; the protection
  interface binds version/profile/session/direction context and must open the
  whole nonce/body/tag envelope before canonical decoding;
- a module-private listener-free runtime adapter that executes a versioned
  ten-phase logical schedule across decode, server material, token open,
  replay access, readiness selection, complete store scanning, fixed result
  normalization, token issue, response protection, and completion. It uses
  absolute logical store-slot continuation cursors and returns one protected
  fixed `InvalidContinuation` shape for invalid, expired, mismatched, or
  replayed tokens when no higher-priority store or projection-readiness failure
  applies. Token protection binds the checkpoint and codec session; each path
  models one replay lookup and write-back, while cover writes use a separate
  non-durable slot rather than the real-token namespace;
- an internal store interface and bounded plaintext mock implementation;
- exact logical store-call schedules and schedule-equivalence tests;
- an aggregate-only corpus measurement with an exact joint event/live/peak
  state histogram, a separately applied checked full-capacity two-table sizing
  model, and an optional adapter for canonical `zaino-state::IndexedBlock`
  streams;
- a bounded plaintext finalized-projection oracle plus a default-off
  `shadow-parity` fixture that compares every observed standard address with
  ordinary-source results at one identical immutable vector checkpoint;
- a private generic finalized-event coordinator that stages a complete public
  block into cloned plaintext resolver state, performs every ordered standard
  event sink call synchronously, and commits the in-memory checkpoint only
  after all calls succeed;
- a feature-gated private sink implementation on the owning business-command
  worker that derives the standard address from each event, admits one whole
  append command, and consumes its reply before reporting completion;
- a crate-internal offline projection owner that validates network, schema, key
  epoch, and all three projection/layout admission bounds before backend
  allocation, then exclusively owns the coordinator and worker through coarse
  readiness and consuming shutdown outcomes;
- a fixed continuation-token codec with injected protection/replay interfaces;
- `rostl-experimental`, pinned to `8c3a12d2`, which binds separate volatile
  `CircuitORAM` and recursive-position-map instances to the exact 38-byte
  directory and 82-byte event-page records on Linux x86_64. A private offline
  construction path places those stores behind the same business-command
  worker for the offline projection owner; it has no runtime/service caller,
  and unsupported hosts reject construction before creating upstream state.

It does **not** contain a production envelope protector or nonce owner,
production encryption, durable ORAM persistence, TDX attestation, protobufs,
or a network listener, and it makes no production privacy claim. Codec and
runtime tests
use a non-cryptographic deterministic integrity fixture; they prove exact
bytes, protection-interface plumbing, one single-bit rejection at every byte
offset, canonical rejection, and equality of the modeled logical phase/store
schedule—not cryptographic authentication, confidentiality, equal
instructions, allocator behavior, memory/page accesses, timing, or transport
work. The private runtime validates opaque continuation fields through injected
interfaces before engine use and collapses their semantic failures to one
protected outcome unless store or projection readiness takes precedence; it
does not supply production AEAD, nonce uniqueness, trusted time, or durable
replay protection.
The listener-free `zainod-oram corpus capture` runner can feed canonical
mainnet blocks into the core and atomically publish a revalidated
measurement artifact without sizing assumptions. The fully offline
`zainod-oram corpus size` command revalidates that complete artifact and applies
one explicit model into a separate digest-bound atomic qualification. No
full-mainnet capture or sizing artifact exists yet. Static fixture parity is
not live-backend, finalised-database, reorg, or mainnet shadow evidence.
The follow-on load-foundation slice adds read-only access to the explicit table
capacity and admission inputs. The companion `zainod-oram corpus
validate-sizing` command reopens an existing capture and sizing directory,
revalidates both existing bundles, and recomputes the sizing qualification
against the captured measurement. This creates no artifact and instantiates no
ORAM backend, store, or worker; it does not execute a load, measure performance,
or provide mainnet evidence.
Upstream `rostl` panic/recovery, persistence, side-channel, and licensing gates
remain unresolved.
The event coordinator is a portable sink/checkpoint ordering model. A private
offline owner composes it with the business-command worker and, on supported
hosts, the typed `rostl` stores, but no runtime or service calls that owner. The
coordinator retains the plaintext outpoint-owner resolver
needed to map spends to standard-address events. A sink failure may leave a
partial event prefix in the discarded sink candidate; the prior in-memory
checkpoint does not advance, the coordinator drops the sink and fails closed,
and no rollback or automatic retry is attempted. The checkpoint binds only the
public network, height/hash, schema version, and key epoch. It has no
authenticated state root, durable publication, rollback defense, or
crash-atomic coupling to sink mutations.
The worker can own either the fake-backed command core or, on Linux x86_64, the
two exact typed volatile `rostl` stores. It implements the private synchronous
projection-event sink and is consumed by the private offline projection owner,
but it is not connected to the query engine or durable checkpoint publication. Its
internal snapshot exposes queue/lifecycle plus aggregate completion, rejection,
and reply-delivery counters; no safe export policy is claimed. Queue saturation
rejects without fallback, shutdown drains accepted FIFO commands, and cloned
handles cannot access raw storage operations. Abandoning a read ticket does not
cancel accepted work and is nonterminal. Abandoning any append ticket latches
the same terminal fault, independent of whether the command has entered or how
the executor resolves it. The fault carries no outcome class, and the worker
returns fixed history rather than an insert/replay disposition. Internal reply
variants are not yet mapped to a uniform protected service outcome. A command
already in flight when a late abandonment latches may finish its backend call,
but its reply fails closed; commands that have not entered the executor do no
further backend I/O. Retaining a reply ticket does not block worker progress or
shutdown. Panics caught by the worker, synchronous connector, or event
coordinator—including a discarded sink's destructor—still invoke Rust's
process-wide panic hook, so future real backend panic payloads must be
identifier-free and a panic-free or controlled boundary remains a production
requirement. Candidate records are not zeroized, and accepted
volatile mutations have no durable acknowledgement or crash-retry guarantee.
An unexpected worker-loop panic makes the active accepted command's outcome
indeterminate and drops the uniquely owned executor.
The one-event page is the deliberately inefficient append-only compatibility
baseline: filling a multi-event tail page would require an upsert. The typed
adapter implements logical unique insertion with the same two-access sequence
for a healthy miss and duplicate: read/remap, then remap and
`write_or_insert`. `Cmov` selection supplies the requested record on a
miss and the exact previously read bytes on a duplicate. A duplicate therefore
changes physical ORAM position state but preserves the logical record and
occupancy; the table reports a coarse duplicate failure. Result disagreement,
an impossible occupancy state, or a caught upstream panic terminal-latches the
table. An indeterminate write still requires discard and reconciliation.
The direct table stays usable after a definite duplicate, but the enclosing
two-table executor treats any insertion error as terminal because its preflight
should have excluded that duplicate.
An impossible occupancy state is already terminal corruption: its detection
may stop after the first read/remap rather than performing the healthy
two-access schedule. No uniform physical failure schedule is claimed.

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

This remains an unauthenticated volatile research backend, not a production
ORAM store or authenticator.
The module-private synchronous connector obtains occupancy from its owned typed
backends, scans the directory and every bounded event ordinal on successful
preflights, validates a contiguous history, derives the next ordinal, and
preflights both insertions before its first write. A possible partial or
uncertain mutation terminal-latches the connector as unusable. The offline owner
preserves only the prior committed checkpoint, consumes and joins the failed
worker, and forbids retry or later backend I/O; rebuild orchestration remains
absent. Its fake handles model the command semantics portably; the
offline Linux constructor separately owns the two real typed backends. This is
not crash atomicity, persistence, rollback, or a physical obliviousness claim.
The connector is wired to the module-private business-command worker, whose
Linux-only offline constructor can own the two typed `rostl` stores. That
constructor is composed with the projection coordinator by the private offline
owner. No runtime or service calls the owner, and the connector is not wired to
a query engine or durable checkpoint publisher.

Cross-table script ownership is checked for the requested event, but an
unrelated event collision cannot be associated with its directory without more
protected reads or a wider authenticated record. The 38/82-byte formats
contain no MAC,
generation tag, content authentication, or rollback protection. The injected
seed and keyed-hash state are not zeroized or memory-locked, and no seed
generation, persistence, or rotation lifecycle exists. Source-level fixed
scanning is not proof of equal instructions, branches, allocations, memory/page
accesses, or timing. The pure planner still accepts caller-supplied vacancy and
occupancy model inputs; the module-private connector and worker close
executor-command TOCTOU, and the Linux-only offline constructor creates two
non-aliased ORAM/map pairs. The old raw worker surface has been removed. The
portable schedule tests exercise the same insertion helper used by the real
stores. The actual Linux backend and worker run in the inherited generic native
CI lane. Final capture-head native run `29224873175` passed strict all-target,
all-feature Clippy and all 161 tests while executing the complete typed
store/coordinator/owner lifecycle. Exact `SmokeV1` head `17356db0` passed
strict all-target, all-feature Clippy for both research crates plus the
204-test `zaino-oram` and 39-test `zainod-oram` suites in native run
`29250757780` (job `86818420630`); its Linux-only qualification tests exercised
the real typed backend. This is generic hosted-Linux correctness evidence, not
target-CPU, TDX, load, benchmark, billion-operation, mainnet, or physical-trace
qualification. Reply abandonment
relies on the module-private trusted owner dropping tickets normally;
deliberately leaking a ticket with `mem::forget` is outside this offline model.

The canonical dummy encoding is versioned `[1, 0, ...]`; all-zero `Default` or
`Zeroable` storage is invalid and may only be an ignored scratch buffer after a
definitive backend miss. In a sparse table, only a backend miss is free: finding
a canonical dummy is corruption, not reusable capacity, and pre-inserting
dummies would make later real inserts reject as duplicates. The differing
record sizes are safe only in distinct typed stores; a future unified padded
value needs an authenticated kind tag.
Slots, ordinals, occupancy, and nested event fields remain sensitive and must
not enter logs, errors, or metrics. The volatile two-ORAM worker has no
authenticated composite commit, durable checkpoint coupling, or seed
persistence/rotation protocol. The
logical sizing model charges every allocated 38-byte directory cell, every
allocated 82-byte event cell, and position-map entries for both full capacity
domains; occupancy changes admission/load flags but never reduces modeled
bytes. Its flat position-map width and backend expansion remain uncalibrated
operator assumptions. They do not model the pinned backend's tree blocks,
recursive maps, stash, initialization temporaries, allocator/runtime working
set, or measured RSS. `fits_modeled_constraints` therefore combines only
configured count limits with the uncalibrated memory model; it is not proof of
insertion success, collision probability, TDX fit, or 30% RSS headroom. The
sizing qualification carries `insertion_bound=false`,
`backend_calibrated=false`, and `rss_measured=false` alongside those booleans;
none of these assumptions or projections is part of a corpus measurement.
The schedule model does not establish equal instruction, memory, allocation,
page, timing, or packet behavior.
Those components remain gated by ADR-0007 and the feasibility criteria in
`docs/notes/oram-enabled-zaino-plan.md`.
