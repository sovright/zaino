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
  thread and admits only whole address-history, key-addressed live-slot, and
  append business commands, with no caller-supplied probe, raw record, table,
  or insert surface;
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
- a separate deterministic `FullMapSaturationV1` qualification. Independent
  workers fill the directory-admission and event-admission bounds exactly while
  the other table retains reserve, verify the complete admitted state, then
  require one boundary-crossing append to fail closed and latch terminal state.
  Its distinct aggregate report is evidence about logical admitted-map
  boundary correctness only—not physical table exhaustion, random or
  adversarial target-load behavior, performance, recovery, TDX, or mainnet
  readiness;
- compiled privacy-profile-v5 validation that binds the logical store and
  recent-snapshot budgets, padded inputs, fixed response/envelope shapes,
  cover/token lifetime, timeout bucket, and a single-worker FIFO
  queue/overload policy, plus total committed replay-transaction capacity,
  the parameter named public trusted-time expiry-bucket width, and the parameter
  named proactive fixed garbage-collection interval. These replay-policy values
  contribute to profile identity; v5 also binds the authenticated replay-entry
  v2 semantics. It does not provide trusted time or execute expiry, garbage
  collection, deletion, or capacity reclamation.
  Runtime fixtures bind a nonzero recent-snapshot shape and execute its complete
  ordinal-only scan through a concrete runtime-owned
  `FrozenRecentSnapshot<N>`. Each frozen snapshot binds an in-memory generation,
  exact finalized identity, recent tip height/hash, and its internally computed
  fixed-slot commitment;
- a crate-internal versioned request/response codec that seals one
  complete-budget-derived profile ID, fixed checkpoint, prepared query,
  optional opaque 128-byte continuation field, session binding, protected
  outcome, and exact result slots into a single compile-time envelope. Checked
  layout arithmetic rejects profile/page shapes that cannot fit; the protection
  interface binds version/profile/session/direction context and must open the
  whole nonce/body/tag envelope before canonical decoding;
- crate-internal XChaCha20-Poly1305 protection primitives for request envelopes,
  response envelopes, and continuation tokens. The three roles own separate
  zeroized 256-bit key objects, use fixed 192-bit nonces, and authenticate
  distinct canonical domain prefixes plus every existing public
  protection-context field. Fixed vectors and exhaustive single-byte mutation
  tests over the shared primitive, plus cross-direction and
  continuation-context tests, pin the wrapper contract. This is a
  cryptographic primitive only. The full raw security-bundle composer is
  restricted to `#[cfg(test)]`; those fixtures exercise real request/response
  and continuation protection, wrong-key rejection, token-tamper rejection,
  and replay rejection without exposing either concrete key-bearing type.
  Non-test runtime code instead retains one profile-bound, non-`Clone`
  `ActiveSecurityLease` as the sole owner of its protection, replay, material,
  namespace, epoch, and release authority. No service/session handshake, key
  derivation/provisioning/rotation, nonce source or uniqueness owner, trusted
  clock, runtime-integrated durable replay provider, attestation binding, or
  KMS/TDX lifecycle is selected. The required joint ownership, rollback, and
  release contract is fixed by
  [ADR 0009](../../docs/adr/0009-private-query-runtime-security-state-owner.md);
- a module-private witness-bound security-state persistence foundation. Its
  fixed-width, versioned snapshot binds stable service, protocol, owner, key,
  projection, profile, session, and security-epoch identity to opaque serving
  and component-state digests. A mutation stages and synchronizes the local
  snapshot before advancing an injected exact sequence-and-digest freshness
  witness. Startup accepts only an exact local/witness match; missing, corrupt,
  mismatched, oversized, or ambiguous state fails closed without automatic
  repair. Version-one transitions prohibit namespace and epoch rollback and
  require complete binding rotation with a new owner generation. The crate
  provides no production witness, atomic component/witness transaction, or
  runtime caller for this foundation;
- a module-private crash-durable local replay-journal foundation. It implements
  the existing atomic request plus real-or-cover continuation guard seam using
  a fixed-size sealed version-two current-state record and version-two entry
  records (`ZORJENT2`). Each persisted real continuation claim is one
  authenticated typed value containing its opaque replay key and a nonzero,
  one-based ceiling expiry-bucket ordinal. The authenticated current record
  remains version two and binds the exact compiled profile ID; protection also
  binds an opaque journal context, and all fixed record widths are unchanged.
  The next sequence candidate becomes durable before
  `current.bin`, the sole local commit marker, and committed entries are then
  immutable. Startup opens only the exact committed sequence paths and never
  inspects the later candidate; every retry uniformly replaces that
  non-authoritative path. Only a deterministic test protector exists. The
  store is not runtime-wired, its total committed-transaction bound is derived
  from the compiled profile and is lifetime cumulative. Committed entries are
  not expired, deleted, compacted, or reclaimed, and request claims have no
  expiry. The store assumes one live writer without a process lock.
  At this standalone-journal layer, an absent `current.bin` opens as empty so
  an initial pre-marker crash can retry; the journal alone cannot detect
  deletion of a previously committed marker. It supplies no rollback resistance,
  trusted time, nonce journal, production key/nonce owner, or access-oblivious
  memory or persistence;
- a module-private replay/snapshot coordinator. Initial provisioning is an
  explicit operation distinct from opening existing state. Existing-state open
  accepts only an exact outer-snapshot/current-replay match. Each successful
  replay commit's sealed durable path mints one move-only receipt binding its
  opaque per-open journal identity and pre- and post-commit digests. Before
  advancing the outer local snapshot and injected witness, the coordinator
  checks that the same live journal recognizes the receipt and its post-commit
  digest is still current. It never infers transition direction or repairs
  either store. Any outer failure after a replay commit latches that coordinator
  instance fail closed. A hard witness rejection leaves durable
  local state ahead, so a fresh open fails with `WitnessLocalMismatch`; an
  advance-then-error can fresh-open successfully when the witness did advance.
  No non-test runtime or security-owner caller constructs the coordinator in
  this slice. Replay, outer-snapshot, and witness advancement are not one atomic
  transaction. Profile ID v5 binds total committed replay-transaction capacity
  and the named expiry-bucket-width and garbage-collection-interval parameters
  together with the entry-v2 semantics. Journal/coordinator construction
  derives the lifetime-cumulative transaction bound from the compiled profile,
  and outer-sequence exhaustion is rejected before replay commit. There is no
  trusted-time provider, replay-maintenance expiry or eligibility
  classification, maintenance state or watermark, deletion, count reduction,
  compaction, reclamation, or garbage-collection path. Request claims have no
  expiry. V5 requires fresh provisioning and does not migrate or dual-accept v4
  state; any
  later incompatible persisted replay successor requires another profile
  identity. A future maintenance mutation must mint a dedicated receipt
  consumed through the serialized replay-current -> outer-local -> witness
  path. Runtime/owner wiring remains open;
- a module-private listener-free runtime adapter that executes a versioned
  ten-phase logical schedule across decode, server material, token open,
  replay access, readiness selection, complete recent-snapshot and finalized
  store scanning, fixed result normalization, token issue, response protection,
  and completion. Its serving-epoch contract accepts one generation-bound
  lease and derives both the finalized store and currentness observer from that
  lease. It scans an immutable clone of the pinned `FrozenRecentSnapshot<N>`;
  the snapshot's fixed-slot content commitment is computed internally, and its
  lineage digest additionally binds its generation, exact finalized identity,
  and recent tip height/hash. Fault and
  post-construction corruption hooks are `#[cfg(test)]` only and absent from the
  production API. The runtime binds that lineage digest into the continuation
  query digest; each round completes the configured scan before rechecking exact
  checkpoint identity and recomputing both the content and lineage commitments.
  It merges recent creates and spends before pagination and uses one combined
  finalized-plus-recent continuation cursor domain. Malformed same-outpoint
  sequences, owner mismatches against finalized outputs, and duplicate creates
  become a protected all-dummy `ProjectionNotReady` result only after the full
  modeled work and latch readiness. Query-derived `source_calls` remain modeled
  at zero. Invalid, expired, mismatched, and replayed tokens return one protected
  fixed `InvalidContinuation` shape when no higher-priority store or
  projection-readiness failure applies. Token protection binds the checkpoint
  and codec session; each path models one replay lookup and write-back, while
  cover writes use a separate non-durable slot rather than the real-token
  namespace. After the complete response is protected and the logical trace is
  finished, the runtime observes the lease-bound currentness capability and
  double-checks the epoch and recent-generation Arcs; a stale or unavailable
  observation discards the encoded envelope as one uniform external failure;
- a private single-writer recent-snapshot publication model that clears an
  active generation before refresh, uses an opaque ticket for exact activation,
  retains immutable pinned leases, and permits a final current-generation
  check. Deterministic tests cover advances, same-height and shortening reorgs,
  failed builds, stale tickets, finalized rollback, and overflow. Under
  `corpus-zaino`, the owner accepts a generation-free converted candidate only
  through the current outstanding ticket, requires its finalized identity and
  recent tip height/hash to match the ticket exactly, and moves its slots into
  the owner-generated `FrozenRecentSnapshot`. Direct raw-slot activation exists
  only for tests. Under the same feature, a private refresh controller
  invalidates publication before its sole await, captures and validates the
  Zaino transparent-projection input, converts under the outstanding ticket,
  rechecks the opaque source boundary, and publishes one serving-epoch Arc
  last. That epoch binds an owner-issued finalized store with matching identity,
  the exact recent generation, the opaque NFS revision, and a query-independent
  currentness capability. A default-off, crate-internal non-test factory consumes
  one already-pinned lease specialized to the concrete finalized serving store
  and constructs the listener-free runtime. It derives all six protected
  checkpoint fields from the lease identity and accepts no independent
  checkpoint, store, or currentness observer. A private process-lifetime owner
  now retains that exact refresh controller and one stable runtime state. Each
  refresh retires the active runtime epoch before capture, refreshes the
  controller from the committed checkpoint of the supplied exact finalized
  store, pins only the controller-published epoch, and activates it through the
  exact-lease path. Epoch replacement preserves the injected envelope and token
  protectors, replay guard, material source, codec session binding, compiled
  profile, and monotonic fail-closed health. Failed refresh, pinning, or runtime
  construction leaves no active epoch and never restores the stale one;
  repeated logical stop is idempotent. A listener-free response-release gate
  lets one completed round retain a non-`Clone` outstanding permit. While that
  permit is held, later handle, refresh, and explicit shutdown attempts reject
  before mutating retained owner or runtime state; dropping it reopens the gate
  unless it is already closed, while a successful stop or owner drop closes the
  gate permanently. Once refresh has retired the epoch, cancellation never
  restores it;
- the crate's only public private-query runtime boundary is the small
  lifetime-safe `FixedEnvelopeRuntime`, `PendingFixedEnvelope`, and
  `PrivateQueryUnavailable` facade. A pending value retains the guarded round
  while lending response bytes, so callers cannot extract detached response
  bytes. The concrete process/runtime owner remains private, with no public
  constructor or factory;
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
  readiness. A consuming Ready-only handoff now moves the exact worker into a
  non-cloneable read-only finalized serving-store facade, derives its six-field
  serving identity inside the owner boundary, and leaves no append-capable
  handle behind. Every successful in-profile logical slot read, absent a
  backend or worker failure, executes one complete fixed-profile
  directory/event-history command and folds the full padded history into dense
  creation-order live outputs without a cross-call cache. The fold rejects
  decreasing event heights and any event above the owner-bound committed
  checkpoint. Invalid histories and worker faults collapse to one unavailable
  store error;
- a fixed continuation-token codec with injected protection/replay interfaces;
- `rostl-experimental`, pinned to `8c3a12d2`, which binds separate volatile
  `CircuitORAM` and recursive-position-map instances to the exact 38-byte
  directory and 82-byte event-page records on Linux x86_64. A private offline
  construction path places those stores behind the same business-command
  worker for the offline projection owner and its Ready-only serving-store
  handoff. The exact-lease factory and process-lifetime owner are its
  crate-internal non-test runtime construction seams; there is no service or
  listener caller, and unsupported hosts reject construction before creating
  upstream state.

It does **not** contain a production protector/replay/material-provider bundle,
trusted clock or nonce ledger, durable ORAM persistence, TDX attestation,
protobuf route, or network listener, and it makes no production privacy claim.
Codec and runtime tests
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
The earliest frozen-snapshot evidence used mock-constructed contents. The
adjacent publishable `zaino-state` crate exposes an ORAM-agnostic snapshot API
that value-binds a caller-supplied finalized checkpoint to one immutable NFS
snapshot, checks its declared tip, height-map segment from seam through tip,
mapped payload identities, and parent continuity, then returns blocks strictly
above the seam without DB/source fallback. Its current-boundary read rechecks
canonical-component readiness and opaque NFS Arc identity before returning.
Under the default-off `corpus-zaino` feature, a private refresh controller uses
that input, an immutable identity-pinned finalized-outpoint classifier, and the
ticketed publication owner to build and publish a serving epoch. Publication is
last and binds the owner-issued finalized store, owner-assigned recent
generation, opaque NFS Arc identity, and query-independent post-work,
runtime-return currentness capability. The crate-internal exact-lease factory
can consume an already-pinned epoch containing the concrete finalized serving
store and build the listener-free runtime. The runtime derives its store, observer, and
protected checkpoint only from that lease, completes the fixed-work response,
and performs the final fail-closed observation before returning it.

The private process-lifetime owner now invokes that controller's live-subscriber
refresh path, owns one stable runtime state, retires its active epoch before
capture, pins the controller-published epoch, and activates a replacement only
after deriving the protected checkpoint from the exact store-bound lease
identity. The runtime's injected protectors, replay guard, material source,
session binding, compiled profile, and health latch survive epoch replacement;
health can only move toward failed closed. A failed refresh or replacement has
no stale fallback, and repeated logical stop remains a no-op after the first
stop. One non-`Clone` response permit can remain outstanding after a completed
round. While it is held, later handle, refresh, and explicit shutdown attempts
reject before changing owner or runtime state. Dropping the permit reopens the
gate unless it is already closed; a successful stop or owner drop closes it
permanently. Once refresh has retired the active epoch, cancellation never
restores it. The finalized-runtime pending round also owns a narrow release
witness over its expected epoch identity, cloned opaque capture boundary, and
shared currentness observer. Its first fallible byte borrow atomically enters checking,
re-observes and compares the source, and commits authorization; mismatch,
observer failure, or owner closure leaves the gate closed. Unpolled drop makes
no observation. The witness retains neither the serving lease nor the
finalized store, so an intentionally protected terminal response remains
releasable after internal epoch retirement when the source still matches its
exact capture.

This private composition seam does not enforce a process-wide singleton. The
adjacent `zainod-oram` package now consumes the exported lifetime-safe facade
from its crate-private listener-free adapter and mock-backed custom Tonic
codec/body. The body retains only the pending value
until its first outbound poll, then gates its fixed-envelope protobuf encoding
on a fallible release-time currentness check. A stale response emits no DATA and
one uniform `Unavailable` trailer shape; dropping an unpolled body releases the
pending value without borrowing its bytes.

That adjacent mock proof does not construct or route this crate's concrete
process owner, or implement a generated Tonic service or listener. The
finalized-runtime
witness is internal to this crate; tests exercise the exact helper delegated to
by the owner, not a successfully refreshed ready-owner lifecycle. A public
constructor or factory is intentionally absent; concrete production providers
must satisfy ADR 0009 before the private owner can be assembled outside tests.
The protection primitives still have no production key/session/nonce owner and
there is no qualified durable replay or trusted-material bundle. This does
not implement or prove concurrent
query admission, FIFO execution, queue saturation, overload rejection,
waiting, deadlines, draining, or clean shutdown of the underlying worker. Its
stop is logical: it retires the active runtime epoch and rejects later
handle/refresh attempts. The real response permit and late-release witness
remain listener-free and are not integrated with the response body or a
transport write. Neither release check establishes currentness at socket write,
peer delivery, or transport completion; the canonical source may advance
immediately afterward. Lifetime-safe cross-crate real-owner body integration
remains open.
The separate security-state store fixes local-before-witness ordering and exact
startup reconciliation for a future composite-state digest, but it has no
production freshness witness and does not persist nonce reservations, trusted
time, or keys. A separate local replay journal now persists the logical request
and continuation claim sets, but remains runtime-unwired, unwitnessed, and
protected only by a test fixture; runtime replay state therefore remains
volatile. A module-private coordinator owns both stores in this foundation.
Explicit initial provisioning is distinct from existing-state open, which
requires the outer snapshot to match the current replay digest exactly. A
successful replay commit's sealed durable path mints a move-only receipt that
binds its opaque per-open journal identity and pre/post digests. The coordinator
accepts it only from that same live journal and while its post-digest remains
current, then advances the outer local snapshot and injected witness. It
performs no direction inference or repair. A post-replay outer error latches the
same instance; a hard witness rejection fresh-opens as
`WitnessLocalMismatch`, while witness advance-then-error can reconcile on a
fresh open. No non-test runtime or security-owner caller constructs the
coordinator. The three ordered persistence/authority steps are not one atomic
transaction.
Profile ID v5 binds replay capacity and the named public trusted-time
expiry-bucket-width and proactive fixed garbage-collection-interval parameters
and the authenticated replay-entry v2 semantics. Each persisted real
continuation claim is one typed value containing its opaque replay key and
nonzero, one-based ceiling expiry-bucket ordinal. The journal derives its
lifetime-cumulative persisted capacity from the compiled profile and seals that
exact profile ID in its unchanged version-two current record; all fixed record
widths remain unchanged. The ordinal is metadata, not an expiry or deletion
decision. There is no trusted-time provider, replay-maintenance expiry or
eligibility classification, maintenance state or watermark, request-claim
expiry, garbage
collection, committed-entry deletion, count reduction, compaction, or capacity
reclamation. V5 state requires fresh provisioning and has no v4 migration or
dual acceptance. Any later incompatible persisted replay successor requires a
new profile identity. A future maintenance mutation must mint a dedicated
receipt consumed through the serialized replay-current -> outer-local ->
witness path. The available XChaCha20-Poly1305 protectors are wired only
through a private fixture-backed runtime composition, not a production
key/session owner; the clock/material source and nonce/replay mechanisms are
not production implementations. The frozen snapshot's lineage digest binds
owner-assigned generation and exact finalized/tip metadata to the internally
computed deterministic slot
commitment, but does not authenticate that metadata or prove its canonical
ancestry. Neither commitment is an authenticated canonical/live Zaino snapshot
root. This slice supplies no durable persistence, authenticated provenance,
production cryptographic ownership, physical-obliviousness, allocator or timing
equivalence, rollback resistance, TDX, target-load, or mainnet evidence.
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
