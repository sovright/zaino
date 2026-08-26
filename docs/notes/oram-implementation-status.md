# ORAM-enabled Zaino implementation status

- Split from the normative delivery plan on 2026-07-23.
- Architecture and gates: [ORAM-enabled Zaino fork plan](oram-enabled-zaino-plan.md).
- Evidence ledger: [Phase 0/1 feasibility report](oram-phase0-1-feasibility-report.md).
- Current stop-gate result:
  [Phase 0 kill-gate report](oram-phase0-kill-gates-2026-07-23.md).
- Current project decision: Phase 0 remains NO-GO for private-server integration
  on technical measurement and compiled-obliviousness grounds. Licensing
  remains a tracked distribution-readiness concern, not a Phase 0 blocker.
- Completed Gate 1 capture operation:
  [2026-07-26 mainnet capture log](oram-phase0-mainnet-capture-log-2026-07-26.md).
- Gate 1 insertion-budget implementation work log:
  [2026-07-27 work log](oram-gate1-insertion-budget-status-2026-07-27.md).
- Completed current-profile Gate 1 insertion evidence:
  [2026-07-27 mainnet insertion-bound log](oram-gate1-mainnet-insertion-bound-log-2026-07-27.md).
- Gate 1 live-base/chunked-delta sizing work log:
  [2026-07-28 work log](oram-gate1-hybrid-sizing-status-2026-07-28.md).
- Completed Gate 1 Mainnet hybrid-sizing result:
  [2026-07-29 result and provisional logical finalist](oram-gate1-hybrid-sizing-result-2026-07-29.md).
- Completed Gate 2 dynamic timing campaign result:
  [2026-07-28 timing evidence](oram-gate2-timing-evidence-2026-07-28.md).
- Recorded fixed-work versus SLO constraint:
  [2026-07-31 consistency note](oram-fixed-work-slo-consistency-2026-07-31.md).
- Codegen-guard churn analysis and its ADR:
  [2026-08-11 churn note](oram-codegen-guard-churn-2026-08-11.md).
- Recent-snapshot scan-width analysis:
  [what the evidence actually says](recent-snapshot-scan-width.md).

This file is the implementation chronology. Entries here describe completed
research slices and their limits; they do not override the normative plan or
clear any Phase 0 gate.

Implementation began on `feat/oram-private-foundation` after fast-forwarding the
local `dev` branch to the recorded target fork point. The initial implemented
scope establishes the ADR, fixed business/persistence/envelope and continuation
shapes, exact profile coupling, a bounded plaintext test store, logical
store-call schedule tests, mainnet corpus capture and measurement tooling
separated from the full-capacity two-table sizing model, a shared transparent
event seam, and a
pinned volatile `rostl` experiment. Later stacked slices add a module-private synchronous command core
over two typed table interfaces, a bounded worker that owns that exact core,
and separate volatile `rostl` stores for the exact 38-byte directory and
82-byte event-page records.
The core validates the public capacity shape, performs a complete directory
plus bounded-history preflight, derives the append ordinal from owned-backend
observations, and terminal-latches a possibly partial mutation for discard. The
worker admits only whole history-read/append commands; the former raw-key and
raw-record worker surface is removed. Their deterministic fake model prevents
executor-command interleaving. A private Linux-only offline constructor creates
two non-aliased ORAM/map pairs and places them behind the same worker. A
crate-internal offline owner validates the projection/layout identity and
admission profile before allocation, composes the finalized-event coordinator
with that worker, and consumes shutdown without exposing raw stores. No runtime
or service calls the owner. Its healthy
miss/duplicate insertion path always performs read/remap followed by
write-or-insert/remap, selecting the prior bytes on duplicate. This path has
generic native Ubuntu 24.04 x86_64 execution evidence at small 8/16-entry table
capacities in a dedicated CI lane with immutable action pins and pinned
Rust/nextest tools, in addition to the current macOS host's portable and
cross-compile checks. This does not claim target-capacity behavior, physical
obliviousness, TDX qualification, or crash atomicity. A later portable slice adds
a private generic finalized-event coordinator: it stages a whole block through
the existing plaintext spend-owner resolver, completes every synchronous event
sink call, and commits the in-memory checkpoint last. The owning atomic worker
now implements that private sink boundary and consumes each append reply before
returning. The private offline owner composes the coordinator, worker, and
`rostl` stores, while a sink failure can still leave a partial prefix in a
discarded candidate. A later listener-free contract slice adds a crate-internal
versioned request/response codec with checked profile-capacity coupling, a
complete-budget-derived profile ID, fixed checkpoint/query/token/session/result
fields, direction separation, canonical decoding, and an injected
whole-envelope protection interface. Its deterministic protector is a
non-cryptographic test fixture. A later provider slice adds crate-internal
XChaCha20-Poly1305 implementations with separately owned zeroized request,
response, and continuation role-key objects plus canonical domain-separated
associated data. A private opaque dependency composer now exercises those
providers end to end through the listener-free runtime: wrong request keys fail
before material/replay work, while encrypted pagination, token tampering, a
valid continuation claim, and replay rejection retain the complete modeled
trace. A later internal security-contract slice replaces the independent
material/counting-replay fixture seams in that composition with one
crate-private, fixture-only owner. Canonical versioned identities distinguish
authenticated request-nonce replay from continuation replay. One atomic
in-memory transaction always completes the request lane together with a cover
or claim-or-cover continuation lane and returns a semantic duplicate decision
plus a non-`Clone` replay-commit authority. Material acquisition returns a
separate non-`Clone` reservation authority for the exact fixture time and
nonces. An opaque process-local security epoch binds both authorities to the
same round and validates them together with epoch currentness at response
release; unavailable or retired state fails closed.

This remains deterministic in-process fixture evidence. It provides no
production durable replay, trusted clock, nonce ledger, key management,
rollback resistance, TDX, listener, transport-write, or peer-delivery
evidence. Profile ID v6 binds the existing replay-policy dimensions,
replay-entry v2 (`ZORJENT2`), and replay-current v3 (`ZORJCUR3`). Each persisted
real continuation claim remains one authenticated typed value containing its
opaque replay key and a nonzero, one-based ceiling expiry-bucket ordinal. The
fixed-width current record now stores a `u64` maintenance watermark while
entry v2 and all record widths remain unchanged. Zero is the sentinel for no
classified bucket; a nonzero value is the inclusive recorded highest fully
expired continuation expiry bucket for future maintenance classification. The
raw recorded value is not authority. This state executes no request expiry,
garbage collection, replay-entry deletion, claim-count reduction, compaction,
reclamation, or bounded retention, so capacity remains lifetime cumulative.
The runtime's bare host-supplied `u64` remains observed time rather than
trusted-time authority. The existing ten-phase logical schedule is unchanged.
The required joint owner, rollback, lifecycle, and response-release invariants
are fixed by
[ADR 0009](../adr/0009-private-query-runtime-security-state-owner.md), while
production provider selections and evidence remain open. The private child
runtime owns the modeled decode/token/replay/full-scan/issuance/encode sequence,
validates combined finalized-plus-recent cursors, preserves token expiry across
pages, maps semantic token failures to one protected fixed
`InvalidContinuation` page
when no higher-priority store or projection-readiness failure applies, and
records the same ordered ten-phase logical trace for successful protected
outcomes. Token protector context binds the checkpoint and codec session, and
every replay path models one lookup plus one write-back while cover writes stay
outside the real-token namespace.
The profile-v6 ID binds that schedule, the continuation lifetime, padded input
and response shapes, the recent-snapshot scan budget, the timeout bucket, an
explicit single-worker FIFO execution/queue/reject-at-capacity policy, and the
three public replay-policy dimensions plus the authenticated replay-entry-v2
and replay-current-v3 semantics. The listener-free runtime now executes a nonzero, profile-bound,
ordinal-only full scan through a concrete runtime-owned
`FrozenRecentSnapshot<N>`. The frozen type computes its fixed-slot content
commitment internally rather than accepting a generic source-reported digest;
its fault and post-construction corruption hooks are `#[cfg(test)]` only and
absent from the production API. The runtime binds the
snapshot's in-memory generation, exact finalized identity, recent tip
height/hash, and content commitment into one lineage digest. Continuation query
binding v2 uses that digest, and each round completes the configured scan before
rechecking exact checkpoint identity and recomputing both content and lineage
commitments. It merges recent creates and spends before paginating
across the combined cursor domain. Malformed same-outpoint sequences, owner
mismatches against finalized outputs, and duplicate creates fail closed as a
protected all-dummy `ProjectionNotReady` result only after full modeled work and
latch readiness. Query-derived `source_calls` remain modeled at zero. This
closes only the mock-constructed logical scan/merge slice. A private in-memory
single-writer publication model now retires the active generation before
refresh, admits only its opaque outstanding build ticket, and lets pinned leases
check whether they remain current. A default-off `corpus-zaino` slice supplies a
private, generation-free conversion candidate that consumes
`CanonicalRecentChainSnapshot` plus an immutable, identity-pinned
finalized-outpoint classifier, preserves dense standard-event slots in canonical
order, and tracks nonstandard states. The private publication owner remains the
sole generation authority: it accepts that candidate only through its current
outstanding ticket, requires exact finalized identity and recent tip height/hash,
and moves the candidate's slots into `FrozenRecentSnapshot`. Direct raw-slot
activation is test-only. A private refresh controller now invalidates before its
only await, consumes one coherent finalized-plus-NFS capture, performs conversion
under the outstanding ticket, rechecks the opaque source boundary, and publishes
one atomic serving-epoch Arc last. That Arc binds an owner-issued finalized
store generation whose identity must match, the owner-assigned recent
generation, the opaque NFS revision, and the post-work, runtime-return
currentness capability. A separately tested listener-free runtime contract
accepts the same lease shape, derives both its finalized store and observer from
that lease,
scans an immutable copy of the pinned recent generation, executes and protects
the complete fixed-work response, then re-observes the exact finalized identity
and source boundary. Any mismatch, unavailable observation, or in-flight epoch
replacement latches readiness and discards the encoded envelope as one uniform
external failure. A default-off, crate-internal non-test factory consumes
one already-pinned serving-epoch lease specialized to the concrete finalized
store and constructs that runtime. It derives all six protected checkpoint
fields from the lease identity rather than accepting an independent checkpoint,
store, or currentness observer. A private process-lifetime owner now retains
that exact refresh controller and one stable runtime state. It retires the
active runtime epoch before capture, passes the committed checkpoint of the
supplied exact finalized store into the controller, pins only the
controller-published epoch, and derives the replacement runtime checkpoint from
that exact store-bound lease identity. Epoch replacement preserves the injected
envelope/token protectors, replay guard, material source, codec session binding,
compiled profile, and monotonic fail-closed health. Failed refresh, pinning, or
epoch construction leaves no active epoch and never restores the stale one.
Repeated logical stop is idempotent. A listener-free response-release gate now
allows one completed response to retain a non-`Clone` outstanding permit.
While held, that permit makes later handle, refresh, and explicit shutdown
attempts reject before mutating retained owner or runtime state. Permit drop
reopens the gate unless it is already closed; a successful stop or owner drop
closes it permanently. The finalized-runtime pending round now also owns only
the expected epoch identity, cloned opaque capture boundary, and shared
currentness capability needed for release. Its first fallible byte borrow atomically moves
the gate through checking and authorization, re-observes the source, and closes
admission permanently on mismatch, unavailability, or owner closure. Dropping
an unpolled pending round performs no observation. The witness does not retain
the serving lease, snapshot, or finalized store, so an intentionally protected
terminal response remains releasable after internal epoch retirement when the
source still matches its exact capture. Once refresh has retired the epoch,
cancellation never restores it. A private Ready-only adapter now consumes the
exact finalized projection worker into an
identity-bound, non-cloneable serving store. Every successful in-profile read,
absent a backend or worker failure, executes a complete key-addressed
fixed-history worker command and folds the full padded event history into dense
creation-order live outputs without caching. Decreasing event heights and events
above the exact owner-bound checkpoint are rejected. The process-lifetime owner
is not an enforced process singleton or service caller. Its release gate is
not a listener, transport-write, or currentness-at-write proof. Its late
release check is internal to `zaino-oram`, and the canonical source may advance
immediately after that check. It does
not establish concurrent admission, FIFO execution, queue/overload handling,
waiting, deadlines, draining, or clean underlying-worker shutdown. An
independent `zaino.private.v1` query protobuf and a crate-private listener-free
`zainod-oram` adapter tested against a mock runtime port now exist. A custom
mock-backed Tonic codec/body retains the pending response until first outbound
body poll, checks currentness before borrowing the fixed bytes, emits the exact
protobuf DATA frame on success, and suppresses a stale response as uniform
`Unavailable` trailers with no DATA. Dropping an unpolled body performs no
check or byte borrow. The concrete owner, its bytes, and release permit remain
private. The adapter does not construct the owner or implement the generated
Tonic service. A lifetime-safe real-owner facade and body integration remain
open; there is not yet a non-test production protector/replay/material provider
bundle from which to build an honest public owner factory. Body-poll currentness
is not socket-write or peer-delivery currentness.
The logical stop only retires the active epoch and rejects later handle/refresh
attempts. This path does not authenticate the tip, ancestry, or slot
provenance. The lineage commitment is not an authenticated canonical/live Zaino
snapshot root. Live NFS
service routing, authenticated provenance, durable rollback authority, physical
obliviousness, allocator and timing equivalence, TDX, mainnet, and target-load
evidence remain open.
Production AEAD, trusted clock and nonce ownership, witness-backed replay
storage integrated with the outer state and runtime, guarded real-owner
protobuf body/transport framing, concrete owner routing, and a service
lifecycle also remain integration gates.

The private crate now has the first persistence sub-slice required by that
provider bundle: a fixed-width composite security-state snapshot and an
injected exact sequence-and-digest freshness-witness contract. The local
snapshot becomes durable before witness advancement; restart serves only an
exact local/witness match, while mismatches and ambiguous commits fail closed.
The version-one successor policy keeps service/protocol/profile identity stable,
prevents owner/key/projection regression, and requires a new owner generation
plus fresh session/security bindings for rotation.
The next component sub-slice is also present: a crate-private local replay
journal implements the atomic request plus applied real-or-cover continuation
guard using exact fixed-size records sealed under an opaque journal context. It
synchronizes a replaceable `head + 1` candidate before atomically replacing
`current.bin`, treats that file as the sole local commit marker, and rebuilds
only its exact sequence prefix. Recovery never opens the later candidate;
every retry replaces it uniformly, while committed entries remain immutable.
Duplicate requests and continuations both record cover, and one public
transaction bound is enforced before any secret-dependent claim condition.
The journal has only a deterministic test protector, derives its total
transaction bound from compiled profile v6, has no process lock for its assumed
single writer, and has no runtime caller. Its unchanged entry-v2 format
(`ZORJENT2`) persists each real continuation claim as one authenticated typed
value containing the opaque replay key and a nonzero, one-based ceiling
expiry-bucket ordinal. Current v3 (`ZORJCUR3`) adds a recorded `u64`
maintenance watermark, and all fixed record widths remain unchanged.

A module-private coordinator now binds the replay journal into the outer
security-state snapshot. Explicit initial provisioning is distinct from opening
existing state; an existing open accepts only an exact
outer-snapshot/current-replay match. A successful query replay commit's sealed
durable path mints one move-only replay receipt. A greater maintenance
watermark's durable current-only path mints a distinct move-only maintenance
receipt, so maintenance cannot be mistaken for request replay. The coordinator
accepts either only from the same live journal and while its post-transition
digest remains current, then advances the outer local snapshot and injected
witness without inferring transition direction or repairing either store. Both
follow replay-current -> outer-local -> witness ordering. Any outer failure
after replay-current advances latches that coordinator instance fail closed. A
hard witness rejection leaves local state ahead and makes a fresh open fail
with `WitnessLocalMismatch`; an advance-then-error can fresh-open successfully
when the witness did advance.
These foundations are not a concrete production witness or protector, a nonce
or trusted-time journal, a key/nonce owner, runtime/owner construction path, an
atomic combined replay/snapshot/witness transaction, deployed rollback result,
or access-oblivious memory/page/storage/timing implementation. Profile ID v6
binds total committed replay-transaction capacity, public trusted-time
expiry-bucket width, proactive fixed garbage-collection interval,
authenticated entry-v2 semantics, and current-v3 semantics.
Journal/coordinator construction derives the persisted transaction bound from
that profile and preflights outer-sequence exhaustion before replay commit.
The watermark is a `u64`: zero is the sentinel for no classified bucket, and a
nonzero value is the inclusive recorded highest fully expired continuation
expiry bucket for future maintenance classification. A lower proposal rejects.
An equal proposal returns typed `NoAdvance` without a write, receipt, or outer
sequence advance. A greater proposal durably advances replay-current and mints
the distinct maintenance receipt without appending an entry or changing claim
sets or counts. The raw recorded watermark is not trusted-time, epoch, profile,
currentness, expiry, or retirement authority. Profile v6 requires fresh
provisioning with no migration or dual acceptance of profile-v5/current-v2 or
earlier state.

The mutation/coordinator surface remains module-private with no non-test caller
and no trusted-time/epoch/profile grant. Any visibility widening or runtime
wiring must first consume a live epoch/profile/currentness-bound move-only
grant. There is no request expiry, garbage-collection execution, replay-entry
deletion, count reduction, compaction, reclamation, or bounded retention;
capacity remains lifetime cumulative.

The adjacent publishable `zaino-state` crate now exposes the ORAM-agnostic
`ChainIndexSnapshot::canonical_recent_chain` seam. It value-binds a
caller-supplied finalized `BlockIndex` to one immutable NFS `Arc`, verifies the
seam, declared tip, height-map segment from seam through tip, mapped payload
identity, and parent continuity, ignores side blocks, and returns cloned blocks
strictly above the seam oldest-first without DB/source fallback. The private
`corpus-zaino` conversion candidate can consume this value together with an
immutable, identity-pinned finalized-outpoint classifier, preserve dense
standard-event slots, and track nonstandard states without assigning a
generation. The private publication owner can consume that candidate only
through the matching outstanding ticket, verify its exact finalized/tip metadata,
and construct the owner-generated `FrozenRecentSnapshot`; direct raw-slot
activation remains test-only. The controller publication contract and the
listener-free runtime consumption contract exercise the same generation-bound
epoch-lease shape, including the owner-issued finalized store, opaque NFS Arc
identity, and bound post-work, runtime-return currentness capability. The
process-lifetime owner provides a non-test path that drives the controller
refresh, pins its published lease, and replaces only the runtime's epoch-scoped
engine/snapshot/lease state while retaining its process-scoped dependencies,
session/profile, replay state, and health latch. It retires before capture and
offers no stale fallback after a failed refresh or build; once refresh has
retired the epoch, cancellation does not restore it.
Its listener-free response gate permits one non-`Clone` completed response to
remain outstanding and rejects handle/refresh/shutdown before mutating retained
owner or runtime state until permit drop reopens it unless already closed;
successful stop and owner drop close it permanently. The finalized-runtime
pending round adds an internal first-release witness over exact identity,
opaque capture, and the same currentness capability, with atomic fail-closed
authorization before its byte borrow. It retains neither the serving lease nor
the store, performs no observation when dropped unpolled, and still permits an
intentionally protected terminal response after internal epoch retirement when
the source capture remains exact. An adjacent crate-private
listener-free adapter validates the independent query protobuf against a mock
runtime port without exposing the concrete owner's bytes or permit. Its custom
Tonic codec/body retains the mock pending response until first outbound body
poll, then checks currentness before fixed-envelope protobuf encoding. Tests
prove the exact successful DATA frame, stale suppression as uniform
`Unavailable` trailers with no DATA, and cancellation before poll without a
response-byte borrow. The application does not construct or route the real
owner, and no generated service or listener calls it. No enforced process
singleton, concurrent admission/FIFO/queue/wait/deadline/drain policy,
real-owner response-body integration, transport-write or peer-delivery
currentness proof, or clean worker-shutdown proof exists. The canonical source
may advance after either release check. This path does not provide persistence,
an authenticated root or provenance, durable
rollback authority, production cryptography/clock/nonces/replay, physical or
timing evidence, TDX, target-load, or mainnet service evidence.

The following two paragraphs preserve the evidence boundaries of earlier
slices; their then-current controller and epoch limitations are superseded only
by the private, separately tested contracts above, not by production service
integration.

At exact conversion code head
`32084cd8e047c64b34fcfae5fd0283533fe21793`, a detached worktree on the
dedicated Ubuntu 24.04 x86_64 GCP builder passed all 294 all-feature
`zaino-oram` tests, strict all-target Clippy with `clippy::unwrap_used` denied,
and rustfmt. This is cache-preserving generic-builder correctness evidence for
the conversion candidate only; it is not production-resolver, runtime,
generation/publication, atomic whole-serving-epoch, service/cryptography,
target-load, physical-obliviousness, TDX, or mainnet evidence.

At exact owner-handoff code head
`a55728308ff4e3cf5189079b923b84345dd3069f`, a detached worktree on the
same builder passed all 299 all-feature `zaino-oram` tests, including four
Linux-only real-backend cases; nextest run
`d665131d-1a08-4248-a308-c92e1cc5bd0b`. Strict all-target Clippy with
`clippy::unwrap_used` denied passed in 16.81 seconds, and rustfmt passed. This
covers exact ticket/candidate metadata matching, capability consumption,
stale-ticket preservation, owner-only production lineage/frozen construction,
and content/generation binding. It remains generic-builder correctness evidence,
not a production resolver or caller, live DB/NFS acquisition, race-free refresh
controller, atomic whole-serving epoch, durability, authenticated provenance,
service/cryptography, target-load, physical-obliviousness, TDX, or mainnet
evidence.

The typed-qualification slice added a listener-free qualification runner for the real
typed worker. It executes one fixed nine-command correctness sequence covering
empty reads, inserts, an exact replay, independent address histories, and clean
shutdown, then emits only correctness totals and identifier-free aggregate
worker counters. The default-off `typed-qualification` feature exposes
`zainod-oram qualification run`, which publishes that report as an atomic,
read-back-verified three-file JSON, text, and digest-bound provenance artifact.
The native Linux lane compiles, lints, and tests both research crates. At exact
`SmokeV1` head `17356db0`, native run `29250757780` (job `86818420630`) passed
strict all-target/all-feature Clippy for both crates plus the 204-test
`zaino-oram` and 39-test `zainod-oram` suites; its Linux-only qualification
tests exercised the real typed backend.
The artifact digest binds the compact typed JSON report into provenance only;
staged read-back separately checks the text rendering. The bundle is unsigned,
self-reported, and explicitly unbound from source, lockfile, toolchain, binary,
CI-run identity, or execution attestation.
This slice is not a benchmark and supplies no latency, RSS, stash, physical
access-trace, persistence, TDX, mainnet-capacity, or runtime-service evidence.
The subsequent isolated offline slice added a separate named `SmokeV1` stress
qualification. It executes a fixed 64-step mix of reads, unique appends, and
exact replays across four modeled addresses, checks a bounded reference model
after each command and in periodic/final sweeps, and checks that a cross-address
command rejection leaves the worker healthy. A separate constrained worker
checks that an accepted second unique append exceeds the event limit, returns
`FailedClosed`, and latches terminal state; one later read and append are
rejected at admission, and shutdown returns the expected stopped, faulted
snapshot. Its CLI exposes no numeric or backend tuning knobs. The artifact
contains fixed public schema/profile/backend/shape metadata, aggregate
counters/digests/flags/snapshots, and unsigned target-label provenance; it
contains no raw modeled address/event/seed fields or per-operation results.
This closes a CI-smoke correctness gap only: target-load and adversarial
full-map experiments, a `10^9`-operation soak, latency/RSS/stash/queue-load
measurement, physical trace, persistence and recovery, target CPU/TDX, signed
provenance, full-mainnet sizing, and the mainnet gate all remain separate
required work. The follow-on load-foundation slice adds a read-only `corpus
validate-sizing` command that reopens and revalidates the existing capture and
sizing bundles, then recomputes the sizing qualification against its captured
measurement. It creates no artifact, accepts no runtime or workload knobs,
instantiates no ORAM backend, store, or worker, and makes no load, performance,
hardware, or mainnet claim.
The adjacent `FullMapSaturationV1` slice is a separate deterministic
qualification, not an extension of `SmokeV1`. Two independent workers reach
the exact directory-admission and event-admission boundaries while retaining
physical table reserve, verify all admitted histories and replay behavior, and
then require the next boundary-crossing append to fail closed and latch. Its
separate aggregate artifact closes only the logical admitted-map boundary
correctness gap. At that slice boundary, random or adversarial target-load
experiments, actual physical capacity exhaustion, performance and memory
measurements, persistence and recovery, physical traces, target CPU/TDX, signed
provenance, full-mainnet sizing, and the mainnet gate remained open.
The next `BuilderFoundationV1` slice adds a separate source-bound target-load
foundation for a generic Linux x86_64 builder. It consumes a complete validated
capture plus its recomputed sizing qualification, then uses the sizing model's
exact directory/event capacities, admission limits, and per-address event bound
only when they fit a fixed research envelope: power-of-two directory capacity
64..=512 with admission at least 48, power-of-two event capacity 128..=4096
with admission at least 96, 3..=64 events per address, four probes per table,
and a one-command worker queue. Warmup stops 16 directory slots and 48 event
slots below the supplied admission limits. The deterministic shuffled measured
phase then performs exactly 256 blocking commands: 160 hot reads, 48 reads from
the resident non-hot warmup set (the fixed `cold` class), 32 unique appends to
hot addresses, and 16 unique appends to new cold addresses, filling both
logical admission limits while checking every result against an in-memory
reference model. The report records typed-worker call latency with synthetic
input preparation and result verification outside each command timer. Its
nearest-rank percentiles therefore describe the synchronous worker API; with
48 append samples, append p99 equals the maximum. Mixed-phase completion rates
use the entire measured-phase wall clock, including driver preparation and
correctness checks, and are not isolated read or append throughput. It also
records process-wide `/proc/self/status` RSS samples and the process-lifetime
`VmHWM` (including pre-run driver/runtime memory), clean-shutdown lifecycle/queue counters,
and a deterministic logical occupied-probe collision schedule. It explicitly
marks queue contention as unmeasured and both stash state and physical access
traces as `backend-unobservable`.

The listener-free command is:

```text
zainod-oram qualification target-load \
  --profile builder-foundation-v1 \
  --capture-dir <CAPTURE_DIR> \
  --sizing-dir <SIZING_DIR> \
  --output-dir <NEW_DIR>
```

Publication is restricted to Linux x86_64 and produces a distinct
read-back-verified JSON/text/provenance bundle. The output may not be nested
under either validated input, and staged read-back is rebound to both loaded
sources. Even when executed on the
dedicated GCP builder, this profile is only a bounded single-caller research
measurement. It does not qualify the intended CPU or TDX instance, durable
persistence or recovery, a `10^9`-operation soak, full-mainnet capacity,
attestation, signed provenance, stash behavior, physical-obliviousness, or
mainnet readiness.
The following recovery-foundation slice adds a crate-internal, fixed-width
authenticated public projection manifest. Each immutable content-addressed
manifest binds a monotonic publication sequence, the prior manifest digest,
network/schema/key identity, a per-rebuild projection epoch, finalized
height/hash, event count, and a deterministic semantic event-log root. A keyed
BLAKE2s MAC authenticates the manifest while an injected external freshness
witness advances only from the exact prior sequence/digest pair to the exact
next pair. Publication orders the immutable manifest and non-authoritative
`CURRENT` hint before the external witness, with deterministic failpoints at
each boundary; restart ignores `CURRENT`, authenticates the witness-selected
manifest, and either requires a fresh genesis-forward worker rebuild or remains
unready. The projection coordinator publishes only after all worker mutations
succeed and commits its in-memory checkpoint only after publication; publisher
errors and panics fail the candidate closed. Portable fake-worker tests and a
Linux-x86_64-gated typed-ROSTL test exercise shutdown, restart, a new projection
epoch, and semantic-root equivalence across deterministic rebuild.

This is public checkpoint/freshness and rebuild-contract evidence, not durable
ORAM recovery. The ROSTL buckets, recursive position maps, stash, table
contents, and query-induced mutations remain volatile; no production
freshness-witness or key owner is wired, no cold-rebuild RTO is measured, and
the recovery directory remains a trusted, exclusive-writer boundary.
The next source-bound rebuild slice adds a listener-free mainnet qualification
runner for one fresh volatile worker. It validates the capture/sizing lineage,
freezes a non-finalized source snapshot, preverifies the capture checkpoint
before allocation, and feeds every genesis-forward block to both the typed
projection owner and a fresh corpus scanner. A report is accepted only when the
recomputed measurement exactly equals the capture, the worker reaches the exact
checkpoint and semantic root, and shutdown is clean. Session drop also shuts
down and discards an unfinished candidate.

Its declared rebuild budget intentionally measures only worker allocation
through source-matched readiness. Source-service startup, snapshot selection,
checkpoint preverification, shutdown, and artifact publication are recorded or
performed outside the pass/fail window; this is not labeled a full-service RTO.
The atomic three-file artifact records the source backend, fixed snapshot,
serviceable and verified checkpoint, and explicitly uncontrolled source-cache
state. A budget miss is valid negative evidence: the artifact is published
before the command returns failure. The slice therefore supplies source-bound
fresh-worker replay plumbing and timing semantics, not controlled cold-cache,
target-hardware, durable recovery, TDX, physical-trace, full-mainnet, or mainnet
readiness evidence.

The completed insertion-budget slice reuses the validated full-Mainnet
capture/sizing lineage and a preverified fixed source snapshot, but analyzes
only the current 1x-capacity, four-probe layout under eight fixed deterministic
schedules and a zero-bps sampled failure budget. All eight schedules exhausted
both table lanes. The runner atomically published and read-back validated its
three-file typed NO-GO artifact before returning the documented unsuccessful
status. This is exact-profile sampled negative evidence, not a probability
distribution, probabilistic or worst-case bound, alternative-profile result,
backend calibration, physical trace, target-hardware/TDX result, or mainnet
readiness claim. Exact run context and the preserved artifact are in the
[dated insertion-bound log](oram-gate1-mainnet-insertion-bound-log-2026-07-27.md).

The hybrid-sizing slice adds a separate fixed-profile source-bound replay for a
logically immutable live-UTXO base plus bounded append-only add/spend delta
generations. It preserves created-versus-spent event kind, reconstructs the
identifier-free final live-UTXO histogram, and computes base-page shapes for
1, 8, and 16 entries plus genesis-aligned delta maxima for 288-, 1,152-, and
8,064-block public intervals. Generation page totals sum individually rounded
per-address requirements; they do not assume cross-address packing. This is
model input only: it implements no serving store, generation switch, compactor,
growth projection, backend calibration, RSS/TDX measurement, failure bound, or
readiness claim. The bounded scope and next evidence step are recorded in the
[dated hybrid-sizing work log](oram-gate1-hybrid-sizing-status-2026-07-28.md).

The Gate 2 remediation stack removes secret-dependent control flow from the
ORAM insertion path and then builds the apparatus that would detect its return.
A compiled-output guard fails the build when the access path leaves its
approved codegen profile; it pins a complete per-instruction profile including
memory addressing, a closed mnemonic allowlist, exact `Cmov` loop bounds, call
multiplicity, byte-range coverage, and a non-vacuity check. Because it reads
x86-64 ELF release output, it runs only on Linux x86-64 and a maintainer host
on another architecture cannot exercise it. On top of that the stack adds a
paired timing experiment driver and then hardens the evidence it produces:
matched long-lived tables, predeclared measurement matrices, a durable attempt
ledger, an independent evaluator, and a null control that discards the arm
label and performs identical work through both arms. The driver builds a fresh
table per measurement and times only the single insertion; both arms insert the
same probe key and hold occupancy equal, differing only in the filler set,
which removes key identity and table growth as confounds. This is measurement
apparatus, not a result.

The campaign result is recorded and clears nothing. The null control puts the
harness baseline at `|AUC - 0.5| <= 0.026` and also exposes a systematic +33 to
+63 ns mean difference between first- and second-measured positions with no
hit/miss distinction present, so the mean difference is not a usable statistic
here and the rank statistics carry the result. The directory arms separate at
capacity 1,024 across seven seeds, five to six times baseline, because insert
and overwrite genuinely differ in cost inside upstream `write_or_insert`.
Wall-clock stops resolving that difference by capacity 4,096 and it does not
return at 8,192 or 16,384. The honest reading is *not measurable by this method
at these sizes*, not *oblivious*: production capacity is 16,777,216, three
orders of magnitude beyond where the signal vanished, and a rising noise floor
masks a leak rather than removing it, so a PMU or cache-timing adversary could
recover what wall-clock cannot. The operator-supplied assumption that upstream
`rostl` is trusted on secret-dependent branches is recorded as an explicit
named premise while 68 unclassified upstream branches remain. This is
wall-clock evidence from one harness on one host class; it supplies no PMU,
cache, or physical-trace result, and Gate 2 moves only by written review. Exact
figures and the premise are in the
[dated timing-evidence note](oram-gate2-timing-evidence-2026-07-28.md).

The same sweep produces a constraint that two already-recorded numbers cannot
both satisfy. The Gate 1 capture records a fixed-work floor of 13,440,092
logical accesses per request; the Gate 1 qualification inputs propose a
completed-query p99 of 1,000 ms; together they allow 74 ns per logical access.
Measured per-insertion cost is 4,849 ns at capacity 1,024 fully cache-resident,
rising to 12,424 ns at 16,384 — the fastest operation measured anywhere, at a
configuration 16,384 times smaller than the production directory, already
exceeds that budget by 65x. This does not show the design infeasible. It shows
that the flat 4 + 4H schedule and a one-second p99 cannot both hold, and that
fixed work and service SLO are one joint decision rather than two independent
qualification rows. The measurements are sufficient to establish the
constraint, not to satisfy it, and it closes no blocking row. The derivation is
in the [dated consistency note](oram-fixed-work-slo-consistency-2026-07-31.md).

A separate slice addresses guard churn without weakening detection. Five
recorded guard failures were unrelated to the properties the guards protect,
and two ended in a wrong conclusion being reported — once genuine drift called
churn, once the reverse. The proposal note and ADR 0901 identify pinned callees
by mangled path prefix plus a complete asserted instantiation count instead of
full hashes, require both guards to report provenance and CI to refuse a stale
base, and derive the expected symbol size, branch count and return count from
the reviewed profile rather than restating them. The ADR's second decision —
pinning the codegen-unit partition — was made conditional on a Linux x86-64
experiment, which ships as a script plus a `workflow_dispatch`-only job that is
a diagnostic and on no push or pull-request trigger. The experiment was then
run and reported: stable at codegen-units 16 and stable at 1, injected code
volume moving nothing at either setting, so by the record's own decision rule
the partition hypothesis is refuted, decision 2 is withdrawn rather than
adopted on faith, and `[profile.release] codegen-units = 1` is not set. The
premise is corrected in place as well: churn event 4 had been recorded as
unrelated cross-crate code moving a symbol when the same branch also added
same-crate code, and the disassembly shows all three guarded symbols growing
identically, branches, returns and calls unchanged at exactly 26, 1 and 4, and
the new instructions being an auto-vectorised byte-wise record serialisation.

Two guard-mechanism repairs follow from that reading, and neither admits the
codegen it was prompted by. The RIP-relative constant pin becomes an ordered
sequence — each entry carrying mnemonic, destination register and exact bytes,
matched by position, with the pinned byte length also the width compared and a
load at an unpinned position failing closed — replacing two hard-coded 16-byte
`pand` masks whose pairing was itself unchecked and which could not express the
third, 4-byte constant the vectorised form loads. The pinned sequence is
unchanged in content, so the committed profiles still match; the change adds
the capacity to express a third constant without adding one. Separately, the
guard's emission path is split from its enforcing path by an explicit size
policy, so candidate profiles can be regenerated after a size change without
editing the pin blind first, while checking still enforces it; the guard's own
fixtures now derive their symbol addresses from the size constant so their
adjacency and overlap assertions stay meaningful across regenerations. The
committed pins still describe the pre-vectorisation codegen: `EXPECTED_SYMBOL_SIZE`
remains `0xca9`, no regenerated profile has been admitted, ADR 0901 requires
manual assembly review before any is, and the measured mnemonic set needs four
additions and three removals before it could regain set-equality. This slice
supplies detection mechanism and one refuted hypothesis; it supplies no
compiled-obliviousness result and clears no part of Gate 2. The failure
inventory is in the
[dated churn note](oram-codegen-guard-churn-2026-08-11.md) and the decisions in
[ADR 0901](../adr/0901-oram-codegen-guard-symbol-identity.md).

On the query side, the recent-snapshot scan width — previously marked only as
unmeasured — is derived from the committed Gate 1 capture and then refused. The
recent snapshot is one flat all-address array, so the statistic that sizes it
is the widest generation's *total* delta events at the selected 288-block
interval, not the per-address maximum the earlier comment cited; the
per-address histogram is a marginal over the wrong axis and cannot size this
dimension at any resolution. The new sizing module is deterministic and
integer-only, takes the exact maximum over generations plus a growth margin
rather than a quantile — because a narrow recent width means the generation
cannot be published at all, for anyone, where a narrow finalized width costs
one address a round trip — and returns an explicit unserviceable verdict rather
than a truncated width. `MAINNET_QUERY_SLOTS` is left at 256 and the
fail-closed conversion is kept. Two follow-on slices change the cost rather
than the verdict: the two query-independent `N^2` sweeps are hoisted out of the
query into a per-generation precomputed scan, dropping the per-query polynomial
to `(store_reads + 1) * N` and raising the admissible ceiling, with results
proved unchanged against verbatim copies of the removed predicates kept as
oracles; and publication's own pair sweep is replaced by a shared sort on
outpoint, making publication `O(N log N)` and verified bit-identical against
those same oracles exhaustively over all 2,197 three-slot snapshots plus named
fixtures. Publication is off the request path and reads only public snapshot
data, so its comparison sort carries no per-query signal. A further slice
models the whole argument in code: both join strategies, both ceilings, both
costs and the verdict become one computed value, the two levers that could
close the residual are priced and neither is tuned, and the annotation pass's
feasibility threshold is stated as a testable function of an unmeasured
distinct-address count. ADR 0900 is corrected in the same slice: address →
txids is a different fold over the same stored history, not a second
address-keyed projection with its own width. The committed mainnet capture
remains unservable under every modelled join, no readiness flag is set, and no
width, threshold or budget constant is moved. The numbers, the levers and what
the analysis does not claim are in the
[scan-width note](recent-snapshot-scan-width.md).

The record-annotation stack then builds the design change that analysis names
as the blocking item, up to but not including its production publication pass.
The store gains an oblivious in-place update — a compare-and-set on an occupied
slot, routed on the typed backend through the already-qualified exact-upsert
schedule the codegen guard disassembles and pins — and records gain a
three-bit annotation carried in spare address-cell flag bits, so the record
width that feeds the ORAM block size and the guard's `Cmov` loop bound is
unchanged and the pinned profile identifier does not move. Business equality
ignores the annotation and replay identity is still decided against the
appended event, so exact-replay and uniqueness keep their meaning. The set of
writes a command may perform is closed as an explicit mutation enum, and the
annotate command runs the same complete fixed read schedule as a read before
its single compare-and-set. ADR 0902 states the extended contract — store union
annotations are a pure function of source and generation — verified against the
source-bound cold-rebuild qualification rather than assumed, and records both
what it does not cover and the obligations an annotation pass must satisfy.
Subsequent slices supply those pieces: the annotation computation itself, which
delegates to the query's own join so the stored value is by construction the
value the query would have computed; a validated admission reserve, so a
profile sized one slot below capacity is rejected at configuration instead of
refusing every annotation at the first write; the history ordinal behind every
live slot, without which a pass built on the existing fold would have written
the wrong record for any address ever spent from; the pass's permitted access
shape, which allows a varying per-address write count because the pass has no
client and runs over public chain shape, and forbids annotating a padding
ordinal; and a write path on the serving-store facade reachable only through
`&mut self`, never through the store handle a query sees, with a caller-owned
filter that declines a record before any oblivious schedule is paid for.

The hoist itself then lands on the read side: the annotation travels through
the fold and out to the engine, and the query reads the stored pair instead of
rescanning the snapshot once per finalized slot. An occupied record carrying no
annotation fails closed as not-ready rather than recomputing the join, because
recomputing would silently restore the per-query cost the hoist exists to
remove while answering from a generation that never published the record. What
has *not* landed is the production publication-time pass: the store's
annotation entry point has no non-test caller, and the recent-snapshot
publication controller contains no annotation code, so on `main` the annotation
is written only by tests and harnesses. The distinct-address measurement that
decides whether one annotation pass fits one rebuild interval is also still
unmeasured. This stack therefore supplies a store contract, a computation, an
access-shape obligation, a write path and an engine read path; it supplies no
mainnet capacity result, no wall-clock measurement of an annotated-join query,
and no readiness claim, and it moves neither the scan width nor the comparison
headroom. The contract is in
[ADR 0902](../adr/0902-store-annotations-are-a-pure-function-of-source-and-generation.md).

The fork contains no production
encryption, durable ORAM, network service, attestation, or production privacy
claim. Per the Phase 0 stop rule, private-server work remains closed while the
mainnet/RSS, recovery, side-channel, and hardware gates are open. The missing
authoritative repository license and notice evidence remains tracked as
distribution-readiness due diligence, not a Phase 0 blocker.
