# Private-query keys, nonces, time, and replay state share one rollback-resistant owner

## Status

Accepted for the ORAM research fork as the required runtime-owner contract.
This decision does not select a KMS, trusted-time authority, freshness witness,
durable store, session handshake, or TDX deployment. It does not authorize a
service, host-obliviousness claim, or mainnet privacy claim.

## Context

[ADR 0007](0007-private-query-service-and-leakage-model.md) treats the host OS,
VMM, storage, and scheduling as adversarial and requires freshness failures to
fail closed. [ADR 0008](0008-private-query-xchacha-protection-primitive.md)
selects the XChaCha20-Poly1305 transcript and three distinct key roles, while
deliberately deferring ownership of sessions, keys, nonces, time, replay state,
rollback protection, and attestation.

The listener-free runtime now exercises the real protectors through injected
dependencies, but those seams do not yet form a production security boundary:

- the runtime owner accepts a caller-supplied `key_epoch`, `session_binding`,
  and `RuntimeDependencies` bundle whose protector, replay, and material-source
  components remain independently constructible by the caller;
- `RoundMaterialSource` returns a bare host-supplied Unix timestamp plus
  response and token nonces without a freshness or reservation proof; that
  `u64` is only observed time in the research runtime, not trusted-time
  authority;
- authenticated request nonces have no production uniqueness/replay owner;
- `ReplayBinding` does not explicitly namespace claims by deployment, key
  epoch, or session binding;
- the logical replay interface calls its cover slot non-durable even though a
  durable real claim and a non-durable cover write would be distinguishable to
  the host; and
- response release rechecks the serving epoch, but not the security state that
  supplied keys, nonce reservations, time, and replay commitments.

A bundle made from `SystemTime`, `OsRng`, three byte arrays, and an in-memory
set would compile behind those interfaces. It would not survive host rollback,
process snapshots, nonce-state reuse, a crash around replay commit, or
multi-replica deployment. The production boundary therefore has to own these
dependencies as one state machine rather than let an application assemble
them independently.

## Decision

Production private-query dependencies come from one opaque security-state
owner. The concrete name and provider remain internal, but the owner must
jointly control:

- deployment and service identity;
- the active key and projection epochs;
- session establishment and the session binding;
- request, response, and continuation-token key roles;
- authenticated request-nonce claims;
- server response/token nonce reservation;
- trusted expiry time;
- continuation replay claims and cover operations;
- the external rollback/freshness witness;
- health, rotation, restart, and shutdown; and
- a release-time witness for the complete security epoch.

No production application/runtime-owner constructor may accept raw role keys,
a session binding, a clock, a nonce source, or a replay guard as independent
arguments. Internal protector and KDF constructors may receive key material at
minimum visibility. Tests may continue to inject narrow deterministic fixtures.

### Security epoch and key roles

One active security epoch is identified by at least the deployment/service
identity, nonzero key epoch, projection epoch, effective profile/configuration,
and owner-instance generation. The key epoch and projection epoch are distinct:
one cannot stand in for the other. Their allocation and retirement are
committed by the external freshness witness, and an identifier retired there
is never reused.

Every authenticated session receives one nonzero 32-byte session binding that
is unique to its completed handshake and active security epoch. The binding is
derived by the selected authenticated handshake or from secret exporter
material. Its transcript/context commits the protocol version, authenticated
server/workload identity, completed handshake transcript, any selected client
identity, effective profile/configuration, key and projection epochs, and one
unique session identifier. It is never a configuration value or arbitrary
caller input. Early data is not accepted.
Resumption or reconnection creates a new binding unless a future protocol
proves equivalent replay and key-separation properties. Continuation tokens
remain scoped to the exact session binding, so a lost session restarts
pagination.

Request and response envelope keys are session-scoped. The continuation-token
key is server-only and is never exported to a client. The owner derives or
provisions all three roles with explicit, versioned domain separation and
rejects activation if any two effective keys are equal. Effective keys and
their nonce namespaces must also change before a retired security epoch can be
replaced. Secret key bytes, exporter material, nonce state, and replay keys do
not cross the opaque owner boundary or appear in diagnostics.

The key authority releases or unwraps material only for an attested owner whose
measurement, effective configuration/profile, security epoch, and external
witness state match its policy. Changing the advertised key epoch rebuilds the
complete security owner; it cannot retain prior keys, session state, or
material, and it cannot reuse a prior replay namespace as active state. Retired
replay and witness state remain committed until trusted expiry and the
profile-defined garbage-collection ceremony permit removal.

The exact handshake, exporter/KDF, KMS, and sealing provider remain separate
provider selections. A TLS-based selection must use exporter material from a
completed handshake, not early-exporter material, and distinct registered or
`EXPERIMENTAL` private-use labels and contexts for each purpose, following TLS
1.3 exporter semantics in
[RFC 9846 section 7.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-7.5)
and label-format requirements in
[RFC 5705 section 4](https://www.rfc-editor.org/rfc/rfc5705.html#section-4).

### Nonce ownership

Nonce uniqueness is enforced per effective key, not merely assumed from a
large nonce size.

- The trusted client owns request-nonce generation and must never reuse a
  nonce under one request key. After authenticating an envelope, the server
  performs one session-scoped request-nonce claim on every path. A duplicate
  completes the profile-fixed protected work and cannot cause request-specific
  semantic mutation or a continuation-token claim to be applied twice.
- The security owner reserves response and continuation-token nonce space in
  separate role namespaces before returning round material. Reservations are
  rollback-resistant and crash-safe; a crash burns every uncertain value or
  range. Returning a nonce that might have been returned previously under the
  same effective key is a terminal owner failure.
- A replica receives a distinct owner-instance namespace and effective keys or
  a disjoint witness-reserved range. Process-local counters, host-persisted RNG
  state, and best-effort uniqueness are insufficient.

The 192-bit wire nonce may be encoded from a reserved prefix/counter or another
reviewed injective allocation. Plain `OsRng` is not, by itself, rollback or
snapshot evidence. Any probabilistic construction must prove that key and RNG
state cannot repeat across the complete adversarial lifecycle.

Round material is acquired before any real continuation claim, as the current
runtime requires. In the production contract, acquisition succeeds only after
the owner has committed the nonce reservation and established fresh trusted
time for that round. It returns an opaque nonce/time reservation authority that
is retained separately from the later replay-commit authority through response
release.

### Trusted time

Host `SystemTime`, the guest wall clock, and an unsigned network time response
are not security time. Token expiry uses a nondecreasing time value authorized
outside host-controlled state. A provider may supply either:

- a fresh, non-replayable authority ticket for each round; or
- a bounded authority lease whose passage is enforced by a reviewed trusted
  monotonic timer and whose generation is rollback-protected.

The authority value or lease binds the deployment and security epoch. A
regression, stale/replayed lease, excessive forward jump, exhausted lease, or
authority outage makes the owner unready. Advancing time may expire tokens and
reduce availability; it must never extend a token's validity or resurrect an
expired token. Time refresh runs independently of secret queries or with one
profile-fixed operation on every round.

The current runtime's bare `u64` Unix timestamp remains an observed
host-provided value even when tests choose it deterministically. It becomes
trusted time only after the future owner validates an authority ticket or
lease, commits the required rollback-resistant state, and returns a typed
authority tied to that validation. Naming, bucketing, or persisting the
observed value does not confer authority.

### Durable replay and rollback

Request-nonce and continuation claims use explicit namespaces. A request-nonce
record identity includes, directly or through one collision-resistant
canonical digest, at least the deployment/service and protocol/profile
versions, key epoch, owner-instance generation, exact session binding,
request-key role/version, and authenticated request nonce.

A continuation claim identity includes, directly or through one
collision-resistant canonical digest, at least:

- deployment/service and protocol version;
- key epoch, owner-instance generation, and session binding;
- projection epoch and profile;
- authenticated query, cursor, expiry, and token nonce; and
- the authenticated token/context identity needed to prevent cross-namespace
  aliasing.

Request-nonce claims have no expiry in the current protocol. A continuation
token's expiry therefore cannot authorize deletion of its paired request
claim, reduction of the request-claim count, or reclamation of replay capacity.
Profile v5 replay-entry format v2 persists each real continuation as one
authenticated typed claim containing its opaque replay key and a nonzero,
one-based ceiling expiry-bucket ordinal. The ordinal is
`ceil(expiry_unix_seconds / expiry_bucket_width_seconds)` and is constructed
with overflow-safe arithmetic only after token authentication and profile
validation.
The persistence boundary does not accept the key and ordinal as independently
supplied values. This ordinal is authenticated metadata, not trusted-time
authority, replay-maintenance expiry or eligibility classification, or
authorization to delete either claim.

The canonical request and continuation replay-key encodings and their
collision-resistant digests are versioned and covered by the profile identity.
Raw replay fields never cross to the persistence provider: encoding is
colocated with the applicable envelope/token boundary or exposed through a
narrow opaque record-key interface. A profile or encoding change creates a
distinct namespace and cannot reinterpret an older record.

Persistent record identities are keyed opaque digests, but host-visible
storage addresses and access traces remain profile-fixed or use a reviewed
oblivious construction. Using the digest as an ordinary host-visible database
key is insufficient because repeated access would reveal token equality. Raw
query or token fields are never host-visible keys.

Every authenticated round performs one profile-fixed replay transaction. A
fixed request-nonce lane and a continuation real-or-cover lane are processed
together; a duplicate request selects cover behavior for the continuation lane
and cannot claim its token. Real claims and cover operations have the same
host-observable read, write,
commit, synchronization, witness, and error shape. A cover transaction changes
only a dedicated dummy namespace/root and never consumes a valid token, but it
cannot skip the durable/witness work performed by a real claim. The current
`ContinuationReplayGuard` statement that cover state is non-durable is a
production-compiled trait contract; it must be revised or replaced before it
can back a production owner.

The production replay interface accepts the authenticated request-nonce claim
and continuation real-or-cover selection in one combined transaction and
returns an opaque replay-commit authority proving that both lanes finalized
together.
`RoundMaterialSource::next_round_material` cannot implement that transaction by
itself because it receives no authenticated request nonce.

A successful real claim is linearizable and crash-durable before response
release. A crash or later failure after that commit consumes the token; the
system favors replay safety over retry availability. An ambiguous commit
leaves the owner unready until the external authority proves the committed
state. Capacity is a compiled public profile bound. Garbage collection uses
public expiry buckets only after trusted expiry plus the declared skew margin
and applicable key/session retirement. It runs on a proactive or profile-fixed
schedule, is never triggered by a private query, and capacity exhaustion fails
closed without eviction or fallback.

Before qualification, the compiled profile and profile ID are versioned to
bind replay capacity, expiry-bucket and garbage-collection cadence, witness
operations, nonce-reservation shape, trusted-time work, and the complete
real-or-cover transaction budget. None of these may remain an unmodeled
provider choice.

Local encryption, MACs, sealed blobs, and attestation prove integrity or
identity, not freshness. One external monotonic witness commits a canonical
digest of the composite security state, including:

- active/retired key and owner-instance epochs;
- response and token nonce high-watermarks or reserved ranges;
- request and continuation replay generation/root;
- trusted-time ticket/lease generation; and
- the active projection and serving identity.

The witness namespace survives process and host restart, never disappears or
regresses outside an explicit recovery ceremony, and provides linearizable
compare-and-advance semantics. Host-local state is usable only when it exactly
matches the authoritative witness. Missing, ahead, behind, corrupt,
equivocating, or unavailable state is never served.

### Implemented persistence foundation

The research crate now contains a private fixed-width snapshot store for the
outer composite security-state commitment. The snapshot binds a nonzero
sequence; stable service, protocol, owner-generation, key, projection, profile,
session, and security-epoch identity; an opaque serving-identity digest; and an
opaque digest of the component state. A versioned domain-separated BLAKE2s
digest plus the sequence is the value compared by an injected freshness
witness. Version one fixes the layout at 204 bytes with compile-time offsets
and a golden encoding. Reads are bounded to that exact size and reject trailing
bytes.

The store stages and synchronizes a new local snapshot, atomically replaces and
synchronizes `current.bin`, and only then performs the witness
compare-and-advance. Startup has one exact reconciliation matrix: both sides
absent is empty; a present witness requires a readable, valid, byte-derived
local snapshot with the same sequence and digest; every other combination is
unready. Staging files are never recovery authority. An ambiguous local
replacement or witness advance latches that store instance, and a fresh
instance must reconcile with the authoritative witness before use. There is no
truncate, repair, or retry path after ambiguity.

Within version one, service identity, protocol version, and profile identity
cannot change. Owner-generation, key, and projection epochs cannot regress.
Any epoch or session/security-binding change is a complete identity rotation:
the owner generation must increase and both the session and security-epoch
bindings must change. A future namespace or protocol migration requires a new
reviewed transition rather than being silently blessed by a higher witness
sequence.

The crate now also contains a local replay component-store foundation. A
crate-private journal records each request lane together with its applied
real-or-cover continuation lane in one ordered transaction. Exact fixed-size
version-two current-state and version-two entry record bodies are sealed through
an injected protector and opaque journal context. Entry v2 (`ZORJENT2`) persists
each real continuation replay key and its nonzero, one-based ceiling
expiry-bucket ordinal as one typed claim. The current-state format remains v2,
all fixed record widths remain unchanged, and the current state binds the exact
compiled profile ID. Replay identities, lane tags, expiry ordinals, counters,
and the entry chain are not plaintext record fields. Sequential entry filenames
still expose the public transaction sequence. The next sequence candidate is
synchronized before the atomic `current.bin` replacement, and only
`current.bin` defines the locally committed prefix. Startup opens exactly that
profile-bound prefix, reconstructs both claim sets and the chain digest, and
requires an exact match with the sealed current state. It never opens
`head + 1`; every retry replaces that non-authoritative
candidate without inspecting its contents, while entries at or below the
committed head remain immutable. Duplicate requests and duplicate continuations
both persist cover, and a noncanonical duplicate claim fails closed on recovery.
One public transaction bound is checked before any secret-dependent claim
condition.

A module-private coordinator now defines how that replay state feeds the outer
security-state commitment. Its versioned, domain-separated composite
security-component digest currently commits the replay-journal component
digest. Initial provisioning is an explicit operation that constructs the
first outer snapshot from the journal's current digest; it is distinct from
opening existing state, and refuses an already provisioned outer store. An
existing open refuses a missing outer snapshot and accepts only an exact match
between that snapshot and the current replay digest. A journal latched
indeterminate after an ambiguous durability result cannot supply component
state.

Live advancement remains intentionally directional. A successful replay
commit's sealed durable path mints one move-only receipt whose private fields
bind the journal's opaque per-open instance identity and the component digests
immediately before and after that commit. Production receipt construction is
confined to that durable path; a synthetic constructor exists only under
`#[cfg(test)]` for rejection cases. The coordinator consumes a receipt only
after the same live journal recognizes the instance identity and confirms that
the post-advance digest is still its current head. It also requires that its
cached outer snapshot commits the pre-advance digest, then constructs the exact
successor from the post-advance digest. It advances the outer local snapshot and
injected witness in the security-state store's local-before-witness order. The
coordinator does not infer whether the journal or snapshot is ahead, rewrite
either component, or provide an automatic repair path.

If replay commits but successor construction, outer replacement, or witness
advancement returns an error, the same coordinator instance latches
indeterminate and releases no replay-commit authority to its caller. A hard
witness rejection occurs after local replacement, so a fresh open fails with
`WitnessLocalMismatch`. If the witness advances and then returns an error, the
same instance still latches, but a fresh instance can reconcile the exact
advanced local and witness state and open successfully.

These are ordered local recovery foundations, not provider selections or
production rollback claims. The replay journal has only a deterministic test
protector, and no non-test runtime or security-owner caller constructs the
coordinator. The replay-journal commit, outer-snapshot replacement, and witness
advancement are not one atomic transaction: replay may be durably ahead after
an outer failure, and the protocol responds by latching rather than claiming
automatic repair. Profile ID v5 supersedes v4. It retains the total committed
replay-transaction capacity, public trusted-time expiry-bucket width, and
proactive fixed garbage-collection interval bindings and adds the authenticated
entry-v2 semantics above. Journal/coordinator construction derives the
persisted transaction bound from the compiled profile, and outer-sequence
exhaustion is rejected before replay commit. The current head remains version
two and all fixed record widths remain unchanged.

This v5 metadata does not provide trusted time, replay-maintenance expiry or
eligibility classification, maintenance state or a watermark,
garbage-collection execution, replay-entry deletion, claim-count reduction,
compaction, or capacity reclamation. Request claims still have no expiry, and
journal capacity
remains a lifetime committed-transaction bound. V5 requires fresh provisioning:
there is no in-place v4 migration, v4/v5 dual acceptance, or reinterpretation of
an existing v4 journal. A later incompatible persisted replay format or
semantic successor requires another profile identity. Earlier profile and
journal generations likewise have no dual-acceptance or in-place path. The
journal assumes exactly one live writer without enforcing a process lock. There
is no production freshness
witness, production replay protector/key/nonce owner, nonce-reservation
journal, trusted-time journal, key persistence, attestation binding, owner
construction path, or service caller.
At the standalone-journal layer, a missing `current.bin` is locally
indistinguishable from first initialization and opens as empty so an initial
pre-marker crash can retry. An existing coordinator open detects loss or
deletion of a previously committed replay marker when the outer snapshot
remains, because the resulting digests do not match. Rollback or deletion of
both local stores still requires a production external freshness witness to
detect.
The path-based filesystem helpers reject direct symlink components but do not
provide dirfd-based no-follow traversal or adversarial-host TOCTOU protection.
The journal makes no access-oblivious memory, page, storage, or timing claim.
The coordinator does not establish production rollback resistance, TDX
security, mainnet readiness, or access-oblivious qualification.
The first qualified deployment remains single-owner as required below.

A future replay-maintenance mutation must advance the authenticated replay
current state through its durable path and mint a dedicated move-only typed
maintenance receipt. It must not reuse the query replay-commit receipt or
mutate replay files out of band. The coordinator consumes that receipt through
one serialized replay-current -> outer-local -> witness transition, retaining
the existing fail-closed ambiguity and latching rules at every boundary.

### Lifecycle and response-release ordering

The owner moves through explicit unready, provisioning, active, retiring, and
stopped states. Activation validates the complete security identity, distinct
role keys, current time authority, nonce reservations, replay capacity/root,
serving identity, and attestation inputs before admitting a request.

Startup first reconciles the witness and durable security state, then
provisions keys/time/nonces/replay state, activates a current serving epoch,
and produces matching attestation inputs. Only the resulting opaque active
facade may be handed to the application; the listener is not exposed earlier.

Rotation and restart follow this order:

1. close admission and the response-release gate;
2. drain or discard pending responses without releasing bytes;
3. reconcile the exact composite state with the external witness;
4. retire or advance the security epoch and burn uncertain nonce ranges;
5. provision/derive new role keys, session state, time authority, replay
   namespace, and nonce reservations;
6. bind the current serving/projection identity and attestation evidence; and
7. reopen admission only after every component is current.

Restart advances to a fresh security epoch by default. Resuming an exact epoch
is allowed only when every durable component reconciles with the witness and
the protocol proves that no nonce, request, session, or token state can repeat.
There is no partial recovery and no fallback to independently constructed
providers.

A response can be authorized for transport only after:

- request-nonce and real-or-cover replay commits are durable;
- its response/token nonce reservations are committed;
- protected encoding has completed;
- the retained nonce/time reservation and replay-commit authorities match this
  response and security epoch; and
- both the serving-epoch witness and security-epoch witness still match.

Any owner failure latches the runtime unready, closes release, retires the
active epoch, and returns only the existing coarse external failure. A pending
response from a retired security epoch is never released even when its serving
epoch is still current.

Graceful shutdown closes admission, resolves or discards every pending release,
commits the final security state, and then destroys session/key material. An
abrupt `Drop` that only closes an in-memory gate is fail-closed cleanup, not
evidence that durable shutdown completed.

The first qualified deployment is single-owner and session-affine, with exactly
one active authenticated session per process owner. A new handshake retires the
whole process owner before constructing a fresh one, and a token is not
accepted by another process or replica. Supporting concurrent sessions first
requires a process-serving-owner/per-session-runtime refactor. Shared replay
state, token migration, active/active key use, and cross-replica nonce
allocation require a new reviewed protocol and qualification evidence.

## Required implementation gates

Before a production dependency factory or service can be exposed:

- `FinalizedRuntimeOwner` must consume one opaque active security lease rather
  than independently supplied `key_epoch`, `session_binding`, and generic
  dependencies;
- the application package may receive only a narrow opaque facade and pending
  response type; concrete keys, providers, epochs, and witnesses remain inside
  `zaino-oram` at the minimum visibility that compiles;
- round material must carry a committed nonce/time reservation authority, not
  bare host-derived values; a later revised replay interface must accept the
  request-nonce plus continuation real-or-cover selection and return a separate
  combined replay-commit authority;
- replay identity and storage must include a versioned canonical encoding of
  the complete security namespace behind a narrow opaque interface, and
  real/cover operations must share one qualified durable transaction shape;
- the compiled profile/version/profile ID must bind replay capacity,
  garbage-collection cadence, witness operations, nonce reservation, trusted
  time, and maintenance work before qualification;
- pending response release must witness both serving and security currentness;
- pending responses must retain and validate both the nonce/time reservation
  and combined replay-commit authorities at release;
- the release-gate lifecycle must close admission before draining or discarding
  outstanding responses; the current idle-only shutdown contract is
  insufficient;
- `zaino-oram` must expose only the minimum opaque process and pending-response
  facades, `zainod-oram` must implement local ports without receiving concrete
  providers, and the generated private route must be registered on an actual
  listener under that owner;
- the first service must enforce exactly one active session per process owner;
  multiple sessions require a process-owner/per-session-runtime refactor;
- the client must implement and qualify per-request-key nonce uniqueness;
  server duplicate detection limits effects but cannot recover AEAD
  confidentiality after client nonce reuse;
- key rotation, process restart, witness ambiguity, time rollback, nonce-range
  exhaustion, replay capacity, crash-after-claim, and crash-before-release must
  have deterministic fail-closed tests at every commit boundary;
- native target tests must show no nonce reuse or replay resurrection across
  restarts and injected rollbacks; and
- host-visible instruction, memory/page, storage, timing, network, log, and
  error equivalence still require independent qualification under ADR 0007.

Passing source-level mocks is necessary but not production evidence. Provider
code, deployment configuration, authority policy, and recovery ceremony require
independent cryptographic, Rust, operations, and TEE review.

## Deferred provider selections

This ADR fixes the ownership and failure contract but does not select:

- the authenticated client/session handshake or exact exporter/KDF labels;
- KMS, key sealing/provisioning, revocation, or recovery service;
- trusted-time ticket/lease authority and timer mechanism;
- external monotonic witness implementation;
- replay-store engine, oblivious access method, transaction format, capacity,
  or garbage-collection interval;
- nonce prefix/range size and reservation batch size;
- concrete TDX attestation verifier, migration policy, or cloud deployment; or
- a multi-replica protocol.

Each selection must satisfy this ADR without weakening a compiled profile or
reusing an epoch, key, nonce namespace, or replay namespace.

## Consequences

- The current generic dependency composer is referenced only by tests and is
  unreachable from production construction; this ADR does not turn it into a
  production owner.
- Convenient host-local providers remain useful test doubles but cannot be
  renamed or documented as production implementations.
- Pagination is session-affine. A reconnect, restart, rotation, or owner
  retirement invalidates outstanding continuation tokens and may require the
  client to restart the query.
- Durable real and cover replay work may be materially more expensive than an
  in-memory set. That cost belongs in the compiled profile and target-load
  qualification.
- A crash after a durable claim can lose a response while consuming its token.
  This is an explicit availability tradeoff for at-most-once continuation use.
- The external witness and time authority become part of the trusted computing
  base and must be available before the private service becomes ready.
- Attestation must bind the effective security identity and authority policy;
  attestation alone still does not establish freshness or obliviousness.

## Considered alternatives

- **Let the application assemble independent production providers.** Rejected:
  it permits mismatched epochs, reused keys/nonces, host time, and replay state
  that cannot be checked atomically at release.
- **Use `SystemTime`, `OsRng`, and an in-memory hash set initially.** Rejected
  as a production milestone because host rollback, snapshot, crash, and replica
  reuse remain outside those objects' contracts.
- **Persist real replay claims but keep cover writes volatile.** Rejected:
  synchronization and witness traffic would reveal whether a token was valid.
- **Treat a local MAC, sealed file, or TDX attestation as rollback protection.**
  Rejected: each can authenticate stale state without an external monotonic
  freshness authority.
- **Share one static service key and nonce generator across replicas.**
  Rejected: compromise and collision domains become fleet-wide and rollback or
  split-brain can repeat nonce state.
- **Allow tokens to migrate across sessions or replicas in the first service.**
  Rejected: the current transcript binds the exact session, and migration would
  require a shared key/replay/nonce protocol with new leakage and rollback
  analysis.
