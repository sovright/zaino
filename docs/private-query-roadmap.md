# Private query: what remains before shipping

Tracks the work implied by
[ADR 0010](adr/0010-interim-honest-but-curious-deployment-posture.md) — an
honest-but-curious operator inside an attested TEE, with network observers in
scope and clients untrusted.

This file exists because issues are disabled on this repository. Each entry
names why it is required, where the code is, and how big it is. Sizes are
Quick / Short / Medium / Large, never wall-clock.

Nothing here authorizes a privacy claim on its own. ADR 0007 remains the target
model and continues to gate a mainnet claim.

## Required for any privacy claim

### 1. Serve from the ROSTL backend, with parity coverage — Short + Medium

Do these together: the parity test is what shows the swap did not change
answers.

`FinalizedProjectionBuilder::start` calls
`OfflineProjectionOwner::new_on_qualification_memory`
(`packages/zaino-oram/src/inner_codec/private_service.rs:365`).
`QualificationMemoryTable` indexes a `Vec` at secret-derived indices, so the
served path is not oblivious and carries no privacy claim.

The typed ROSTL path already exists: `new_with_publisher` calls
`spawn_typed_rostl_worker` (`projection_owner.rs:90-100`), behind the
`rostl-experimental` feature, Linux x86-64 only.

- [ ] Select ROSTL in the serving builder; fail closed at startup if it is
      unavailable rather than falling back silently
- [ ] Remove or re-scope `--allow-qualification-backend` so a privacy-claiming
      deployment cannot reach the non-oblivious backend
- [ ] End-to-end test: build and refresh a real projection, establish client key
      material, send valid protected `QueryPage` calls through the bound
      listener, decrypt, and compare against ordinary Zaino query semantics
      across empty, nonempty, spent, recent, pagination, invalid, duplicate,
      refresh, and restart cases

No test currently sends a valid protected query through a refreshed listener.
The `shadow-parity` test is static and does not traverse the RPC — reuse it as
an oracle, do not replace it.

### 2. Client key establishment, session isolation, and TLS — Medium

Blocks real use regardless of adversary model: clients are untrusted even when
the operator is not.

The binary calls `PrivateRuntimeKeys::ephemeral()`. There is no path for a
wallet to obtain session keys, no per-client isolation, and no server identity
on the private listener.

- [ ] How a wallet authenticates the service and obtains request/response keys
- [ ] Per-client or per-session derivation, so one client cannot decrypt or
      forge another's traffic
- [ ] Rotation, revocation, restart, and recovery behavior
- [ ] TLS / server identity — AEAD envelopes give confidentiality but do not let
      a wallet authenticate the endpoint
- [ ] Zeroization and crash/core-dump policy

Interacts with the replay journal: ephemeral keys make persisted journal records
unreadable after restart, so key custody and freshness are entangled.

### 3. Coarse data-independence in the query engine — Medium

An oblivious table under a leaky engine is not private.

After the table returns a record, `engine.rs` branches on secret-derived data —
`store_slot.is_occupied()`, short-circuit `&&`, `continue` on empty recent slots
— and writes output at secret-derived response indices. `consider_candidate`
early-returns; `finalized_snapshot_relation`, semantic validation, and
recent-liveness checks use `continue` / `any` / comparisons on protected
records. That reveals whether the address exists, roughly how many outputs it
has, and whether pagination was needed.

- [ ] Convert the inner loops to fixed-loop conditional-select over fixed-width
      records

Harden the existing engine; do not rewrite the subsystem. Under ADR 0010,
cache-line precision is not required. Hit/miss, result cardinality, and
pagination are.

### 4. Whole-round response release timing — Medium

Network observers stay in scope even though the operator does not.

Fixed envelope width and one-request-per-connection admission are necessary but
not sufficient: the response releases when variable computation and queueing
finish.

- [ ] Measure the complete route from accepted fixed request to write completion
- [ ] Make protected success and protected semantic failure perform the same
      work and produce the same response shape
- [ ] Adopt a fixed release schedule or batching epoch, with an explicit
      overrun / fail-closed policy
- [ ] Verify response frames and gRPC status/trailers are indistinguishable
      across protected outcomes
- [ ] Keep allocation, serialization, back-pressure, and refresh interaction
      from reintroducing query-dependent timing

## Required for mainnet scale

### 5. Re-measure `recent_snapshot_scan_slots` — Medium/Large

`MAINNET_QUERY_SLOTS = 256` in `profile.rs` (~line 582), with an adjacent
comment admitting it is unmeasured and deliberately ignores an observed
per-address-generation maximum of 153,037 delta events. Recent-snapshot
conversion fails with `CapacityExceeded` — fail-closed, no silent truncation —
so mainnet cannot publish or serve.

A 153,037-slot fixed scan per query may be fixed-shape but operationally
unusable, so this is not merely a larger constant.

- [ ] Either set a justified bound covering the admitted population with margin,
      or shorten/restructure the public rebuild interval so a measured bound is
      feasible
- [ ] Enforce admission before publication

PR #96 landed a per-address delta-event histogram that is computed, validated,
and printed but feeds no sizing decision. Wire it, or record why it cannot
ground this constant.

### 6. Bounded replay-journal checkpointing and reclamation — Medium

The journal is append-only and never reclaims. Transaction capacity is
lifetime-based, duplicate attempts consume it too, and recovery rebuilds both
claim sets by scanning every committed entry at startup. The source notes
entries cannot be safely deleted until an authenticated base/checkpoint format
exists.

- [ ] Authenticated checkpoint preserving the exact active claims, bound to the
      freshness witness, allowing old entries to be reclaimed
- [ ] Recovery bounded by checkpoint plus a bounded suffix

Related: `ReplaySnapshotCoordinator` still has no production construction site —
`inner_codec/composition.rs` (~line 149) builds `ReplayJournalStore` directly.
Under ADR 0010 that is crash-recovery correctness rather than rollback defence;
it stays required for ADR 0007.

## Housekeeping

### 7. ADR numbering collision with upstream — Quick

`docs/adr/` contains two `0007`s after the upstream sync: upstream's
`0007-block-persistence-is-a-row-set-boundary.md` and this fork's
`0007-private-query-service-and-leakage-model.md`. The fork's ORAM ADRs occupy
0007-0009 and upstream is actively adding in that range — their zcashd-removal
PR (zingolabs#1395) claims `0008`.

- [ ] Move fork ADRs to a reserved range or a `fork-` prefix, and update
      cross-references. ADR 0010 links to
      `0007-private-query-service-and-leakage-model.md`.

### 8. Duplicate-code backlog — Medium

`.dupes-ignore.toml` carries 16 entries marked TRACKED (real duplication,
deferred so the refactor is reviewable on its own) and 5 marked PERMANENT
(merging them would make the code worse). The largest cluster is the
`zainod-oram` artifact provenance / publish / validate family.

- [ ] Extract the artifact family into one shared helper and drop its entries

## Deferred under ADR 0010

Still required for ADR 0007's model. Deferred is a statement about the first
deployment, not a decision that the work is unnecessary.

- Controlled-channel and page-fault attack mitigation
- Rollback protection as an adversarial control
- Attestation as a hard gate before key release
- Whole-binary constant-time proof
- Oblivious replay-claim lookups — `RequestReplayKey` derives from a fresh
  per-request nonce and `ContinuationReplayKey` includes a fresh token nonce, so
  those probe locations are not address-correlated
- An audit of the pinned alpha `rostl` revision, which may ship unaudited under
  an explicit experimental caveat
