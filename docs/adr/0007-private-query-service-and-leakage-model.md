# Private queries use a dedicated fixed-envelope service over a derived ORAM projection

## Status

accepted for the ORAM research fork; this decision does not authorize a
mainnet privacy claim until the gates below pass.

## Context and decision

The existing `CompactTxStreamer` contract exposes exact protobuf collections,
variable-length byte fields, and naturally terminating streams. Its transparent
address methods can also trigger an exact number of validator and raw-transaction
lookups. Replacing only their backing map with ORAM would still disclose result
cardinality, completion, and query-dependent work to the host. The current
`LightWalletIndexer` traits cannot express the fixed budgets, opaque outcomes,
or cover rounds required for a host-oblivious claim.

We decide:

1. **The legacy service remains unchanged and carries no new privacy claim.**
   Existing wallets continue to use `CompactTxStreamer` with the same wire and
   indexer behavior.
2. **Private queries use a new `zaino.private.v1` service.** Its query RPC
   accepts and returns one exactly sized encrypted envelope selected by an
   attested, compiled privacy profile. Compression is disabled. Authenticated
   domain outcomes, including misses and private validation failures, stay
   inside the envelope and completed queries have a uniform outer status,
   frame count, byte count, completion shape, and configured work budget.
3. **The first operation is transparent-address UTXO lookup.** Additional
   methods receive no privacy claim until their complete storage, source, wire,
   and continuation paths satisfy the same leakage model.
4. **The protected finalised-address index is a derived ORAM projection.**
   `NodeBackedChainIndex` and its validator remain authoritative. Projection
   state is disposable and deterministically rebuildable from public chain
   data; it is not a `FinalisedSource` variant and ORAM failure cannot change
   canonical chain state.
5. **Every query combines finalised ORAM state with a complete fixed-work scan
   of the bounded non-finalised-state snapshot.** The public finalised
   height/hash watermark defines the seam. Recent state must not use an
   address-keyed plaintext cache, query-driven backfill, or variable-work
   fallback. Mempool privacy is outside the first operation.
6. **The private engine and TLS termination run inside the same attested TDX
   workload initially.** The workload generates its TLS identity internally,
   and evidence binds that key to the measured binary, private schema, privacy
   profiles, effective security configuration, projection checkpoint, key
   epoch, and applicable CPU policy. Administration, if networked at all, uses
   a separate mTLS loopback, Unix, or vsock endpoint that is never public.
7. **ORAM is isolated behind a default-off engine abstraction.** A new
   non-published crate owns fixed records, projection ingest, padding,
   continuation tokens, checkpointing, and mock/real engines. Experimental
   ORAM and TDX dependencies must not enter the ordinary build unless their
   additive features are selected.
8. **The private runtime does not become a dependency of a publishable Zaino
   crate.** A separate non-published `zainod-oram` application owns its private
   protobuf contract and service, and depends on `zaino-oram` plus
   ORAM-agnostic public Zaino seams. This preserves the stable-release rule
   that normal dependencies of publishable crates resolve from crates.io.

## Security boundary and leakage model

The protected adversary controls the host OS and VMM, host-visible storage and
I/O, network outside the trust domain, and scheduling. It may observe page faults,
ciphertext traffic, timing, storage traffic, aggregate resource use, and may
delay, drop, replay, reorder, or roll back host-controlled state. It does not
control the client and its verifier, the accepted CPU/TDX trust chain, the
measured workload and keys created inside it, or the configured authoritative
Zcash consensus source. Integrity or freshness failure must make the private
service unready or fail closed; denial of service is not prevented.

Within one public privacy profile, the design intends to hide:

- queried addresses, txids, outpoints, and continuation state;
- hit versus miss, private validation outcome, exact result count, and the last
  real result page;
- logical ORAM keys, query-selected physical storage locations, allocations,
  source calls, and backfill;
- private values and query outcomes in logs, metrics, traces, and errors.

The profile explicitly permits observation of:

- request arrival, client network metadata, connection duration, and aggregate
  service load;
- service/schema version, attested profile identifier, method class if exposed
  as separate RPCs, and the profile's fixed request/response size class;
- coarse public chain epoch, height/hash, sync lag, database capacity, and
  growth;
- continuation count when the client does not execute the profile's fixed cover
  rounds.

Every accepted profile fixes its padded input slots, ORAM reads/writes, full NFS
scan work, result slots, request/response bytes, page and cover-round budgets,
timeout bucket, and concurrency policy. A runtime configuration may select an
attested profile but cannot weaken constants while retaining its identifier.
TDX attestation establishes measurement and key binding; it does not by itself
establish semantic obliviousness or remove CPU side channels.

## Advancement gates

**Phase 0 — feasibility.** Stop before service integration unless a measured
mainnet corpus plus growth horizon fits the intended TDX instance with at least
30% RSS headroom and no host swapping; capacity, hot-address, stash, and queue
failures are typed and fail closed; a credible authenticated recovery or
measured rebuild plan and RTO exist; the pinned compiler/CPU/ORAM trace and
assembly experiments support the claim; dependency licensing permits the
intended distribution; and the leakage budget is accepted.

**Phase 1 — deterministic contract.** The mock engine must demonstrate equal
configured logical store operations, source calls, allocations, envelopes,
frames, completion shape, and outer statuses for hit, miss, empty, full,
cap-hit, invalid-domain, and early/late-match cases. Continuation tampering,
expiry, replay, and profile/query/epoch mismatch must be rejected without
changing the public shape. Golden tests must show no legacy API change.

**Mainnet claim.** The fork remains experimental until it has exact shadow
parity across finalised seams, reorgs, restarts, and both validator backends; a
full-corpus build and at least seven days of mainnet shadowing; target-load soak
results on intended TDX hardware with the required headroom and recovery time;
release-binary instruction, memory/page, allocation, timing, frame, log, and
admin-traffic trace equivalence; fail-closed attestation, rollback, capacity,
and recovery behavior; resolved dependency licenses; and independent
cryptographic/side-channel, Rust, TEE/deployment, and leakage-claim review with
all blockers closed.

## Considered options

- **Make the existing `CompactTxStreamer` private in place.** Rejected: its
  wire shapes and established client behavior are observably variable, and
  changing them would break compatibility.
- **Implement an alternate `LightWalletIndexer`.** Rejected: the traits expose
  legacy exact-response types and do not define the protected protocol or its
  deterministic work contract. The private engine is the narrower boundary.
- **Make ORAM an authoritative `FinalisedSource`.** Rejected: the address-only
  projection cannot satisfy that capability surface, and alpha ORAM capacity,
  stash, persistence, or recovery failures must not own chain correctness.
- **Protect finalised state but query recent state directly.** Rejected: an
  address-indexed NFS lookup or query-driven validator/backfill request leaks
  the key or outcome. Every query performs the profile-fixed full bounded scan.
- **Copy `rostl` or `oblivious_node` directly into the server.** Rejected:
  they are research inputs, not production backends. Any selected engine stays
  pinned behind the abstraction and must pass the same capacity, correctness,
  recovery, compiler, leakage, audit, and licensing gates.

## Consequences

- Privacy-aware clients need a new attestation and fixed-cover-round protocol;
  legacy clients receive compatibility, not host-obliviousness.
- The service pays profile-fixed CPU, memory, bandwidth, padding, and latency
  costs even for empty or invalid-domain queries. A single mutable ORAM worker
  is the initial correctness model because reads remap positions.
- Private readiness is stricter than ordinary indexer readiness. A missing,
  lagging, hash-mismatched, rolled-back, corrupt, or exhausted projection is
  never served through an ephemeral or plaintext fallback.
- Public chain ingest, checkpoint advancement, rebuild, and key rotation must
  be proactive and independent of secret queries. Address-bearing plaintext
  journals are forbidden.
- Logs and metrics are allowlisted to declared aggregate/public fields; they
  cannot include query identifiers, private outcomes, cardinality, or page
  position.
- The research fork has a separate application/package boundary. Reusable
  upstream changes flow toward ORAM-agnostic chain/indexer APIs; existing
  publishable packages do not depend on the internal ORAM or private-proto
  crates.
- Graduation requires a new ADR that either publishes `zaino-oram` with a
  crates.io-compatible dependency graph, merges the reviewed engine into a
  publishable crate, or makes the separate internal `zainod-oram` boundary
  permanent.
- The detailed delivery sequence, candidate records, and verification work are
  maintained in
  [the ORAM-enabled fork plan](../notes/oram-enabled-zaino-plan.md). Changes to
  this security boundary or leakage budget require a new ADR rather than an
  implementation-only edit.
