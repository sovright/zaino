# ORAM-enabled Zaino fork: architecture and delivery plan

- Status: proposed research fork, not production-ready.
- Prepared: 2026-07-12.
- Target fork point: [`zingolabs/zaino@c94ae247`](https://github.com/zingolabs/zaino/commit/c94ae247de7286fd3337e313559bb3d62bdcbd5d), the live `origin/dev` head inspected for this plan.
- Design seed: [TEE-backed lightwalletd / Zaino with `rostl` and `oblivious_node`](https://gist.github.com/zmanian/61f6b2b1afad08729356d5f226fdfbb3).

Implementation began on `feat/oram-private-foundation` after fast-forwarding the
local `dev` branch to the recorded target fork point. The initial implemented
scope is deliberately narrower than Phase 1: it establishes the ADR, fixed
business/persistence/envelope shapes, exact profile coupling, a bounded
plaintext test store, and logical store-call schedule tests. It contains no
real ORAM, encryption, network service, attestation, or production privacy
claim.

## Executive decision

Build the fork as a new, feature-gated private-query subsystem, not as another implementation of `LightWalletIndexer` and not as a replacement for Zaino's canonical/finalised storage.

The target shape is:

1. Preserve `CompactTxStreamer` byte-for-byte and behavior-for-behavior for existing wallets. It remains compatibility-only and carries no new host-oblivious privacy claim.
2. Add a separate `PrivateCompactTxStreamer` contract whose requests and responses are fixed-size encrypted envelopes selected from attested privacy profiles.
3. Add a derived `OramProjection` alongside the existing finalised state, non-finalised state (NFS), and mempool. The validator/chain index remains authoritative; the ORAM projection is disposable and deterministically rebuildable.
4. Store finalized transparent-address state in ORAM. For recent blocks, scan the entire bounded NFS snapshot with fixed work on every private query and merge it with the finalized result.
5. Run the private engine in-process first, inside the same TDX trust boundary as the private gRPC listener. Process isolation is a later hardening option, not an MVP requirement.
6. Start with one method: a fixed-profile private transparent-address UTXO query. Do not add private transaction, mempool, or block-range claims until their complete data paths are protected and padded.
7. Treat `rostl` as an experimental candidate behind an engine abstraction. Current upstream is alpha, volatile, fixed-capacity, and missing production recovery/persistence features. A successful spike is a prerequisite, not a formality.
8. Keep the research runtime in new non-published packages. Existing publishable Zaino crates may expose ORAM-agnostic chain-data seams, but they must not acquire a normal dependency on `zaino-oram`; the repository's stable-release policy requires their non-test dependencies to resolve from crates.io.

This deliberately revises the gist's suggestion to implement an alternate `ObliviousLightWalletIndexer`. The current traits are coupled to exact legacy protobuf types, variable-length vectors, and naturally terminating streams. They cannot express fixed page budgets, opaque outcomes, uniform errors, or cover traffic. The live code also consolidated the old State/Fetch split into one `NodeBackedIndexerService`, making a third whole backend the wrong level of abstraction.

## Evidence from current Zaino

All links in this section are pinned to `c94ae247`.

- Both validator connection modes now launch one `NodeBackedIndexerService`: [`packages/zainod/src/indexer.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zainod/src/indexer.rs#L42-L69).
- `ZcashIndexer` and `LightWalletIndexer` are public service traits whose private-sensitive methods use legacy proto requests, exact responses, and receiver streams: [`packages/zaino-state/src/indexer.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/src/indexer.rs#L156-L953).
- The gRPC adapter is a thin delegate to those traits: [`packages/zaino-serve/src/rpc/grpc/service.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-serve/src/rpc/grpc/service.rs#L21-L133).
- Transparent address balance, txid, and UTXO queries still pass directly from `ChainIndex` to the validator source: [`packages/zaino-state/src/chain_index.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/src/chain_index.rs#L2313-L2345).
- `GetTaddressTransactions` first gets the exact txid list and then performs one raw-transaction lookup per match: [`packages/zaino-state/src/indexer/node_backed_indexer.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/src/indexer/node_backed_indexer.rs#L1572-L1615).
- The legacy proto exposes repeated fields, variable bytes, exact unary lists, and naturally terminating streams: [`service.proto`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-proto/lightwallet-protocol/walletrpc/service.proto#L219-L305).
- Finalised state now routes between persistent v1 and ephemeral sources through `FinalisedSource`: [`finalised_source.rs`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/src/chain_index/finalised_state/finalised_source.rs#L221-L243). An address-only ORAM projection does not implement this source's full capability surface and should not become a third variant.
- The optional plaintext address-history table is finalised-only, disabled by default, and keyed directly by address script. It is useful as an event-extraction reference but cannot answer private queries under a storage-observer threat model: [`zaino-state/Cargo.toml`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/Cargo.toml#L33-L40), [`db_schema_v1.txt`](https://github.com/zingolabs/zaino/blob/c94ae247de7286fd3337e313559bb3d62bdcbd5d/packages/zaino-state/src/chain_index/finalised_state/finalised_source/db_schema_v1.txt#L129-L132).

Language-server workspace symbols and references on the target commit confirmed the trait definitions, the sole production `NodeBackedIndexerServiceSubscriber` implementation, and the address-query call chain into `ChainIndex`. Source reads were then used to inspect behavior inside those resolved symbols.

## Privacy claim and threat model

### Protected adversary

The strong profile targets an operator who controls the host OS, hypervisor-visible I/O, persistent storage, and network outside the trust domain, but does not control:

- the client and its attestation verifier;
- the CPU package and accepted TDX trust chain;
- the measured release workload and keys generated inside it;
- the configured authoritative Zcash validator/consensus source.

The host may observe request arrival, public listener use, ciphertext, storage traffic, page faults, scheduling, and aggregate resource use. It may delay, drop, reorder, replay, or roll back host-controlled state. The service must detect integrity/freshness failures and fail closed, but it cannot prevent denial of service.

### Intended hidden values

For requests in the same public privacy profile, the host should not learn:

- queried transparent addresses, txids, outpoints, or continuation state;
- hit versus miss or private validation/domain outcome;
- exact result count or the page containing the last real result;
- logical ORAM keys or query-dependent storage locations;
- query-derived backfill, allocation, or source calls;
- private values through logs, metric labels, traces, or error details.

### Explicitly public or budgeted leakage

The initial profile may reveal:

- request arrival time, client network metadata, and connection duration;
- private service version and attested profile ID;
- the profile's fixed request/response byte class and fixed page budget;
- coarse public chain epoch, height/hash, and sync lag;
- method class if separate RPC methods are used;
- client continuation count unless the client performs the profile's required cover rounds;
- total database capacity/growth and service-level aggregate load.

Each profile must define fixed values for maximum padded addresses, ORAM reads/writes, NFS scan work, response slots, request/response bytes, cover rounds, timeout bucket, and concurrency policy. The actual constants are a Phase 0 output based on mainnet corpus measurements; they must not be guessed in the API.

### Out of scope for the first claim

- denial of service and traffic analysis that requires continuous cover traffic;
- a compromised client or malicious authoritative validator;
- power, thermal, frequency, speculative-execution, and undocumented CPU side channels;
- hiding which public chain epoch/profile the client selected;
- legacy `CompactTxStreamer` response cardinality, size, timing, and termination;
- private transaction or mempool queries before their complete source/storage paths land.

Intel's Data Operand Independent Timing mode covers only a documented instruction subset and is not automatically enabled by TDX. DOIT state and supported CPU policy must therefore be part of startup self-check and attestation, not an assumed TEE property.

## Target architecture

```text
                                     authoritative public chain data
                                                |
                                      NodeBackedChainIndex
                                  /---------+---------\
                                 /          |          \
                        FinalisedState      NFS       Mempool
                              |              |
                              | public       | bounded snapshot
                              +-------+------+
                                      |
                         deterministic projection ingest
                                      |
                               OramProjection
                         /------------+-------------\
                        /                            \
             finalized ORAM pages          fixed-work NFS scan
                        \                            /
                         \-------- merge/filter ---/
                                      |
                            PrivateQueryEngine
                                      |
              attested private gRPC listener (TLS ends in TDX)
                                      |
                            privacy-aware clients

 existing CompactTxStreamer -> existing legacy listener -> existing indexer
 admin/repair control       -> separate mTLS loopback/vsock listener
```

### Component boundaries

`zaino-state` remains authoritative for public chain snapshots and indexed blocks. It should expose one narrow, business-layer projection feed that cannot perform address/txid queries. The feed carries public chain events such as finalized block application and a race-free NFS snapshot/watermark.

`zaino-oram` is a new non-published crate containing the private engine, fixed business/persistent types, padding, tokens, ingest, checkpointing, and attestation providers. Keeping the x86_64/TEE/alpha dependency outside `zaino-state` avoids making the stable state crate platform-specific and isolates security review. Only the engine handle, configuration, projection-source interface, and attestation-provider interface should be public; all other items begin private and widen only as compilation requires.

`zainod-oram` is a new non-published application package. Its private `proto/` directory owns the independent `zaino.private.v1` service, attestation, and optional admin modules. Do not edit the upstream lightwallet protocol subtree/symlinked proto files and do not make the ordinary `zaino-proto` release carry an experimental contract.

`zainod-oram` also owns the private adapter generic over `PrivateQueryEngine`, the attested listener, optional admin routes, configuration, metrics, and lifecycle orchestration. Domain results and validation failures are encoded inside the fixed envelope; outer gRPC status is uniform for completed private queries.

The existing publishable `zaino-serve` and `zainod` packages remain free of a `zaino-oram` dependency. `zainod-oram` composes `zainodlib` and other public building blocks, then starts/rebuilds the projection, starts the attested private listener, optionally starts the admin listener, aggregates readiness/status, and shuts components down in dependency order. If a reusable seam is missing, add an ORAM-agnostic API to the publishable crate rather than introducing the internal dependency in the opposite direction.

### Listener policy

Use a dedicated private/attestation listener by default. It must:

- terminate TLS inside the TDX workload with an enclave-generated key;
- disable compression;
- enforce exact message limits, concurrency limits, and fixed deadline buckets;
- serve private query and public attestation/info methods only.

Keep the current legacy listener unchanged. It may be co-located inside the same TDX workload, but it does not inherit the private-service claim.

Admin ingest/control must use a distinct mTLS listener bound only to loopback, Unix domain socket, or vsock and must never be published by Docker/cloud networking. In the initial in-process mode, Rust method calls should replace network ingest entirely. The network admin plane is needed only for a later split workload or operator lifecycle controls.

### Why ORAM is a derived projection

The validator and `NodeBackedChainIndex` already own canonical chain selection, reorg handling, and rebuildable finalised state. Making alpha ORAM storage authoritative would couple chain correctness to stash failures, fixed capacity, volatile position maps, and incomplete recovery.

The projection therefore has a public checkpoint:

```text
{ network, schema_version, key_epoch, finalized_height, finalized_block_hash }
```

The safe advancement protocol is:

1. The canonical finalised batch commits.
2. The projection deterministically applies the corresponding public block range.
3. ORAM state reaches a complete new epoch.
4. The projection atomically publishes the new checkpoint/root.
5. Startup compares the checkpoint height/hash to authoritative finalised state.
6. A projection behind the canonical state replays public blocks. A projection ahead, hash-mismatched, corrupt, or capacity-exhausted is never served; it is rebuilt or requires explicit recovery.

No plaintext address-bearing outbox is allowed. A journal may contain public block references or encrypted fixed-size deltas only.

### Finalised ORAM plus fixed-work NFS

Persistently protected state covers finalized blocks only. Every private query also scans the complete bounded NFS snapshot with profile-fixed work, then applies recent outputs/spends over the finalized ORAM result.

This avoids persistent ORAM rollback for ordinary reorgs, reuses Zaino's existing bounded reorg model, and prevents a recent-address keyed cache from becoming a new leak. The finalized seam/watermark decides exactly which block is present in each layer. Tests must cover advancing seams, shortening reorgs, side chains, and a spend created on one side of the seam and consumed on the other.

If the fixed NFS scan cannot meet the target latency/memory profile, the design returns to review. It must not silently introduce a query-keyed plaintext overlay.

## Data model

The first supported business operation is transparent-address UTXO lookup. The engine must finish it without a query-dependent read from LMDB, the validator, or a raw-transaction service.

Candidate fixed records are:

- `AddressKey`: network/domain-separated digest of a canonical transparent locking script;
- `AddressDirectory`: fixed metadata for a bounded number of page slots;
- `AddressEventPage`: fixed array of output/spend events plus explicit occupancy/dummy bits;
- `UtxoEvent`: txid, output index, value, height, script kind/hash, and mined/spent flags;
- `ProjectionCheckpoint`: public chain watermark plus schema/key epoch and authenticated root;
- `ContinuationState`: cursor/profile/query digest/epoch/expiry/nonce, encoded as a fixed-length AEAD token.

The existing address-history code may supply a shared plain function that extracts address events from an `IndexedBlock`. Both the ordinary index path and ORAM projection may call that function. Do not duplicate the extraction logic and do not use a macro when a function can express it.

All ORAM-stored representations are persistence-boundary types. Follow the repository convention:

- `PersistentX::from_business(&X)`;
- `PersistentX::into_business(self)` or a typed fallible variant;
- `pub(super)` for persistent types/methods unless a narrower scope compiles;
- no `From`/`TryFrom` impl crossing the persistence boundary.

Private wire conversion lives on business types as `to_wire` / `try_from_wire`, with typed rejection reasons and adjacent round-trip/golden tests. Generated protobuf types do not contain business validation.

### `rostl` compatibility decision

Current [`rostl@8c3a12d2`](https://github.com/obliviouslabs/rostl/commit/8c3a12d2febf17b024f2e949428b3bc526d74172) is `0.1.0-alpha9` and declares Rust 1.84/x86_64. Its `UnsortedMap` is fixed-capacity, requires `Pod` keys/values, mutates on `get`, and has no native delete, resize, iteration, or persistence API. Circuit ORAM uses a fixed stash and contains unimplemented recovery paths. `rostl-storage` currently provides only a memory store and is not wired into Circuit ORAM.

The spike must choose between:

1. an append-only event-page design that needs insertion but not deletion/upsert and folds all profile-bounded events on query; or
2. an audited/pinned fork or upstream contribution adding typed upsert/delete, external storage, recovery, and failure tests.

Option 1 is the MVP preference if mainnet hot-address distributions fit a practical fixed profile. If they do not, the project must not paper over capacity with a leaky fallback.

Because every read remaps ORAM positions, the initial engine is a single mutable worker with explicit queueing. Async gRPC concurrency does not imply concurrent ORAM execution. Fixed-shape batching or sharding is allowed only after trace-equivalence and shard-selection leakage are analyzed.

### Persistence policy

The first real-ORAM milestone may be volatile and rebuild on restart, but it must be labeled research-only. A production milestone requires one of:

- a disk/external-memory ORAM whose data, position map, stash, and query-induced mutations share an authenticated atomic persistence protocol; or
- a measured cold rebuild that meets the declared recovery-time objective while the private service remains unready.

Serializing raw in-memory ORAM occasionally is not automatically correct: reads mutate it, host rollback must be detected, and a crash must not resurrect a stale logical-to-physical mapping.

## Private wire contract

Use an outer protobuf message with one always-present, exactly sized `bytes envelope`. Repeated dummy protobuf records are unsuitable because proto3 omission and encoding length can change the visible shape.

A minimal public contract is:

```proto
package zaino.private.v1;

service PrivateCompactTxStreamer {
  rpc QueryPage(FixedEnvelope) returns (FixedEnvelope);
  rpc GetEvidence(AttestationChallenge) returns (AttestationEvidence);
  rpc GetPublicInfo(PublicInfoRequest) returns (PublicInfo);
}
```

`QueryPage` hides method class as well as values. A weaker deployment may use one method per query class, but that class becomes declared public leakage.

Inside the protected envelope:

- requests contain fixed padded address/input slots, profile, snapshot constraint, token, nonce, and authentication/session binding;
- responses contain fixed result slots, dummy/real indicators, domain outcome, checkpoint, `has_more`, and a fixed continuation token;
- hit, miss, malformed domain input, exhausted result budget, and projection-not-ready behavior consume the same profile work and return the same outer shape/status when a request was authenticated and decoded safely.

Protocol/authentication/rate-limit failures may use a small stable set of generic outer statuses. Detailed internal errors never cross the private boundary.

Continuation tokens bind version, profile, query digest, projection epoch/root, cursor, expiry, and nonce. They never encode remaining result count visibly. A token does not hide when the client stops: strong profiles require a fixed number of cover rounds; weaker profiles document continuation-count leakage.

## Attestation and key binding

The private TLS identity is generated inside the workload. Evidence must bind:

- production image/binary measurement and expected platform/TCB policy;
- private TLS public key;
- private proto/schema version;
- compiled privacy-profile table and effective security configuration hash;
- ORAM implementation/version, key epoch, projection checkpoint/root;
- DOIT policy and startup self-check result;
- caller challenge/nonce and evidence freshness.

The client verifies evidence before trusting the connection and re-attests after key, image, profile, or epoch-policy changes. Debug images, wrong environment/arguments, stale/revoked TCB policy, downgraded profiles, mismatched roots, and unverified TLS keys fail closed.

Attestation proves measurement and binding. It does not prove that the measured program is semantically oblivious; trace testing, assembly review, and external audit remain separate gates.

The reference `tdx_easy_https` deployment can inform verifier behavior, but its pinned quote-verifier crate is AGPL-3.0-or-later and the submodule lacks a clear root license. Resolve the licensing/integration boundary before redistribution.

## Configuration and features

Do not add `BackendType::Oram`; backend now selects the validator connection, while private projection is orthogonal.

Keep portable/mock code as the default build of the non-published research packages. Add default-off `rostl` / Linux-x86_64 `tdx` features to `zaino-oram`, and gate the `zainod-oram` binary behind its own `oram_private_service` feature. Do not propagate these features through the publishable `zainod` or `zaino-serve` feature graphs.

`zainod-oram` always deserializes its `[privacy]` config section, then returns a clear startup error when the selected engine or attestation provider was not compiled. This avoids feature-dependent config parse drift. A strong profile must reject incompatible builds/configuration, including unencrypted private transport and query-driven recovery.

Illustrative configuration fields, with final names decided in the ADR:

```toml
[privacy]
enabled = false
profile_set = "research-v1"
public_listen_address = "127.0.0.1:9137"
max_sync_lag = 2

[privacy.oram]
capacity = 0
storage_path = ""
key_epoch = 0

[privacy.attestation]
provider = "mock"

[privacy.admin]
enabled = false
listen_address = "127.0.0.1:9138"
```

Security-critical sizes are compiled profile constants and appear in attestation evidence. Runtime configuration chooses an allowed profile; it cannot invent a weaker shape under the same profile ID.

## Logging, metrics, and readiness

Private-path logs and metrics must never contain an address, txid, outpoint, token, query digest, private outcome, result count, page position, or detailed query-derived error. Aggregate method/profile/QPS/queue/health metrics are allowed only when declared public leakage. Domain outcomes stay inside the encrypted response, keeping host-visible outer status uniform.

Readiness requires:

- a committed projection checkpoint whose height/hash matches authoritative state;
- sync lag within the attested profile threshold;
- no stash/queue/capacity/corruption failure;
- attestation identity/evidence generation ready;
- required TLS and admin policy active.

Existing finalised readiness may route reads through an ephemeral source while persistence catches up. Private readiness must never use that fallback for address queries. The private endpoint fails closed until the protected projection is usable.

## Delivery phases

### Phase 0 — fork baseline, threat model, and feasibility gate

Deliverables:

- branch from `origin/dev@c94ae247` or a fresher explicitly recorded commit;
- ADR `docs/adr/0007-private-query-service-and-leakage-model.md`;
- a public leakage matrix and privacy-profile schema;
- a corpus scanner that reports only aggregate mainnet counts/distributions: distinct address scripts, events per address, live UTXOs per address, script classes, hottest-address tails, record sizes, and projected growth;
- pinned `rostl`, compiler, target CPU, TDX platform, and dependency/license inventory;
- an exact candidate fixed record compiled with Zaino's Rust 1.96 toolchain and `rostl` constraints;
- baseline memory/latency/stash/queue experiments on random full-map workloads, not repeated key-zero microbenchmarks;
- assembly/trace experiment covering the upstream compiler-preservation concern.

Go/no-go:

- the target corpus plus growth horizon fits the intended TDX instance with at least 30% RSS headroom and no host swapping;
- there is a credible recovery/persistence plan and declared RTO;
- capacity, hot-address, stash, and insertion-queue failure are typed/fail-safe rather than panics or leaky fallback;
- dependency licensing permits the intended distribution;
- the team accepts the precise leakage budget and client contract.

If these fail, stop before server integration. Possible next moves are a different ORAM construction, a sharded/public-bucket design with a revised leakage budget, or upstream `rostl` work.

### Phase 1 — private contract and deterministic trace model

Deliverables:

- `packages/zaino-oram` skeleton with business records, persistence/wire conversions, fixed-envelope codec, profile table, continuation tokens, typed errors, and a deterministic mock `ObliviousStore`;
- independent private/attestation proto generation under `zainod-oram/proto`;
- private service adapter tested against the mock engine;
- access-trace recorder that counts logical reads, writes, allocations, source calls, frames, and bytes;
- legacy golden/parity tests proving no `CompactTxStreamer` change.

Acceptance:

- hit, miss, empty, full, cap-hit, domain-error, and early/late-match cases have the same configured store-operation count, envelope size, frame count, completion shape, and outer status;
- token tamper, expiry, query/profile/epoch mismatch, and replay are rejected inside the fixed work/shape;
- every synchronous test uses `#[test]`; Tokio attributes appear only where the body awaits.

### Phase 2 — offline real ORAM and shadow parity

Deliverables:

- pinned `rostl` adapter behind `ObliviousStore`;
- selected append-only event-page or audited upsert design;
- deterministic projection from `IndexedBlock` fixtures and finalised snapshots;
- single-worker mutation queue, capacity/stash/queue telemetry, and fail-closed transitions;
- research-only volatile rebuild path if durable external memory is not yet available;
- shadow comparison against ordinary Zaino UTXO results at the same finalized checkpoint.

Acceptance:

- exact parity for all fixture addresses, including multiple outputs, same-block spends, duplicates, and empty results;
- no query causes a validator, LMDB address index, raw transaction, or query-derived backfill call;
- at least `10^9` mixed random reads/inserts/adversarial collision operations at target load with zero overflow, panic, corruption, or lost entry before mainnet advancement;
- node-year failure probability is documented from analysis/testing rather than assumed.

### Phase 3 — live finalised projection and fixed-work NFS merge

Deliverables:

- narrow public-chain projection feed from `zaino-state`;
- finalised checkpoint/watermark protocol and catch-up replay;
- race-free NFS snapshot plus complete fixed-work recent-chain scan;
- startup comparison, rebuild, key rotation, and shutdown sequencing;
- crash/failpoint harness for every mutation/checkpoint boundary;
- shadow mode on live direct and RPC validator backends.

Acceptance:

- parity across seam advancement, longer/same-height/shortening reorgs, pure revert, and restart;
- no stale-canonical response;
- behind state replays, while ahead/hash mismatch/corrupt/overflow state stays unready and rebuilds or fails explicitly;
- kill-after-every-step tests recover deterministically without query-derived repair.

### Phase 4 — private service integration

Deliverables:

- private/attestation listener with exact limits and compression disabled;
- `zainod-oram` config, feature selection, lifecycle/status/readiness, and safe aggregate metrics;
- clientless fixed-envelope/frame/access-trace tests;
- a reference client that follows attestation and fixed cover-round rules;
- separate mTLS admin/control listener only where network control is required.

Acceptance:

- legacy wire/API behavior remains unchanged;
- private service starts only with a matching committed projection and permitted profile;
- packet capture confirms profile-fixed application frames/bytes and completion shape;
- source-call counters prove zero private-keyed host/validator calls after readiness;
- logs/metrics pass automated secret-field and outcome/cardinality review.

### Phase 5 — TDX deployment and remote attestation

Deliverables:

- separate deterministic `deploy/tdx/` image/manifests rather than overloading normal Docker deployment;
- enclave-generated quote-bound TLS identity;
- production verifier, key pin/rotation, nonce/freshness, image/config/profile/epoch checks;
- DOIT enablement/self-check where supported and an explicit fallback policy where not;
- rollback/restart/key-rotation/migration runbooks;
- hardware-only CI/smoke lane.

Acceptance:

- production (not debug) image attests and wrong image/env/args/profile/key/epoch/TCB cases fail closed;
- private key material never enters a host-mounted config path;
- admin listener is unreachable from public/container networking;
- measurements are reproduced on at least two supported CPU generations with DOIT on/off results recorded.

### Phase 6 — mainnet shadow, audit, and claim gate

Deliverables:

- full mainnet corpus build and at least seven days of read-only shadow parity;
- 24–72 hour target-load soak on intended TDX hardware;
- p50/p95/p99/p999 latency, sustained QPS, queueing, update contention, peak RSS, stash pressure, bandwidth, rebuild/RTO, and key-rotation results;
- release-binary instruction, page/memory-access, allocation, timing, frame, log, and admin-traffic traces across contrasting secret cases;
- independent cryptographic/side-channel, Rust memory-safety, TEE/deployment, and leakage-claim audit;
- resolved dependency licenses and pinned SHAs/compiler.

Acceptance:

- zero shadow mismatches/stale-canonical responses and zero unhandled capacity/recovery failures;
- target capacity retains at least 30% RSS headroom;
- no pre-registered classifier distinguishes secret cases within the same public profile above the accepted threshold;
- every audit blocker is resolved;
- operators and client teams approve the final published leakage budget.

Until this phase passes, label the fork experimental and do not call it mainnet-ready or host-oblivious.

### Phase 7 — additional private methods

Add methods one complete data path at a time:

1. transparent balance/deltas if they reuse the protected event fold without new leakage;
2. transparent txid pages;
3. raw transaction payload storage and padded transaction pages;
4. private `GetTransaction` only after txid lookup and payload length are protected;
5. mempool snapshots with fixed input lists, fixed work, fixed output slots, and cover timing;
6. private block batches only if hiding wallet birthday/sync progress is a real client requirement.

Do not describe `GetTaddressTransactions` as private while it still performs one observable source fetch per matched txid.

## Work breakdown and likely files

| Workstream | Likely files | Primary output |
|---|---|---|
| Threat model/decisions | `docs/adr/0007-*.md`, this note | accepted adversary, leakage profiles, stop/go rules |
| ORAM library | `packages/zaino-oram/Cargo.toml`, `src/{lib,engine,store,records,error}.rs` | isolated, pinned engine with mock and `rostl` adapters |
| Padding/tokens | `packages/zaino-oram/src/{padding,continuation}.rs` | fixed envelopes, cover budgets, AEAD-bound tokens |
| Projection/recovery | `packages/zaino-oram/src/{ingest,projection,checkpoint}.rs` | finalized projection, watermark, rebuild/recovery |
| Attestation | `packages/zaino-oram/src/attestation/{mod,mock,tdx}.rs` | quote-bound in-memory TLS identity/evidence |
| Public-chain feed | `packages/zaino-state/src/chain_index.rs`, `non_finalised_state.rs`, adjacent types/tests | narrow indexed-block/checkpoint/NFS snapshot seam |
| Private wire/application | `packages/zainod-oram/proto/*.proto`, `build.rs`, `src/{main,service,admin,config,error,metrics}.rs` | non-published `zaino.private.v1`, private/public-attestation routes, lifecycle, readiness, safe aggregates |
| Publishable seams | narrowly scoped files in `zaino-state` / `zainod` only where required | ORAM-agnostic projection source and reusable indexer startup APIs |
| Deployment | `deploy/tdx/`, deterministic build inputs, verifier | measured reproducible TDX workload |
| Unit/property tests | beside each implementation module | conversions, padding, tokens, trace counts, crash model |
| Service tests | `live-tests/clientless/` | frame/shape/status/source-call equivalence |
| Hardware/E2E | `live-tests/e2e/`, dedicated CI lane | attested TLS, restart, cover rounds, TDX evidence |

After implementation rebases onto current `dev`, update the root changelog and each changed package changelog. An internal research-package change does not create a changelog entry in an untouched publishable crate.

## Verification commands to add/use

Focused development should culminate in:

```text
makers lint-boundary-conversions
makers lint
makers test packages -E 'package(zaino-oram)'
makers test clientless -E 'test(private_)'
makers test e2e -E 'test(private_)'
cargo check --workspace --all-targets --no-default-features
cargo check -p zaino-oram --all-targets --features rostl,tdx
cargo check -p zainod-oram --all-targets --features oram_private_service
```

Add a dedicated `makers test oram` front door that runs unit/property, clientless trace-equivalence, and hardware-gated subsets without weakening the existing default-off feature build. Nightly all-features compilation is not a substitute for executing privacy invariants.

Every new persistent/wire round trip lives next to the conversion. Production code propagates or handles errors and contains no `.unwrap()`. Tests prefer typed `Result`, descriptive `expect`, or assertions. Multi-thread Tokio tests require a comment naming the actual race/concurrency invariant.

## Risk register

| Risk | Consequence | Mitigation / stop condition |
|---|---|---|
| `rostl` alpha/missing recovery | panic, lost item, false privacy/correctness | pin SHA/compiler; typed recovery fork; `10^9`-operation and failure-bound gate |
| no disk-backed Circuit ORAM | excessive RAM or restart rebuild | corpus/RSS/RTO gate; no-go if target needs nonexistent external-memory support |
| mutating reads/single mutex | poor throughput and persistence complexity | single-worker correctness first; benchmark batching; no secret-dependent sharding |
| compiler changes oblivious operations | secret-dependent branches/instructions | pin compiler, inspect assembly, trace-test release binary, external review |
| hot/unbounded addresses | cap overflow or cardinality leak | aggregate corpus tails, fixed public profiles, fail closed, never fallback |
| variable legacy wire shapes | host learns count/size/termination | privacy claim only on fixed-envelope service; legacy unchanged |
| raw tx/source follow-up reads | matched txids leak through N host calls | UTXO-only MVP; store protected payload before transaction claim |
| LMDB/ORAM dual-state crash | inconsistent/stale projection | public height/hash watermark, replay/rebuild, kill-point tests, unready on mismatch |
| NFS/reorg mismatch | stale or wrong UTXO answer | complete fixed NFS scan, seam/reorg property tests, canonical checkpoint binding |
| query-driven recovery | query identifiers/work leak | proactive public ingest only; strong profiles compile/configure leaky recovery out |
| TLS outside TEE | plaintext query disclosed | enclave-generated quote-bound key; attested private listener; fail closed |
| storage rollback | valid measurement serves stale state | attest epoch/root, client freshness/height policy, rollback witness or rebuild |
| logging/metrics | direct or outcome side channel | allowlisted aggregate schema and automated trace/log review |
| TDX/DOIT overclaim | unmodeled side channels | narrow published claim, attest DOIT state, multi-CPU test, independent audit |
| licensing ambiguity | redistribution/compliance blocker | obtain root license confirmation; isolate/replace AGPL verifier boundary |
| upstream fork drift | expensive rebases/security fixes missed | isolate new crate/proto, minimize edits to legacy paths, regularly rebase on `dev` |

## Upstream dependency assessment

### `rostl`

Reviewed at [`8c3a12d2`](https://github.com/obliviouslabs/rostl/commit/8c3a12d2febf17b024f2e949428b3bc526d74172): research-quality building blocks, not a turnkey persistent Zaino backend. Material open items include compiler-preserved obliviousness ([#8](https://github.com/obliviouslabs/rostl/issues/8)), Circuit ORAM stash recovery ([#13](https://github.com/obliviouslabs/rostl/issues/13)), failure-probability testing ([#24](https://github.com/obliviouslabs/rostl/issues/24)), and map queue recovery ([#32](https://github.com/obliviouslabs/rostl/issues/32)). The manifest declares `MIT OR Apache-2.0`, but a root license file was not recognized during review; confirm before distribution.

### `oblivious_node`

Reviewed at [`d00718df`](https://github.com/obliviouslabs/oblivious_node/commit/d00718dfdfd38dd50ec2e315e35ab54f25cd5067): valuable reference for public/admin plane separation, fixed records, ORAM traversal, and attested deployment, but explicitly a PoC. Its root lookup is intentionally direct/leaky, traversal is capped, ORAM state is volatile, reads/ingest serialize through one mutex, and reorg/restart logic is not suitable for Zaino unchanged. Its CLI disables leaky request-driven recovery by default, but supplied deployment stacks enable it; the Zaino strong profile must not.

Published reference memory guidance also shows why the sizing gate is first-order: a 16,777,216-node configuration accounts for roughly 9.4 GB of raw node values before ORAM tree, keys, buckets, recursive position maps, and runtime overhead. Zaino must measure its own fixed record and real address-event distribution on intended TDX hardware.

## First implementation slice

The first mergeable slice should stop before real wallet serving:

1. ADR and leakage table.
2. `zaino-oram` crate with fixed UTXO event/page business and persistent types.
3. Aggregate corpus scanner and memory model.
4. Mock logical-schedule engine plus fixed envelope/token codec.
5. Pinned `rostl` volatile adapter exercised only by offline fixtures.
6. Shadow parity at one finalized snapshot.
7. A written Phase 0/1 go/no-go report.

That slice answers the expensive unknowns—capacity, API fit, compiler behavior, throughput, and recovery—without prematurely exposing a privacy service or forcing the alpha ORAM dependency into Zaino's ordinary production path.
