# Zaino
Zaino is an indexer for the Zcash blockchain implemented in Rust.

Zaino provides all necessary functionality for "light" clients (wallets and other applications that don't rely on the complete history of blockchain) and "full" clients / wallets and block explorers providing access to both the finalized chain and the non-finalized best chain and mempool held by either a Zebra or Zcashd full validator.


### Motivations
With the ongoing Zcashd deprecation project, there is a push to transition to a modern, Rust-based software stack for the Zcash ecosystem. By implementing Zaino in Rust, we aim to modernize the codebase, enhance performance and improve overall security. This work will build on the foundations laid down by [Librustzcash](https://github.com/zcash/librustzcash) and [Zebra](https://github.com/ZcashFoundation/zebra), helping to ensure that the Zcash infrastructure remains robust and maintainable for the future.

Due to current potential data leaks / security weaknesses highlighted in [revised-nym-for-zcash-network-level-privacy](https://forum.zcashcommunity.com/t/revised-nym-for-zcash-network-level-privacy/46688) and [wallet-threat-model](https://zcash.readthedocs.io/en/master/rtd_pages/wallet_threat_model.html), there is a need to use anonymous transport protocols (such as Nym or Tor) to obfuscate clients' identities from Zcash's indexing servers ([Lightwalletd](https://github.com/zcash/lightwalletd), [Zcashd](https://github.com/zcash/zcash), Zaino). As Nym has chosen Rust as their primary SDK ([Nym-SDK](https://github.com/nymtech/nym)), and Tor is currently implementing Rust support ([Arti](https://gitlab.torproject.org/tpo/core/arti)), Rust is a straightforward and well-suited choice for this software.

Zebra has been designed to allow direct read access to the finalized state and RPC access to the non-finalized state through its ReadStateService. Integrating directly with this service enables efficient access to chain data and allows new indices to be offered with minimal development.

Separation of validation and indexing functionality serves several purposes. First, by removing indexing functionality from the Validator (Zebra) will lead to a smaller and more maintainable codebase. Second, by moving all indexing functionality away from Zebra into Zaino will unify this paradigm and simplify Zcash's security model. Separating these concerns (consensus node and blockchain indexing) serves to create a clear trust boundary between the Indexer and Validator allowing the Indexer to take on this responsibility. Historically, this had been the case for "light" clients/wallets using [Lightwalletd](https://github.com/zcash/lightwalletd) as opposed to "full-node" client/wallets and block explorers that were directly served by the [Zcashd full node](https://github.com/zcash/zcash).


### Goals
Our primary goal with Zaino is to serve all non-miner clients -such as wallets and block explorers- in a manner that prioritizes security and privacy while also ensuring the time efficiency critical to a stable currency. We are committed to ensuring that these clients can access all necessary blockchain data and services without exposing sensitive information or being vulnerable to attacks. By implementing robust security measures and privacy protections, Zaino will enable users to interact with the Zcash network confidently and securely.

To facilitate a smooth transition for existing users and developers, Zaino is designed (where possible) to maintain backward compatibility with Lightwalletd and Zcashd. This means that applications and services currently relying on these platforms can switch to Zaino with minimal adjustments. By providing compatible APIs and interfaces, we aim to reduce friction in adoption and ensure that the broader Zcash ecosystem can benefit from Zaino's enhancements without significant rewrites or learning curves.

### Scope
Zaino will implement a comprehensive RPC API to serve all non-miner client requests effectively. This API will encompass all functionality currently in the LightWallet gRPC service ([CompactTxStreamer](https://github.com/zcash/librustzcash/blob/main/zcash_client_backend/proto/service.proto)), currently served by Lightwalletd, and a subset of the [Zcash RPCs](https://zcash.github.io/rpc/) required by wallets and block explorers, currently served by Zcashd. Zaino will unify these two RPC services and provide a single, straightforward interface for Zcash clients and service providers to access the data and services they require.

In addition to the RPC API, Zaino will offer a client library allowing developers to integrate Zaino's functionality directly into their Rust applications. Along with the RemoteReadStateService mentioned below, this will allow both local and remote access to the data and services provided by Zaino without the overhead of using an RPC protocol, and also allows Zebra to stay insulated from directly interfacing with client software.

Currently Zebra's `ReadStateService` only enables direct access to chain data (both Zebra and any process interfacing with the `ReadStateService` must be running on the same hardware). Zaino will extend this functionality, using a Hyper wrapper, to allow Zebra and Zaino (or software built using Zaino's `IndexerStateService` as its backend) to run on different hardware and should enable a much greater range of deployment strategies (eg. running validator, indexer or wallet processes on separate hardware). It should be noted that this will primarily be designed as a remote link between Zebra and Zaino and it is not intended for developers to directly interface with this service, but instead to use functionality exposed by the client library in Zaino (`IndexerStateService`).


## Project Structure

```
packages/                          Cargo workspace member crates
  zaino-proto/                       Protocol buffer definitions
  zaino-common/                      Shared utilities and configuration
  zaino-fetch/                       Blockchain data fetching (JSON-RPC backend)
  zaino-state/                       Chain state and indexer service library
  zaino-serve/                       gRPC server (CompactTxStreamer)
  zainod/                            Daemon binary

live-tests/                        Live-test suite — root-workspace members, run against zcashd/zebrad
  e2e/                               End-to-end partition (wallet client -> Zaino -> validator)
  clientless/                        Clientless partition (Zaino services -> live validator, no client)
  zaino-testutils/                   Shared test harness and utilities
  test_binaries/                     Symlinked zcashd/zebrad/zcash-cli binaries
  test_environment/                  Container build context
    Containerfile                      CI/test container image definition
    entrypoint.sh                      Container entrypoint (binary symlink setup)
    test-container-permissions.sh      Container permission / volume-mount tests

docs/                              Architecture diagrams, specs, and usage guides
tools/                             Development tools, shell helpers, makefiles
  scripts/                           Shell scripts (CI tag computation, helpers, lints)
  makefiles/                         cargo-make task definitions (lints, rocksdb, notify)
.github/                           CI workflows and issue templates
.githooks/                         Git hooks (pre-push)
.config/containers.conf            Rootless podman defaults (userns, security)

Cargo.toml                         Top-level workspace manifest
Cargo.lock                         Resolved dependency graph (committed)
Makefile.toml                      cargo-make task definitions
rust-toolchain.toml                Pinned Rust toolchain
deny.toml                          cargo-deny policy (licenses, advisories)
.env.testing-artifacts             Version pins for test container (Rust, zcashd, zebrad)

Dockerfile                         Production container image
entrypoint.sh                      Production container entrypoint
.dockerignore                      Docker build context exclusions

README.md                          This file
CHANGELOG.md                       Release notes
CLAUDE.md                          AI-contributor guidelines
CONTRIBUTING.md                    Human-contributor guide
LICENSE                            Apache-2.0 license text
.gitignore                         Git ignore patterns
```

## ORAM research-fork status

The non-published `zaino-oram` research crate now keeps one profile-bound,
non-`Clone` `ActiveSecurityLease` as the sole internal owner of runtime
security state. Full raw security-bundle assembly is available only to tests.
The crate exports only the small lifetime-safe `FixedEnvelopeRuntime`,
`PendingFixedEnvelope`, and `PrivateQueryUnavailable` facade consumed by
`zainod-oram`; pending responses retain their release authority and never
export detached response bytes. The concrete runtime owner remains private,
with no public constructor or factory.

The crate also contains a private, fixed-width security-state persistence
foundation. It binds the complete security identity to opaque serving and
component-state digests, commits local state durably before advancing an
injected exact freshness witness, and accepts startup state only when the local
sequence/digest exactly matches that witness. Ambiguous replacement or witness
advancement fails closed. No production witness or runtime owner uses this
store yet.

Alongside it, a crate-private local replay-journal foundation durably orders
one request lane with one real-or-cover continuation lane. Its fixed-size
version-two entry records (`ZORJENT2`) seal replay identities and semantic state
behind an injected protector, bind that protection to an opaque journal
context, and synchronize the next sequence candidate before the sole
`current.bin` commit marker. Each persisted real continuation claim is one
typed value containing its opaque replay key and a nonzero, one-based ceiling
expiry-bucket ordinal. The fixed-width version-three current record
(`ZORJCUR3`) additionally records a `u64` maintenance watermark without
changing any record width; entry v2 remains unchanged. Recovery rebuilds only
the exact committed sequence range, restores that separately persisted
watermark, and never inspects a later candidate; retries replace that
non-authoritative candidate uniformly. It is not connected to the runtime and
has only a deterministic test protector. Its total committed-transaction bound
is derived from compiled profile v6, and it assumes a single live writer
without enforcing a process lock.

A module-private coordinator now joins those two local foundations. Initial
provisioning is an explicit operation distinct from opening existing state, and
an existing open accepts only an exact match between the outer snapshot and the
current versioned, domain-separated replay-component digest. Each successful
replay commit's sealed durable path produces one move-only replay receipt
binding its opaque per-open journal identity and pre- and post-commit digests.
A greater maintenance watermark instead produces a distinct move-only
maintenance receipt that cannot be consumed as query-commit evidence. Before
advancing the outer local snapshot and injected witness, the coordinator checks
that the same live journal recognizes the applicable receipt and its
post-transition digest is still current. Both transitions therefore retain the
serialized replay-current -> outer-local -> witness order. It never infers
transition direction or repairs either store. Any outer failure after the
replay transition latches that coordinator instance fail closed. After a hard
witness rejection, a fresh open rejects the durable-local/witness mismatch with
`WitnessLocalMismatch`; if the witness advanced before returning an error, a
fresh open can reconcile and succeed.

This protocol is not one atomic transaction across the replay journal, outer
snapshot, and witness. No non-test runtime or security-owner caller constructs
the coordinator in this slice; owner integration remains separate.

The private profile identifier is now v6. It retains the replay-policy and
version-two entry bindings while selecting current-state v3 (`ZORJCUR3`).
Profile v6 requires fresh profile-bound journal and outer-state provisioning:
there is no in-place migration or dual acceptance of profile-v5/current-v2 or
earlier state. All current and entry record widths remain unchanged. Replay
journal and coordinator construction derive the lifetime-cumulative
transaction bound from the compiled profile, and the coordinator rejects an
exhausted outer sequence before committing replay.

The persisted maintenance watermark is a `u64`: zero is the sentinel for no
classified bucket, and a nonzero value is the inclusive recorded highest fully
expired continuation expiry bucket for future maintenance classification. The
raw recorded value is not itself trusted-time, epoch, profile, currentness, or
retirement authority. A lower proposal is rejected. An equal proposal returns
the typed `NoAdvance` outcome without a current-record write, receipt, or outer
sequence advance. A greater proposal durably advances only `ZORJCUR3`, mints
the distinct maintenance receipt, and then follows the coordinator ordering
above. It does not append an entry or change either claim set or counter.

The mutation/coordinator surface remains module-private, has no non-test caller,
and receives no trusted-time/epoch/profile grant. Any visibility widening or
runtime wiring must first consume a live, epoch/profile/currentness-bound,
move-only grant. The expiry ordinal and recorded watermark are classification
metadata only: this slice adds no request expiry, replay-entry deletion,
claim-count reduction, compaction, reclamation, bounded retention, or
garbage-collection execution. Capacity remains lifetime cumulative.

This is still source-level research evidence. A production protector/replay/
material-provider bundle, generated route and listener, runtime-integrated
witness-backed replay, trusted clock, nonce ledger, key management, production
freshness-witness ownership and advancement, proactive replay maintenance,
atomic combined persistence, rollback deployment evidence, TDX,
mainnet, target-load, access-oblivious qualification, and transport-write or
peer-delivery evidence remain open. The existing ten-phase logical schedule is
unchanged. See the
[implementation plan](./docs/notes/oram-enabled-zaino-plan.md),
[feasibility report](./docs/notes/oram-phase0-1-feasibility-report.md), and
[runtime security-owner ADR](./docs/adr/0009-private-query-runtime-security-state-owner.md).

## Server network exposure

Zaino exposes two servers, with different defaults reflecting their transport
security:

- **gRPC** (`[grpc_settings]`): may bind to a public address only when TLS is
  configured (`[grpc_settings.tls]` with `cert_path` / `key_path`). Binding to a
  non-private address without TLS is rejected at startup. The
  `no_tls_use_unencrypted_traffic` build feature disables this enforcement (and
  logs a startup warning) — for testing or trusted networks only.
- **JSON-RPC** (`[json_server_settings]`): has **no transport encryption** and
  is intended for loopback or trusted private networks only. By default it may
  bind only to private/loopback addresses (RFC1918, IPv6 ULA, or loopback);
  public or unspecified (`0.0.0.0` / `::`) bind addresses are rejected at
  startup. The `allow_unencrypted_public_json_rpc_bind` build feature lifts this
  restriction (and logs a startup warning) for deployments on trusted private
  networks where encryption is handled externally (e.g. containers behind a
  service mesh or proxy that terminates TLS).

**Security implication:** the JSON-RPC interface transmits unencrypted traffic.
Do not expose it to untrusted networks, and only enable
`allow_unencrypted_public_json_rpc_bind` when an external layer secures the
connection.

## Running tests

The test suites run inside a **podman** container via `makers` (cargo-make):

```sh
makers test            # packages/* tests that need no live validator (default)
makers test live       # both live partitions (clientless + e2e) + combined summary
makers test all        # everything: packages then live
```

zcashd-backed tests are **off by default**; add `--with-zcashd` to include them
(there is no implicit or env-var path — see docs/adr/0005). On lower-resource machines you
may hit occasional contention flakes under full parallelism — re-run, or lower
`test-threads` in the nextest config. See [docs/testing.md](./docs/testing.md)
for full instructions.

## Documentation
- [Use Cases](./docs/use_cases.md): Holds instructions and example use cases.
- [Testing](./docs/testing.md): Holds instructions for running tests.
- [Live Service System Architecture](./docs/zaino_live_system_architecture.pdf): Holds the Zcash system architecture diagram for the Zaino live service.
- [Library System Architecture](./docs/zaino_lib_system_architecture.pdf): Holds the Zcash system architecture diagram for the Zaino client library.
- [ZainoD (Live Service) Internal Architecture](./docs/zaino_serve_architecture_v020.pdf): Holds an internal Zaino system architecture diagram.
- [Zaino-State (Library) Internal Architecture](./docs/zaino_state_architecture_v020.pdf): Holds an internal Zaino system architecture diagram.
- [Internal Specification](./docs/internal_spec.md): Holds a specification for Zaino and its crates, detailing their functionality, interfaces and dependencies.
- [RPC API Spec](./docs/rpc_api.md): Holds a full specification of all of the RPC services served by Zaino.
- [Cargo Docs](https://zingolabs.github.io/zaino/): Holds a full code specification for Zaino.


## Security Vulnerability Disclosure
If you believe you have discovered a security issue, and it is time sensitive, please contact us online on Matrix. See our [CONTRIBUTING.md document](./CONTRIBUTING.md) for contact points.
Otherwise you can send an email to:
zingodisclosure@proton.me


## License
This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the [LICENSE](./LICENSE) file for details.
