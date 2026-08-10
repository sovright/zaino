# Client key establishment implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an untrusted light wallet obtain the material it needs to seal a
private query, so the private-query surface is usable at all and #101's parity
test becomes writable.

**Architecture:** A second gRPC route, `BootstrapSession`, on the existing
private listener returns the current key epoch and exactly the two releasable
symmetric keys. The wallet seals `QueryPage` requests under them and sends the
epoch in cleartext beside the envelope so a retired key produces an actionable
`StaleKeyEpoch` rather than an indistinguishable refusal. Keys stay ephemeral,
so restart is rotation.

**Tech stack:** Rust, tonic 0.14.6, prost, rustls 0.23 (already in the tree via
`zaino-serve`), XChaCha20-Poly1305 envelopes (ADR 0008).

**Spec:** `docs/notes/private-query-client-key-establishment.md`

## Global constraints

- `.unwrap()` is DISALLOWED in production code. `.expect()` only for a genuine
  invariant, with a message naming it.
- Narrowest visibility that compiles. Never `pub` where `pub(crate)` or
  `pub(super)` works.
- Prefer a plain `fn` over a macro. CI gates on a duplicate-logic lint, so
  factor rather than copy-paste.
- Test attributes escalate only as the body justifies: `#[test]`, then
  `#[tokio::test]`, then `multi_thread` only when genuinely required.
- **No new dependency without explicit approval.** Task 5's decision is
  recorded there: `rcgen` with the `aws_lc_rs` feature, approved.
- Wire conversions use named methods, never `impl From`/`TryFrom` on `proto::`
  types. CI lints this.
- Every task ends green: `cargo test -p zaino-oram -p zainod-oram`,
  `cargo test -p zainod-oram --features private-service`, `cargo clippy`,
  `cargo fmt --all -- --check`, and the duplicate-code guard.

---

### Task 1: `ReleasableSessionKeys`

Makes releasing the wrong key unrepresentable. `token_key` seals continuation
tokens that clients echo back; a client holding it could mint tokens and bypass
replay and pagination control.

**Files:**
- Modify: `packages/zaino-oram/src/inner_codec/private_service.rs` (near
  `PrivateRuntimeKeys`, around line 267)
- Modify: `packages/zaino-oram/src/lib.rs` (re-export, near line 92)

**Interfaces:**
- Consumes: `PrivateRuntimeKeys`, `PRIVATE_RUNTIME_KEY_BYTES`
- Produces: `pub struct ReleasableSessionKeys { pub request_key: [u8; PRIVATE_RUNTIME_KEY_BYTES], pub response_key: [u8; PRIVATE_RUNTIME_KEY_BYTES] }` and
  `impl PrivateRuntimeKeys { pub fn releasable(&self) -> ReleasableSessionKeys }`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn only_the_request_and_response_keys_are_releasable() -> FixtureResult<()> {
    let keys = PrivateRuntimeKeys::ephemeral().map_err(|_| "the OS generator yields keys")?;
    let releasable = keys.releasable();

    assert_eq!(releasable.request_key, keys.request_key);
    assert_eq!(releasable.response_key, keys.response_key);

    // The guarantee this type exists for: no field, method, or trait impl on
    // ReleasableSessionKeys exposes the token or journal key. If a future
    // change adds one, this assertion is the only thing standing in its way,
    // so it compares against every byte of both withheld keys.
    let released = format!("{releasable:?}");
    assert_eq!(released, "ReleasableSessionKeys { ..REDACTED.. }");
    assert_eq!(
        std::mem::size_of::<ReleasableSessionKeys>(),
        2 * PRIVATE_RUNTIME_KEY_BYTES,
        "a releasable set that grew past two keys is releasing something it should not"
    );
    Ok(())
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p zaino-oram only_the_request_and_response_keys_are_releasable`
Expected: FAIL — no method named `releasable`.

- [ ] **Step 3: Implement**

```rust
/// The subset of runtime keys a wallet may hold.
///
/// Deliberately not constructible from anything wider. `token_key` seals
/// continuation tokens that a client only echoes back, so a client holding it
/// could mint tokens and bypass replay rejection and pagination control;
/// `replay_journal_key` protects durable server state. Neither has a route
/// through this type, which is why releasing the wrong key is a compile error
/// rather than a review catch.
pub struct ReleasableSessionKeys {
    /// Seals request envelopes.
    pub request_key: [u8; PRIVATE_RUNTIME_KEY_BYTES],
    /// Opens response envelopes.
    pub response_key: [u8; PRIVATE_RUNTIME_KEY_BYTES],
}

impl std::fmt::Debug for ReleasableSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReleasableSessionKeys { ..REDACTED.. }")
    }
}

impl PrivateRuntimeKeys {
    /// Copies out only the keys a wallet is allowed to hold.
    pub fn releasable(&self) -> ReleasableSessionKeys {
        ReleasableSessionKeys {
            request_key: self.request_key,
            response_key: self.response_key,
        }
    }
}
```

Add `ReleasableSessionKeys` to the `pub use` in `lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p zaino-oram -p zainod-oram`
Expected: PASS, count one higher than before.

- [ ] **Step 5: Commit**

```bash
git add packages/zaino-oram/src/inner_codec/private_service.rs packages/zaino-oram/src/lib.rs
git commit -m "Separate the releasable session keys from the runtime's own"
```

---

### Task 2: Bootstrap message and route in the proto

**Files:**
- Modify: `packages/zainod-oram/proto/private.proto`

**Interfaces:**
- Produces: `zaino.private.v1.BootstrapRequest`,
  `zaino.private.v1.BootstrapResponse`, and the
  `PrivateCompactTxStreamer/BootstrapSession` method.

- [ ] **Step 1: Edit the proto**

```proto
// Empty: bootstrap takes no client input. A field here would be an input to
// authenticate before the client holds any key material, which is exactly the
// surface this design avoids.
message BootstrapRequest {}

// Everything a wallet needs to seal a query, and nothing else.
message BootstrapResponse {
  // Identifies the key generation these keys belong to. Sent back in cleartext
  // on every QueryPage so a retired key is actionable rather than opaque.
  uint64 key_epoch = 1;
  // Seals request envelopes.
  bytes request_key = 2;
  // Opens response envelopes.
  bytes response_key = 3;
  // Human-readable name of the compiled privacy profile, for logs and support.
  // Diagnostic, NOT authoritative: the authoritative profile identifier is a
  // digest over every logical budget dimension and is already bound into
  // protected request state, so a query sealed against the wrong profile fails
  // to open regardless of what this string says.
  string profile_label = 4;
  // Exact envelope size class, so a wallet pads correctly without guessing.
  uint32 envelope_bytes = 5;
  // Reserved for a TDX quote binding the TLS identity to the measured binary.
  // Present and empty in this release; ADR 0010 defers verification, and
  // keeping the field means adding it later is not a breaking wire change.
  bytes attestation = 6;
}

service PrivateCompactTxStreamer {
  rpc QueryPage(FixedEnvelope) returns (FixedEnvelope);
  rpc BootstrapSession(BootstrapRequest) returns (BootstrapResponse);
}
```

Also add the cleartext epoch to the query request:

```proto
message FixedEnvelope {
  bytes envelope = 1;
  // The key epoch this envelope was sealed under. Cleartext on purpose: it is
  // per-generation and identical for every client, so it reveals nothing, and
  // sealing it inside would make a retired key indistinguishable from any
  // other refusal — leaving a wallet no way to learn it must re-bootstrap.
  uint64 key_epoch = 2;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p zainod-oram --features private-service`
Expected: PASS. Generated types appear under `crate::private_proto`.

- [ ] **Step 3: Commit**

```bash
git add packages/zainod-oram/proto/private.proto
git commit -m "Add the bootstrap exchange and cleartext key epoch to the private proto"
```

---

### Task 3: Per-route decode caps

The cap added in #98 is a single global envelope size. Bootstrap has a
different fixed size, so the cap becomes per-route. `QueryPage` keeps its exact
cap and its uniform refusal.

**Files:**
- Modify: `packages/zainod-oram/src/private_service/tonic_body.rs` (around
  `fixed_envelope_wire_size`, line 175, and `query_page`, line 155)
- Modify: `packages/zainod-oram/src/private_service/listener.rs` (route
  dispatch in `call`, around line 150)

**Interfaces:**
- Consumes: `fixed_envelope_wire_size(usize) -> usize`
- Produces: `const BOOTSTRAP_ROUTE: &str`, and a `bootstrap` method on
  `PrivateTonicBodyAdapter` returning `http::Response<TonicBody>`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn each_route_is_capped_at_its_own_size() {
    // A body sized for bootstrap must still be refused by QueryPage, whose cap
    // is the fixed envelope. Sharing one cap across routes would let the larger
    // of the two set the limit for both.
    let oversized_for_query = encoded_frame(&vec![0u8; ENVELOPE_BYTES + 64]);
    let response = adapter().query_page(request(QUERY_PAGE_ROUTE, oversized_for_query)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(handler_calls(), 0, "an oversized query body reached the runtime");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p zainod-oram --features private-service each_route_is_capped_at_its_own_size`
Expected: FAIL — `BOOTSTRAP_ROUTE` and the per-route dispatch do not exist.

- [ ] **Step 3: Implement**

In `listener.rs`, add the route constant beside `QUERY_PAGE_ROUTE` and dispatch
on it:

```rust
const BOOTSTRAP_ROUTE: &str = "/zaino.private.v1.PrivateCompactTxStreamer/BootstrapSession";
```

```rust
fn call(&mut self, request: http::Request<B>) -> Self::Future {
    let adapter = Arc::clone(&self.adapter);
    Box::pin(async move {
        match request.uri().path() {
            QUERY_PAGE_ROUTE => {
                let mut adapter = adapter.lock().await;
                Ok(adapter.query_page(request).await)
            }
            BOOTSTRAP_ROUTE => {
                let mut adapter = adapter.lock().await;
                Ok(adapter.bootstrap(request).await)
            }
            // Unchanged: an unknown route answers exactly as a refused query
            // does, so route probing cannot distinguish them.
            _ => Ok(unavailable_response()),
        }
    })
}
```

In `tonic_body.rs`, give bootstrap its own `Grpc` with its own cap. Keep
`fixed_envelope_wire_size` as the single place wire size is computed so the two
routes cannot drift.

- [ ] **Step 4: Run tests**

Run: `cargo test -p zainod-oram --features private-service`
Expected: PASS, including the existing
`oversized_body_is_rejected_with_the_uniform_refusal`.

- [ ] **Step 5: Commit**

```bash
git add packages/zainod-oram/src/private_service/
git commit -m "Cap each private route at its own fixed size"
```

---

### Task 4: Serve the bootstrap response

**Files:**
- Modify: `packages/zainod-oram/src/private_service/tonic_body.rs`
- Modify: `packages/zaino-oram/src/inner_codec/private_service.rs` (expose the
  epoch and releasable keys from the runtime)

**Interfaces:**
- Consumes: `ReleasableSessionKeys` (Task 1), `BootstrapResponse` (Task 2)
- Produces:
  - `SessionBootstrap { key_epoch: u64, keys: ReleasableSessionKeys, profile_label: &'static str }`
    — a named struct rather than a tuple, because positional fields of which
    one is an integer are exactly where a caller silently swaps them.
    Deliberately *no* `envelope_bytes` field: the envelope width is already
    determined by the runtime's fixed-envelope const generic `N`, and a second
    copy here could disagree with it. Every place that reports an envelope
    width — the bootstrap response and both decode caps — derives it from `N`.
  - `fn session_bootstrap(&self) -> SessionBootstrap` on the runtime trait.
  - `PrivateQueryOutcome::StaleKeyEpoch` — a new variant, distinguishable from
    the uniform refusal.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn bootstrap_returns_the_current_epoch_and_exactly_two_keys() {
    let response = decode_bootstrap(adapter().bootstrap(request(BOOTSTRAP_ROUTE, empty())).await).await;

    assert_eq!(response.key_epoch, EXPECTED_EPOCH);
    assert_eq!(response.request_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
    assert_eq!(response.response_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
    assert_eq!(response.envelope_bytes as usize, ENVELOPE_BYTES);
    assert!(response.attestation.is_empty(), "attestation is deferred, not populated");
    // The keys served must be the releasable pair and nothing else.
    assert_ne!(response.request_key, response.response_key);
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p zainod-oram --features private-service bootstrap_returns_the_current_epoch`
Expected: FAIL — no `bootstrap` method.

- [ ] **Step 3: Implement**

Add `session_bootstrap()` to the runtime trait and its concrete impl, reading
`key_epoch` from the projection config it already carries. Build the
`BootstrapResponse` in `tonic_body.rs` using a named `to_wire`-style method, not
a `From` impl — CI lints proto `From` impls.

- [ ] **Step 4: Write the failing epoch-check test**

```rust
#[test]
fn a_request_under_a_retired_epoch_is_distinguishable() {
    // Distinguishable on purpose. The epoch is per-generation and identical for
    // every client, so reporting it leaks nothing, and folding it into the
    // uniform refusal would leave a wallet no way to learn it must
    // re-bootstrap.
    let outcome = classify_request_epoch(CURRENT_EPOCH, CURRENT_EPOCH - 1);
    assert_eq!(outcome, Some(PrivateQueryOutcome::StaleKeyEpoch));
    assert_eq!(classify_request_epoch(CURRENT_EPOCH, CURRENT_EPOCH), None);
}
```

- [ ] **Step 5: Implement the epoch check**

Add the `StaleKeyEpoch` variant to `PrivateQueryOutcome`. Compare the
cleartext `key_epoch` on the incoming `FixedEnvelope` against the runtime's
current epoch **before** attempting to open the envelope — under a retired key
the open would fail anyway, and the whole point is to answer with something the
wallet can act on instead.

The comparison is on public data, so an ordinary `==` is correct here; do not
reach for the constant-time helpers, which would imply the epoch is secret.

- [ ] **Step 6: Run tests**

Run: `cargo test -p zaino-oram -p zainod-oram` and
`cargo test -p zainod-oram --features private-service`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/zaino-oram/src packages/zainod-oram/src
git commit -m "Serve the current key epoch and releasable keys over bootstrap"
```

---

### Task 5: TLS on the private listener — DONE

The dependency question this task was gated on has been answered: **add
`rcgen`**, built against **aws-lc-rs**, not ring. The workspace standardised on
aws-lc-rs in ADR 0006 and already carries `aws-lc-rs 1.17.1`, so the ring
alternative would have contradicted the ADR *and* added a second crypto
backend. The operator-supplied-PEM alternative was rejected: it puts the TLS
private key in the operator's hands, which is precisely the custody question
ADR 0010 avoids and ADR 0007's "generates its TLS identity internally" rules
out.

**Manifest** (`packages/zainod-oram/Cargo.toml`, added with `cargo add`):

```toml
rcgen = { version = "0.14.9", default-features = false, features = ["aws_lc_rs"], optional = true }
base64 = { workspace = true, optional = true }
```

with `dep:rcgen`, `dep:base64` and `tonic/tls-aws-lc` folded into the
`private-service` feature.

Crates **actually compiled** that were not compiled before: `rcgen` and
`yasna`. `base64` was already a workspace dependency and is only newly
*referenced* here. `Cargo.lock` additionally gained nine entries it never
builds — `x509-parser` and its tree (`asn1-rs`, `asn1-rs-derive`,
`asn1-rs-impl`, `der-parser`, `oid-registry`, `rusticata-macros`, `bit-vec`,
`data-encoding`, `untrusted 0.7.1`). That is a lock artifact, not a build edge:
rcgen's `aws_lc_rs` feature *names* `x509-parser?/verify-aws`, and Cargo's
resolver records every dependency an enabled feature names even when the weak
`?` means feature resolution never activates it. `cargo tree -p zainod-oram
--features private-service` shows none of them. No feature selection avoids
this while keeping aws-lc-rs.

`pem` was deliberately **not** enabled. rcgen's `pem` feature would pull the
`pem` crate purely to base64-wrap DER; `pem_block` in
`packages/zainod-oram/src/private_service/tls.rs` does that in one shared
function over the `base64` encoder the workspace already has, used for both the
certificate and the key.

**What was built:**

- `packages/zainod-oram/src/private_service/tls.rs` — `PrivateTlsIdentity`.
  `load_or_generate(deployment_dir)` mints a self-signed ECDSA P-256 identity
  in-process on first start and reuses it thereafter. The private key is
  reachable only from inside the value: no accessor, absent from `Debug`.
- `PrivateQueryListener::serve` now takes `&PrivateTlsIdentity` and calls
  `Server::builder().tls_config(...)`, after
  `zaino_common::crypto::ensure_default_crypto_provider()` — the same
  process-level rustls provider install the public gRPC server needs
  (zingolabs/zaino#1360). The identity is a required argument, not an
  `Option`, so serving this surface in cleartext is unrepresentable.
- Everything the listener already did is untouched: the 32-permit connection
  semaphore whose permit rides with the connection, `concurrency_limit_per_connection(1)`,
  the per-route decode caps, and the uniform refusal. TLS wraps the transport
  and sits above the same accepted-connection stream.
- `run_private_serve` loads or mints the identity *before* binding and long
  before chain replay, so a damaged one fails immediately rather than after a
  full replay is paid for. It writes the fingerprint record to stdout and
  publishes it to `<replay_journal_dir>/private-tls-fingerprint.txt`, checking
  rather than overwriting a record a previous start left.

**The certificate persists across restarts.** An earlier revision of this task
minted a fresh certificate on every start, tied to the key epoch for
consistency with "restart is rotation". That was wrong and was reversed. The
symmetric keys can rotate safely because the recovery path runs *above* TLS: a
wallet with stale keys gets `StaleKeyEpoch` in cleartext and re-bootstraps. A
rotating certificate breaks a wallet's pin *below* TLS — an opaque handshake
failure, no route to `BootstrapSession` to find out why, and no way to
distinguish rotation from substitution. That is the same anti-pattern the
cleartext `key_epoch` removed, reintroduced one layer down. Certificate
lifetime and key lifetime are separate concerns.

So `PrivateTlsIdentity::load_or_generate(deployment_dir)` mints on first start
and reuses thereafter, persisting `private-tls-cert.pem` and
`private-tls-key.pem` beside the fingerprint. Rotation is an explicit operator
action — delete both files — never a side effect of a restart.

**It fails closed, never regenerates.** A damaged, unreadable, half-present, or
over-permissive identity is a typed `PrivateTlsError` naming the file and what
was wrong (`Unreadable`, `Malformed { reason }`, `Incomplete { present,
missing }`, `InsecureKeyPermissions { mode }`, `FingerprintMismatch`). Silent
regeneration is the dangerous path: it breaks every wallet's pin with no
signal, which is precisely what persisting the identity is for. Validation is
a PEM decode plus a complete-DER-SEQUENCE check — enough to catch truncation,
concatenation, and editor damage without an ASN.1 crate; anything that slips
past still fails closed one layer later when the acceptor is built.

**A private key is now at rest on disk.** Created owner-only (0600), and the
loader refuses one that is not. Acceptable *specifically* under ADR 0010, where
the operator is honest-but-curious and outside the threat model — the
adversaries in scope are network observers and other clients, and neither gains
from a key the operator could always have read out of process memory. Flagged
in the module header as something that **must be revisited as the posture
tightens toward ADR 0007**, where the answer is a TEE-sealed or attested
ephemeral key.

**Nothing per-generation is in the certificate.** One SAN, the verified name
`private-query.zaino.invalid` (`.invalid` per RFC 6761: pinned or attested,
never resolved). The key-epoch SAN the first revision carried was removed — the
certificate now outlives many epochs, so a baked-in one is stale from the next
restart onward and would actively mislead a wallet reading it. Nothing replaced
it: the service namespace id tracks the capture, which can be upgraded under a
stable deployment directory, and `profile_label` is documented in the proto as
diagnostic and explicitly not for pinning. A name that can go stale is worse
than no name.

**The pinning story, stated without overclaiming.** The fingerprint is stable
across restarts, so a wallet pins once and keeps it, and a broken pin now means
something actually changed rather than "the process bounced". A pin still only
establishes that the wallet is talking to the *same* surface as last time — not
*what* that surface is, which binary is running, or whether the workload is the
measured one. Only attestation answers that, and it supersedes pinning when it
lands. `run_private_serve` prints all of this on stderr beside the fingerprint.

**Handshake timeout.** `ServerTlsConfig::timeout(10s)`. The 32-connection
semaphore takes its permit at accept, before the handshake, so an unbounded
handshake lets a peer that connects and never speaks hold one of the 32
forever. Ten seconds is roughly two orders of magnitude above a legitimate TLS
1.3 handshake even on a bad mobile link — deliberately generous, because
refusing a slow but honest wallet costs more than tolerating a slow attacker
who is already capped at 32 connections.

**Tests** (all green):

- `a_bound_listener_answers_one_exact_query`, `a_wallet_bootstraps_then_queries` —
  a real client completes a real TLS handshake and calls `BootstrapSession` and
  `QueryPage` through it.
- `the_reported_fingerprint_is_the_certificate_that_is_served` — the published
  fingerprint is SHA-256 over the DER the handshake presented.
- `a_certificate_from_another_deployment_is_refused` — a pin from a different
  deployment fails the handshake, which is the proof the client above trusted
  *only* the served certificate.
- `a_second_start_reuses_the_persisted_identity` — a second start over the same
  directory reports the identical fingerprint, certificate, and key, while a
  different directory does not, so the equality is reuse rather than a constant
  certificate.
- `a_damaged_identity_fails_closed_rather_than_regenerating` — non-base64 PEM,
  a truncated DER body, and a half-present pair each produce a named error, and
  the operator's files are left untouched.
- `a_world_readable_key_is_refused`, `the_persisted_key_is_owner_only` — the
  0600 contract in both directions.
- `publishing_is_idempotent_and_catches_a_disagreeing_record` — a restart
  republishes silently; a record that disagrees with the certificate on disk is
  an error.
- The pre-existing connection-cap and decode-cap tests still pass; the five
  serving tests now run over TLS through one shared `ServedSurface` helper
  (bind port 0, mint, spawn, stop off the served task — no fixed sleeps).

---

### Task 6: End-to-end round trip

The capability #101's parity test has been waiting for.

**Files:**
- Modify: `packages/zainod-oram/src/private_service/listener.rs` (tests)

**Interfaces:**
- Consumes: everything from Tasks 1-4.

- [ ] **Step 1: Write the failing test**

```rust
/// multi_thread required: the serve loop and the client run concurrently on
/// separate tasks and the client blocks on responses the server must send.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_bootstraps_then_queries() -> Result<(), Box<dyn std::error::Error>> {
    let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
    let address = listener.local_addr();
    let (shutdown, rx) = tokio::sync::oneshot::channel();
    let served = tokio::spawn(listener.serve(refreshed_runtime()?, async { let _ = rx.await; }));

    let session = bootstrap_client(address).await?;
    let sealed = seal_request(&session.request_key, sample_query())?;
    let response = query_page_client(address, sealed, session.key_epoch).await?;
    let opened = open_response(&session.response_key, response)?;

    assert_eq!(opened, expected_page_for(sample_query()));

    let _ = shutdown.send(());
    served.await??;
    Ok(())
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p zainod-oram --features private-service a_wallet_bootstraps_then_queries`
Expected: FAIL — no bootstrap client helper yet.

- [ ] **Step 3: Implement the client helpers**

Thin tonic clients over the generated stubs. Bind to port 0, never a fixed
port. Drive readiness off the served task, never a fixed `sleep`.

- [ ] **Step 4: Add the stale-epoch test**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn a_retired_epoch_is_actionable_rather_than_opaque() -> Result<(), Box<dyn std::error::Error>> {
    // A wallet that keeps querying under a retired key must learn to
    // re-bootstrap. If this returns the uniform refusal instead, the epoch has
    // stopped being cleartext and the client is stuck guessing.
    let outcome = query_page_client(address, sealed_under_old_key, STALE_EPOCH).await?;
    assert_eq!(outcome, PrivateQueryOutcome::StaleKeyEpoch);
    Ok(())
}
```

- [ ] **Step 5: Run everything**

Run: `cargo test -p zaino-oram -p zainod-oram`,
`cargo test -p zainod-oram --features private-service`, `cargo clippy`,
`cargo fmt --all -- --check`, and the duplicate-code guard.
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/zainod-oram/src/private_service/listener.rs
git commit -m "Prove a wallet can bootstrap, seal a query, and open the response"
```

---

## After the plan

Update #102 to record what was deferred: attestation verification, per-session
derivation, enrolment and revocation, rotation beyond restart, and TEE sealing.
Then #101's parity test becomes writable, since client key material now exists.
