# Private query: client key establishment

Design for issue #102. Written 2026-08-09.

Scope: how an untrusted light wallet obtains the material it needs to talk to
the private-query surface, under the deployment posture in
[ADR 0010](../adr/0010-interim-honest-but-curious-deployment-posture.md) — an
honest-but-curious operator inside an attested TEE, with network observers in
scope and clients untrusted.

This unblocks the parity test in #101, which cannot send a valid protected
query today because there is no way to obtain client key material at all.

## The problem

`mainnet_private_query_runtime` takes one `PrivateRuntimeKeys` per runtime:
four symmetric keys — `request_key`, `response_key`, `token_key`,
`replay_journal_key`. They were drawn from the OS generator and kept for the
process lifetime.

Nothing distributed them. A wallet therefore could not seal a request, and the
surface could not be used by anyone. That was the functional blocker; the
security questions below follow from how it is resolved.

## Decisions

### Client isolation comes from TLS, not from the envelope

Envelope keys stay runtime-wide. Every wallet holds the same
`request_key`/`response_key`, and TLS — terminated inside the workload, per ADR
0007 — is what stops one wallet reading another's traffic.

State the consequence plainly rather than implying more: a wallet that obtains
another wallet's ciphertext **can** decrypt it. The envelope provides
authenticity, profile and epoch binding, and a fixed traffic shape. It does not
provide client-to-client confidentiality. TLS does.

Per-session derivation was considered and deferred. The bootstrap exchange
below is shaped so it can be added later without changing the wallet's flow.

### Only two of the four keys are releasable

`token_key` seals continuation tokens, which are server-authenticated state
that a client merely echoes back. A client holding it could mint tokens and
bypass replay rejection and pagination control. `replay_journal_key` protects
durable server state. Neither is ever released.

This is enforced in the type system rather than by review. A
`ReleasableSessionKeys` value holds exactly `request_key` and `response_key`,
is the only thing the bootstrap path can serve, and offers no route to the
other two. Handing out the wrong key should be unrepresentable, not merely
caught.

### Wallets bootstrap over attested TLS

A second route on the private listener returns the current key epoch and the
releasable keys. The wallet then seals `QueryPage` requests under them.

A bootstrap RPC was chosen over publishing keys in the profile document because
it handles rotation and epoch change without republishing anything, and because
it is the natural place to add attestation later.

### Attestation is deferred, with room reserved

No attestation gate in this release. Attestation defends against an operator
who swaps the binary, which ADR 0010 places out of model.

The bootstrap response carries an attestation field that is present and empty,
so adding verification later is not a breaking wire change. Until then the
wallet trusts the operator's deployment rather than verifying it, and the
documentation must say exactly that.

For TLS the workload generates its identity internally on first start, and
this is now built (`packages/zainod-oram/src/private_service/tls.rs`). The
process mints a self-signed ECDSA P-256 certificate with `rcgen` over
aws-lc-rs; the private key is drawn in-process, is held only inside
`PrivateTlsIdentity`, and is exposed by no accessor and no `Debug` rendering.
`PrivateQueryListener::serve` terminates on it and takes it as a required
argument rather than an `Option`, so a cleartext private surface is
unrepresentable.

The certificate and its key are **persisted** in the deployment directory and
reused on every subsequent start. This is the one thing here that deliberately
does not follow "restart is rotation", and the reason is the section below it:
a wallet whose *keys* went stale is told so — the cleartext `key_epoch` earns
it `StaleKeyEpoch` and it re-bootstraps — but that recovery path runs *above*
TLS. A wallet whose *pin* broke gets an opaque handshake failure, cannot reach
`BootstrapSession` to discover why, and cannot tell rotation from
substitution. Rotating the certificate would reintroduce, one layer lower,
exactly the opaque failure the cleartext epoch exists to prevent. Certificate
lifetime and key lifetime look like they should match; they are separate
concerns, and only the layer that can explain itself should be allowed to
change.

Rotation is therefore an explicit operator action — delete the certificate and
key — never an implicit consequence of a restart. A damaged, unreadable, or
half-present identity **fails closed** with a typed error naming the file:
silently regenerating would break every wallet's pin with no signal at all,
which is the failure mode this whole arrangement exists to avoid.

The cost is a private key at rest on disk, readable by the operator. That is
acceptable *specifically* under ADR 0010's interim posture, where the operator
is honest-but-curious and out of the threat model; the adversaries in scope are
network observers and other clients, and neither gains from a key the operator
could always have read out of process memory. The file is created owner-only
(0600) and the loader refuses one that is not. **This must be revisited as the
posture tightens toward ADR 0007**: against an operator in scope, a key at rest
is a key the operator holds, and the answer there is a TEE-sealed or attested
ephemeral key, not this.

Nothing per-generation is encoded into the certificate. It carries one SAN, the
name a wallet verifies against (`private-query.zaino.invalid`; `.invalid` per
RFC 6761 because this identity is pinned or attested, never resolved). An
earlier revision carried the key epoch in a second SAN; that is now wrong, and
was removed — the certificate outlives many epochs, so a baked-in one would be
stale from the next restart onward and would actively mislead a wallet reading
it. The same objection retires the other candidates: the service namespace id
tracks the capture, which can be upgraded under a stable deployment directory,
and `profile_label` is documented in the proto as diagnostic and explicitly not
for pinning.

The process writes the fingerprint (SHA-256 over the served DER, hex) to stdout
and to `<replay_journal_dir>/private-tls-fingerprint.txt`, so an operator has
something concrete to publish and a wallet has something concrete to pin. On a
later start the published record is checked rather than overwritten: a
disagreement with the certificate on disk means the pair is not what operators
told wallets to expect, and that too fails closed.

**What a pin is worth, without overclaiming.** It is stable across restarts, so
a wallet pins once and keeps it, and a broken pin now means something actually
changed rather than "the process bounced". But a pin still only establishes
that the wallet is talking to the *same* thing it talked to last time. It says
nothing about *what* that thing is — which binary is running, whether the
workload is the measured one. Only attestation answers that; ADR 0010 defers
it, and when it lands it supersedes pinning entirely.

The listener also bounds one TLS handshake at ten seconds
(`ServerTlsConfig::timeout`). The 32-connection semaphore takes its permit at
accept, before the handshake, so without a bound a peer that connects and never
speaks would hold one of the 32 indefinitely. Ten seconds is roughly two orders
of magnitude above a legitimate handshake even on a poor mobile link, so it is
deliberately generous: refusing a slow but honest wallet costs more than
tolerating a slow attacker, who is already capped at 32 connections.

### Restart is rotation

This is about the four symmetric keys, and only them. The TLS identity above is
the deliberate exception and persists; the section above says why.

Keys stay ephemeral. A restart mints fresh ones, so wallets re-bootstrap,
outstanding continuation tokens become invalid, and the replay journal starts
empty.

This avoids key custody entirely, which is the point. Sealing keys to the TEE
would preserve tokens and journal across restart but pulls in the custody
question ADR 0010 deferred, needs the rollback authority from #106, and cannot
be tested without TDX hardware. Persisting them unsealed contradicts ADR 0010's
own posture, since an honest-but-curious operator is assumed to look.

Because each restart draws fresh keys, this is **not** an AEAD nonce-reuse
hazard.

The key epoch is drawn *with* the keys, from the same generator, by
`EphemeralKeyGeneration::draw`. Neither half can be obtained alone. A fixed or
independently chosen epoch would make restart-is-rotation inert: the keys would
change while the epoch stood still, and a wallet holding retired keys would see
the uniform refusal instead of `StaleKeyEpoch` — the exact opaque outcome the
cleartext epoch exists to prevent.

### The key epoch travels in cleartext

The wallet sends `key_epoch` beside the sealed envelope, not inside it.

If the epoch were only inside, a request sealed under a retired key would fail
to open and would be indistinguishable from any other refusal, so the wallet
could never learn that re-bootstrapping is what it needs to do. The epoch is
not secret — it is per-generation and identical for every client — so a
distinguishable `StaleKeyEpoch` outcome leaks nothing and makes the client's
behaviour obvious.

`key_epoch: u64` already exists on the runtime's projection config and is
already bound into the replay namespace digest. This reuses it rather than
introducing a second notion of epoch.

## Wire and listener changes

A second route,
`/zaino.private.v1.PrivateCompactTxStreamer/BootstrapSession`, beside
`/zaino.private.v1.PrivateCompactTxStreamer/QueryPage`, which today is the
listener's only one. Its response carries the key epoch, the two releasable
keys, the profile *label*, the envelope size class, and the empty attestation
field.

The label is diagnostic and explicitly not authoritative — the field is named
`profile_label` so no wallet author pins on it. The authoritative profile
identifier is a digest over every logical budget dimension and is already bound
into protected request state, so a query sealed against the wrong profile fails
to open regardless of what the label says. Publishing the digest here would add
a second thing to pin without adding a check the envelope does not already
make.

ADR 0007 already lists "method class if exposed as separate RPCs" among
permitted observations, so a distinguishable bootstrap method sits inside the
accepted leakage budget. Bootstrap takes no secret input, so it needs none of
`QueryPage`'s uniform-shape discipline.

The decode cap added in #98 is currently a single global fixed-envelope size.
It becomes per-route: `QueryPage` keeps its exact cap and its uniform refusal
for everything else; `BootstrapSession` gets its own fixed size. The connection
cap of 32 and the per-connection request limit of 1 are unchanged and apply to
both.

## Testing

- Bootstrap releases exactly two keys, and `token_key`/`replay_journal_key` are
  unreachable through the public API. This is the test that would catch the
  worst mistake in the design.
- Full round trip: bootstrap, seal a request, call `QueryPage`, open the
  response. This is the missing capability that #101's parity test needs.
- A request under a retired epoch produces `StaleKeyEpoch`, distinguishable
  from a uniform refusal, and a wallet that re-bootstraps then succeeds.
- Restart yields a different epoch, and the previous key fails cleanly rather
  than silently.
- Per-route decode caps: an oversized bootstrap body and an oversized
  `QueryPage` body are each rejected against their own limit, and `QueryPage`'s
  refusal stays indistinguishable.

## Out of scope

Each of these is deferred by a decision above, not overlooked. Issue #102
should be updated to say so.

- Attestation verification — the field exists and is empty.
- Per-session key derivation.
- Enrolment, revocation, and per-client identity.
- Key rotation other than restart.
- Sealing keys to the TEE, and journal or token survival across restart.

## What this does not achieve

A wallet using this cannot verify what it is talking to; it trusts the
deployment. Wallets are not cryptographically isolated from each other at the
envelope layer, only at the transport. Both follow from ADR 0010's posture and
both must be revisited before the ADR 0007 claim.
