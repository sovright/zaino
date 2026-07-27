# Private-query envelopes use a versioned XChaCha20-Poly1305 primitive

## Status

Accepted for the ORAM research fork. This decision selects a crate-internal
cryptographic primitive and transcript only. It does not authorize a service,
deployment, production-key, TDX, host-obliviousness, or mainnet privacy claim.

## Context

ADR 0007 requires authenticated fixed envelopes and continuation tokens, but it
does not select an AEAD, key roles, or canonical associated-data bytes. The
existing wire-shaped codecs already reserve a 24-byte nonce and 16-byte
authentication field. Their injected test protectors prove codec behavior but
are intentionally non-cryptographic.

Leaving the transcript implicit would let implementations disagree about field
order or domain separation. Reusing one key across request, response, and token
nonce spaces would also be unsafe: request nonces are supplied by a client,
while response and token nonces will be supplied by the server. A direction tag
in associated data does not make nonce reuse under one key safe.

The repository's prerelease Zcash dependency graph pins
`crypto-common = 0.2.0-rc.1`. RustCrypto `chacha20poly1305` 0.11 requires the
incompatible stable `crypto-common ^0.2` line. RustCrypto 0.10.1 is already in
the resolved workspace graph, supports XChaCha20-Poly1305, zeroizes its retained
key on drop, and has the same Apache-2.0-or-MIT licensing accepted elsewhere in
the workspace.

## Decision

The research implementation uses XChaCha20-Poly1305 with:

- a 256-bit key;
- a 192-bit nonce;
- a 128-bit detached authentication tag; and
- authenticated decryption before plaintext release.

The provider types own separate request-envelope, response-envelope, and
continuation-token key objects. No provider internally reuses one key object
across those roles. A future production owner must either provision independent
key material for all three roles or use a reviewed, explicitly domain-separated
KDF and must prevent callers from supplying the same effective key to multiple
roles.

The version-1 envelope associated data is the exact concatenation:

1. ASCII `zaino.private.v1/aead/envelope/v1`;
2. envelope format version as big-endian `u16`;
3. direction as one byte (`1` request, `2` response);
4. the 16-byte compiled profile identifier; and
5. the 32-byte session binding.

The version-1 continuation associated data is the exact concatenation:

1. ASCII `zaino.private.v1/aead/continuation/v1`; and
2. the existing canonical 89-byte continuation protection context: checkpoint
   fields followed by the 32-byte codec session binding.

The implementation remains crate-private. Constructors require key material in
`Zeroizing<[u8; 32]>`; the retained RustCrypto cipher key zeroizes on drop.
Encryption failure maps to the existing coarse provider-unavailable result.
Authentication failure maps to rejection and leaves the ciphertext buffer
unchanged. Fixed vectors are cross-checked against Go's independent
`x/crypto/chacha20poly1305` v0.47.0 implementation, and tests cover nonce,
ciphertext, tag, associated-data, context, direction, and wrong-key mutation.

The direct dependency stays on RustCrypto 0.10.1 until the workspace's Zcash
cryptography graph can move coherently. A version upgrade requires the same
fixed vectors and full workspace dependency-policy checks; it does not by
itself require a wire-format change if the transcript remains interoperable.

## Deferred ownership decisions

The required joint ownership and fail-closed lifecycle for these concerns is
now fixed by
[ADR 0009](0009-private-query-runtime-security-state-owner.md). Concrete
provider selections and implementations remain deferred. This ADR deliberately
does not define or implement:

- the concrete client/server handshake, exporter labels, or interoperability;
- key derivation, provisioning, rotation, revocation, KMS, or sealing provider;
- the rollback-resistant request, response, and continuation nonce allocator;
- the trusted-time, durable replay, capacity, garbage-collection, and external
  freshness providers;
- attestation evidence for the owner and its effective configuration; or
- a public opaque runtime factory, listener, transport, or service lifecycle.

Those providers and API changes must satisfy ADR 0009 before the private
runtime is exposed outside its crate. Provider unavailability continues to fail
closed under the contract established by the preceding fallible-protection
slice.

## Consequences

- The codec has one exact, reviewable cryptographic transcript instead of an
  implementation-defined use of its context fields.
- Request, response, and token protection cannot accidentally share one cipher
  object inside these providers.
- The 24-byte nonce already present in the fixed shapes is used directly, so
  this decision does not change envelope or token lengths.
- The primitive can be tested without inventing session, KMS, TDX, clock, or
  replay semantics.
- A production owner remains blocked until the deferred decisions above are
  resolved and independently reviewed.

## Considered alternatives

- **One key plus direction in associated data.** Rejected because direction
  authentication does not prevent nonce-reuse damage across independently
  controlled nonce spaces.
- **Derive all role keys in this slice.** Deferred because no root-key
  establishment, KDF transcript, session scope, key epoch, or attestation
  binding has been selected.
- **Upgrade to RustCrypto 0.11 now.** Rejected for this slice because it cannot
  resolve alongside the current prerelease Zcash `crypto-common` pin without a
  broader dependency migration.
- **Keep only deterministic protectors until service integration.** Rejected
  because freezing and testing the cryptographic transcript now narrows the
  later owner and client interoperability review without exposing a service.
