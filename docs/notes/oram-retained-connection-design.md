# Retained-connection private client foundation

Status: proposed next research implementation after ADR0904. No accepted guest
image policy or private-wallet readiness is created by this design. Current
evidence, bootstrap, and codec helpers are inputs to the implementation; their
existence does not establish a connection capability.

## Scope

Implement one connection, one attestation attempt, one activated bootstrap,
and first-page transparent UTXO queries using the existing fixed profile.
Keep REPORT_DATA v1 unchanged. Do not add pagination, a connection pool,
automatic recovery, a freshness witness default, or a new server transcript.
The client uses the authoritative compiled envelope width, currently 24,576
bytes, rather than a separately maintained constant.

The new transport code belongs in `zaino-private-client`. Keep protocol messages
generated from the single canonical protobuf. Select actual TLS/HTTP APIs
against the repository's pinned dependency versions during implementation;
this note specifies ownership and verification requirements, not an assumed
library capability. The current codec's `corpus-zaino` dependency closure is
explicitly retained for this slice, pending a separate feature extraction.

## Ownership and operation order

1. A private pending-connection owner holds one connected TLS stream, the
   actual peer leaf certificate/SPKI digest, an immutable verifier-owned policy,
   and a fresh 64-byte OS-generated challenge. No caller supplies a reusable
   challenge to the transport API. There is no bootstrap or query operation on
   this owner. Public connection configuration contains only reviewed endpoint
   and local policy/helper installation choices.
2. Establish TLS 1.3 with HTTP/2 ALPN. The bootstrap TLS trust policy may defer
   issuer/hostname authority to attestation, but must still perform ordinary
   CertificateVerify proof-of-possession checks with the selected crypto
   provider and reject unsupported algorithms. Do not use a verifier that
   returns success for handshake signatures. Extract SHA-256 of DER
   SubjectPublicKeyInfo from the actual peer leaf on this stream. Use a reviewed
   bounded DER implementation; the test-only certificate walker is not a
   production parser. Bound certificate chain/body input and handshake time.
3. Give this already-handshaken stream to HTTP/2 without a second TLS wrapper.
   If using a tonic connector, its only connection source is a guarded
   `Option<stream>`: first call takes it, every subsequent call returns terminal
   failure. It never dials a socket. No raw channel/connector getter or Clone
   implementation is exposed by the capability owner. Disable transport/RPC
   retries where configurable, and test any implicit library reconnect path.
4. Send only `GetEvidence`. Enforce the protobuf/message size bound before
   parsing, then validate version, field widths, echoed challenge, actual peer
   SPKI, and reviewed binary/config/profile/schema policy. Recompute the frozen
   258-byte v1 transcript. Retain the exact parsed evidence and raw quote as a
   private immutable snapshot for this attempt.
5. Invoke the existing hash-pinned local Go verifier with the policy cloned into
   that parsed attempt. Its exact quote digest, serialized policy-byte digest,
   REPORT_DATA, schema, and limited scope must correlate. A blocking helper must
   run off the async executor; cancellation must not leave an unbounded worker.
   Its existing deadline/kill/reap contract bounds any already-running helper.
   No successful subprocess output can resume an attempt whose stream/owner was
   dropped or cancelled. Do not accept server-supplied receipt JSON.
6. Internally retain the local receipt, the exact verified evidence snapshot,
   and the same channel together. There is no public constructor that turns
   arbitrary `LocalQuotePolicyReceipt` plus arbitrary `EvidenceResponse` into
   an admitted connection. In particular, do not verify one mutable protobuf
   object and later compare bootstrap against a modified copy.
7. Fetch bootstrap on this same connection only after quote/policy verification.
   Use the strict named wire conversion, comparing expected network and the
   verified evidence's profile/schema/key epoch/finalized anchor. Preserve the
   explicit canonical-to-display hash conversion. Validate version, key/binding
   widths, empty legacy attestation, and authoritative compiled envelope width.
   Build the existing production first-page codec from this exact context.
8. Only now construct the public research client capable of a first-page query.
   It owns the retained channel and codec privately. A query method accepts a
   business address/minimum height and seals internally; it does not accept an
   externally manufactured protected envelope. Decode responses with exact
   checkpoint validation and refuse continuation-required responses. Serialize
   calls through this owner, with one outstanding request, until a reviewed
   multiplexing/correlation design exists.
9. Any verification refusal, cancellation, transport failure, or reconnect
   attempt consumes/drops the attempt and its challenge. A new connection starts
   the entire sequence again. Fresh per-attempt ownership avoids an unbounded
   consumed-nonce registry. Never persist admission across process restart.

## What the binding means

REPORT_DATA v1 binds a fresh challenge and a TLS public key, not a unique TLS
session or exporter. Two streams using the same key and challenge cannot be
distinguished cryptographically by v1. Local ownership and the single-use
connector prevent an accepted capability migrating to a replacement stream;
do not claim exporter binding or write a test asserting otherwise.

Additional bootstrap fields are authenticated transitively by the retained
TLS stream and the accepted workload's publication behavior. They are not
individually quoted. The finalized anchor within the serving identity is not
the recent tip, recent contents, or an authenticated ORAM root. Current serving
is frozen for the listener lifetime. A cached bootstrap describes that frozen
context; it is not a currentness or readiness oracle. Live refresh requires a
separate atomic publication/re-attestation design.

The caller's trust policy and client filesystem are trusted. A local helper
receipt proves its limited quote/collateral/field checks, not guest-image
approval, cloud configuration, public-chain freshness, or operator privacy.
Until an independently reviewed immutable guest policy exists, only explicit
research/diagnostic execution is possible. Do not synthesize a permissive
checkpoint witness or derive accepted measurements from the quote under test.

## Minimum tests

- A real local TLS/HTTP2 test independently extracts the actual certificate
  SPKI and observes the complete order: handshake, evidence, local verification,
  bootstrap, first-page query. Successful synthetic verifier/provider data is
  labelled plumbing evidence and cannot exercise a production acceptance mode.
- A route recorder proves zero bootstrap/query calls after wrong challenge,
  wrong SPKI/key, unsupported version, malformed/oversized evidence, policy
  mismatch, helper refusal/timeout/correlation failure, or cancellation.
- The TLS verifier refuses invalid handshake signatures. A proxy presenting a
  different key cannot substitute a valid quote from another endpoint.
- A single-use connector counter proves it supplies only the original stream;
  closing it or eliciting library reconnect never dials or sends sensitive
  traffic on another connection. A new owner uses a fresh challenge. Do not use
  same-key/same-challenge cross-stream data as a cryptographic negative test.
- Mutation/substitution of evidence between successful verification and
  bootstrap is impossible through the public API; internal regression tests
  refuse mismatched profile/schema/epoch/network/finalized height/hash/binding
  context. Include nonuniform hash bytes and actual compiled envelope width.
- Client cancellation and late helper completion cannot create a usable client.
  A refused bootstrap drops the attempt, and no protected query is sent.
- Exercise the production first-page codec against the existing typed runtime
  on Linux, with a known positive ordinary-source UTXO and an absent address.
  Check exact records, fixed envelope width, response-checkpoint refusal, and
  explicit continuation-required refusal. These are separate from synthetic
  TLS/provider tests and remain gated on the genuine runtime refresh fixture.

## Hardware qualification after local integration

A hardware experiment must run the real ephemeral-key Zaino listener and
ConfigFS quote provider, preserve the exact live TLS stream through evidence
and bootstrap, and use full cryptographic collateral verification. A signed
baseline diagnostic quote with arbitrary REPORT_DATA cannot serve as a positive
v1 client fixture: its challenge bytes do not equal a valid Zaino transcript.

The existing administrator-accessible Ubuntu guest can establish only an
explicit diagnostic end-to-end quote exchange. An accepted workload experiment
requires the separate reviewed immutable guest, no-admin boot path, complete
MRTD/RTMR/CCEL policy, and negative gates. Neither experiment by itself proves
ORAM physical obliviousness, mainnet capacity, rollback resistance, or a
complete wallet interface.
