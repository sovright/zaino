# Complete wallet privacy scope and an isolated TDX research experiment

## Status

Accepted for planning on 2026-09-12. Amends ADR-0007's research sequencing and
makes its deployment assumptions concrete. No implementation evidence or
production deployment authorization is created by this decision.

Supersedes the proposed ADR-0010 operator-trusted posture for the user's
outside-TEE operator goal. ADR-0900 supplies the initial three-operation wallet
inventory, but inherits no permission to defer attestation or trust the operator
with keys for this goal. Existing XChaCha and TLS/bootstrap implementations on
main `753f3fc5` are reusable foundations, not missing work or privacy evidence.

## Context

ADR-0007 selects an appropriate private-query architecture, but a private UTXO
RPC alone does not protect a wallet workflow that subsequently discloses selected
transaction IDs through legacy RPCs. Logical schedule tests and generic-builder
correctness also do not establish what an operator outside TDX can observe.
Deferring all real transport and attestation work until after feasibility leaves
the complete-path leakage assumption untested at the point it should guide
backend selection.

## Decision

1. The product goal is to hide queried addresses and results from the outside
   operator within an explicit leakage budget. Network anonymity and arbitrary
   CPU side-channel resistance are not implied. Inventory and qualify every
   method, follow-up request, retry, and client termination decision used by a
   claimed wallet workflow. No silent legacy fallback is permitted.
2. The first deployment candidate places consensus validation and the private
   query path inside the measured guest. An external authoritative validator
   requires its own reviewed trust decision, including authentication,
   consensus/freshness checks, and disclosure of external trusted parties.
   Public ingest is independent of client query keys in either layout.
   A client verifies fresh evidence binding the measured workload/configuration
   to its TLS peer before trusting bootstrap keys or sending sensitive queries.
   Current operator-readable TLS key persistence must be replaced by ephemeral
   in-guest custody or reviewed TEE sealing. Shared envelope keys do not supply
   client-to-client confidentiality independent of TLS.
3. An accepted guest gives the operator no root/debug shell, memory or key
   export, or query-inspection authority. Attested image/configuration policy
   and allowlisted administration enforce this boundary; a private socket is
   not sufficient. Host rollback remains subject to the existing key/witness
   and freshness gates.
4. Permit a narrowly isolated, default-off TDX research harness before the
   production integration gate opens. It may compose real attestation, TLS,
   envelope protection, ORAM, recent-state scan, and transport with a controlled
   reference client and synthetic identities. It must have no public listener,
   real-wallet traffic, or production credentials. This is a planning exception
   for that experiment, not permission to deploy a production service.
   Fresh in-guest keys/session epochs invalidate prior tokens at boot/rebuild.
   Snapshot resume, cloning, and migration must be prevented by verified platform
   policy or covered by a reviewed external freshness/nonce owner; merely
   generating keys at startup does not protect restored memory state.
5. Prioritize physical operator-observation evidence and full-mainnet capacity
   and full-service recovery measurements over further correctness-only slices.
   Pre-register leakage experiments and retain negative or missing results.
   Finite trace tests do not replace algorithm/assembly review or independent
   audit. All ADR-0007 production and mainnet claim gates remain mandatory.

## Consequences and acceptance

The UTXO milestone remains useful but cannot be labeled a complete private
wallet backend. Required later methods precede the selected workflow's claim.
The TDX experiment may use a fixed research profile at small capacity; that
does not qualify mainnet scale, production key operations, or multi-CPU safety.

The [delivery plan](../notes/oram-enabled-zaino-plan.md) specifies the experiment,
measurements, decision artifact, and complete workflow requirements. The
[feasibility report](../notes/oram-phase0-1-feasibility-report.md) retains NO-GO
for production integration until its measured blockers close. Failed feasibility
requires a revised backend/design or an explicitly reviewed leakage-budget ADR,
not a weakened profile under an existing identity.
