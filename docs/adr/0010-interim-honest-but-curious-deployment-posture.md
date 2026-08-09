# Interim deployment posture: honest-but-curious operator inside an attested TEE

## Status

proposed

Narrows the *deployment posture* for the first private-query release. It does
not amend, weaken, or supersede the adversary model in
[0007](0007-private-query-service-and-leakage-model.md), which remains the
target and continues to gate any mainnet privacy claim.

## Context and decision

ADR 0007 protects against an adversary that "controls the host OS and VMM,
host-visible storage and I/O, network outside the trust domain, and
scheduling," that may "observe page faults," and that may "delay, drop, replay,
reorder, or roll back host-controlled state." That is a malicious-host model.
It is the right destination, and it is why the freshness witness, rollback
authority, attestation binding, and cover-round machinery exist.

It is also expensive, and 0007's own mainnet gates make clear it is not close:
seven days of mainnet shadowing, release-binary instruction/memory/page/timing
trace equivalence, and independent side-channel review, among others.

The first deployment does not need that adversary. The operator is a party we
run and trust not to attack the workload: they will not patch the binary,
attach a debugger, induce page faults, replay storage, or roll back state. They
are *curious* — they may look at what is visible without effort. The workload
still runs inside an attested TEE, so memory contents are encrypted against the
host, but memory access **addresses** remain visible at page granularity, and
that is exactly the channel a curious operator can read passively.

We decide:

1. **The first release assumes an honest-but-curious operator inside an
   attested TEE.** The operator does not modify the workload, single-step it,
   induce page faults, or manipulate host-controlled state. Active host attacks
   are out of model for this posture and remain in model for 0007.

2. **Network observers stay in scope.** Anyone on the path may time and count
   requests. Nothing here relaxes the fixed request/response size class or the
   uniform completion shape 0007 requires.

3. **Clients stay untrusted.** The operator not being an adversary says nothing
   about wallets. Per-client session isolation, replay rejection, and resource
   bounds are unchanged.

4. **The authorized claim is narrower and must be stated as such.** This
   posture supports: *the queried address and result contents are hidden from
   passive observation of storage and memory access patterns, and from network
   content.* It does **not** support: *the host operator cannot learn the
   queried address.* Release material must not make the second claim.

## What this posture defers

Each item stays required for 0007's model. Deferring is a statement about the
first deployment, not a decision that the work is unnecessary.

- **Controlled-channel and page-fault attack mitigation.** These are active
  attacks by definition.
- **Rollback protection as an adversarial control.** The freshness witness and
  `ReplaySnapshotCoordinator` are still needed, but for crash-recovery
  correctness rather than to resist a host that rewinds state deliberately.
  This lowers the urgency of an external, operator-inaccessible authority; it
  does not make a host-local witness acceptable under 0007.
- **Attestation as a hard gate before key release.** Still worth building, and
  required before the claim in 0007 can be made.
- **Whole-binary constant-time proof.** Relaxed to the absence of *coarse*
  data-dependent behavior; see below.
- **Oblivious replay-claim lookups.** `RequestReplayKey` is derived from a
  fresh per-request nonce and `ContinuationReplayKey` includes a fresh token
  nonce, so those hash-set probe locations are not address-correlated. They
  reveal repeat/duplicate structure, which the protocol already returns to the
  caller. Under 0007's adversary this still warrants review; under this posture
  it does not block.

## What this posture does not relax

- **The ORAM backend is still required.** A TEE encrypts memory contents, not
  access addresses. Page-granular access patterns over a plaintext-indexed
  table are passively readable, which is precisely what a curious operator
  would see. Serving from the qualification-memory backend carries no privacy
  claim of any kind.
- **Coarse data-independence in the query engine.** Hit versus miss, result
  cardinality, and whether pagination occurred must not be visible in timing or
  page-access shape. Cache-line precision is not required here; these three are.
- **Per-client key establishment and session isolation.** Independent of the
  operator's intent.
- **Fixed response shape and fail-closed readiness.** Unchanged from 0007.
- **The log, metric, and error allowlist.** A curious operator reads logs first.
  This is the cheapest leak to create and the easiest to avoid.

## Consequences

- A first release becomes reachable without 0007's full mainnet gate list,
  provided the claim is stated in this posture's terms.
- The pinned alpha `rostl` dependency may ship **unaudited** under an explicit
  experimental caveat. An unaudited ORAM is a weak assumption against a
  malicious host and a tolerable one against a curious operator who is not
  hunting for stash-correlation artifacts. 0007's audit expectation stands for
  the mainnet claim.
- Two claims now exist in the tree. Every privacy statement in documentation,
  release notes, and client-facing material must say which posture it is made
  under. An unqualified "private" is wrong under both.
- Work deferred here is deferred, not cancelled. Anything that would make
  returning to 0007's model harder — a host-local freshness authority treated
  as permanent, or a design that assumes no rollback — is not acceptable.

## Considered options

- **Amend 0007 to the weaker adversary.** Rejected. It would retroactively
  invalidate the rationale for the freshness witness, rollback authority, and
  cover rounds, and would likely see that work dropped rather than sequenced.
  The strong model is the destination.
- **Ship under 0007 unchanged.** Rejected for the first release: its mainnet
  gates require mainnet shadowing, full trace equivalence, and independent
  side-channel review, none of which a first deployment can satisfy, and
  waiting for all of them delays useful deployment for a threat this operator
  does not pose.
- **Make no posture decision and ship with an informal claim.** Rejected. The
  gap between "runs in a TEE" and "hides the query from the host" is exactly
  where an overclaim happens, and an undocumented model cannot be reviewed.

## Revisiting

This posture is superseded, not amended, when the deployment moves to an
operator who is not trusted — a third-party host, a multi-tenant environment,
or any deployment the Zcash community is asked to trust without trusting its
operator. At that point 0007's model and its mainnet gates apply in full.
