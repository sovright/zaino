# Activated private client bootstrap context

## Status

Accepted for the isolated research implementation on 2026-09-12. Extends the
client boundary of ADR-0009 under ADR-0903. Production and complete-wallet
acceptance gates remain open.

## Context

The existing bootstrap releases envelope keys, a profile, and a key epoch.
The actual codec also needs the runtime security lease's session binding and
the exact checkpoint derived from its accepted serving identity. The parity
harness has those values privately, so its successful queries do not establish
that a production client can construct the same request. Reconstructing that
context from an independently captured finalized projection can select a
different serving generation.

## Decision

The runtime owner publishes one immutable client bootstrap context only after
successful serving activation. It obtains the security lease, releasable keys,
profile, and exact codec checkpoint from the same accepted owner state. The
listener's fixed-envelope const generic remains the single source of envelope
width, which the client checks against its compiled profile. This codec
checkpoint is the finalized anchor within the accepted
recent serving identity, not its recent tip or an ORAM root. It includes network,
finalized height and hash,
schema version, projection epoch, and key epoch. Hash byte order is explicit
at each boundary and crosses through named, validated methods. Callers cannot
provide a replacement checkpoint or session binding to the owner.

The existing protobuf is the single wire specification. New fields preserve
legacy tags and carry an explicit context version. The production client
rejects missing, unknown-version, malformed, unsupported-profile, and
inconsistent contexts; absence never selects the parity harness or a legacy
fallback. An unready runtime refuses to release a usable bootstrap context.

Network, profile, schema, epochs, and chain checkpoint are public metadata
under the selected leakage budget. The random session binding is a codec
domain separator, not a secret or attestation credential. Request and response
keys remain deliberately releasable to admitted clients. Their shared runtime
scope continues to rely on TLS for client-to-client confidentiality; publishing
this context does not create envelope-level client isolation or disclose
server-only continuation and replay secrets.

REPORT_DATA v1 remains unchanged. A trusted client verifies a fresh challenge,
the actual TLS peer's SPKI, the quote/collateral, and independently approved
workload/configuration policy before trusting bootstrap or sending queries.
It then receives the owner-derived context on that same retained TLS stream,
checking overlaps with accepted evidence and verifier-owned policy. TLS
authenticates these additional context fields transitively; they are not
individually included in the quote. The attested finalized anchor and the
runtime's serving identity must not be conflated, and coherence must be
established from the accepted owner's publication rules.

The initial server freezes its activated serving generation for the listener's
lifetime. Evidence and bootstrap are derived from that frozen generation.
The listener's cached bootstrap describes that generation; it is not a live
readiness receipt. Terminal owner failure closes query release, and asking the
owner for a new context after failure must refuse.
The client never carries admission across reconnection: a disconnected stream
requires a fresh pending client and attestation exchange. V1 binds a TLS key
and challenge, not a unique TLS session/exporter. Serving live refresh will
require a separate atomic generation/publication and re-attestation design.

## Validation and limits

The following are acceptance requirements, not a record that all checks have
already passed. The foundation implements owner context and evidence/helper
checks; retained-connection admission and its transport tests belong to the
next integration milestone.

Wire golden tests preserve existing tags and cover strict context validation,
including hash byte order. Runtime tests must prove bootstrap is unavailable
before activation and derives from the accepted generation afterward. The
production codec must seal/open using that context, with a real subscriber
advance demonstrating the old context's refusal and a fresh context's usable
query path. Client tests must refuse evidence/context mismatches before any
query and enforce ownership of the retained connection.

This context does not commit to recent snapshot contents, authenticate an ORAM
root, or prove rollback resistance. A fresh quote is not a state-freshness
witness. No accepted immutable guest policy, hardware leakage result, or
full-mainnet capacity claim is created by publishing these fields.
