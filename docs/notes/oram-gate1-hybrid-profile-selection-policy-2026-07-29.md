# ORAM Gate 1 hybrid-profile selection policy — 2026-07-29

This note pre-registers how the
`live-utxo-base-delta-v1` Mainnet sizing result will be interpreted. It was
written before the retained Mainnet hybrid-sizing replay completed. Its
purpose is to prevent a small-looking logical result from being promoted
post hoc into a production profile without the physical evidence required by
the [architecture and delivery plan](oram-enabled-zaino-plan.md).

This policy does not change the current Gate 1 decision. Gate 1 remains open,
and a hybrid-sizing winner is at most a **provisional logical finalist** until
all hard gates below pass.

## Candidate domain

A candidate is the tuple:

```text
(base entries per page, delta entries per page, generation interval)
```

The closed candidate domain is:

- base entries per page: `1`, `8`, or `16`;
- one shared page width for the separate add and spend page classes: `1`, `8`,
  or `16`; and
- generation interval: `288`, `1,152`, or `8,064` public blocks.

This produces 27 candidates. Base and delta widths do not have to match.
Independent add and spend widths are outside this decision because the
current artifact does not report the exact same-generation combined footprint
for independently selected widths.

The generation schedule is public and genesis-aligned. It is a sizing input,
not a private value and not yet an approved production cadence.

## Evidence admission

Before using the result, the reviewer must validate:

1. the report schema and `live-utxo-base-delta-v1` profile identifier;
2. the retained capture digest, checkpoint height and hash, expected block
   count, and network;
3. the contextual sizing-artifact lineage;
4. the source snapshot and aggregate replay match;
5. the canonical text rendering and the read-back-validated three-file
   publication; and
6. the executed source commit and release-binary digest in an external run
   record, because the current provenance does not bind either one.

Failure of any admission check rejects the run; it does not select a fallback
candidate.

## Logical derivations

For every candidate, the review records the following without applying a
verdict:

- current final-checkpoint base pages, allocated entries, live entries,
  padding entries, and maximum base pages for one address;
- maximum total add pages and maximum total spend pages for one generation;
- exact maximum same-generation total of the separate add and spend page
  classes;
- maximum per-address add pages and maximum per-address spend pages;
- a conservative fixed page-read lower bound:

  ```text
  maximum base pages for one address
    + maximum per-address add pages
    + maximum per-address spend pages
  ```

- a conservative active-delta capacity bound:

  ```text
  maximum total add pages + maximum total spend pages
  ```

- a conservative post-delta result bound:

  ```text
  maximum final live UTXOs for one address
    + maximum per-address add events
  ```

The conservative sums may combine maxima observed in different generations
or at different addresses. They are deliberate safety bounds. The report's
maximum total of separate pages is the exact observed same-generation
combined footprint and must remain separately visible.

These are logical lower bounds, not complete query or memory budgets.
Directory probes, ORAM expansion, position maps, stash, allocator overhead,
fixed NFS scanning, response padding, cover rounds, queueing, old/new
generation overlap, and rebuild workspace are added by later qualification.

The base rows describe the final capture checkpoint. They do not prove that
every historical or projected rebuild seam has an equal or smaller base.

## Inputs required before qualification

The following policy inputs must be recorded before a provisional finalist can
be promoted to a qualification candidate:

- target TDX memory;
- approved growth horizon and base/delta growth assumptions;
- exact separate-table topology for base, add, and spend pages;
- exact release-compiled persistent record sizes;
- validated ORAM admission/load policy and accepted failure bound;
- maximum fixed page reads, latency, queue depth, and single-worker
  throughput;
- rebuild duty-cycle and recovery-time limits; and
- response-slot and fixed-envelope bounds.

An unset input is not permission to optimize for the metrics that happen to be
available. It leaves the production profile unselected.

## Hard gates

A candidate is rejected unless all of the following pass on its exact compiled
production path:

1. Projected base and delta occupancy fit the validated ORAM admission policy
   at the accepted failure bound.
2. Fixed query work meets the declared latency, throughput, and queue budgets.
3. Generation construction and compaction meet the declared duty-cycle and
   recovery-time budgets.
4. Peak target-hardware RSS, including old/new generation overlap and rebuild
   workspace, is at most 70% of target memory.
5. Host and guest swap remain exactly zero.
6. The exact base-read, delta-read, fold, and sealed-page-write paths pass the
   required Gate 2 release-codegen and dynamic physical-trace qualification.

No logical page-count advantage can waive a hard gate. If every candidate is
rejected, Gate 1 remains NO-GO and the design returns for revision.

## Tie-break order

Only candidates that pass every hard gate may be compared. The pre-registered
tie-break order is:

1. lowest fixed query page reads;
2. greatest measured target-hardware RSS headroom;
3. lowest rebuild duty cycle and generation-write volume;
4. lowest logical allocation and padding; then
5. narrower base width, narrower delta width, and longer interval, in that
   order.

Raw page count alone is not a selection rule. Wider pages can reduce logical
reads while increasing record width, padding, ORAM expansion, copy cost, and
rebuild memory.

## Allowed decision labels

- **REJECTED** — an admission check or hard gate failed.
- **PROVISIONAL LOGICAL FINALIST** — best logical candidate under the admitted
  Mainnet artifact, with one or more physical qualification inputs still open.
- **QUALIFICATION CANDIDATE** — exact record layout and numerical policy inputs
  are frozen so physical Gate 1 and Gate 2 work may run.
- **PRODUCTION PROFILE** — every hard gate passed on the exact compiled path
  and the written Gate 1 and Gate 2 reviews approved promotion.

A review based only on the hybrid-sizing replay can assign at most the first
two labels. It cannot produce a Gate 1 GO, a Gate 2 GO, or a Mainnet-readiness
claim.
