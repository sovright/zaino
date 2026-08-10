# Recent-snapshot scan width: what the evidence actually says

Status: analysis. Resolves the sizing question in issue #105. Recommends a
design change; does **not** change `MAINNET_QUERY_SLOTS`.

## Summary

The recent-snapshot scan width was an unmeasured constant (`256`) whose comment
claimed a rescan would ground it. That claim was wrong twice over.

1. **The statistic everyone was reaching for is the wrong marginal.** The
   comment, and issue #105 following it, cite `max_per_address_delta_events`
   = 153,037. The recent snapshot is one flat all-address array, so the capacity
   it must cover is the widest generation's *total* delta events:
   **1,386,025** at the selected 288-block interval. Nine times larger. The
   per-address histogram PR #96 added cannot size this dimension at any
   resolution, because it is a marginal over the wrong axis.
2. **No width covers that demand, because the scan is quadratic.** Covering
   1,386,025 events (plus margin, 1,732,532 slots) costs roughly
   **6.0 x 10^12 slot pairings per request** — every request, including misses.
   The current 256-slot design point costs 394,240. That is a factor of about
   1.5 x 10^7, not a tuning gap.

So: **no serviceable width exists under the current recent-state structure.**
Setting 1,732,532 would be honest about the demand and unusable; leaving 256 is
usable and fails closed on mainnet. Both are non-answers, and the code now says
so explicitly instead of asserting a number.

## Why the width is fixed at all

ADR 0007 §5 and its rejected option *"Protect finalised state but query recent
state directly"*: every query performs the profile-fixed full bounded scan
because a variable scan leaks which addresses have recent activity. The width is
hashed into the profile identifier. It is a privacy parameter, not a knob.

ADR 0010 narrows the *deployment posture* to an honest-but-curious operator but
explicitly does not relax fixed work: "Nothing here relaxes the fixed
request/response size class or the uniform completion shape 0007 requires."
Memory access **addresses** stay visible at page granularity under 0010, which
is precisely the channel a data-dependent scan would leak into. So 0010 does not
license a shorter or variable scan either.

## The numbers

Source: `docs/evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/`,
mainnet height 3,425,046, 3,425,047 blocks replayed.

| Interval | Generations | max total delta events | max per-address delta events |
| --- | --- | --- | --- |
| 288 blocks (~6 h) | 11,893 | 1,386,025 | 153,037 |
| 1,152 blocks | 2,974 | 5,000,651 | 161,480 |
| 8,064 blocks | 425 | 11,253,237 | 232,491 |

288 blocks is the interval `SELECTED_GENERATION_INTERVAL_BLOCKS` picks, so
1,386,025 is the operative demand. For scale, the replay's total is 351,872,272
delta events over 3.4 M blocks — an average of 103 per block. The worst
288-block window averages **4,813 per block**, a ~47x burst.

### The cost polynomial

Per query, over a snapshot of `N` slots (`packages/zaino-oram/src/engine.rs`):

| Loop | Pairings |
| --- | --- |
| `recent_snapshot_is_semantically_valid` | `N * N` |
| `finalized_snapshot_relation`, once per finalized slot read | `store_reads * N` |
| `recent_creation_is_live`, once per recent slot | `N * N` |

Total `2N^2 + store_reads * N`, with `store_reads = 1028` for the mainnet
profile.

### Budget and verdict

`scan_width::mainnet_scan_width_policy` sets the per-query budget at 4x what the
already-reviewed 256-slot design point costs — a stated operational choice, not
a measurement:

- design point: `2*256^2 + 1028*256` = **394,240** pairings
- budget: **1,576,960** pairings
- widest width the budget admits: **667 slots**
- demand with the 25% growth margin: **1,732,532 slots**
- cost of that width: **~6.0 x 10^12** pairings
- overrun: **~3.8 x 10^6 x** the budget

At an optimistic 10^9 pairings/second/core that is about **100 minutes per
query**, against a 250 ms timeout bucket.

## Statistic and risk policy, stated plainly

`scan_width::recent_snapshot_scan_width` uses the **exact maximum over
generations, plus a 25% growth margin**, and deliberately not a quantile.

The asymmetry with the finalized side is the reason. On the finalized side, a
width below an address's demand costs *that one address* an extra round trip —
graceful, per-query degradation, which is why 256 covering 98.85% of live-UTXO
holders is a defensible design point. On the recent side, a width below a
generation's demand means `ConvertedRecentSnapshot::push` returns
`CapacityExceeded` and **the generation cannot be published at all**. There is
nothing fresh to serve, for anyone. A 99.9th-percentile width over 11,893
generations still admits roughly twelve unpublishable generations, i.e. twelve
service outages. There is no partial-credit regime to trade against, so the
policy is: cover the maximum, or refuse.

Queries that would exceed the width are therefore **not truncated and not
degraded** — the snapshot conversion fails closed before publication, which is
the correct behavior and is preserved. What changes is that the refusal is now
computed and asserted in a test rather than discovered on mainnet.

## What would have to change

### A. Shorten the public rebuild interval — insufficient alone

To reach 667 slots from 1,386,025 needs a ~2,000x reduction. The worst window
already averages 4,813 delta events *per block*, so even a **1-block** rebuild
interval leaves demand ~7x over the ceiling — and per-block republication of the
finalized projection is not operationally plausible. Shortening the interval
helps linearly and the wall is quadratic. Not a fix on its own.

### B. Hoist the two query-independent loops to publication time — real, partial

`recent_snapshot_is_semantically_valid` and `recent_creation_is_live` depend
**only on the snapshot**, not on the query. Both are properties of the
published generation. Computing them once at `FrozenRecentSnapshot`
construction and storing a per-slot `live` bit removes both `N^2` terms and
costs nothing in leakage: the result is public snapshot shape shared by every
query in the generation, which the engine's own comments already assert.

Per-query cost becomes `(store_reads + 1) * N` = `1029N`. The ceiling rises from
667 to **1,532 slots** — a 2.3x width improvement, and more importantly it
removes the quadratic. This is a contained change and should be made regardless
of what else happens.

### C. Make the finalized/recent join linear — the actual unlock

After B, the wall is `store_reads * N`: `finalized_snapshot_relation` re-scans
the whole snapshot once per finalized slot read to find recent spends that
cancel a finalized candidate. That is a nested-loop join. Replacing it with an
oblivious sorted merge or a fixed-size oblivious hash makes the recent-side cost
`O(N + store_reads)`, at which point the budget admits **1,575,932 slots** —
within 10% of the 1,732,532 the mainnet demand requires, closable by a modest
budget increase or a 144-block interval.

At that design point the snapshot is roughly 1.7 M slots at order-100 bytes each
= **~200 MB**, double-buffered across publication = ~400 MB, streamed in full
every query. At ~10 GB/s that is ~20-40 ms per request, inside the 250 ms
bucket, and caps a single-worker FIFO service at roughly 25-50 queries/second.
Expensive but not absurd — and it is a real design point, unlike the current
one.

This is genuine oblivious-algorithms work, not a refactor.

### D. Explicit admission policy — required in any case

Whatever width is chosen, the service needs a stated policy for a generation
that exceeds it, since chain conditions can always produce one. Fail-closed
non-publication is the current behavior and is correct; what is missing is that
it should be a *declared* operational limit with alerting, not an unhandled
capacity error. A width chosen from a max-plus-margin makes this a rare
exception rather than an expected condition.

## Recommendation

1. Keep `MAINNET_QUERY_SLOTS = 256` and keep the fail-closed conversion. Do not
   raise it to a number nobody can execute.
2. Land B (hoist the query-independent loops). Contained, no leakage cost,
   removes the quadratic.
3. Treat C as the blocking design item for a mainnet recent-state scan. Until it
   exists, the private service cannot serve mainnet, and no `EvidenceScope`
   mainnet-readiness flag should be set. (None currently is.)
4. Rescan to populate `per_address_delta_event_histogram` anyway — it is real
   evidence, it just answers a different question: how many round trips an
   address's *recent* results take, i.e. `response_slots`, not the scan width.
   `scan_width::per_address_pagination_coverage` consumes it for that.

## Where this lives in code

- `packages/zaino-oram/src/scan_width.rs` — the sizing function, the policy, the
  cost polynomial, the committed-capture constants, and the tests. All integer
  arithmetic; no float and no hash-map ordering influences a width.
- `hybrid_sizing::SourceBoundHybridSizingReport::selected_recent_snapshot_demand`
  — feeds the correct statistic from a validated report.
- `hybrid_sizing::SourceBoundHybridSizingReport::selected_per_address_delta_distribution`
  — feeds PR #96's histogram to the coverage function, its correct consumer.
- `scan_width::tests::the_committed_mainnet_capture_is_unserviceable` — fails the
  moment the capture, the polynomial, or the headroom changes enough to make the
  scan servable, at which point the width can be derived rather than asserted.
