# Recent-snapshot scan width: what the evidence actually says

Status: analysis. Resolves the sizing question in issue #105. Recommends a
design change; does **not** change `MAINNET_QUERY_SLOTS`.

## Summary

The recent-snapshot scan width was an unmeasured constant (`256`) whose comment
claimed a rescan would ground it. That claim was wrong twice over, and the
design change that would fix it is blocked and still short.

1. **The statistic everyone was reaching for is the wrong marginal.** The
   comment, and issue #105 following it, cite `max_per_address_delta_events`
   = 153,037. The recent snapshot is one flat all-address array, so the capacity
   it must cover is the widest generation's *total* delta events:
   **1,386,025** at the selected 288-block interval. Nine times larger. The
   per-address histogram PR #96 added cannot size this dimension at any
   resolution, because it is a marginal over the wrong axis.
2. **No width covers that demand.** Covering 1,386,025 events (plus margin,
   1,732,532 slots) costs **1,782,775,428 slot pairings per request** — every
   request, including misses — against a stated budget of 1,576,960. That is a
   factor of about 1,130, not a tuning gap.

   This was `6.0 x 10^12` pairings and a factor of `3.8 x 10^6` before
   recommendation B below landed; the hoist removed the quadratic, and the
   demand still does not fit.

3. **The one design change that would close it is blocked, and still 9.93%
   short.** Annotating each recent record with the join's answer at publication
   makes the per-query cost `N + store_reads` instead of `(store_reads + 1) * N`
   — 1,733,560 comparisons against a 1,576,960 budget. That closes 1,130x down
   to under 10%, and not to zero. It is also not implementable against the
   current store: `UniqueTable` has no update primitive. §C and §E below.
4. **Whether even that is affordable turns on a number nobody has measured** —
   the distinct addresses a generation touches. §F states the run that would
   produce it and the exact threshold (1,221,061) above which the hoist stops
   being a design option, as a function the code already asserts.

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
| `finalized_snapshot_relation`, once per finalized slot read | `store_reads * N` |
| the recent-slot sweep, one address comparison each | `N` |

Total `(store_reads + 1) * N` = `1029N`, with `store_reads = 1028` for the
mainnet profile.

Two `N * N` terms — `recent_snapshot_is_semantically_valid` and
`recent_creation_is_live` — used to sit in this table. Recommendation B below
moved them to snapshot publication, where they are paid once per generation.
The engine still sweeps every slot on every query; it now reads their results
in `O(1)` per slot from `recent_snapshot::RecentSnapshotScan`.

### Budget and verdict

`scan_width::mainnet_scan_width_policy` sets the per-query budget at 4x what the
already-reviewed 256-slot design point cost — a stated operational choice, not
a measurement. The hoist removed work from the query; it did not change how much
per-query work an operator is willing to fund, so the budget stays anchored to
the reviewed figure (`scan_width::REVIEWED_DESIGN_POINT_COMPARISONS`) and what
rises is the width it admits:

- reviewed design point: `2*256^2 + 1028*256` = **394,240** pairings
- budget: **1,576,960** pairings
- widest width the budget admits: **1,532 slots** (was 667 before the hoist)
- demand with the 25% growth margin: **1,732,532 slots**
- cost of that width: **1,782,775,428** pairings
- overrun: **1,130x** the budget

At an optimistic 10^9 pairings/second/core that is about **1.8 seconds per
query**, against a 250 ms timeout bucket — still ~7x over on wall clock, and
1,130x over the stated pairing budget. Better than the pre-hoist 100 minutes,
and still not servable.

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

To reach 1,532 slots from 1,386,025 needs a ~900x reduction. The worst window
already averages 4,813 delta events *per block*, so even a **1-block** rebuild
interval leaves demand ~3x over the ceiling — and per-block republication of the
finalized projection is not operationally plausible. Not a fix on its own.

### B. Hoist the two query-independent loops to publication time — landed

`recent_snapshot_is_semantically_valid` and `recent_creation_is_live` depended
**only on the snapshot**, not on the query. Both are properties of the
published generation. They are now computed once at `FrozenRecentSnapshot`
construction, into a `recent_snapshot::RecentSnapshotScan` carrying a
snapshot-wide `semantically_valid` flag and a per-ordinal `live` bit. Both
`N^2` terms are gone from the per-query cost, and this costs nothing in
leakage: the results are public snapshot shape shared by every query in the
generation, which the engine's own comments already asserted about slot
occupancy. The engine's sweep over every slot is unchanged; no branch on a
precomputed flag skips or shortens any loop.

Per-query cost is now `(store_reads + 1) * N` = `1029N`. The ceiling rose from
667 to **1,532 slots** — a 2.3x width improvement, and more importantly the
quadratic is gone. It is not, on its own, enough to serve mainnet.

### C. Make the finalized/recent join linear — the actual unlock, and still short

With B landed, the wall is `store_reads * N`: `finalized_snapshot_relation` re-scans
the whole snapshot once per finalized slot read to find recent spends that
cancel a finalized candidate. That is a nested-loop join. Replacing it with a
per-record annotation computed once at publication — an oblivious sorted merge
or a fixed-size oblivious hash — makes the recent-side cost `N + store_reads`.

`scan_width::JoinStrategy` names both design points so the distance between them
is computed rather than asserted, and `scan_width::mainnet_sizing_model` sizes
the capture under both:

| | shipped (`NestedLoopRelation`) | hoisted (`AnnotatedRecords`) |
| --- | --- | --- |
| per-query cost | `(store_reads + 1) * N` | `N + store_reads` |
| cost at the required width | 1,782,775,428 | 1,733,560 |
| widest width the budget admits | 1,532 | 1,575,932 |
| over budget by | **1,130x** | **9.93%** |
| headroom multiple that would fund it | 4,523 | **5** |

So the hoist closes three orders of magnitude and stops **9.93% short** —
1,733,560 comparisons against a 1,576,960 budget, a width of 1,732,532 against a
ceiling of 1,575,932. That residual is the whole remaining argument, and §E
below prices the two ways to close it.

At that design point the snapshot is roughly 1.7 M slots at order-100 bytes each
= **~200 MB**, double-buffered across publication = ~400 MB, streamed in full
every query. At ~10 GB/s that is ~20-40 ms per request, inside the 250 ms
bucket, and caps a single-worker FIFO service at roughly 25-50 queries/second.
Expensive but not absurd — and it is a real design point, unlike the current
one.

This is genuine oblivious-algorithms work, not a refactor. It *was*
**structurally blocked** on a store primitive that did not exist: `UniqueTable`
(`packages/zaino-oram/src/layout/atomic_store.rs`) exposed `capacity`, `read`,
`occupied_records` and `insert_unique` and *no update primitive*, and records
are folded from an append-only event history, so there was no way to write an
annotation back onto a published record.

**That block is removed.** `UniqueTable::update_present` is a compare-and-set
on an occupied slot, implemented for both backends; `AddressEventPage` carries
a `RecordAnnotation` in spare flag bits, outside replay identity and outside
the event log root; and the executor and worker carry an annotate mutation
mode. ADR 0902 states the extended store contract — *store union annotations is
a pure function of `(source, generation)`* — and verifies it against the
source-bound cold-rebuild qualification. The annotation *computation*, the
publication-time pass, and the engine change remain to be built; the model
below is unchanged, because none of the numbers move until they are.

### D. Explicit admission policy — required in any case

Whatever width is chosen, the service needs a stated policy for a generation
that exceeds it, since chain conditions can always produce one. Fail-closed
non-publication is the current behavior and is correct; what is missing is that
it should be a *declared* operational limit with alerting, not an unhandled
capacity error. A width chosen from a max-plus-margin makes this a rare
exception rather than an expected condition.

### E. Closing the residual 9.93% — two levers, priced

Only two things in the model can move: the per-query budget, and the demand. The
code prices both and **tunes neither** — the point is to make the tradeoff
explicit, not to reach a servable verdict by moving a constant.

#### E1. Raise `ACCEPTED_COMPARISON_HEADROOM` from 4 to 5

- **What it costs.** Every query, including misses, pays 25% more fixed work:
  the budget goes from 1,576,960 to 1,971,200 pairings, a ceiling of 1,970,172
  slots against the 1,732,532 required. `model.minimum_comparison_headroom`
  computes the 5 exactly, as `ceil(1,733,560 / 394,240)`.
- **What it assumes.** That an operator will fund five reviewed design points
  rather than four. The constant was never a measurement — it is a stated
  operational choice about how much fixed work a width may add relative to an
  already-reviewed design point — so raising it does not contradict any
  evidence. It also assumes the added work still fits the 250 ms timeout
  bucket, which at these widths is dominated by streaming ~200 MB, not by
  comparisons.
- **What would justify it.** A wall-clock measurement of an annotated-join
  query at ~1.73 M slots on target hardware, showing p99 inside the 250 ms
  bucket at the intended QPS. That is a benchmark of a design that does not
  exist yet, so it comes after the hoist, not before.

#### E2. Shorten the 288-block rebuild interval

- **What it costs.** Publication runs more often — at the linear-scaling
  estimate of 261 blocks, about 10% more publication work per unit time, plus a
  correspondingly shorter window for each annotation pass (§F).
- **What it assumes.** That demand scales linearly with the interval. **The
  capture says it does not.** The worst 288-block window averages 4,813 delta
  events per block against a whole-replay mean of 103 — a ~47x burst. When
  bursts concentrate like that, the worst *sub*-window carries more than its
  proportional share, so the true demand at 261 blocks is *above* the linear
  estimate. `model.linear_interval_blocks` returns 261 and its documentation
  says plainly that this is a ceiling on a usable interval, not a usable
  interval.
- **What would justify it.** A rescan reporting `max_total_delta_events` at
  candidate intervals below 288. The committed capture measures 288, 1,152 and
  8,064 blocks and nothing else, so **this lever cannot be evaluated from
  anything in the tree today.**

#### Recommendation: E1, and only after the hoist exists

E1 is defensible on present evidence; E2 is not yet *evaluable*, which is a
different and weaker position than being indefensible.

1. E2's feasibility depends on burst structure at intervals nobody has measured,
   and the one thing we do know about that structure — a 47x burst — points the
   wrong way. The linear estimate leaves a ~9% margin that a superadditive
   distribution plausibly eats entirely. Choosing a lever whose feasibility
   turns on an unmeasured property is how the 256 constant happened.
2. E1 is a single integer, computable now, moving a constant the record already
   describes as an operational choice rather than a measurement. It changes what
   an operator agrees to fund; it does not change what is known.
3. E1's risk is bounded and uniform — 25% more fixed work on every query. E2's
   benefit is unquantified and its risk lands on publication, which is where the
   annotation pass (§F) is already the tightest constraint.

**But neither should be moved yet.** At headroom 4 or 5 the shipped nested-loop
join is 1,130x or 904x over regardless; the residual 9.93% is a property of a
design that does not exist. Deciding the headroom before the hoist lands would
be tuning a constant against a hypothetical. The correct order is: unblock the
store primitive, build the hoist, measure it, then raise the headroom with a
timing result attached.

### F. The measurement that is still missing

The hoist's publication cost is `distinct_addresses_per_generation *
store_reads` oblivious reads — each visited address's finalized history, re-read
to decide the join — plus at most one write per published slot. **That number is
not in the tree.**

`distinct_addresses_per_generation` is the union ADR 0902 obligation 6 requires,
not the generation's finalized delta: `addresses(snapshot_g) ∪
addresses(snapshot_g−1) ∪ addresses appended since the last completed pass`. A
snapshot entry dropped by a reorg changes an annotation while emitting no
finalized delta event, so a delta-only count understates the pass. Both snapshot
terms are bounded by the snapshot slot count, so the union does not change the
order of the cost — but the run below must accumulate the union, or it measures
the wrong quantity. `MAINNET_CAPTURE_MAX_TOTAL_DELTA_EVENTS` is a pinned
constant, no capture file is committed, and the report's
`distinct_standard_addresses` is a whole-replay figure over 3.4 M blocks, not a
per-generation one.

**The run that would produce it.** The same Gate 1 hybrid replay that produced
`hybrid-mainnet-2316644-h3425046-v1`, re-run with a per-generation distinct
touched-address count accumulated per rebuild interval and reported as a new
`max_distinct_addresses` field on `RebuildIntervalReport`, alongside the
existing `max_total_delta_events`. The accumulator already tracks per-generation
address state (`SparseGenerationTracker`), so this is a new maximum over data it
already visits, not a new pass. Populating
`per_address_delta_event_histogram` in the same run gives the *mean* distinct
addresses per generation for free — `total_addresses / generation_count`, since
its buckets count (address, generation) observations — but the max is the figure
that decides feasibility and needs the new field.

**The threshold.** `AnnotationPublicationBudget` states it as a testable
function. One annotation pass must fit one rebuild interval: 288 blocks at 75 s
target spacing is 21,600 s. At the reference cost of 17,184 ns per oblivious
operation — the slowest median `insert_record_unique` the Phase 0 session
measured, at a 2^14 event table, which over-charges a read and under-reaches
mainnet table sizes, and is therefore a *parameter* of the function rather than
an assumption inside it — the interval funds 1,256,983,240 operations. Less the
1,732,532 writes, over 1,028 reads per address:

> **The record-annotation hoist becomes infeasible if the worst 288-block
> generation touches more than 1,221,061 distinct addresses.**

That threshold is informative precisely because it sits *below* the trivial
upper bound. A generation has at most one distinct address per delta event, so
the ceiling is 1,386,025 — and 1,221,061 is **88.09%** of it. The hoist
therefore fails only if the worst window's burst is nearly perfectly
address-disjoint, at fewer than 1.14 delta events per touched address. Bursts
are normally the opposite: concentrated on few addresses. So the expected
outcome is that the hoist is affordable, and the measurement is worth running to
confirm rather than to discover a blocker.

`scan_width::tests::the_annotation_hoist_is_infeasible_above_a_stated_distinct_address_count`
asserts the threshold, and
`a_slower_oblivious_operation_lowers_the_annotation_threshold` shows the
reference rate is a parameter of the answer rather than a hidden assumption. The
day the measurement lands, the answer is `budget.fits(measured)`.

## Recommendation

1. Keep `MAINNET_QUERY_SLOTS = 256` and keep the fail-closed conversion. Do not
   raise it to a number nobody can execute.
2. ~~Land B (hoist the query-independent loops).~~ **Done.** Contained, no
   leakage cost, removed the quadratic; the ceiling is now 1,532 slots.
3. Treat C as the blocking design item for a mainnet recent-state scan. Until it
   exists, the private service cannot serve mainnet, and no `EvidenceScope`
   mainnet-readiness flag should be set. (None currently is.) C's store-contract
   prerequisite — a `UniqueTable` update primitive and an annotation field — has
   landed under ADR 0902; the computation and the publication pass have not.
4. **Do not move `ACCEPTED_COMPARISON_HEADROOM` or the rebuild interval yet.**
   §E prices both; the residual 9.93% they would close belongs to a design that
   does not exist. When the hoist lands, raise the headroom to 5 with a timing
   result attached — that is the recommended lever, for the reasons in §E.
5. Run the rescan in §F, adding a per-generation `max_distinct_addresses` field.
   It decides whether the hoist is affordable at all, and the threshold
   (1,221,061) is already asserted in code so the answer is immediate. Count the
   ADR 0902 obligation 6 union, not the finalized delta — see §F.
6. Rescan to populate `per_address_delta_event_histogram` in the same run — it is
   real evidence, it just answers a different question: how many round trips an
   address's *recent* results take, i.e. `response_slots`, not the scan width.
   `scan_width::per_address_pagination_coverage` consumes it for that. Per ADR
   0900 this now also sizes the address → txids operation, whose deeper page is
   its only marginal cost over address → UTXOs.

## What this note does *not* claim

It does not claim the address-keyed projection serves only one wallet operation.
ADR 0900 previously said the mainnet cost question was larger than this note
frames it, on the grounds that address → txids was a second projection with its
own width. That was wrong and the ADR has been corrected: `UtxoEvent` carries
`txid` and a `Created`/`Spent` kind, the stored history retains both kinds, and
`finalized_live_utxo_at` folds that history down to live UTXOs only at read
time. address → txids is a different fold over the same stored history — same
projection, same `store_reads`, same width. Fixing this width fixes it for two of
the three operations in the minimal set. Only txid → transaction needs a new,
differently-keyed index.

## Where this lives in code

- `docs/adr/0902-store-annotations-are-a-pure-function-of-source-and-generation.md`
  — the store contract the hoist needs, and the obligations the annotation pass
  must satisfy for it to hold.
- `packages/zaino-oram/src/scan_width.rs` — the sizing model, the policy, both
  cost polynomials, the two levers, the annotation-feasibility threshold, the
  committed-capture constants, and the tests. All integer arithmetic; no float
  and no hash-map ordering influences a width.
- `scan_width::JoinStrategy` — the shipped nested-loop join and the modelled
  record-annotation hoist, so the gap between them is computed, not asserted.
- `scan_width::RecentSnapshotSizingModel` / `mainnet_sizing_model` — the whole
  argument as one value: demand, required width, cost and ceiling under both
  joins, and the verdict.
- `scan_width::AnnotationPublicationBudget` — whether one annotation pass fits
  one rebuild interval, and the distinct-address threshold above which it does
  not.
- `hybrid_sizing::SourceBoundHybridSizingReport::selected_recent_snapshot_demand`
  — feeds the correct statistic from a validated report.
- `hybrid_sizing::SourceBoundHybridSizingReport::selected_per_address_delta_distribution`
  — feeds PR #96's histogram to the coverage function, its correct consumer.
- `scan_width::tests::the_committed_mainnet_capture_is_unserviceable` and
  `the_mainnet_model_is_unservable_under_both_joins` — the tripwires. They fail
  the moment the capture, either polynomial, the growth margin, or the headroom
  changes enough to move the verdict, at which point the width can be derived
  rather than asserted.
