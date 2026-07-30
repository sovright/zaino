# Gate 1 growth and overlap policy

Date: 2026-07-30

Status: pre-registered input; no v2 result and no Gate 1 promotion

## Decision

The next source-bound replay is fixed as the
`live-utxo-base-delta-growth-v2` profile in the existing
`zaino-oram-source-bound-hybrid-sizing-v1` artifact envelope. It must measure
five complete, consecutive, genesis-aligned target-year windows for the
selected 16-entry, 288-block base/delta tuple and derive one non-compounding
three-year planning bound.

The growth rule uses positive changes in absolute counts. It is not a
percentage model, a statistical forecast, or a guarantee that future Mainnet
growth will resemble the measured history. The resulting profile expires and
is requalified at least annually and before every network upgrade. Missing
evidence, an expired profile, an unadmitted network upgrade, or a public
capacity/work bound reached at runtime fails private service closed. There is
no implicit resize, fallback profile, or continued service on stale
qualification.

This `growth-v2` profile is a one-checkpoint experiment definition. Its source
binding is pinned to:

```text
measurement_blake2s256 =
  aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127
checkpoint_height = 3,425,046
checkpoint_hash =
  0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4
```

The annual or network-upgrade replacement is a newly pre-registered profile
with a new exact source binding; this profile must not slide its windows to an
arbitrary newer capture.

The online overlap topology is also frozen:

- at most two base ORAMs, two add ORAMs, and two spend ORAMs may exist at once;
- the old base, sealed old deltas, and new active deltas remain the serving
  view while one new base is constructed;
- one atomic public barrier switches the base and retires the sealed deltas;
- no third delta generation may be allocated; and
- failure to demonstrate build, overlap, publication, and cleanup within 25%
  of the generation interval rejects qualification. If a live rebuild has not
  crossed its publication barrier by the next generation boundary, private
  service fails closed.

This policy does not change the current Gate 1 **NO-GO** decision.

## Target-year window

[ZIP 208](https://zips.z.cash/zip-0208) defines the post-Blossom block target
spacing as 75 seconds. [ZIP 206](https://zips.z.cash/zip-0206) deployed Blossom
on Mainnet at height 653,600 and identifies ZIP 208 as a primary consensus
change. The v2 conversion therefore pins:

```text
target_year_blocks
  = 365 days * 24 hours/day * 60 minutes/hour * 60 seconds/minute
      / 75 seconds/block
  = 420,480 blocks

target_year_generations
  = 420,480 / 288
  = 1,460 complete generations
```

`420,480` is exactly divisible by `288`. These are target-time windows, not
claims about actual elapsed wall time. Target spacing is a consensus-profile
input that can change at a network upgrade, which is why a network upgrade
invalidates this qualification even if the retained source data remains
otherwise readable.

The retained v1 checkpoint is height 3,425,046 after 3,425,047 applied blocks.
The last complete genesis-aligned 288-block generation before that checkpoint
ends at height 3,424,895. V2 must report these exact five windows:

| Window | Inclusive start height | Inclusive end height | Blocks |
| --- | ---: | ---: | ---: |
| 1 | 1,322,496 | 1,742,975 | 420,480 |
| 2 | 1,742,976 | 2,163,455 | 420,480 |
| 3 | 2,163,456 | 2,583,935 | 420,480 |
| 4 | 2,583,936 | 3,004,415 | 420,480 |
| 5 | 3,004,416 | 3,424,895 | 420,480 |

The exact checkpoint tail from height 3,424,896 through 3,425,046 remains part
of the checkpoint state and full-history delta maxima, but it is not silently
treated as a sixth or complete target-year window.

## V2 replay and report

V2 must replay the canonical standard-address event stream through the exact
checkpoint and retain aggregate-only measurements. It must reuse the existing
typed source admission, checkpoint preverification, canonical text, and atomic
three-file publication path. V1 evidence remains immutable and is lineage
input; a v2 run publishes a new sibling bundle.

The replay scanner validates source identity and continuity before and during
measurement. For each target-year window, the report must retain:

- start and end applied-block indices and the exact applied block count;
- exact base pages at the ending checkpoint for the selected 16-entry page;
- distinct standard addresses, total live standard UTXOs, and the maximum live
  standard UTXOs for one address at the ending checkpoint;
- the maximum, over every genesis-aligned 288-block generation in that window,
  of total add pages, total spend pages, and exact separate add-plus-spend
  pages; and
- the corresponding maximum per-address add, spend, and separate page counts,
  plus the event counts needed to revalidate every page ceiling.

The report must also retain the same delta maxima over the complete replay
history, including the checkpoint's trailing partial generation as a
separately identified input. It must not retain addresses, outpoints, dense
address identifiers, or per-event records.

Window records are evidence, not selectable command-line inputs. The five
height ranges, 16-entry width, 288-block generation, 75-second target spacing,
and three-window horizon are fixed by this note. Any mismatch rejects the run
rather than selecting a nearby window or candidate.

## Absolute growth derivation

For each ending-state metric, v2 retains the state immediately before the
first target-year window and the state at each of the five window ends:

```text
base_pages
distinct_standard_addresses
live_standard_utxos
maximum_live_standard_utxos_for_one_address
```

It computes the five target-year increases:

```text
positive_increase(1, metric)
  = max(0, window_end(1, metric) - window_start(1, metric))

positive_increase(i, metric)
  = max(0, window_end(i, metric) - window_end(i - 1, metric)),
    for i in 2..=5

growth_step(metric)
  = max(positive_increase(1, metric),
        positive_increase(2, metric),
        positive_increase(3, metric),
        positive_increase(4, metric),
        positive_increase(5, metric))
```

“Absolute” means the raw integer difference, not a percentage. A decrease
contributes zero and never earns capacity credit. The fixed planning horizon is
three target-year windows:

```text
planning_horizon_blocks = 3 * 420,480 = 1,261,440
planning_horizon_generations = 3 * 1,460 = 4,380

projected(metric)
  = exact_checkpoint(metric) + 3 * growth_step(metric)

qualification_expiry_height
  = checkpoint_height + 420,480

capacity_horizon_end_height
  = checkpoint_height + 1,261,440
```

For each total and per-address 288-block delta metric, v2 first computes that
metric's maximum inside each target-year window. It applies the same four
positive adjacent-window comparisons to those five annual maxima:

```text
delta_growth_step(metric)
  = max(0, annual_peak(2) - annual_peak(1),
           annual_peak(3) - annual_peak(2),
           annual_peak(4) - annual_peak(3),
           annual_peak(5) - annual_peak(4))

projected_delta_bound(metric)
  = full_history_288_block_peak(metric)
      + 3 * delta_growth_step(metric)
```

All multiplication, addition, ceiling, and capacity conversion is checked.
Each projected logical demand is independently passed through the pinned Rostl
spare-record and power-of-two capacity derivation. Physical bytes are never
obtained by multiplying the current byte result by a growth percentage.
The existing fixed-page capacity command therefore selects checkpoint demands
for the v1 profile and these projected demands for the v2 profile.

Maxima may come from different windows, generations, or addresses. They remain
separate conservative inputs; v2 must not manufacture an unmeasured joint
distribution. The projected hot-tail and per-address delta values update the
fixed page-work bound as well as table capacity.

This deterministic rule deliberately favors auditability over a claim of
predictive accuracy. Five historical windows do not establish a probability
distribution, confidence interval, stationarity claim, worst-case future
bound, or accepted node-year failure probability.

## Requalification and admission

Qualification is valid only for the exact source checkpoint, compiled profile,
target-spacing rule, target hardware, binary, and three-target-year capacity
bound that passed every Gate 1 and Gate 2 hard gate.

The operator must publish and admit a replacement result:

1. at least once every target year, before the current qualification expires;
2. before activation of every Zcash network upgrade, whether or not that
   upgrade is expected to change target spacing; and
3. immediately after any admitted source discontinuity, deep reorg, schema or
   record change, capacity-bound breach, or materially different physical
   topology.

Runtime admission tracks public aggregate occupancy and the approved total and
per-address generation bounds. It rejects before an ORAM admission limit or
fixed-work bound can be exceeded. The worker still completes its approved
fixed failure schedule before latching terminal state. Capacity exhaustion,
arithmetic failure, source drift, missed requalification, or an unadmitted
network-upgrade activation makes the private projection unavailable; it does
not trigger dynamic resizing, a shorter query path, another candidate tuple, or
plaintext/source fallback.

## Online overlap topology

One successful generation transition has the following public phases:

1. At a genesis-aligned 288-block boundary, seal the current add and spend
   ORAMs. The old base plus those sealed deltas remains immutable.
2. Allocate one new active add ORAM and one new active spend ORAM. New finalized
   events enter only this generation.
3. Construct one candidate base ORAM by streaming and folding the old base and
   sealed deltas. During construction, queries remain pinned to the old base,
   both sealed deltas, and both new active deltas. The candidate base is never
   partly served.
4. Verify the complete candidate base, exact public checkpoint, semantic root,
   source lineage, capacity, and publication identity.
5. Cross one atomic public barrier. New query leases pin the candidate base
   with the already-active new deltas; the sealed deltas retire. Old leases
   drain before their base and delta storage is released.

The resulting maxima are:

| Physical class | Maximum simultaneous ORAMs | Roles at peak |
| --- | ---: | --- |
| base | 2 | old serving base and new candidate base |
| add | 2 | sealed old add and new active add |
| spend | 2 | sealed old spend and new active spend |

There is no third generation, merge queue, plaintext overflow lane,
secret-dependent shard, or in-place capacity extension. A query lease observes
one published base identity and the exact two public delta generations required
by that phase; it never mixes a partially built base with serving state.

The qualification compaction budget is 25% of one target generation:

```text
288 blocks * 75 seconds/block * 25% = 5,400 seconds
```

Construction, overlap, verification, atomic publication, lease drainage, and
cleanup are all charged to that measurement. A result above 5,400 seconds
fails qualification. In live operation, failure to publish before the next
288-block boundary is a hard safety boundary: allocating a third generation is
forbidden, so private service stops.

## Workspace rule

Destination ORAMs are rebuild workspace and are counted in peak topology and
whole-process RSS. Candidate base pages are encoded and inserted directly into
the candidate base ORAM while the old base and sealed deltas are streamed.
Only fixed-size page encoders, bounded transfer buffers, authenticated
manifests, and backend-required construction state may exist beside the
declared ORAMs.

The implementation must not materialize a separate full base-page or
delta-page corpus in memory or on local storage and then copy it into the
destination ORAM. Such a corpus would be an additional full-size workspace,
would change peak RSS and storage traffic, and is outside this topology. If the
pinned backend internally requires construction over-allocation, that memory
is measured as backend workspace rather than hidden behind this rule.

## Claim boundary

This note pre-registers inputs and failure behavior. It does not itself provide:

- a v2 replay result or an accepted growth number;
- evidence that 75-second target spacing equals observed wall-clock spacing;
- a statistical, probabilistic, percentage, compound-growth, or worst-case
  future-chain guarantee;
- directory, manifest, allocator, backend-construction, source-cache, or
  complete process-memory bounds;
- target-TDX peak RSS, zero-swap, stash pressure, or admission-failure evidence;
- proof that the six-ORAM overlap fits the target;
- measured 25% compaction duty, cold-rebuild RTO, query latency, throughput, or
  queue behavior;
- an exact overlap-path fixed-work, code-generation, physical-trace, or Gate 2
  pass;
- durable ORAM recovery, crash-safe barrier implementation, production
  attestation, or service availability; or
- Gate 1 promotion or Mainnet readiness.

The v2 result may still reject the selected tuple through projected capacity,
overlap RSS, fixed-work growth, duty cycle, or any later hard gate. An admitted
growth model cannot waive those failures.
