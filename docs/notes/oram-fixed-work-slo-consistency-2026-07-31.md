# Fixed work versus service SLO — a cross-row consistency constraint

Date: 2026-07-31
Status: measurement-backed input to the Gate 1 blocking-decision table

This note reports measured per-insertion cost and sets it against two numbers
already on record. It closes no blocking row. It argues that two of those rows —
**fixed work** and **service SLO** — cannot be closed independently of each
other, and supplies the measurement needed to close them together.

## The two recorded numbers

- The Gate 1 mainnet capture records a **fixed-work floor of 13,440,092 logical
  ORAM accesses per request** (`4 + 4H`, `H = 3,360,022`, the hottest measured
  address history).
- The Gate 1 qualification-inputs note proposes a **completed-query latency of
  p99 at most 1,000 ms**.

Together these imply a per-logical-access budget of

```
1,000 ms / 13,440,092 = 74 ns
```

## Measured per-insertion cost

From the Gate 2 timing sweep, native x86-64 builder, single pinned core, 25%
fill, 1,000–2,000 measurements per cell. These are complete
`insert_record_unique` operations (read/remap, branchless select,
write-or-insert/remap, eviction), not bare logical accesses.

| Capacity | Directory median | Event median |
| ---: | ---: | ---: |
| 1,024 | 4,849 ns | 8,525 ns |
| 2,048 | 5,883 ns | 9,803 ns |
| 4,096 | 11,115 ns | 15,300 ns |
| 8,192 | 11,728 ns | 16,118 ns |
| 16,384 | 12,424 ns | 17,184 ns |

Cost grows roughly with tree depth, with a step between 2,048 and 4,096 where
the structure stops being cache-resident, then a shallower slope of about
0.6–1.0 µs per capacity doubling.

## The gap

The **fastest operation measured anywhere** — 4,849 ns, directory table at
capacity 1,024, entirely cache-resident, a configuration 16,384× smaller than
the production directory — is already **65× above the 74 ns budget**.

Extrapolating the observed per-doubling slope to production capacities, and
noting that at 2²⁴ directory records (~638 MB) and 2²⁹ event records every tree
level is a DRAM access rather than a cache hit, a plausible band is 15–50 µs per
access. Against the fixed-work floor:

| Per-access cost | Time for one request |
| ---: | --- |
| 74 ns (required) | 1.0 s |
| 4,849 ns (best measured, toy size) | ~65 s |
| 15 µs (extrapolated, optimistic) | ~3.4 min |
| 50 µs (extrapolated, conservative) | ~11 min |

The extrapolation is rough and clearly labelled as such. The conclusion does not
depend on its precision: the gap is two to three orders of magnitude, and the
best directly measured number already misses by 65× at a toy size.

## What this does and does not mean

**It does not mean the design is infeasible.** It means the flat `4 + 4H`
schedule and a 1-second p99 are mutually exclusive. Reading `4 + 4H` literally,
every request pays the hottest address's history because fixed work cannot vary
with the secret — that is the point of the schedule, and also its cost.

The hybrid direction already under design — immutable base pages, active add and
spend pages, compaction — appears to be exactly the response: it exists to stop every request from scanning the full history. That is consistent with **fixed work** being
recorded as `unset` rather than settled.

**What it does mean** is that the fixed-work row carries a hard constraint from
the SLO row. Any proposed schedule must satisfy

```
accesses_per_request  ×  measured_cost_per_access  ≤  latency_target
```

At a measured 15–50 µs per access and a 1-second target, that caps a request at
roughly **20,000 to 67,000 logical accesses** — three orders of magnitude below
the current floor. Either the schedule reaches that, or the latency target moves,
or the target hardware changes the per-access cost by a factor nobody has
demonstrated.

## Recommended handling

1. Treat **fixed work** and **service SLO** as one joint decision. Approving
   either alone can produce an internally inconsistent qualification profile.
2. Require any candidate schedule to state its accesses-per-request and be
   multiplied against a *measured* per-access cost at the candidate capacity,
   not an assumed one.
3. Measure per-access cost at the target capacity on the target host before
   freezing either row. The numbers above are from a research backend on a
   generic builder and should not be used as the production figure — they are
   sufficient to establish the constraint, not to satisfy it.

## Limitations

- Complete insertions, not isolated logical accesses; a bare access is cheaper,
  but not by the required two-to-three orders of magnitude.
- Single host, single pinned core, `zebrad` resident, research backend, no
  production tuning.
- Largest configuration measured is 16,384 slots against production targets of
  16,777,216 and 536,870,912. Everything beyond 16,384 is extrapolation.
- Median wall-clock only. No PMU counters and no tail characterisation beyond
  p90, so this speaks to feasibility, not to a p99 commitment.
