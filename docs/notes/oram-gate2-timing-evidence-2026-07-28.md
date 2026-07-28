# ORAM Gate 2 dynamic timing evidence — 2026-07-28

This note is preliminary. It describes the supported dynamic timing experiment,
but it does not report a timing result because the exact driver-emitted JSON
artifacts from the builder have not been retained in this repository. The
normative decision remains in the
[Phase 0 kill-gate report](oram-phase0-kill-gates-2026-07-23.md), and Gate 2
remains **NO-GO**.

## Standing assumption

This work was directed to proceed under an explicit, operator-supplied
assumption that upstream `rostl` is trusted with respect to secret-dependent
branches. That assumption is load-bearing and is recorded here so no reader
inherits it silently. It does not replace the uncompleted upstream branch and
indirect-call audit, and it does not alter the static compiled-path finding in
the kill-gate report.

## Question and method

The dynamic experiment asks whether a host observer can distinguish a directory
or event insertion-path hit from a miss using wall-clock time.

The supported driver:

- rebuilds a fresh, equal-occupancy table before every measurement;
- inserts the same probe key in both labelled arms, changing only whether the
  key is already present;
- uses warm-up pairs and balanced, randomized AB/BA ordering;
- measures both directory and event records in each invocation;
- records the raw pairs, experiment plans, schedule seeds, shape, selected
  timing mode, scheduler counters, and host-policy snapshots in one JSON
  artifact;
- requires CPU affinity, scheduler-stat availability, runqueue-wait admission,
  and the declared quiescence policy; and
- evaluates the predeclared pooled, order-conditioned, and
  position-conditioned mean/CDF equivalence bounds.

The pooled mean in an equivalence report is the scheduled hit-label duration
minus the scheduled miss-label duration. It is not a first-position minus
second-position contrast. Different seed values are schedule and resampling
seeds; they do not by themselves make sequential same-host runs independent.

Classifier AUC is retained as a descriptive diagnostic. It has no universal
acceptance threshold and does not replace the predeclared mean/CDF equivalence
bounds.

## Supported null controls

The driver supports three timing modes:

- `hit-miss`: the scheduled hit label executes a hit and the scheduled miss
  label executes a miss;
- `forced-hit`: both scheduled labels execute a hit; and
- `forced-miss`: both scheduled labels execute a miss.

The forced modes exercise the same driver, record kinds, admission checks,
statistics, and artifact publication path as the hit/miss experiment. Because
both scheduled labels execute the same operation in a forced mode, these runs
can expose measurement-procedure separation without introducing a second
acceptance criterion.

## Evidence retention

Future evidence used by this note must be the exact JSON emitted by the timing
driver and committed verbatim under `docs/notes/artifacts/oram-gate2/`.

- Historical `zaino-oram-insert-timing-v1` artifacts, if recovered, remain
  unchanged and can be described only as legacy hit/miss evidence.
- New `zaino-oram-insert-timing-v2` artifacts identify their timing mode, the
  quiescence-policy result for every environment snapshot, and the aggregate
  affinity, scheduler-stat, and runqueue-wait admission results.
- A completed run rejected by a post-start admission check is retained as a
  negative artifact rather than discarded. Pre-start refusal or a measurement
  error produces no timing artifact.
- Numerical claims must cite committed artifact paths and be reproducible from
  their raw pairs.

Numbers will not be reconstructed from console output, prose, or memory.

## Current limitations

- No exact timing JSON is committed, so there is no auditable dynamic result to
  summarize yet.
- The experiment is wall-clock only. PMU, cache-timing, and co-resident
  adversary measurements require a suitable qualification host.
- The operator-supplied upstream trust assumption leaves the upstream compiled
  control-flow audit open.
- Dynamic timing evidence cannot overturn the existing static compiled-path
  failure.

## Effect on Gate 2

None. Gate 2 remains **NO-GO**. A future update may add narrowly scoped,
artifact-derived descriptive findings after admitted hit/miss and forced-mode
runs are retained. Clearing Gate 2 still requires the work listed in the
normative kill-gate report and written review of that decision.
