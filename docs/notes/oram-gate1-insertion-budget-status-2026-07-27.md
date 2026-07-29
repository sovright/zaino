# ORAM Gate 1 insertion-budget work log — 2026-07-27

This dated note records the first Gate 1 implementation slice. It is a work
log, not a change to the normative
[architecture and delivery plan](oram-enabled-zaino-plan.md) or the current
[Phase 0 kill-gate decision](oram-phase0-kill-gates-2026-07-23.md).

## Starting state

- The Gate 0 pull-request stack is merged into `main`. The Gate 1 branch starts
  from `8016d0219c04e9d916c0f5c7c09fed0f5b620608`.
- The completed full-Mainnet capture remains the source corpus. Its aggregate
  counts and current-corpus logical sizing are recorded in the
  [capture log](oram-phase0-mainnet-capture-log-2026-07-26.md).
- Missing authoritative `rostl` license and notice files remain a release
  concern. They do not block this technical Gate 1 work or creation of the
  Sovright fork.

## Current slice

This slice implemented and locally verified a deterministic insertion-budget
analyzer. The qualification:

1. verifies the existing capture and sizing inputs;
2. replays the exact current corpus through the production standard-address
   event extraction path;
3. evaluates the current-capacity, four-probe layout against eight fixed
   deterministic keyed insertion schedules; and
4. publishes a digest-bound report that records success or failure against the
   selected diagnostic failure budget.

The fixed schedules make repeated runs over the same inputs reproducible. They
do **not** turn the schedules into independent random samples or a probability
distribution. This first slice deliberately does not search doubled or
quadrupled capacities or eight- and sixteen-probe alternatives; a current-layout
miss will determine the scope of that follow-up instead.

The source-bound mainnet replay subsequently completed at executed source
`a4c5599260a0e2dd3ba15526117bec06743e6227`. It atomically published a valid
three-file artifact, passed semantic and digest read-back validation, and
returned the documented unsuccessful status for a typed NO-GO. The
[dated evidence log](oram-gate1-mainnet-insertion-bound-log-2026-07-27.md)
records the exact result and links the
[preserved bundle](../evidence/oram/gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/).

## Claim boundary

Even after a successful deterministic replay, this slice alone will not
establish:

- a probabilistic insertion-failure bound;
- a worst-case insertion guarantee;
- capacity under projected chain growth;
- calibrated physical expansion for an ORAM backend;
- target-TDX peak RSS, no-swap behavior, or 30% measured headroom;
- compiled access-path obliviousness; or
- Mainnet service or private-server readiness.

Any reported GO or NO-GO applies only to the exact captured corpus, the
recorded deterministic schedules, the current-capacity four-probe layout, and the
selected diagnostic failure budget. Gate 1 remains **IN PROGRESS** until its
remaining growth, backend, and target-hardware evidence is available.

## Completed evidence and next step

The completed run is a deterministic sampled NO-GO only for the current
1x-capacity, four-probe layout under eight fixed schedules and a zero-basis-point
sampled failure budget. It does not establish a probabilistic or worst-case
bound, and it does not close Gate 1.

The next evidence step is to test a remediated insertion design or explicit
alternative profiles, then complete the still-open growth, backend-calibration,
failure-bound, and target-TDX RSS/headroom work recorded in the
[kill-gate report](oram-phase0-kill-gates-2026-07-23.md).
