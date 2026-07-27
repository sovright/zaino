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

Implementation and local verification are in progress for a deterministic
insertion-budget analyzer. The intended qualification:

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

No remote qualification artifact or Gate 1 result has been published for this
slice yet. Until the remote replay completes and its artifact passes semantic
and digest read-back validation, this is implementation work rather than
evidence.

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

## Next evidence step

Finish local review and verification, run the analyzer against the retained
full-Mainnet capture source, publish and validate the resulting artifact, and
then update the kill-gate report with the measured result and its exact claim
boundary.
