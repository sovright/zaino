# ORAM Gate 1 hybrid-sizing work log — 2026-07-28

This dated note records the implementation slice that measures the proposed
live-UTXO-base plus append-only-delta design. It is a work log, not a change to
the normative
[architecture and delivery plan](oram-enabled-zaino-plan.md) or the current
[Phase 0 kill-gate decision](oram-phase0-kill-gates-2026-07-23.md).

## Starting state

- The completed current-profile insertion run is a typed NO-GO for the exact
  1x-capacity, four-probe layout under all eight fixed schedules. Its evidence
  remains in the
  [dated insertion-bound log](oram-gate1-mainnet-insertion-bound-log-2026-07-27.md).
- The full-Mainnet capture reports 351,872,272 lifetime standard-address
  events but 27,500,704 final live standard UTXOs. It does not yet report the
  live-UTXO page and bounded-delta shapes needed to assess the hybrid.
- This slice is stacked on the insertion-budget branch so its source-bound
  replay and artifact lineage remain reviewable independently.

## Current slice

The new fixed `live-utxo-base-delta-v1` measurement:

1. validates the existing capture and its sizing-context lineage, then
   preverifies the capture checkpoint before analysis allocation;
2. replays the canonical standard-address event stream while preserving
   created-versus-spent kind and dense address indexing;
3. reconstructs the exact final live-UTXO-per-address histogram without
   publishing addresses, outpoints, or dense address identifiers;
4. computes exact logically immutable base-page counts, maximum pages per
   address, allocated entries, and padding for fixed page sizes of 1, 8, and
   16 entries;
5. partitions the replay into genesis-aligned public generations of 288, 1,152,
   and 8,064 blocks, including the trailing partial generation; and
6. records maximum total and per-address add, spend, and combined delta events
   and page requirements for each fixed interval and page size.

Delta pages are address-keyed. A generation's total page requirement is the
sum of each address's individually rounded page requirement, not the rounded
generation-wide event total. Adds and spends remain separate page classes in
this evidence so the report does not silently choose a future co-packing rule.

The command atomically publishes exactly three read-back-validated files:
`hybrid-sizing.json`, `hybrid-sizing.txt`, and `provenance.json`. Candidate
page sizes and rebuild intervals are compiled profile constants rather than
caller-selected tuning knobs.

Only the capture measurement and its digest enter the hybrid-sizing
calculation. The prior sizing qualification is validated and retained as
context lineage; none of its model values affect the result.

## Claim boundary

This slice is sizing evidence only. It does not implement a serving store,
multi-entry persistent page, delta compactor, generation switch, query fold,
or in-place upsert/delete path. It also does not establish:

- projected growth or a selected production rebuild cadence;
- insertion, stash, probabilistic, or worst-case failure bounds;
- query latency, fixed-work acceptability, throughput, or queue behavior;
- physical ORAM expansion or backend calibration;
- peak RSS, allocator overhead, no-swap behavior, or 30% headroom;
- target CPU, TDX, physical-trace, or attestation qualification; or
- Mainnet service or private-server readiness.

Generation boundaries are public block-count schedules for measurement. Their
presence in this report does not approve those schedules for production.
Successful publication reports `hybrid_sizing_verdict=not-assessed`; it is not
a GO or NO-GO result.

The replay uses a checkpoint-preverified indexed source and an immutable
non-finalized-state snapshot. Finalized-store reads remain live, so the
provenance does not claim one immutable finalized-plus-non-finalized snapshot
generation. The completed aggregate measurement must still match the retained
capture exactly.

## Next evidence step

After local and native-CI verification, run this command against the retained
Mainnet indexed source at the capture checkpoint when the shared builder is
available for non-timing work. Use the source-bound result to decide whether
the live-base/chunked-delta shape has a practical fixed profile. Only an
accepted shape should advance to backend expansion, target-TDX RSS,
fixed-query-work, rebuild/RTO, and failure-bound qualification.
