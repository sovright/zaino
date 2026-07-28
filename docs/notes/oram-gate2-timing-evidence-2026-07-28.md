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

## Manifest-v1 status

The runner now implements an immutable `zaino-oram-timing-manifest-v1`
artifact. A strict `zaino-oram-timing-manifest-request-v1` supplies:

- all three modes in fixed order (`hit_miss`, `forced_hit`, `forced_miss`);
- sorted, uniquely named directory/event occupancy points;
- sorted, uniquely named process-level repeat blocks with distinct root seeds;
  and
- measured/warm-up pair counts plus mean, CDF, load, competing-process, and
  runqueue-wait bounds.

An illustrative request (not a normative Gate 2 policy) is:

```json
{
  "schema": "zaino-oram-timing-manifest-request-v1",
  "policy": {
    "pairs": 500,
    "warmup_pairs": 50,
    "mean_bound_nanos": 1000.0,
    "cdf_distance_bound": 0.1,
    "max_load_average_1m": 1.0,
    "max_competing_processes": 0,
    "max_runqueue_wait_ratio": 0.01
  },
  "modes": ["hit_miss", "forced_hit", "forced_miss"],
  "occupancy_points": [
    {
      "id": "low",
      "directory_capacity": 1024,
      "directory_initial_occupancy": 16,
      "event_capacity": 1024,
      "event_initial_occupancy": 32
    },
    {
      "id": "peak",
      "directory_capacity": 2048,
      "directory_initial_occupancy": 512,
      "event_capacity": 2048,
      "event_initial_occupancy": 768
    }
  ],
  "repeat_blocks": [
    {"id": "repeat-a", "root_seed_hex": "0000000000000001"},
    {"id": "repeat-b", "root_seed_hex": "0000000000000002"}
  ]
}
```

The runner materializes the complete requested Cartesian product in repeat
block, occupancy point, then fixed-mode order. Each cell receives a
domain-separated BLAKE2s-derived seed, and duplicate derived seeds are rejected.
The artifact directory contains exactly canonical `manifest.json` and the
unchanged canonical `release-receipt.json`. The manifest binds the verified
receipt bytes, source revision, main-binary digest and size, package version,
and a boot-scoped host fingerprint.

Creation and same-boot execution admission require the fixed Linux x86_64
release build whose receipt matches the invoking `zainod-oram` executable:

```text
zainod-oram qualification timing create-manifest \
  --request request.json \
  --release-receipt release-receipt.json \
  --output-dir manifest-v1

zainod-oram qualification timing verify-manifest \
  --manifest-dir manifest-v1 \
  --release-receipt release-receipt.json \
  --expected-manifest-blake2s256 <retained-digest>
```

The creation command prints the BLAKE2s-256 digest of canonical
`manifest.json`. Retain that digest outside the artifact directory. Structural
inspection can then revalidate canonical manifest and receipt bytes after a
reboot or on another supported host without claiming execution admission:

```text
zainod-oram qualification timing inspect-manifest \
  --manifest-dir manifest-v1 \
  --expected-manifest-blake2s256 <retained-digest>
```

This machinery does not yet prove temporal predeclaration. The standalone
timing driver cannot consume a manifest or bind output to a manifest cell, no
attempt ledger or external append-only witness exists, and no real
qualification manifest has been retained. A manifest could still be created
after observing an unbound run.

The host binding is self-reported, boot-scoped, unattested, and
`tdx_qualified=false`. Raw machine ID, boot ID, CPU model/microcode, and DMI
strings affect the combined fingerprint but are not persisted; kernel release,
logical CPU count, memory size, target OS/architecture, and the combined
fingerprint are public. Same-boot admission intentionally fails after reboot.
Selected CPU, SMT, governor/frequency/turbo, mitigation state, and other
attempt-time controls still need binding in the attempt record.

The embedded release receipt is unsigned. It proves local canonical receipt
integrity and binary digest/size agreement, not source derivation or execution
attestation. Timing-binary codegen plus directory/event physical traces are
declared as required companion roles only; no such evidence is attached.
Manifest policy is operator-supplied and does not yet encode Gate 2 minimum
coverage or maximum acceptable thresholds. Accordingly, the fixed evidence
contract remains authoritative with `can_clear_gate2=false`.

## Question and method

The dynamic experiment asks whether a host observer can distinguish a directory
or event insertion-path hit from a miss using wall-clock time.

The supported driver:

- builds two long-lived logical twin tables once per record kind;
- maintains equal public occupancy and either a one-record substitution with
  one exclusive key per table (`hit-miss`) or identical key sets (forced
  modes);
- inserts the same probe key in both labelled arms, then performs one untimed
  fixed-work cover insertion on each physical table;
- runs covers in fixed physical order `[0, 1]`, alternates logical roles, and
  maximally balances randomized AB/BA ordering inside each physical-role
  stratum;
- grows both tables by exactly one record after every warm-up and measured pair;
- measures both directory and event records in each invocation;
- records raw pairs, experiment plans, distinct schedule/resampling seeds,
  deterministic occupancy windows, state-control semantics, selected timing
  mode, scheduler counters, and host-policy snapshots in one JSON artifact;
- requires CPU affinity, scheduler-stat availability, runqueue-wait admission,
  and the declared quiescence policy; and
- evaluates the caller-declared pooled, order-conditioned, and
  position-conditioned mean/CDF equivalence bounds.

The pooled mean in an equivalence report is the scheduled hit-label duration
minus the scheduled miss-label duration. It is not a first-position minus
second-position contrast. Distinct schedule and resampling seeds do not make
sequential same-host runs independent. V3 rounds carry state forward and grow
occupancy, while the current bootstrap and DKW intervals assume independent
rounds; their stated coverage is therefore nominal, not a formal qualification
guarantee.

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
- Historical `zaino-oram-insert-timing-v2` artifacts retain the fresh-table
  semantics and identify their timing mode, the
  quiescence-policy result for every environment snapshot, and the aggregate
  affinity, scheduler-stat, and runqueue-wait admission results.
- New `zaino-oram-insert-timing-v3` artifacts use the long-lived logical-twin
  model and record pilot versus qualification-candidate intent, configurable
  counts, exact occupancy growth, physical-role order blocking, and explicit
  negative scope flags. V2 and V3 evidence must never be pooled.
- Qualification-candidate v3 runs require at least 500 measured pairs, a count
  divisible by four, and an even warm-up count. A pilot can validate apparatus
  with smaller positive counts and exits successfully when its environment is
  admitted, but cannot satisfy the declared wall-clock criteria. Measured
  qualification strata are exactly balanced; odd-length pilot or warm-up
  strata differ by one with opposite extras preserving global balance.
- A completed run rejected by a post-start admission check is retained as a
  negative artifact rather than discarded. Pre-start refusal or a measurement
  error produces no timing artifact.
- Numerical claims must cite committed artifact paths and be reproducible from
  their raw pairs.

Numbers will not be reconstructed from console output, prose, or memory.

## Current limitations

- No exact timing JSON is committed, so there is no auditable dynamic result to
  summarize yet.
- No real qualification manifest or externally witnessed manifest digest is
  retained, and raw v3 output is not yet bound to a manifest cell.
- There is no durable attempt chain. Pre-start refusals, started runs, terminal
  negative results, and dangling starts therefore cannot yet be audited as a
  complete sequence.
- The currently measured event record is one immutable event per cell, not the
  selected target chunked/generational production projection. V3 records that
  the target projection is not yet implemented.
- Upstream `rostl` initializes part of its physical position state using ambient
  randomness, so the raw driver cannot yet bind an ORAM-state seed.
- Long-lived v3 rounds are serially dependent. Independent process-level repeat
  blocks or an accepted block/time-series method are still required for formal
  inference.
- The experiment is wall-clock only. PMU, cache-timing, and co-resident
  adversary measurements require a suitable qualification host.
- The operator-supplied upstream trust assumption leaves the upstream compiled
  control-flow audit open.
- Dynamic timing evidence cannot overturn the existing static compiled-path
  failure.

## Effect on Gate 2

None. Gate 2 remains **NO-GO**. V3 explicitly records `wall_clock_only=true`,
`physical_trace_complete=false`, `oram_state_seed_bound=false`, and
`can_clear_gate2=false`. A future update may add narrowly scoped,
artifact-derived descriptive findings after admitted hit/miss and forced-mode
runs are retained. Clearing Gate 2 still requires a predeclared retained
multi-run manifest created before attempts and externally witnessed, durable
manifest-cell attempt binding, exact codegen evidence for both executable
paths, directory/event physical traces, fixed normative coverage and threshold
policy, the work listed in the normative kill-gate report, and written review
of that decision.
