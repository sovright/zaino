# ORAM Gate 2 dynamic timing evidence — 2026-07-28

This note is preliminary. It describes the supported dynamic timing experiment
and its manifest-bound durable attempt ledger, but it does not report a timing
result because no complete builder ledger has been retained in this repository.
The normative decision remains in the
[Phase 0 kill-gate report](oram-phase0-kill-gates-2026-07-23.md), and Gate 2
remains **NO-GO**.

## Standing assumption

This work was directed to proceed under an explicit, operator-supplied
assumption that upstream `rostl` is trusted with respect to secret-dependent
branches. That assumption is load-bearing and is recorded here so no reader
inherits it silently. It does not replace the uncompleted upstream branch and
indirect-call audit, and it does not alter the static compiled-path finding in
the kill-gate report.

## Manifest-v1 and attempt-ledger status

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

The standalone `zainod-oram-timing` binary remains useful for pilots, but its
output is not manifest-bound. Qualification attempts use the synchronous
`run-cell` command in the release-bound main binary. The operator must create a
real empty ledger directory before the first attempt and invoke one fresh,
CPU-pinned process per cell:

```text
mkdir timing-ledger-v1

taskset -c <CPU> zainod-oram qualification timing run-cell \
  --manifest-dir manifest-v1 \
  --release-receipt release-receipt.json \
  --expected-manifest-blake2s256 <retained-manifest-digest> \
  --ledger-dir timing-ledger-v1
```

`run-cell` redoes same-boot manifest, release-binary, host, CPU-affinity,
quiescence, scheduler-stat, and attempt-control admission. It always selects
the next unconsumed manifest cell; there are no CLI flags that can alter the
cell. The command is dispatched before logging or Tokio initialization. It
durably publishes a canonical `Started` link before the first ORAM operation,
then publishes exactly one `CompletedPositive`, `CompletedNegative`, or
`StartedError` terminal link. Positive and negative completions retain the
exact raw `zaino-oram-insert-timing-v3` bytes beside the terminal record.
Pre-start refusal publishes no link.

Each link is an immutable, fixed-width numeric child directory. Canonical
minified `record.json` links to the preceding record digest and binds the
manifest digest, manifest runner version, release identity, boot-scoped host,
complete cell inputs, and fixed limitation flags. A killed publisher can leave
an internal stage directory; replay ignores only the publisher's exact
numeric-stage grammar after proving the entry is a real directory without
following links. Every other unexpected file, directory, symlink, name gap,
illegal state transition, digest mismatch, or raw-v3 mismatch fails replay.

If a process dies after `Started` but before its terminal link, the cell is
already consumed and must not be rerun. Seal it explicitly:

```text
zainod-oram qualification timing seal-dangling \
  --manifest-dir manifest-v1 \
  --expected-manifest-blake2s256 <retained-manifest-digest> \
  --ledger-dir timing-ledger-v1
```

Sealing records `prior_process_interrupted` as `StartedError`, advances to the
next cell, and is non-repeatable. Inspect retained state offline, optionally
requiring an exact externally retained head:

```text
zainod-oram qualification timing inspect-ledger \
  --manifest-dir manifest-v1 \
  --expected-manifest-blake2s256 <retained-manifest-digest> \
  --ledger-dir timing-ledger-v1 \
  --expected-head-sequence <retained-sequence> \
  --expected-head-blake2s256 <retained-record-digest>
```

Retain each reported head in an independently administered append-only or WORM
system. The in-ledger hash chain detects retained interior omission, but it
cannot detect deletion of an unwitnessed suffix or the entire ledger root.
The external witness is deliberately not asserted by the self-reported record.

The host binding is self-reported, boot-scoped, unattested, and
`tdx_qualified=false`. Raw machine ID, boot ID, CPU model/microcode, and DMI
strings affect the combined fingerprint but are not persisted; kernel release,
logical CPU count, memory size, target OS/architecture, and the combined
fingerprint are public. Same-boot admission intentionally fails after reboot.
Each attempt additionally binds the selected CPU and allowance, online and
sibling topology, SMT state, scaling driver/governor/minimum/maximum/current
frequency, boost/turbo controls, microcode, CPU flags and bugs, vulnerability
files, kernel command line, clocksource, scheduler-stat control, per-task
speculation controls, NUMA cpuset, and effective NUMA policy. Effective policy
is obtained fail-closed from `/usr/bin/numactl --show`; the reporter's absolute
path and BLAKE2s digest are recorded. The same stable controls must match before
and after each cell and across the entire matrix; observed current frequency is
recorded but excluded from equality. This remains self-reported evidence, and a
substituted reporter can lie.

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
  negative terminal rather than discarded. A post-start measurement error
  becomes `StartedError`; only a pre-start refusal produces no attempt link.
- Numerical claims must cite committed artifact paths and be reproducible from
  their raw pairs.

Numbers will not be reconstructed from console output, prose, or memory.

## Current limitations

- No exact timing JSON is committed, so there is no auditable dynamic result to
  summarize yet.
- No real qualification manifest, complete attempt ledger, or independently
  witnessed manifest/head sequence is retained yet.
- The ledger and host/control snapshots are self-reported and not temporally
  attested. The record contains no external/WORM head witness and cannot detect
  deletion of an unwitnessed suffix or the ledger root.
- Replay validates raw-v3 identity, shape, seeds, policy fields, declared
  booleans, and terminal consistency, but it does not independently recompute
  every statistical report, scheduler ratio, or environment decision from raw
  samples. `all_cells_declared_positive=true` is therefore a retained
  runner-declaration summary, not verifier-derived Gate 2 admission.
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

None. Gate 2 remains **NO-GO**. V3 and every attempt record explicitly retain
`can_clear_gate2=false`; V3 also records `wall_clock_only=true`,
`physical_trace_complete=false`, and `oram_state_seed_bound=false`. The
manifest and durable cell binding now exist, but no real matrix has been run or
externally witnessed. A future update may add narrowly scoped,
artifact-derived descriptive findings after the admitted hit/miss and forced
matrix is retained. Clearing Gate 2 still requires independent raw-outcome
evaluation, accepted inference for process-level repeat blocks, exact codegen
evidence for both executable paths, directory/event physical traces, fixed
normative coverage and threshold policy, the work listed in the normative
kill-gate report, and written review of that decision.
