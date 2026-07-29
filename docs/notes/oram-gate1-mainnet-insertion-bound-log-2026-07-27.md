# ORAM Gate 1 mainnet insertion-bound log — 2026-07-27

This is the operational evidence ledger for the first source-bound Gate 1
insertion-budget run. The implementation history remains in the
[work log](oram-gate1-insertion-budget-status-2026-07-27.md), while the
normative decision remains in the
[Phase 0 kill-gate report](oram-phase0-kill-gates-2026-07-23.md) and the
broader evidence assessment remains in the
[feasibility report](oram-phase0-1-feasibility-report.md).

## Reproducible inputs

| Input | Exact identity |
| --- | --- |
| Executed Zaino source | `a4c5599260a0e2dd3ba15526117bec06743e6227` |
| Review context | [PR #63](https://github.com/sovright/zaino/pull/63), `feat/oram-gate1-insertion-budget` into `main` |
| Capture measurement BLAKE2s-256 | `aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127` |
| Sizing qualification BLAKE2s-256 | `7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2` |
| Scenario | `source-bound-insertion-budget-v1` |
| Profile | `current-four-probe-v1` |
| Sampled configuration | 1x capacity, four probes, eight fixed deterministic schedules |
| Sampled failure budget | zero basis points |

The run reopened and validated the complete
[mainnet capture and sizing lineage](oram-phase0-mainnet-capture-log-2026-07-26.md).
It used the direct backend with a fixed `non-finalized-state` snapshot. The
source was serviceable through height 3,426,096, and checkpoint 3,425,046 was
preverified before analyzer allocation against RPC-order hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`.
Source-cache state was explicitly uncontrolled.

## Execution

| Measure | Result |
| --- | ---: |
| Systemd unit | `zaino-oram-gate1-insertion-a4c55992-h3425046-r2` |
| Start | 2026-07-27 12:35:21 UTC |
| Exit | 2026-07-27 21:22:35 UTC |
| Wall time | 8h47m14s |
| CPU time | 8h16m28.832303s |
| Peak cgroup memory | 49,218,367,488 bytes (45.84 GiB) |
| Observed process `VmHWM` | 7,087,972 kB |
| Peak swap | 0 bytes |
| Disk read | 251,614,875,648 bytes |
| Disk written | 1,462,272 bytes |
| Exit status | 1 |

The cgroup memory peak includes filesystem cache and is not a process-RSS or
target-TDX result; the separately observed process high-water mark is recorded
to keep those measurements distinct.

The runner reached the exact checkpoint, recomputed the complete source
measurement, atomically published and read-back validated the artifact, printed
its output directory, and only then returned status 1 because the typed report
exceeded the declared sampled failure budget. The nonzero status is the
documented terminal signal for a valid negative result, not an infrastructure
or publication failure.

## Preserved artifact

The exact three-file bundle is checked in under the narrow
[ORAM evidence convention](../evidence/oram/README.md):

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| [`insertion-bound.json`](../evidence/oram/gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/insertion-bound.json) | 6,381 | `63edc9a617d53acd42ef8654580eb40dfa8dfe5f9c0226f5d3e7901b35b34b36` |
| [`insertion-bound.txt`](../evidence/oram/gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/insertion-bound.txt) | 3,648 | `8d0a53a73f3bd648fc12d68fa611fd09fe34859ab2ba2eadada9b9e195e4d705` |
| [`provenance.json`](../evidence/oram/gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/provenance.json) | 201 | `f49796f9701be065e826108827ef368f5f3a8f5704a25597fa720a8392082694` |

Provenance schema
`zaino-oram-source-bound-insertion-budget-provenance-v1`, runner version
`0.1.0`, binds the compact typed JSON report with BLAKE2s-256 digest
`2577a0e26d0ab024b269fa793f561e5bd068d968fa68d3399ce9d0aa343bf4c9`.
That canonical digest is intentionally different from a digest of the
pretty-printed JSON file. Staged read-back separately checked the typed JSON,
its exact text rendering, source and sizing lineage, failure budget, snapshot,
and provenance.

## Exact sampled result

The replay matched all expected current-corpus totals:

| Measure | Value |
| --- | ---: |
| Blocks | 3,425,047 |
| Standard-address events | 351,872,272 |
| Distinct standard addresses | 9,193,009 |
| Maximum events for one address | 3,360,022 |
| Directory admission / capacity | 9,193,009 / 16,777,216 |
| Event admission / capacity | 351,872,272 / 536,870,912 |

All eight schedules exhausted the four-probe directory lane and the four-probe
event lane. Each sampled failure rate was 10,000 basis points against a
zero-basis-point budget. First directory failures occurred between 739,809 and
969,189 occupied entries; first event failures occurred between 7,709,240 and
16,123,255 occupied entries. No logical limit was reached.

The typed verdict is `no-go`, with recommendation
`current-profile-exceeds-budget`. Both table recommendations are
`current-table-shape-exceeds-budget`; no isolated single-table change was
tested. The measured failure mode is probe exhaustion, not source mismatch,
logical-limit exhaustion, allocation failure, or infrastructure failure.

## Claim boundary

This result is a deterministic sampled **NO-GO only for the exact current
1x-capacity, four-probe layout under eight fixed schedules and a zero-basis-point
sampled failure budget**. It establishes exact chain continuity, source
measurement equality, and standard-event replay order for that run. It does
not establish a probability distribution or rule out a different insertion
design, capacity, or probe profile.

The artifact's explicit nonclaims are:

- projected growth;
- alternative capacity or probe profiles;
- isolated single-table resize;
- logical-limit lane isolation;
- a probability distribution;
- a probabilistic failure bound;
- a worst-case bound;
- probe independence;
- a physical ORAM trace;
- backend calibration;
- target-hardware qualification;
- TDX qualification; and
- mainnet readiness.

The keyed BLAKE2s PRF is assumed rather than proven, and the tested layout uses
odd-step double hashing. The bundle is unsigned, self-reported provenance; it
does not bind the executed source revision, lockfile, toolchain, binary
identity, CI run, operating system, architecture, or execution attestation.
The dated run context records the source revision separately.

Gate 1 therefore remains **IN PROGRESS**, and the Phase 0 decision remains
**NO-GO for private-server integration**. Follow-up work must test a remediated
insertion design or explicit alternative profiles, obtain accepted growth and
failure-bound evidence, calibrate the backend, and measure target-TDX RSS,
zero-swap behavior, and required headroom.
