# ORAM Phase 0 mainnet capture log — 2026-07-26

This is the operational evidence ledger for the completed Gate 1 corpus
capture. The normative decision remains in the
[Phase 0 kill-gate report](oram-phase0-kill-gates-2026-07-23.md).

## Reproducible inputs

| Input | Exact identity |
| --- | --- |
| Combined capture source | `d35d158a9826c75a4ec1c31932c29b43cf4c7163` |
| Pinned Zebra source | `68ba61488a3c4386e6a3bd0370583f4ead153770` |
| Release `zainod-oram` SHA-256 | `49b3ed280790cf3d84f266990693da9158ba34d2137e3bbaf467e0e749cd0bf7` |
| `Cargo.lock` SHA-256 | `4f62bac0f62c8ed2904bb787ff9acef05b51621ac0c5584c4d8007e3b7000678` |
| Direct-backend configuration SHA-256 | `b3843b3c953714f074467eeffb4429d07365183728e54cc061cbef5e1d641711` |

The capture used the direct indexed Zebra backend. Its canonical replay fix
excluded an already-canonical finalized root, and its deterministic build
copied checked-in generated RPC artifacts unless regeneration was explicitly
requested.

## Full capture

- Unit: `zaino-oram-mainnet-d35d158a-h3425046-c16`.
- Start: 2026-07-25 21:29:29 UTC.
- Exit: 2026-07-26 00:12:10 UTC.
- Wall time: 2h42m41s.
- CPU time: 31,030.634454 seconds.
- Peak cgroup memory: 61,879,713,792 bytes. This was mostly reclaimable file
  cache and is not a target-TDX ORAM RSS measurement.
- Swap: zero.
- Exit status: zero.

The scan slowed around the NU5 boundary but completed successfully. This is
evidence that the direct source was sufficient for the aggregate capture, not
a general performance or production-readiness claim.

The runner atomically published exactly three files:

| File | Bytes |
| --- | ---: |
| `measurement.json` | 24,592,554 |
| `measurement.txt` | 2,213,769 |
| `provenance.json` | 460 |

Read-back validation established:

- backend: `direct`;
- snapshot mode: `non-finalized-state`;
- selection mode: `explicit-checkpoint`;
- checkpoint height: 3,425,046;
- checkpoint RPC-order hash:
  `0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`;
- source serviceable height: 3,425,064; and
- canonical compact-JSON measurement BLAKE2s-256:
  `aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127`.

## Aggregate measurement

| Measure | Value |
| --- | ---: |
| Blocks | 3,425,047 |
| Transactions | 17,909,015 |
| Outputs | 189,803,195 |
| Spends | 162,228,939 |
| Distinct standard addresses | 9,193,009 |
| Live standard UTXOs | 27,500,704 |
| Live nonstandard outputs | 73,552 |
| Lifetime standard-address events | 351,872,272 |
| Hottest address event count | 3,360,022 |
| Second-hottest address event count | 3,360,020 |

The smallest supported power-of-two capacities strictly above current
occupancy are:

- directory table: 16,777,216 entries;
- event table: 536,870,912 entries.

For the hottest measured address, the current logical fixed-work floor is
`4 + 4H = 13,440,092` logical accesses per request. Charging every compiled
38-byte directory cell, every compiled 82-byte event cell, and four bytes for
each position-map entry gives 46,875,541,504 logical bytes, approximately
43.66 GiB.

## Honest sizing diagnostics

Two sizing runs each atomically published exactly three files and passed
digest/read-back validation:

| TDX memory model | Qualification digest |
| --- | --- |
| 88 GiB | `ac8ff6f13e00e63c1c6a49e377f2b9908074be247cb7319404cdfe4abf051ea8` |
| 176 GiB | `7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2` |

Both models report that the current-corpus logical allocation fits with 30%
reserved headroom and a backend expansion factor of 10,000 basis points
(1.0x). They deliberately record:

- `insertion_bound = false`;
- `backend_calibrated = false`;
- `rss_measured = false`;
- growth horizon = 0; and
- annual growth = 0.

Therefore these are necessary-condition logical sizing results, not Gate 1
capacity qualification. Gate 1 remains **IN PROGRESS** until approved growth
inputs, insertion/failure bounds, calibrated backend expansion, and measured
target-TDX peak RSS with zero swap and at least 30% headroom are available.
