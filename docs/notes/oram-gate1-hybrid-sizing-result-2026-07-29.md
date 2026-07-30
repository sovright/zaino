# ORAM Gate 1 Mainnet hybrid-sizing result — 2026-07-29

## Decision

The source-bound `live-utxo-base-delta-v1` replay completed and its evidence
bundle was admitted.

The unique **PROVISIONAL LOGICAL FINALIST** is:

```text
base entries per page: 16
delta entries per page: 16
generation interval: 288 blocks
conservative fixed page-read lower bound: 27,159 pages
```

This is not a **QUALIFICATION CANDIDATE**, a Gate 1 GO, or a production
profile. The result minimizes the first pre-registered logical tie-break, but
the physical layout, growth, admission/failure, service, wire/leakage,
compaction/recovery, target-TDX, and Gate 2 policy rows in the
[qualification-input record](oram-gate1-qualification-inputs-2026-07-29.md)
remain open.

## Evidence identity and admission

The retained immutable bundle is
[`hybrid-mainnet-2316644-h3425046-v1`](../evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/).
It contains exactly the three regular files atomically published by the
runner:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `hybrid-sizing.json` | 113,550 | `ebf95374c82f18ce07b629bfe1cd3c6b58bd3ecec59cc80cec3f202615f821f6` |
| `hybrid-sizing.txt` | 76,492 | `dfd1430caa7a41b91701c61c2a0397072b59f2f60dd231f20a884cf231923605` |
| `provenance.json` | 196 | `e97f0d7cbb58121f38d3e332241f359f30b1df2673b502c28849291c5af8575c` |

The execution was externally bound to:

- source commit:
  `2316644c254fa65cbb5162a66acb8789b8abc643`;
- release binary SHA-256:
  `50bd18c4984cfb94781cf4a09ba9915aec67b22290ecbace5897ccb814aec7fe`;
- runner version: `0.1.0`;
- systemd unit:
  `zaino-oram-gate1-hybrid-2316644-h3425046-v1.service`;
- service result: `success`, `ExecMainCode=0`, `ExecMainStatus=0`; and
- canonical hybrid-report BLAKE2s-256:
  `2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828`.

The Linux runner revalidated the contextual sizing input before the result was
retained:

```text
measurement_blake2s256:
  aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127
qualification_blake2s256:
  7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2
```

The source binding is Mainnet height 3,425,046, hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`,
with 3,425,047 expected and applied blocks. The source snapshot was
checkpoint-preverified before analysis allocation, and the replay aggregates
matched the retained capture.

The publication path also validated the typed report, fixed candidate domain,
source lineage, aggregate replay, canonical text, provenance, exact staged
file set, and byte-for-byte equality with the in-memory result before atomic
rename. The external SHA-256 values above protect the retained copy after
publication.

## Run context

The run started at `2026-07-29T03:42:59Z` and completed at
`2026-07-29T12:44:49Z`, a wall time of 9 hours, 1 minute, 50 seconds.
Systemd reported:

- 17 hours, 8 minutes, 33.690 seconds of CPU time;
- 37.8 GiB peak process memory;
- 0 bytes peak swap;
- 98.1 GiB read from disk; and
- 236.0 KiB written to disk.

The execution host was Google Cloud instance ID `1882885340293317688`,
machine type `n2-standard-16`, in `us-central1-a`, with 16 vCPUs,
`MemTotal=65,838,564 kB`, `SwapTotal=0`, Ubuntu 24.04.4, and kernel
`6.17.0-1021-gcp`.

This builder was not the proposed `c3-standard-44` Intel-TDX qualification
target. Its memory and swap observations describe the replay process only;
they are not production ORAM RSS, target-hardware, TDX, or 30%-headroom
evidence.

## Logical result

The admitted replay reconstructed:

- 9,193,009 distinct standard addresses;
- 189,686,488 created standard-address events;
- 162,185,784 spent standard-address events;
- 351,872,272 total delta events;
- 27,500,704 final live standard UTXOs; and
- 30,609,634 maximum network-wide live standard UTXOs during replay.

For the unique logical finalist:

| Metric | Value |
| --- | ---: |
| immutable base pages | 2,388,477 |
| base allocated entries | 38,215,632 |
| base padding entries | 10,714,928 |
| maximum base pages for one address | 16,437 |
| maximum total add pages in one generation | 69,233 |
| maximum total spend pages in one generation | 92,186 |
| conservative separate-delta page sum | 161,419 |
| exact maximum same-generation separate pages | 137,474 |
| maximum add pages for one address | 1,342 |
| maximum spend pages for one address | 9,380 |
| conservative fixed page-read lower bound | 27,159 |

The final live histogram's maximum is 262,983 UTXOs for one address. Adding
the 288-block interval's maximum 21,461 per-address add events gives a
conservative post-delta per-address result bound of 284,444 UTXOs.

The 27,159-page figure is only:

```text
maximum base pages for one address
  + maximum add pages for one address
  + maximum spend pages for one address
```

It excludes directory probes, ORAM path expansion, recursive position maps,
stash work, the fixed recent-chain scan, response padding, cover rounds,
queueing, old/new generation overlap, and rebuild workspace.

## Next gate

The next implementation target is the exact 16-entry base/add/spend record
layout and its fixed-schedule partial-page insert-or-update path. Promotion
requires completing and approving the blocking decision table, deriving
physical capacity and growth bounds, and then running target-hardware RSS,
failure, rebuild, service, and exact-path Gate 2 qualification.

If any physical hard gate rejects this tuple, the policy does not silently
fall back to another logical candidate. Gate 1 remains NO-GO until a complete
candidate passes every hard gate.

The first physical follow-up is recorded in the
[fixed-page capacity lower-bound note](oram-gate1-fixed-page-capacity-lower-bound-2026-07-30.md).
The three selected page tables require at least `20.507935 GiB` under the
pinned Rostl geometry, before every excluded layout, growth, overlap, process,
RSS, failure, and service component. This does not change the Gate 1 decision.
