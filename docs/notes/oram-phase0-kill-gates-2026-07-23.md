# ORAM Phase 0 kill-gate report — 2026-07-23

- Evidence baseline: `3a84280c3b727b434f26b424c4abad90f192d909`.
- Completed mainnet-capture source:
  `d35d158a9826c75a4ec1c31932c29b43cf4c7163`.
- Decision: **NO-GO for private-server integration and ORAM-enabled
  redistribution**.
- Execution policy: later feature slices and qualification-artifact plumbing
  are frozen. Only work that answers or remediates a Phase 0 kill question is
  in scope.
- Evidence boundary: nothing in this report is a TDX attestation, an
  independent rebuild, a legal opinion, or proof of semantic obliviousness.

## Gate summary

| Gate | Current result | Consequence |
| --- | --- | --- |
| Full-mainnet corpus, hot tail, and 30% TDX RSS headroom | **IN PROGRESS** | The reproducible full capture and current-corpus logical sizing completed. Growth, insertion/failure bounds, backend calibration, and target-TDX RSS/no-swap qualification remain open. |
| Compiled `rostl` access-path obliviousness | **FAIL at the exact evidence source** | A secret hit/miss result directly controls conditional jumps even though both cases perform two logical ORAM accesses. The current path cannot make a host-obliviousness claim. |
| Redistribution licensing | **NO-GO: evidence unavailable** | The selected `rostl` crates declare permissive SPDX metadata but the pinned repository contains no authoritative license/notice file. This is not a finding that the code is unlicensed; keep the feature internal and default-off until the rights holder confirms the grant and supplies the required texts. |
| Use upstream versus own the ORAM library | **DECIDED: do not ship upstream unchanged** | A production path requires a licensed Sovright fork or a replacement. Forking is conditional on license clearance and explicit ownership of compiler, recovery, and failure-bound work. |

One failed kill gate is sufficient to keep the project at NO-GO. The completed
mainnet capture answers an independent feasibility question and bounds any
replacement backend.

## Gate 1: mainnet corpus and TDX fit

The reproducible direct-backend run at combined source `d35d158a` completed
against explicit Mainnet checkpoint 3,425,046, hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`.
Its atomic three-file artifact passed semantic and digest read-back validation.
The measurement covers 3,425,047 blocks, 17,909,015 transactions, 9,193,009
distinct standard addresses, and 351,872,272 lifetime standard-address events.
The hottest address has 3,360,022 events.

The smallest supported strict power-of-two capacities are 16,777,216 directory
entries and 536,870,912 event entries. The measured hot tail forces
13,440,092 logical accesses per fixed-work request under the current formula.
The compiled-record logical allocation is 46,875,541,504 bytes
(approximately 43.66 GiB).

Both the 88 GiB and 176 GiB offline models report current-corpus logical fit
with 30% reserved headroom. They also honestly report
`insertion_bound = false`, `backend_calibrated = false`, and
`rss_measured = false`, with zero growth horizon and zero annual growth.
Therefore the necessary-condition corpus result passes, but Gate 1 remains
**IN PROGRESS**. It still requires approved growth inputs, insertion/failure
bounds, calibrated backend expansion, and target-TDX peak RSS with no swap and
at least 30% measured headroom.

The exact build identities, runtime counters, artifact sizes, counts, digests,
and sizing limitations are recorded in the
[dated capture log](oram-phase0-mainnet-capture-log-2026-07-26.md).

## Gate 2: compiled access-path obliviousness

The deterministic release builder completed two byte-identical no-cache builds
from the exact evidence source. The published static
`x86_64-unknown-linux-musl` PIE is 28,130,360 bytes with SHA-256
`d975f4ca3d3f4c9c99befe067a2641c5369ed95f06b9f6e6a16472a30538a666`.
Its canonical 1,302-byte receipt has SHA-256
`989c9b27106dbaf790183664eebe2b45562add4ab465e63f3791b6dd73ad3293`;
the published binary reverified it successfully. The receipt is explicitly
unsigned, unattested, and self-reported procedure-local integrity evidence, not
independent reproduction or execution attestation.

Language-server resolution places the relevant portable insertion core in
`packages/zaino-oram/src/layout/atomic_store/worker/rostl.rs`. It:

1. performs `read_and_remap`, producing private `found_before`;
2. validates occupancy;
3. selects prior or candidate bytes with `Cmov`;
4. performs `write_or_insert_and_remap`; and
5. returns duplicate versus inserted.

The exact-source release disassembly shows the boolean returned in `AL` by
`read_and_remap` being saved and then directly driving a conditional jump in
both record monomorphizations:

- 82-byte event record: call at `0x7ade98`, compare at `0x7adead`, `je` at
  `0x7adeb2`, healthy-path merge at `0x7adec7`;
- 38-byte directory record: call at `0x7ae35f`, compare at `0x7ae374`, `je` at
  `0x7ae379`, healthy-path merge at `0x7ae38e`.

The exact build and inspection commands were:

```console
CONTAINER_ENGINE=podman cargo run --locked --release \
  --manifest-path tools/workbench/Cargo.toml \
  --bin build-deterministic -- --product zainod-oram
nm -nSC --defined-only build/oram-release/zainod-oram
objdump -dC --no-show-raw-insn --start-address=0x7ade10 \
  --stop-address=0x7ae2f7 build/oram-release/zainod-oram
objdump -dC --no-show-raw-insn --start-address=0x7ae300 \
  --stop-address=0x7ae708 build/oram-release/zainod-oram
build/oram-release/zainod-oram release verify-receipt \
  --receipt build/oram-release/release-receipt.json
```

The paths later reconverge and execute the second ORAM access, and the sampled
`Cmov` selection remains branchless. That preserves the modeled two-access
count but produces secret-dependent compiled control flow before the second
access. Static codegen evidence is already sufficient to fail the current gate;
it does not by itself quantify reliable host-observer distinguishability, and a
timing test cannot turn that binary into a pass.

The same result was independently observed in the prior deterministic release
from source `a7172384dc97b4cdd0ffe9ff94358608e338ae64`; the exact-source result
above is authoritative for this report. After remediation, dynamic paired
experiments should use fresh equal-occupancy workers, randomized AB/BA ordering,
CPU pinning, warm-up, at least 500 pairs, bootstrap confidence intervals, a
permutation test, predefined equivalence bounds, and classifier AUC. The
generic GCP builder exposes no hardware PMU, so a final instruction, branch,
and memory-address trace requires a different bare-metal or PMU-enabled
qualification host.

Upstream [`rostl` issue #8](https://github.com/obliviouslabs/rostl/issues/8)
remains open. Spot checks of its cited bitwise expressions compiled to
`setcc`/bitwise/`cmov` sequences, but that was not an exhaustive review and does
not negate the concrete branch in the Zaino insertion wrapper.

## Gate 3: redistribution license

The exact selected dependency is
[`obliviouslabs/rostl@8c3a12d2`](https://github.com/obliviouslabs/rostl/commit/8c3a12d2febf17b024f2e949428b3bc526d74172),
currently also upstream `main`.

- The root and selected crate manifests declare `MIT OR Apache-2.0`.
- Cargo selects `rostl-oram`, `rostl-primitives`, and `rostl-sort`, all
  `0.1.0-alpha9` at that exact revision.
- The pinned recursive repository tree contains no `LICENSE`, `LICENCE`,
  `COPYING`, or `NOTICE` file, and GitHub detects no repository license.
- The default `zainod-oram` build does not select `rostl`; the
  `typed-qualification` / `rostl-experimental` path does.

This is not a finding that upstream has no license. It is a finding that the
project's redistribution-evidence standard is not met. A fork cannot repair
missing permission. The gate requires written rights-holder confirmation plus
the authoritative license and notice texts at the pinned or successor
revision.

`tdx_easy_https` is reference-only. It and `tdx_quote_verifier` are absent from
Zaino manifests, `Cargo.lock`, and all-feature Cargo trees, so their AGPL
declaration creates no current Cargo-closure obligation. If adopted later, the
exact boundary needs a separate review; do not copy it into this fork as a
shortcut.

Primary evidence:

- [`rostl` root manifest](https://github.com/obliviouslabs/rostl/blob/8c3a12d2febf17b024f2e949428b3bc526d74172/Cargo.toml)
- [`rostl` pinned recursive tree](https://api.github.com/repos/obliviouslabs/rostl/git/trees/8c3a12d2febf17b024f2e949428b3bc526d74172?recursive=1)
- [`tdx_quote_verifier` manifest](https://github.com/obliviouslabs/tdx_easy_https/blob/bd48faebeb21a385b8cd7e4451c107e5c60df02c/client/tdx_quote_verifier/Cargo.toml)

## Gate 4: use versus fork

Do not use upstream unchanged for a redistributable or production-intended
service. It remains acceptable only for internal, default-off, volatile
research while the license question is open.

The current Cargo path is narrower than the original risk row:

- [`#8`](https://github.com/obliviouslabs/rostl/issues/8), compiler-preserved
  obliviousness, is directly relevant.
- [`#13`](https://github.com/obliviouslabs/rostl/issues/13), Circuit ORAM stash
  recovery, is directly relevant.
- [`#24`](https://github.com/obliviouslabs/rostl/issues/24), failure-probability
  evidence, is directly relevant.
- [`#32`](https://github.com/obliviouslabs/rostl/issues/32), unordered-map
  queue recovery, is not in the selected crate path. It becomes relevant only
  if `rostl-datastructures` is adopted.

The decision is a **conditional Sovright fork** after license clearance, with
replacement as the fallback if clearance is not prompt. A fork must own at
least:

1. a branchless/error-coarsened API and exact release-codegen gates;
2. typed stash/capacity failures with a defined recovery transition;
3. authenticated persistence or a measured and accepted rebuild RTO;
4. stash and recursive-position-map telemetry that does not create a new
   secret-dependent channel;
5. an analytical and empirical node-year failure bound; and
6. reproducible builds, long-run qualification, and independent security
   review.

Planning estimate, not a delivery quote: approximately 10–18 engineer-weeks
before external review, plus 2–4 calendar weeks for independent review and
ongoing ownership of the pinned compiler/backend qualification matrix. Some
work can overlap, but recovery and codegen qualification are not one-time
patches.

## Next allowed work

1. Obtain approved growth and backend-calibration inputs, define the
   insertion/failure bound, and measure peak RSS plus swap on the intended TDX
   target with at least 30% headroom.
2. Remediate the exact-source compiled branch finding, then rerun static and
   dynamic qualification.
3. Ask the `rostl` rights holder for license confirmation and canonical texts;
   no maintainer has been contacted yet.
4. Provision a PMU-enabled host for the post-remediation instruction, branch,
   memory-address, page, and timing experiment.
5. Do not resume service/provider/replay/artifact slices until a written review
   explicitly changes the Phase 0 NO-GO.
