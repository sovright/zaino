# ORAM Phase 0 kill-gate report — 2026-07-23

- Evidence baseline: `3a84280c3b727b434f26b424c4abad90f192d909`.
- Mainnet-capture compatibility source:
  `c72beedf4761851a892d56bbea0564eae3e4f92e`.
- Observable release-runner source:
  `a53e3269a52567ff11b035dce10fa6ae21b265ad`.
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
| Full-mainnet corpus, hot tail, and 30% TDX RSS headroom | **IN PROGRESS** | A release RPC benchmark made the full scan viable and the explicit-checkpoint run is active, but no full capture or sizing artifact exists yet. No capacity claim is permitted. |
| Compiled `rostl` access-path obliviousness | **FAIL at the exact evidence source** | A secret hit/miss result directly controls conditional jumps even though both cases perform two logical ORAM accesses. The current path cannot make a host-obliviousness claim. |
| Redistribution licensing | **BLOCKED** | The selected `rostl` crates declare permissive SPDX metadata but the pinned repository contains no authoritative license/notice file. Keep the feature internal and default-off until the rights holder confirms the grant and supplies the required texts. |
| Use upstream versus own the ORAM library | **DECIDED: do not ship upstream unchanged** | A production path requires a licensed Sovright fork or a replacement. Forking is conditional on license clearance and explicit ownership of compiler, recovery, and failure-bound work. |

One failed kill gate is sufficient to keep the project at NO-GO. The mainnet
capture remains worth completing because it answers an independent feasibility
question and bounds any replacement backend.

## Gate 1: mainnet corpus and TDX fit

The bootstrap project had no mainnet source. A read-only inventory found an
existing unpruned Zebra 6.2.0 canary in `sovright-bedrock-mainnet`; no production
configuration, process, disk, or snapshot was changed. The existing hourly
snapshot `zebra-auto-hourly-20260723-000120` was cloned into
`sovright-testnet`, mounted on the retained `zaino-oram-build-20260713`
builder, and opened successfully by Zebra 6.2.1 at database format 28.0.0.
The builder is `n2-standard-16`, with 16 vCPU, approximately 62 GiB RAM, and no
swap; it is not a Confidential VM.

The snapshot tip was 3,421,740. A bounded gap feeder supplied only missing
public blocks, each of which the local Zebra consensus verifier accepted. It
stopped after checkpoint 3,422,700, then the node completed ordinary peer sync.
Checkpoint 3,422,700 has RPC-order hash
`0000000000b0632dd891632ddfca4ce4c849cd478036651f64403d6b05e492c7`;
the isolated node, the existing canary, and Blockchair independently agreed.
The research node remains unpruned Mainnet and binds its RPC, health, and
metrics endpoints to host loopback.

The exact-baseline runner failed closed before scanning: the validator reported
NU6.3 at height 3,428,143 while the lockfile's Zebra Chain 11.0 Mainnet schedule
returned `None`. The dedicated compatibility commit `c72beedf` raises only the
workspace `zebra-chain` floor to 11.1, resolves its required stable Zcash
dependency cohort, and adds a regression test at the failing
`verify_reported_upgrades` seam. The targeted test passed on the builder with
255 unrelated tests filtered. The rebuilt 641,161,392-byte debug runner has
SHA-256
`e532fc45137e76db57ade0b26dea74b6589b501eee0babb9e86560c0b636cf94`.
It completed a genesis artifact, exercising the corrected live handshake and
the successful atomic-publication path.

The initial RPC throughput result was an unoptimized debug-build diagnostic:
an explicit 10,000 checkpoint sample scanned 10,001 blocks in 689.82 seconds
at 316,200 KiB peak RSS. The exact release runner from `a53e3269` changes that
operational conclusion. Its 33,097,360-byte binary has SHA-256
`2872b1dbb59582f4f98ae38722f1de9be6203b81e6137093401029dc7c7dd572`.
It scanned the same 10,001-block checkpoint in 72.47 seconds after capture
start, or 86.13 seconds including process startup. The systemd cgroup reported
19.8 MiB peak memory and zero swap. This is still only a throughput diagnostic,
not corpus or TDX evidence.

The direct-backend experiment remains useful but is no longer on the critical
path. Stock `zfnd/zebra:6.2.1` was built without Zebra's compile-time `indexer`
feature, so the exact v6.2.1 tag
(`f3edc40601b4a377693a32c982d4cddf1795fb6f`) was rebuilt with that one feature.
The 184,103,736-byte binary has SHA-256
`e827a35ff84a3d52928d0820340aa61c4d08e2295524c97e707fad2af7c7db31`.
The indexer-only migration completed on a disposable clone and a genesis
capture exercised the direct handshake. A later live replay held the local
read state at 3,421,784 while the stable validator stayed at 3,422,784. The
first streamed hash,
`00000000003aa2bdeedc6917c1455370a46823135b0305c70fac9d8e8e03fc7a`,
was already the secondary database's finalized tip; `zebra-rpc` then reported
`NotReadyToBeCommitted` for that same hash and retried the stream every second.
This is a stale non-finalized-snapshot root-boundary interoperability defect,
not evidence of successful replay. A safe repair must exclude a known finalized
root or prove the exact candidate hash already canonical before skipping it;
suppressing contextual validation or skipping by height would be unsafe. No
direct capture was represented as corpus evidence.

The first full release RPC trace started on the builder at 2026-07-24 02:52:31
UTC against explicit checkpoint 3,423,024 with RPC-order hash
`00000000001de8639497d8903942f3a0e3130082977e0d23c578cf542533773f`.
It reached height 290,000 with a 3.0 GiB cgroup memory peak and zero swap before
being intentionally stopped; no partial artifact was published.

The authoritative run uses the same binary and checkpoint on
`zaino-oram-tdx-c3-44-20260724-v2`, a `c3-standard-44` instance that Google
Cloud reports as configured for Intel TDX with terminate-on-maintenance. The
Ubuntu 24.04 host's 10,001-block smoke scanned in 65.54 seconds. The full run
started at 2026-07-24 03:20:49 UTC and reported serviceable height 3,423,046.
At height 100,000 it had a 3.002 GiB cgroup memory peak and zero swap. These
configuration and runtime counters are not a TDX attestation. The final elapsed
time, measurement files, artifact digests, corpus counts, hot tail, and sizing
result belong here only after atomic publication and read-back validation
complete. Until then, Gate 1 stays **IN PROGRESS** and no capacity claim is
permitted.

Google Cloud currently supports Intel TDX in `us-central1-a`, `-b`, and `-c`
only on regular `c3-standard-*` instances. The existing `n2` VM cannot be
converted in place. The first two candidate qualification targets are:

| Target | RAM | Maximum allowed peak RSS with 30% headroom |
| --- | ---: | ---: |
| `c3-standard-22` | 88 GiB | 61.6 GiB |
| `c3-standard-44` | 176 GiB | 123.2 GiB |

Use `c3-standard-22` only if the full-capacity result stays below 61.6 GiB with
no swapping. Otherwise qualify `c3-standard-44`. The offline sizing model is
not an RSS measurement: it still requires explicit growth, capacity,
admission, hot-address, position-map-width, and backend-expansion assumptions,
then a target-TDX run must measure peak RSS and swapping.

References:

- [Zebra system requirements](https://zebra.zfnd.org/user/requirements.html)
- [Supported Confidential VM configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
- [Creating an Intel TDX Confidential VM](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance)

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

1. Finish the active explicit-checkpoint release RPC capture, validate its
   three-file publication and digests, then run the honest current-corpus
   logical-floor sizing check before any growth or RSS claim.
2. Remediate the exact-source compiled branch finding, then rerun static and
   dynamic qualification.
3. Ask the `rostl` rights holder for license confirmation and canonical texts;
   no maintainer has been contacted yet.
4. Provision a PMU-enabled host for the post-remediation instruction, branch,
   memory-address, page, and timing experiment.
5. Do not resume service/provider/replay/artifact slices until a written review
   explicitly changes the Phase 0 NO-GO.
