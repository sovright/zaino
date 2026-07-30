# Gate 1 hybrid qualification inputs

Date: 2026-07-29  
Status: draft operator and security decision record

## Timing and scope

This note was written while the source-bound
`live-utxo-base-delta-v1` Mainnet replay was still running and before its
output directory existed. At the latest observation available while drafting
this note, the replay had reached height 1,810,000 of 3,425,046. No
`hybrid-sizing.json`, `hybrid-sizing.txt`, or `provenance.json` result had been
published or inspected.

The running evidence identity is:

- source commit:
  `2316644c254fa65cbb5162a66acb8789b8abc643`;
- release binary SHA-256:
  `50bd18c4984cfb94781cf4a09ba9915aec67b22290ecbace5897ccb814aec7fe`;
- systemd unit:
  `zaino-oram-gate1-hybrid-2316644-h3425046-v1.service`; and
- intended output:
  `/mnt/zaino-oram-mainnet/hybrid-sizing-mainnet-2316644-h3425046-v1`.

This record supplements, but does not change, the closed candidate domain,
admission checks, hard-gate order, tie-break order, or decision labels in
[`oram-gate1-hybrid-profile-selection-policy-2026-07-29.md`](oram-gate1-hybrid-profile-selection-policy-2026-07-29.md).
Opening an admitted sizing result can name at most a **PROVISIONAL LOGICAL
FINALIST**.

Values under “fixed requirements” were already normative before the replay
result was opened. Values under “proposed operator defaults” are deliberately
result-independent, but are not effective until approved as one policy
decision. An unset row in the blocking-decision table prevents promotion to
**QUALIFICATION CANDIDATE**.

## Fixed requirements

The following requirements already have a documented basis:

- the sizing grid is the 27 tuples in the selection policy;
- generation intervals in that grid are measurement inputs, not approved
  production cadence;
- whole-process peak RSS must be at most 70% of target guest memory;
- guest and host swap must both remain exactly zero;
- qualification includes at least `10^9` mixed operations at target load with
  zero overflow, panic, corruption, lost entry, or silent fallback;
- there is one mutable ORAM worker and no secret-dependent sharding or
  batching;
- base, add, and spend records remain separate physical classes;
- promotion uses exact release-compiled record types and exact production
  symbols, not synthetic stand-ins; and
- Gate 2 timing uses every required mode and at least 500 measured pairs, with
  a pair count divisible by four and an even warm-up count.

The 176-GiB sizing model retained in the earlier corpus report is not physical
evidence. It assumed no growth, no insertion bound, uncalibrated `1.0x`
physical expansion, and no measured RSS.

## Proposed first target

The first physical-qualification target is proposed as:

- Google Cloud `c3-standard-44`;
- Intel TDX in `us-central1-a`;
- 44 vCPUs and 180,224 MiB (176 GiB) nominal memory;
- no Local SSD dependency;
- a digest- or image-ID-pinned Ubuntu 24.04 Confidential VM-compatible image;
  and
- maintenance policy `TERMINATE`.

The execution record must bind the exact instance ID, guest `MemTotal`, CPU
model and generation, image ID, kernel, microcode, firmware/TCB evidence,
compiler and release flags, binary digest, TDX state, and DOIT policy. The
smaller of guest-visible memory and the declared 176-GiB ceiling is the RSS
denominator.

This machine choice is operationally available and matches the previously
retained 176-GiB logical model, but it remains a proposed operator choice until
the decision table below is approved.

## Chosen hybrid insertion direction

Widths 8 and 16 require mutation of an active partial page. Keeping partial
pages in a query-keyed plaintext map, secret-indexed enclave array, or
variable-work side structure is forbidden.

The implementation direction is a fixed-schedule branchless page upsert:

1. reject only public preconditions before protected access;
2. always perform one ORAM read/remap;
3. transform a found page or canonical empty page without control flow on
   presence, address, event kind, occupancy, or result;
4. always perform one ORAM write-or-insert/remap;
5. update public occupancy with constant-time selection; and
6. classify mismatch, corruption, capacity, or upstream failure only after the
   complete fixed schedule, then fail closed.

Every mutable table retains at least one public spare record so a full table
never has to branch on whether the requested secret key is already present.
Unique insertion remains valid for immutable compaction output.

The logical domains are address metadata, immutable base pages, active add
pages, and active spend pages. This is a design direction, not a complete
physical topology. Exact table count, simultaneous generations, keying,
record bytes, capacity, load, recursive maps, stash, and old/new overlap
remain blocking inputs.

## Proposed operator defaults

The following defaults were proposed before the replay result was opened:

| Input | Proposed value | Evidence to report |
| --- | --- | --- |
| target | `c3-standard-44`, Intel TDX, `us-central1-a` | exact target identity and TDX/DOIT record |
| completed-query latency | p99 at most 1,000 ms | p50/p95/p99/p999 plus raw paired samples |
| sustained throughput | at least 1 completed query/s per worker | completed, failed, and rejected counts |
| mutable execution | one executing request and one queued request | queue wait and overload outcomes |
| compaction duty | at most 25% of the public generation interval | build, overlap, publish, and cleanup time |
| cold rebuild RTO | at most 24 hours | cold-cache allocation through ready-to-serve |

No latency or throughput value is inferred after observing the sizing winner.
No secret-dependent retry, fallback, admission, cancellation, batching, or
timeout behavior may be used to meet a target.

These defaults do not define maximum page reads, growth, failure probability,
record size, response envelopes, or Gate 2 equivalence bounds.

## Blocking decisions

The following table must be completed and approved before a provisional
logical finalist can become a qualification candidate:

| Category | Required frozen input | Status |
| --- | --- | --- |
| target identity | exact CPU, guest memory, image, compiler flags, TDX/TCB and DOIT policy | proposed target only |
| growth | horizon, start point, base/address/hot-tail model, delta peaks, overlap, and source-bound derivation | unset |
| physical layout | exact tables and generations, keys, compiled record bytes, capacity/load/spare policy, recursive maps and stash | [three fixed-page tables have a source-bound 20.507935-GiB retained floor](oram-gate1-fixed-page-capacity-lower-bound-2026-07-30.md); directory, complete topology, growth and overlap remain unset |
| fixed work | exact directory, base, delta, fold, NFS, response, cover, read, write, and upsert schedule | unset |
| failure bound | accepted analytical node-year threshold plus empirical occupancy and adversarial workload | `10^9` empirical minimum only |
| service SLO | latency, QPS, queue, overload, timeout, cancellation, and load definition | proposed latency/QPS/queue only |
| compaction/recovery | cadence, overlap/workspace, publication/failure protocol, duty cycle and RTO | proposed duty/RTO only |
| wire/leakage | padded inputs, NFS slots, result slots, request/response bytes, frame/completion class, cover rounds, continuation rule/lifetime and timeout bucket | unset |
| Gate 2 | exact symbols and case matrix, occupancies, seeds, warm-up, repeat method, equivalence bounds, quiescence limits, trace modality and PMU host | apparatus minimum only |

Test-only constants such as 512-byte envelopes, four NFS slots, two response
slots, a 128-byte token, queue depth one, or illustrative timing bounds do not
close these rows.

## Promotion rule

The retained hybrid artifact is first checked mechanically and reviewed using
the pre-registered logical derivations. That review may name a **PROVISIONAL
LOGICAL FINALIST**.

Promotion to **QUALIFICATION CANDIDATE** requires:

1. explicit approval of every blocking decision above;
2. a new compiled qualification profile and versioned profile ID;
3. exact record-width, capacity, and fixed-work derivations; and
4. Gate 2 targeting the exact production symbols and record
   monomorphizations.

Promotion to **PRODUCTION PROFILE** additionally requires every original hard
gate and every approved numerical gate to pass on the bound release binary
and target.

Any unset input, missing host telemetry, result-dependent policy change, or
synthetic substitute for a production path keeps Gate 1 or Gate 2 at NO-GO.
