# Operator-observation experiment registration

This protocol specifies the evidence required by Track A of the delivery plan.
It is not a measurement result or an approved leakage budget. No accepted guest
or complete continuation client currently satisfies its execution prerequisites.
The local retained-TLS tests use synthetic attestation plumbing; their results
cannot populate the hardware-attestation or operator-observation fields below.

## Freeze the experiment before collecting labeled observations

Commit a registration manifest and record its SHA-256 before the first measured
trial. Changes after inspecting results require a new registration and a new
held-out dataset. Preserve earlier results, including failed and interrupted
runs. The manifest must contain actual values, with no unresolved placeholders:

- source commit and dirty-tree status, lockfile/toolchain/linker/release flags,
  binary and image digests, immutable cloud resource IDs, CPU/microcode/TDX/TCB,
  accepted guest policy, verifier binary/policy digests, and measured DOIT state;
- the compiled profile ID and every fixed request/response width, address/event
  bound, NFS scan width, ORAM operation budget, page/cover-round count, completion
  bucket, queue bound, and concurrency policy; copy these from the executed
  build rather than inventing a smaller measurement-only profile;
- the public checkpoint and exact corpus/fixture digest, validator location,
  source/cache state, generation and key-reset procedure, and proof that client
  inputs do not affect source ingest;
- the operator capabilities actually available to the collector, each sensor's
  resolution and loss behavior, the exact features and analysis programs,
  workload and perturbation schedules, sample counts, randomization procedure,
  train/tuning/held-out partition, and failure/timeout treatment;
- the approved leakage budget, numerical distinguishing-advantage ceiling,
  exact distinguishing game/metric and secret-case sampling priors (including
  how advantage beyond the public-information baseline is computed),
  confidence procedure, multiple-comparison correction, minimum detectable
  effect/power analysis, and the complete rule for a pass, failure, or unresolved
  result. An absent approved ceiling leaves qualification open; statistical
  non-significance alone cannot establish a pass.

All new cloud resources use `sovright-oram-research`. Retain manifests, raw
observations, and derived reports in its private evidence bucket under an
immutable run prefix. Do not place runtime secrets, TLS/envelope keys, wallet
inputs, or privileged guest diagnostics in the operator-observation dataset.

## Contrasting cases and public controls

Every comparison holds the compiled public profile, method, chain snapshot,
public offered load, and scheduled client lifecycle constant. Use synthetic
identities or public-chain fixtures with a separately retained oracle. Trials
must exercise the actual typed ORAM, recent-state merge, envelope codec, and
retained attested TLS route. A fake store, synthetic quote helper, or mocked
transport does not substitute for those components in a measured trial.

| Comparison family | Required contrasting cases |
| --- | --- |
| Address lookup | Miss versus hit; empty versus nonempty; sparse versus dense history |
| Work placement | Early versus late recent-state match; finalized-only versus recent-only versus merged result |
| Capacity | Below versus exactly at the result/page cap; over-cap protected refusal |
| Continuation | Valid versus invalid, expired, and replayed token; real final page versus cover page |
| State transition | Unchanged source polls; actual forward advance; reorganization; generation/key reset |
| Contention | One client versus the registered concurrent load, with identical public load within each secret comparison |
| Failure | Registered scheduling perturbation, ingest contention, integrity failure, and interrupted query |

Unsupported cases remain explicitly unmeasured. In particular, the current
first-page client cannot qualify continuation or cover-round privacy. A
secret-driven stop, retry, fallback, or profile change is an observed outcome,
not a sample to discard. Keep invalid public framing and failed attestation as
separate admission-negative tests: they must not send a private query and must
not be mixed into a hidden address hit/miss comparison.

## Observation provenance

| Surface | Required record and interpretation |
| --- | --- |
| Network | Whole controlled-client session, destinations, packet sizes/directions/times, connection resets, RPC/round counts; include follow-up and retry traffic |
| Storage | Operator-visible I/O addresses, sizes, order, and timing, including query-induced writes and background ingest |
| Memory/pages | Precisely identify the available host-visible page/access sensor and what TDX prevents it observing; do not infer an unavailable channel from guest counters |
| Allocation/resources | Available outside-guest resource/time observations; label guest allocation/RSS instrumentation separately |
| Source requests | Destination, public request type, size, count, and timing; detect query-selected address/txid requests or backfill |
| Logs/administration | All exposed logs, metrics, errors, and administrative output under the declared operator role |
| Backend diagnostics | Trusted instrumentation for ORAM paths, position maps, stash, and work counts, with instrumentation overhead and code differences recorded |

A GCP project administrator is not automatically a hypervisor observer. Record
which adversary each sensor represents. Trusted in-guest traces can diagnose
algorithmic leakage but cannot prove that an unavailable host-visible channel
is safe. Missing sensors, dropped samples, or an unobservable backend dimension
leave their corresponding gates open. An administrator-accessible diagnostic
image cannot supply accepted-image operator-exclusion evidence.

## Trial lifecycle and analysis

1. Verify the frozen source/image/resource identities and independently approved
   guest policy. Complete wrong-image/key/profile, stale-challenge, debug/admin,
   and reset-negative tests before query admission. Snapshot resume, cloning,
   and migration must satisfy the plan's prevention or external-freshness gate.
2. Partition by independent boot/run and query identity, not individual adjacent
   packets. Keep held-out identities and runs out of feature selection, model
   tuning, and stopping decisions. Commit the partition procedure before data
   collection and record seed commitments without revealing labels to the
   operator-side analysis process.
3. Run the frozen warmup and public schedule. Randomize secret case assignment
   within the registered blocks. Retain all offered trials and their outcomes,
   including refusal, crash, missing data, and timeout. Never rerun only failed
   cases into the original dataset or stop sampling when a desired result
   appears.
4. Check exact invariants first: fixed envelope/round shape, permitted source
   requests, log fields, reset behavior, and fixed algorithmic work. A violation
   is negative evidence even if a classifier cannot exploit it reliably.
5. Evaluate the frozen feature/classifier families against a public-information
   baseline on held-out runs. Report effect sizes, uncertainty, and distinguishing
   advantage under the pre-registered dependence and multiple-comparison
   procedures. Include negative controls and pre-registered positive sensitivity
   controls, such as deliberately distinguishable public timing/size changes or
   a known injected diagnostic trace. A dead/censored sensor or sensitivity
   below the registered detectable effect leaves that surface unresolved.
   Disclose instrumentation changes.
   Do not use ordinary independent-sample intervals for correlated packets or
   operations within one boot.
6. Publish a source-bound report with input/analysis digests and one result per
   comparison and observation surface: pass within the approved bound, fail,
   or unresolved. Retain all missing dimensions and unsuccessful trials. An
   approved finite experiment is bounded evidence; independent algorithm and
   exact-release assembly review remain required.

This protocol does not qualify mainnet memory, growth, full-service recovery,
all wallet methods, or arbitrary CPU side channels. Those retain their own
delivery-plan gates.
