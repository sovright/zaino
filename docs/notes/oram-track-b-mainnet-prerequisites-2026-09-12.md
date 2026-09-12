# ORAM Track B mainnet evidence prerequisites — 2026-09-12

Status: retained derivative artifact hashes and recorded lineage checked;
original capture revalidation, physical calibration, and a current authorized
execution host remain open.

This note records the read-only prerequisite audit for the full-Mainnet sizing
and rebuild track. It does not authorize infrastructure changes and does not
claim target-TDX qualification or a full-service recovery-time objective.

## Evidence already available

The [completed capture ledger](oram-phase0-mainnet-capture-log-2026-07-26.md)
records a full-Mainnet aggregate scan at source
`d35d158a9826c75a4ec1c31932c29b43cf4c7163`, from genesis through height
`3,425,046` and RPC-order hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`.
The run completed in 2h42m41s with zero swap. Its canonical measurement digest
is `aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127`.
It measured 9,193,009 distinct standard addresses, 351,872,272 lifetime
standard-address events, 27,500,704 live standard UTXOs, and a maximum history
of 3,360,022 events for one address.

The large three-file capture bundle remains outside Git under the repository's
[evidence retention rule](../evidence/oram/README.md). Two small derivative
bundles are retained. All six retained files were rehashed during this audit
and match the SHA-256 values in their recorded ledgers; this does not recompute
either derivative report from the absent original capture:

- the [one-entry/four-probe insertion bundle](../evidence/oram/gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/)
  matches the three SHA-256 values in its
  [dated ledger](oram-gate1-mainnet-insertion-bound-log-2026-07-27.md). Its
  typed report binds the capture and 176-GiB logical-sizing digests and records
  `verdict = "no-go"` for that exact profile under eight deterministic
  schedules and a zero-basis-point sampled failure budget. This is negative
  evidence for that profile, not a probabilistic failure bound;
- the [hybrid sizing bundle](../evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/)
  matches all three SHA-256 values in its
  [result ledger](oram-gate1-hybrid-sizing-result-2026-07-29.md). It binds the
  same capture digest and identifies a provisional logical finalist: 16-entry
  base and delta pages, a 288-block generation interval, and a conservative
  27,159-page fixed-read lower bound.

The recorded run and retained derivative artifacts support corpus availability
and source-bound logical shape. The original capture could not be semantically
revalidated because its complete bundle is not checked in. This evidence also
does not establish current-chain freshness, approved growth, physical ORAM
expansion, target-TDX RSS, zero-swap headroom, controlled-cache rebuild time,
or full-service recovery.

## Reproducible commands

On a host with an existing healthy mainnet indexed source and Zainod
configuration, the listener-free capture path is:

```console
cargo run --release --locked -p zainod-oram --bin zainod-oram -- corpus capture \
  --config <MAINNET_ZAINOD_TOML> \
  --output-dir <NEW_CAPTURE_DIR> \
  --progress-interval 10000 \
  --fetch-concurrency <1_TO_32> \
  --target-height <PUBLIC_HEIGHT> \
  --target-hash <RPC_ORDER_HASH>
```

`--target-height` and `--target-hash` select and verify one explicit public
checkpoint. Fetch concurrency changes only bounded source-read parallelism;
blocks are delivered to the canonical scanner in height order.

The logical sizing command is offline once the complete capture is available:

```console
cargo run --release --locked -p zainod-oram --bin zainod-oram -- corpus size \
  --input-dir <CAPTURE_DIR> \
  --output-dir <NEW_SIZING_DIR> \
  --growth-horizon-years <YEARS> \
  --annual-growth-bps <BPS> \
  --directory-capacity <SLOTS> \
  --directory-admission-limit <RECORDS> \
  --event-capacity <SLOTS> \
  --event-admission-limit <RECORDS> \
  --max-events-per-address <EVENTS> \
  --position-map-entry-bytes <BYTES> \
  --backend-expansion-bps <BPS> \
  --tdx-memory-bytes <BYTES> \
  --required-headroom-bps <BPS>
```

The earlier 88-GiB and 176-GiB results used zero growth, an uncalibrated 1.0x
backend expansion, and no RSS measurement. Their successful logical-fit flags
must not be promoted into physical capacity claims.

The existing source-bound fresh-worker runner can gather a narrower rebuild
measurement:

```console
cargo run --release --locked -p zainod-oram --bin zainod-oram \
  --features typed-qualification -- qualification cold-rebuild \
  --profile source-bound-builder-v1 \
  --config <MAINNET_ZAINOD_TOML> \
  --capture-dir <CAPTURE_DIR> \
  --sizing-dir <SIZING_DIR> \
  --declared-rebuild-budget-seconds <SECONDS> \
  --output-dir <NEW_REBUILD_DIR> \
  --progress-interval 10000
```

This timer begins immediately before worker allocation and ends after exact
source-measurement equality and typed-worker readiness validation. It excludes
source-service startup, snapshot selection, checkpoint preverification,
shutdown, and artifact publication. The artifact labels source-cache state
`uncontrolled`. The result is allocation-through-readiness evidence only; it
cannot close a controlled cold-cache or full-service RTO gate.

## Bounded attestation design options

This research recommends one candidate for the first experiment, not an
approved production stack: acquire a raw Intel TDX quote in the guest through
Linux ConfigFS and verify it on a separate client/verifier with a pinned Intel
DCAP Quote Verification Library closure plus Google host/instance provenance
checks. Google documents the ConfigFS `inblob`/`outblob` flow, a 64-byte
challenge in `REPORT_DATA`, PCK-certificate host provenance, and the
project/zone/instance digest in `MR_OWNER` in its
[current TDX provenance procedure](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance).
The same procedure recommends Google's `gceprovenance` tool from
`go-tdx-guest`; use it first as an independent oracle for provenance and basic
signature checks rather than adding Go to Zaino's runtime. Google's procedure
explicitly says this tool does not perform full TCB, CRL, or RTMR evaluation;
its success cannot substitute for the complete verifier acceptance policy.

For a Rust implementation, Intel's official DCAP tree provides
`tdx_attest_rs` quote generation and `intel_tee_quote_verification_rs` QVL
bindings with Rust samples. The sample source carries BSD three-clause-style
redistribution terms, while the native DCAP libraries and their transitive
notices still require a pinned license-closure review before adoption. The
[Intel Rust verification sample](https://github.com/intel/confidential-computing.tee.dcap/blob/main/SampleCode/RustQuoteVerificationSample/src/main.rs)
also makes clear that collateral expiration and every nonterminal TCB result
remain verifier-policy decisions; sample success output is not an acceptance
policy. Intel requires PCS collateral to be cached rather than fetched on each
verification and says its `nextUpdate` fields govern refresh in the
[TDX enabling guide](https://github.com/intel/confidential-computing.tee.docs/blob/main/docs/child_docs/intel-tdx-enabling-guide/docs/02/infrastructure_setup.md).

Google Cloud Attestation tokens are an alternative only after resolving a
documentation and product-fit mismatch. Google's general service page lists
Intel TDX support, but the current Confidential VM attestation page says its
Google Cloud Attestation flow is limited to AMD SEV. Confidential Space has a
different token and workload model. Track B should therefore avoid treating a
Google token as available for this plain Confidential VM experiment until a
TDX-specific end-to-end API is confirmed from the selected product and zone.

The guest should generate the TLS key first and construct the exact 64-byte
`REPORT_DATA` as a domain-separated SHA-512 transcript over the verifier's
fresh random challenge, TLS SubjectPublicKeyInfo digest, release/image and
effective-profile digest, schema version, key epoch, and projection checkpoint
root. The verifier must recompute the transcript, verify the quote and current
collateral, enforce exact MRTD/RTMR and debug/attribute policy, verify Google
host and instance provenance, and only then accept that TLS key for the
connection. The present custom bootstrap attestation is empty and carries no
challenge, so it supplies none of these bindings.

Before implementation, freeze a versioned canonical transcript specification:
fixed-width integers with explicit byte order, exact digest algorithms and
widths, domain identifier, and length framing for any variable fields. Hashing
an informal concatenation is insufficient. The quote-producing code must take
the TLS key, effective profile/configuration, and checkpoint from their trusted
workload owners; only the freshness challenge comes from the requesting client.
It must quote the same key the listener owns, not an independently minted
evidence-only key. The verifier extracts SPKI from the peer certificate on the
actual completed TLS connection and requires that connection's proof of key
possession. Today's SHA-256 certificate-DER fingerprint is not an SPKI digest
and must not be silently reused as one.

Expected measurements, instance identity, trust roots, configuration/profile
digests, and allowed TCB states come from verifier-owned policy. Matching two
caller-supplied copies of those values does not establish an approved workload.

Maintain a pending, single-use challenge with an expiry and bind acceptance to
the intended audience, policy version, and TLS connection. A fresh challenge
proves freshness of the quote exchange, not freshness of chain or disk state;
the accepted checkpoint/height policy and external rollback witness remain
separate requirements. A verification receipt is trusted only when produced
inside the client's trusted verifier or authenticated by an explicitly trusted
verifier service; a host-supplied JSON success flag is not authorization.

Unresolved trust constraints remain explicit:

- collateral freshness needs a verifier-side trusted clock, a pinned Intel
  root and Google endorsement roots, maximum collateral age, `nextUpdate`
  handling, revocation policy, and fail-closed rules for every advisory and
  non-OK TCB result;
- the verifier must pin accepted firmware, boot chain and workload
  measurements. TDX MRTD measures firmware and RTMRs measure the later boot
  chain; replay and validation of the CCEL event log are part of the policy,
  as described in Google's
  [attestation overview](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation-overview);
- the c3 target currently maps to Intel Sapphire Rapids and TDX in
  `us-central1-a`, but CPUID can be restricted in a TDX guest and cannot be the
  sole CPU identity check. The exact host provenance and quote TCB fields must
  drive acceptance. Google also documents no live migration for this target;
  resumed-memory snapshots must remain forbidden, and disk snapshot/restore
  must be rejected by the external freshness witness and new challenge/key
  epoch;
- DOIT is a separate runtime policy. Intel says TDX exposes and context
  switches DOIT control, while DOIT covers only listed instruction timing and
  does not hide memory addresses, page behavior, power, thermal, or frequency
  channels. The guest must record enumeration, attempted enablement, a
  read-back/self-check, and the exact worker-thread application policy; the
  physical trace gate remains necessary. See Intel's
  [DOIT guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html).

The next implementation slice is a listener-free, feature-gated evidence
round: define a fixed request containing a 64-byte verifier challenge; borrow
the live ephemeral TLS identity through its private owner; derive the canonical
transcript above; obtain the raw quote through
an injected quote-provider interface; and return a bounded evidence envelope
containing the quote, public binding inputs, and no secrets. A separate
verifier binary should consume an explicit policy file and cached collateral,
cross-check one fixture with pinned `gceprovenance`, reject a changed challenge,
TLS key, profile, measurement, TCB status, expired collateral, or replayed
evidence, and emit a typed verification receipt. Mock tests can establish
transcript and rejection semantics; only the later TDX run can establish real
quote acquisition or operator isolation.

## Remaining Track B gate

The next meaningful execution is physical calibration of one approved layout
on the selected TDX target. Before it runs, the plan must freeze the growth and
hot-tail model, exact table/page generations and capacities, compiled record
widths, load and spare policy, recursive position maps, stash policy, and
accepted insertion/failure bound. The target run must bind the exact instance,
guest memory, CPU, image, kernel, microcode and TCB, compiler and release flags,
binary digest, TDX state, and DOIT policy. It must measure backend expansion,
initialization peak, whole-process peak RSS, allocator overhead, page faults,
guest and host swap, and demonstrate at least 30% RSS headroom at target
capacity.

The existing qualification-input record proposes Google Cloud
`c3-standard-44` with Intel TDX in `us-central1-a`, 44 vCPUs, 180,224 MiB
(176 GiB) nominal memory, no Local SSD dependency, a digest- or image-ID-pinned
Ubuntu 24.04 Confidential VM-compatible image, and maintenance policy
`TERMINATE`. This remains a candidate specification rather than a currently
available target or an approved production profile. Before any host action,
the execution package still needs an approved release source and lockfile,
compiler and release flags, binary and image digests, effective configuration
and profile ID, and a reviewed quote-verifier choice. The plan keeps the
reference AGPL-licensed verifier outside Zaino's dependency and copied-code
closure pending separate review. The client verifier must bind the production
image and platform/TCB policy, workload TLS public key, schema/profile and
configuration, ORAM/key epoch/checkpoint roots, DOIT state, and a fresh caller
challenge; wrong or stale image, configuration, profile, key, epoch, or TCB
evidence must fail closed before test-query admission.

After the configured Google Cloud account was reauthenticated, a read-only
inventory of project `sovright-bedrock-mainnet` found no current ORAM builder
and no confidential-compute or TDX-enabled instance. The historical hybrid
ledger's `n2-standard-16` builder instance ID is absent. Every current
persistent disk is attached; none is named for ORAM or the capture. The project
has no ORAM-named snapshot and no custom image that retains an ORAM or TDX
environment. A read-only audit-log query for the historical instance ID
returned no retained entries. No SSH connection was attempted because
`gcloud compute ssh` can mutate project or instance SSH metadata.

The original capture therefore cannot currently be located or revalidated
from the visible GCP inventory. A new remote run requires an existing
authorized host with the mainnet Zainod configuration and indexed source, or a
separately reviewed target-host action; it also needs either the retained
capture path or a deliberate new checkpoint and a new output directory. The
selected host must be checked for sufficient CPU, memory, and free storage
before any long scan or rebuild is launched. No long-running measurement was
started during this audit. This inventory result does not establish that every
copy of the historical capture was destroyed; it only establishes that no
retained ORAM disk or current TDX target is discoverable in the configured
project's instance, disk, snapshot, or custom-image inventory. A name-filtered
Cloud Storage inventory found one private evidence bucket, whose only
top-level prefixes are `cases/` and `snapshots/`; neither is ORAM- or
corpus-named, so the audit did not recurse into unrelated evidence. The volume
and prefix inventory is not an exhaustive capture-recovery search and does not
rule out an unlabelled copy elsewhere.
