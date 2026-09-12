# Isolated Intel TDX evidence experiment

This directory prepares a disposable Google Cloud Intel TDX guest for a raw
platform and quote diagnostic. The diagnostic Ubuntu guest remains accessible
to an OS Login administrator. It cannot establish an operator-inaccessible
accepted image, verify a workload, or exercise the private query path. It does
not provision the 176-GiB mainnet sizing target or define a production image.

## Pinned target

All new ORAM cloud work uses project `sovright-oram-research` (project number
`486673347298`), created on 2026-09-12. The scripts pass this project explicitly
and do not depend on the caller's active gcloud configuration. It uses the
existing research organization and billing account. Compute Engine, IAP, and
OS Login APIs are enabled; experiments create their own restricted VPCs.

Retain aggregate research evidence in `gs://sovright-oram-research-evidence`
(`us-central1`), which enforces public-access prevention and uniform
bucket-level access. The [recovered mainnet capture ledger](../../docs/notes/oram-mainnet-capture-recovery.md)
records the first retained bundle and its integrity checks.

Historical resources remain where their manifests and ledgers record them.
The mainnet capture and builder are in `sovright-testnet`; the completed small
TDX diagnostic was in `sovright-bedrock-mainnet`. Changing the project for new
runs does not move those disks, restart the historical TDX VM, or qualify its
image. Do not rewrite a historical manifest to target the new project.

The experiment uses `c3-standard-4` in `us-central1-a`: the smallest C3 type
currently exposed there, with 4 vCPUs and 16 GiB RAM. The separate mainnet
capacity candidate remains `c3-standard-44` with 44 vCPUs and 176 GiB.

The boot image is pinned by immutable name and checked numeric ID:

```text
projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20260906
image ID: 6257327608773510097
created: 2026-09-06T03:15:26.996-07:00
features include: TDX_CAPABLE, UEFI_COMPATIBLE, GVNIC, IDPF
```

Re-run the read-only image-ID check immediately before creation. A mismatch
fails the script rather than following the image family.

## Isolation and access

The scripts create a dedicated custom-mode VPC, one `/28` subnet, and one
ingress rule scoped to the experiment's network tag. The rule permits TCP 22
only from Google's IAP TCP-forwarding range `35.235.240.0/20`. The guest has no
external IP, no service account, no OAuth scopes, no Private Google Access, no
Cloud NAT, and no application listener. Existing networks, routes, firewall
rules, instances, and service accounts are untouched.

Administrative access uses IAP plus OS Login. Project SSH keys are blocked.
The operator running `connect-iap.sh` must already have the required IAP tunnel
and OS Login IAM grants; these scripts grant no IAM roles and copy no
credentials. `gcloud compute ssh` can publish the caller's OS Login SSH key and
must only be run as part of an authorized experiment.

The native ORAM workflow retains an `oram-native-build-<run>-<attempt>` artifact
only after the native job's tests and release code-generation checks succeed;
the parallel private-client matrix jobs remain separate checks. It contains
the exact checked Linux x86_64 `zainod-oram`, lockfile, tool version reports,
ELF interpreter/dynamic-linkage report, `build.json`, and `SHA256SUMS`. The
packager refuses the listed ambient compiler, target, and release-profile
overrides in its source. The version reports identify available tools, not a
complete hermetic compiler/dependency closure. Verify all hashes after download and record the
artifact/run identities in the experiment manifest before transfer. The source
commit is the actual checked-out commit (which may be a PR merge commit), not an
assumed PR head. The artifact expires after 30 days; retain the selected bundle
in the dedicated project's private evidence bucket for a recorded experiment.
Check the ELF interpreter and required libraries against the destination image;
the executable is not asserted to be self-contained. This is unsigned CI build
identity, not reproducibility, accepted-image policy,
hardware attestation, or evidence that the executable ran inside TDX.

The guest cannot download packages or source. Transfer only the reviewed
release artifact, verifier challenge, and collection script through
`gcloud compute scp --tunnel-through-iap`; record their SHA-256 digests before
and after transfer. Return only the quote/evidence envelope and aggregate host
facts. Do not transfer Zaino production configuration, validator credentials,
wallet data, or recovery inputs.

## Lifetime and cost bound

The VM is on-demand and requests a `6h` maximum run duration with termination
action `DELETE` and automatic restart disabled. Run the
teardown script after evidence retrieval rather than relying on the deadline.
Compute Engine recalculates a max-run-duration deadline after a manual
stop/start, so the experiment procedure forbids restarting the instance; a
restart requires teardown and a newly reviewed run.

At the current Iowa list rates, `c3-standard-4` is $0.201608/hour and the Intel
TDX surcharge is $0.0033982 per vCPU-hour plus $0.0004555 per GiB-hour. The VM
therefore costs approximately $0.2225/hour, or $1.34 for the six-hour maximum.
A 30-GiB balanced boot disk, IAP traffic, logging, and any network egress are
additional; with no external IP or NAT and only small evidence transfers, use
`$2.00` as the experiment's review budget. Pricing can change, so refresh the
official price sheets before execution.

- [C3 pricing](https://cloud.google.com/products/compute/pricing/general-purpose)
- [Intel TDX surcharge](https://cloud.google.com/confidential-computing/confidential-vm/pricing)
- [VM runtime limit](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)

## Review and execution

Creation is intentionally a separate, reviewable step:

```console
./deploy/tdx/create-experiment.sh <NEW_LOCAL_RUN_DIR>
```

The script generates unique per-run names, records successful creates and
immutable resource IDs in a local manifest, creates the isolated resources,
then makes `verify-cloud-config.sh` assert the intended policy.

- `confidentialInstanceType: TDX`;
- `c3-standard-4`, maintenance `TERMINATE`, no automatic restart, and the
  six-hour delete deadline;
- no access configuration/external IP and no service account;
- NVMe balanced boot disk with auto-delete;
- Secure Boot, vTPM, and integrity monitoring enabled; and
- the single firewall rule has only the IAP source, TCP 22, and experiment tag.

After authorized IAP access, verify inside the guest before transferring or
running the workload:

```console
test -r /sys/firmware/acpi/tables/data/CCEL
test -d /sys/kernel/config/tsm/report
dmesg | grep -i 'tdx\|confidential'
uname -a
lscpu
grep -E 'MemTotal|SwapTotal' /proc/meminfo
findmnt -no SOURCE,FSTYPE,OPTIONS /
```

Generate each quote from a fresh verifier-owned 64-byte challenge. The
workload's canonical versioned transcript must bind that challenge to the
actual TLS peer key owned by the same process; do not substitute the existing
certificate-DER fingerprint for a SubjectPublicKeyInfo binding. Write the
64-byte transcript digest to ConfigFS `inblob` and retrieve `outblob` as
documented by Google's
[TDX provenance procedure](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance).

Once the workload/verifier has produced that exact 64-byte transcript digest,
collect one raw evidence bundle through IAP:

```console
./deploy/tdx/collect-quote-iap.sh \
  <RUN_DIR/manifest.json> \
  <REPORT_DATA_64_BYTE_FILE> \
  <NEW_LOCAL_EVIDENCE_DIR>
```

The helper validates the input width, transfers only the report data and fixed
collector, creates a new guest evidence directory, retrieves the quote, CCEL,
public guest facts and checksums, and verifies those checksums locally. It does
not construct the transcript, run a verifier, or decide acceptance.

Use pinned `gceprovenance` only to cross-check Google host and instance
provenance and basic quote signature/challenge handling. It does not perform a
complete TCB, CRL, RTMR/event-log, workload-measurement, or application-policy
decision. The independent client verifier must enforce verifier-owned expected
measurements and PZID, current Intel collateral and revocation state, CCEL/RTMR
policy, debug rejection, transcript/TLS-key equality, nonce single use and
expiry, and receipt audience/profile/key-epoch bindings. Nonce freshness does
not prove persistent state freshness; the external witness remains responsible
for rollback and epoch acceptance.

Always tear down explicitly:

```console
./deploy/tdx/teardown-experiment.sh <RUN_DIR/manifest.json>
```

Teardown checks recorded immutable IDs and run ownership before deleting the
recorded instance, its known boot disk, firewall rule, subnet, and network.
Evidence must be copied out and hashed first; the package creates no snapshot.
