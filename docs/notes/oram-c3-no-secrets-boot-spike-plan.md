# Minimal C3 TDX no-secrets boot spike

Status: executable implementation plan only. No image has been built, imported,
booted, measured, or approved. No cloud action is authorized by this document.
The spike carries public test data only and cannot establish private Zaino or
ORAM access-pattern privacy.

This is the smallest experiment that can resolve the feasibility questions in
the [accepted guest design](oram-accepted-guest-design.md) and
[C3 lifecycle review](oram-c3-tdx-lifecycle-freshness-review.md): whether one
offline-signed, single-profile UKI plus a fully verified dm-verity root boots on
Google C3 TDX with Secure Boot, whether its complete boot inputs map stably into
QuoteV4 MRTD/RTMRs and strict CCEL replay, and whether evidence remains available
after the guest drops administration capabilities.

## Frozen inputs

Create `deploy/tdx/accepted-guest-spike/inputs.json` in the implementation PR.
The build front door must reject a missing field, a mutable tag/family/channel,
or a digest mismatch before creating an output directory. Its first reviewed
instance pins:

| input | required pin for the first spike |
|---|---|
| source | Zaino commit `821e6477` or a reviewed descendant containing only the spike package |
| Rust | `1.96.0`, matching `rust-toolchain.toml`; exact `rustc -vV` and target component hashes recorded |
| Cargo | repository `Cargo.lock`; `cargo build --locked --offline` after a separately hashed vendor step |
| builder | Linux amd64 OCI image by registry digest, never a tag; Dockerfile/Containerfile SHA-256 recorded |
| base rootfs | Ubuntu 24.04 amd64 cloud/rootfs artifact by immutable URL, byte length, SHA-256, and signed release-manifest identity |
| packages | one dated Ubuntu snapshot URL plus exact package name/version/architecture and `.deb` SHA-256 list; network disabled during assembly |
| kernel | one Linux `>=6.6` package and exact config/source/package digest containing GVE, PCI MSI, SWIOTLB, NVMe, dm-verity, TDX guest/configfs-tsm, and required TDX halt fixes |
| boot | exact `systemd-boot`/`systemd-stub`, `ukify`, initramfs builder, EFI tools, verity tools, and signing-tool package digests |
| Secure Boot | offline spike PK/KEK/db/dbx certificate fingerprints; private signing key path supplied out of band and never copied into build output |
| workload | fixed public evidence-only binary digest; no Zaino keys, wallet data, credentials, operator shell, updater, or workload downloader |
| machine | `c3-standard-4` for feasibility only, one 20-GiB balanced NVMe boot disk, exact supported zone selected at execution review |

The first [upstream selection](../../deploy/tdx/accepted-guest-spike/README.md)
now pins a dated root filesystem, signed snapshot release metadata, and the
amd64 builder base manifest. Its verifier checks retained signatures and
digests, with optional downloaded-rootfs verification. It is not a complete
build input manifest: the exact kernel/package closure, final builder recipe
and digest, workload binaries, and signing certificate fingerprints remain
unresolved. Completing and reviewing those values is implementation step zero.
The build must not silently resolve
“latest,” an image family, a package mirror head, or an unversioned Git branch.

Reproducibility inputs also pin `SOURCE_DATE_EPOCH`, GPT and filesystem UUIDs,
dm-verity salt, empty/reset machine-id treatment, file/archive order, numeric
ownership and modes, locale/timezone, compression parameters, and a
deterministic signing procedure. Builder identity, timestamps of the build
operation, and host diagnostics live in separate provenance receipts; they
must not be embedded in artifacts whose byte identity is compared.

## Build package

The minimum deployment package adds these reviewable files, plus the named
evidence-agent and diagnostic-client implementation prerequisites below:

```text
deploy/tdx/accepted-guest-spike/
  README.md
  inputs.json
  verify-inputs.sh
  build-rootfs.sh
  build-uki.sh
  assemble-image.sh
  verify-artifacts.sh
  negative-tests.sh
  rootfs-files.txt
  kernel.config.required
  evidence-agent.service
  evidence-agent.policy
```

`tools/tdx-evidence-agent` is a required new Rust package and explicit build
target for this spike; it does not exist at this planning head. Its source,
dependency closure, Cargo feature set, binary digest, and tests must be reviewed
before `inputs.json` can become complete. A digest field cannot stand in for
that missing implementation.
`tools/tdx-boot-spike-client` is the corresponding required diagnostic consumer.
It owns the TLS stream and challenge, validates the dedicated transcript, runs
the strict quote-plus-CCEL verifier, and emits only the dedicated diagnostic
receipt. The existing retained Zaino client rejects this scope by design.

Scripts use `set -euo pipefail`, a new mode-0700 output directory, regular-file
and no-symlink input checks, byte caps, and explicit tool-version checks. They
never read cloud credentials. `verify-inputs.sh` hashes every local input before
any build. `build-rootfs.sh` assembles from the pinned package directory with
network disabled and removes shells, SSH, guest agent, OS Login, package/update
services, getty/emergency targets, compilers, debuggers, kexec, core dump
handlers, metadata consumers, and persisted random seeds.

`build-uki.sh` creates exactly one UKI profile containing the kernel, fixed
command line, initramfs, OS release, and dm-verity root hash. The ESP allowlist
contains that UKI and required firmware files only. It rejects companion
credentials, sysext/confext files, addons, alternate profiles, extra initrds,
and microcode fragments. `assemble-image.sh` creates one GPT image with one ESP
and one read-only verity root. Writable runtime paths are tmpfs. There is no
swap or hibernation image.

The evidence-only PID 1 path performs a bounded full read of the verity-protected
root, waits for blocking OS randomness, generates a fresh TLS key and lease ID,
starts the fixed ConfigFS quote worker/evidence RPC, applies its final mount,
device, syscall, capability, and no-new-privileges policy, and only then opens
the private listener. The RPC accepts one 64-byte public challenge and returns
only bounded QuoteV4 bytes plus the fixed CCEL table/log. It exposes no path,
command, upload, metadata, log, shell, key-export, or general file-read method.

This diagnostic RPC uses a separate transcript domain and receipt scope from
Zaino's evidence v1. For an exact 64-byte client challenge, the agent requests:

```text
REPORT_DATA = SHA-512(
  u16be(len("ZAINO-BOOT-SPIKE-EVIDENCE-V1")) ||
  "ZAINO-BOOT-SPIKE-EVIDENCE-V1" ||
  u16be(64) || challenge ||
  u16be(32) || SHA-256(server TLS identity SPKI DER) ||
  u16be(32) || boot_local_lease_id
)
```

All lengths are bytes and every integer is unsigned big-endian. The server
hashes its own retained ephemeral TLS identity used by the listener. The client
owns the fresh challenge, independently derives the same SPKI from the actual
peer certificate on its retained TLS stream,
requires the returned public lease ID to be exactly 32 bytes, recomputes the
transcript, and verifies the quote before accepting the diagnostic result. The
agent creates one TLS key and lease ID after CSPRNG readiness and uses them for
that boot only. Reconnect, response cancellation, or transcript mismatch ends
the attempt. The receipt scope is
`tdx_boot_spike_quote_ccel_diagnostic_v1`, which the production retained-Zaino
client must reject. This proves diagnostic channel/lease binding only; it has
no Zaino binary/config/profile/checkpoint fields and grants no query admission.

## Local gates before cloud review

Run twice on independent clean builders:

```console
./verify-inputs.sh inputs.json
./build-rootfs.sh inputs.json out-a
./build-uki.sh inputs.json out-a
./assemble-image.sh inputs.json out-a
./verify-artifacts.sh inputs.json out-a
```

The second builder writes `out-b`. Approval to import is blocked unless
`verify-artifacts.sh` proves byte-identical workload binary, root filesystem,
verity tree/root, UKI, ESP, disk image, SBOM, file/capability manifest, and
release manifest. It must also prove:

- one UKI profile and no companion/addon/alternate boot inputs;
- kernel config contains every required setting and no debug/kexec/hibernation
  setting selected by policy;
- root filesystem has no forbidden executable, service, socket, writable
  executable path, setuid/setgid file, device node, persisted key/seed, or
  metadata consumer;
- dm-verity covers every root block and the pre-listener sweep reads all of
  them;
- signing-key material and build/cloud credentials do not occur in the image,
  logs, SBOM, or manifest;
- the final manifest contains SHA-256 for every artifact and the expected
  Zaino binary/config/profile fields remain explicitly “not present” for this
  evidence-only spike.

`negative-tests.sh` performs offline checks only. It mutates one root block,
verity-tree block, UKI/signature byte, manifest field, ESP filename, addon,
companion file, and alternate profile in separate copies and requires the
corresponding signature, verity, allowlist, or input-framing verifier to reject
each one. A known-good unmodified artifact must pass each local verifier first.
The local environment has no TDX quote provider, so these tests cannot claim
listener refusal or MRTD/RTMR changes. QEMU or vTPM PCR results cannot substitute
for hardware TDX RTMR evidence. Root-data runtime refusal is tested later on C3
and is valid for every root byte only after the full pre-start verity sweep;
otherwise it proves refusal only when a corrupted block is read.

## Later bounded cloud execution

After separate approval, import the byte-identical disk into the dedicated
`sovright-oram-research` project with `TDX_CAPABLE` and `UEFI_COMPATIBLE`, the
reviewed PK/KEK/db/dbx, and record the immutable image ID. Adapt the existing
per-run-owned `deploy/tdx` scripts rather than editing shared networks or IAM.
The instance has TDX, Secure Boot, vTPM, integrity monitoring, one balanced NVMe
boot disk, `onHostMaintenance=TERMINATE`, `automaticRestart=false`, no service
account, no external IP, no SSH/IAP/serial rule, and no metadata beyond the
three non-executable control flags already reviewed.

A separately owned no-secrets verifier endpoint obtains the evidence over the
private listener. It runs full QuoteV4/current-collateral/closed-field policy
and strict CCEL replay, records cloud assertions separately, and never derives
an allowlist from the received quote. First-boot measurements are diagnostic.
Only repeat clean boots of the same immutable image on the selected C3 target,
plus a documented component-to-MRTD/RTMR map and independent build agreement,
can nominate verifier-owned candidate measurements for review.

Cloud negative gates must cover Secure Boot off, changed image/disk ID, extra
disk, metadata, service account, NIC/firewall, restart/maintenance policy,
DEBUG/MIGRATABLE quote bits, CCEL reorder/mutation, stop/start, reset, attempted
suspend, and disk snapshot/custom-image/machine-image clone. Stop/start and
clone must generate new TLS SPKIs and lease IDs. A fresh client rejects old
evidence, receipts, sessions, and tokens. External authorization/checkpoint
freshness remains required; the guest clock and a guest-checked signed expiry
do not solve pause or rollback.

Every C3 negative begins with an unmodified same-build positive control that
boots, completes the verity sweep, returns a transcript-matched QuoteV4 and
CCEL, and passes strict diagnostic verification. Only then can the separately
mutated image establish Secure Boot/listener refusal or a specific quoted
MRTD/RTMR/CCEL change.

## Exit criteria

The spike passes only if the custom signed image boots with Secure Boot on,
verity and full-read gates complete, evidence works after capability drop,
strict CCEL replay matches every quoted RTMR including zero-event lanes,
identical clean boots meet a reviewed stability rule, and every negative gate
refuses at the claimed cloud, boot, quote, or client boundary. Passing qualifies
only the boot-chain candidate. Adding Zaino, the production ORAM corpus,
accepted image policy, trusted-time/replay witness, physical access-pattern
measurements, and full-service RTO remains separate reviewed work.
