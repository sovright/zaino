# Accepted Zaino TDX guest design

Status: design and negative-gate specification only. It does not approve an
image, derive an allowlist from a received quote, or authorize a cloud build or
deployment.

## What the retained diagnostic established

The run-3 guest booted the pinned public Ubuntu image
`ubuntu-2404-noble-amd64-v20260906` (image ID
`6257327608773510097`) as a private C3 TDX VM. Cloud-side checks required TDX,
Secure Boot, vTPM, integrity monitoring, no service account, one boot disk, no
external IP, and disabled serial-port access. The retained 8,000-byte QuoteV4,
64-byte challenge, and CCEL hashes match the recorded ledger:

| artifact | SHA-256 |
|---|---|
| `quote.bin` | `6385dfeba9b6c48ce175682add1458ca20ed9102a0620e351b6d70185eea7c35` |
| `report-data.bin` | `e7ea0e4b9c03dfbfe5b7bd97bab9c681079ea4e9262b82bf1e252b3fb49d4991` |
| `ccel.bin` | `71c67bb8d325c3adf02d6b207cb6a76248a4d117e57386661de2c4a4b08c7e00` |

That VM deliberately enabled OS Login and an IAP TCP/22 path. An administrator
could enter the guest as root, replace or debug Zaino, inspect its memory, or
cause it to issue evidence for operator-chosen state. The quote proves neither
that Zaino was the workload nor that guest administration was absent. The VM
and owned resources were deleted; `teardown-verified.txt` records cleanup.

Google documents TDX as protecting data in use while leaving availability and
resource lifecycle with the cloud control plane. This design intends to isolate
guest plaintext and query contents only if the measured-boot and guest-admin
closure is implemented and independently accepted. Access-pattern privacy
remains a separate, currently unqualified ORAM gate. The design cannot prevent
stop, delete, traffic denial, or rollback attempts by a sufficiently privileged operator.
[Confidential VM overview](https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview)

## Required guest and control-plane shape

The accepted artifact is one immutable, numeric-ID-pinned custom image built
from reviewed source and package inputs. It boots directly into a fixed Zaino
service and has no general administration path:

- no SSH server, authorized-key parser, OS Login components, serial console,
  emergency shell, getty, debug kernel command line, kexec, ptrace, core dumps,
  or package manager in the runtime image;
- no Google guest agent or other component that executes startup scripts,
  shutdown scripts, user-data, or arbitrary instance/project metadata;
- no service account, access scopes, attached secrets, guest attributes,
  metadata-provided configuration, or workload download at boot;
- no external IP or inbound firewall rule. The sole listener is the fixed-size
  private-query TLS service on a private interface. A separate approved client
  reachability design remains required; opening it is not part of image
  acceptance;
- read-only verified root, read-only executable/configuration, and writable
  `tmpfs` for ephemeral runtime state. Any durable ORAM volume contains only
  public-chain-derived/authenticated material and is mounted with `nodev`,
  `nosuid`, and `noexec` after its format and identity are checked;
- Zaino generates the TLS private key and per-lease key material inside the TDX
  guest after boot and never logs or persists it. The TLS private key and
  token/replay keys have no export path. ADR 0904 deliberately releases the
  request/response envelope keys to an admitted client over the retained,
  attested TLS stream; no admin RPC can retrieve them. Crash or reboot destroys
  the guest copies;
- PID 1 starts only the verifier-rooted mount setup and Zaino, applies a closed
  syscall/capability/device policy, then removes all ambient capabilities. A
  fatal integrity, configuration, entropy, clock, quote-provider, or state
  error leaves the query port closed.

Cloud creation must invert the diagnostic settings: omit the IAP SSH firewall,
set `enable-oslogin=FALSE`, retain `block-project-ssh-keys=TRUE` and
`serial-port-enable=FALSE`, and reject every other project or instance metadata
key. No guest component may consume even these three control-plane flags as
executable code or workload configuration. The accepted-image verifier must inspect actual
returned metadata, service accounts, disks, network interfaces, scheduling,
Shielded settings, and immutable image/disk IDs. Google describes startup
scripts as metadata-delivered code, so merely disabling SSH does not close the
administrator path.
[Startup scripts](https://cloud.google.com/compute/docs/instances/startup-scripts/linux),
[VM metadata](https://cloud.google.com/compute/docs/metadata/overview),
[Shielded VM](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm)

## Build and boot proposal

1. Freeze the Zaino commit, Cargo lockfile, Rust version, target, linker,
   release flags, enabled features, ORAM profile, protobuf output, base-package
   snapshot, kernel, firmware-facing boot components, and build-container
   digest in a reviewed release manifest. Build twice on independent clean
   builders and require identical Zaino binary, root filesystem, verity root,
   UKI, disk image, and SBOM digests. A reproducibility mismatch is a release
   failure.
2. Construct a minimal GPT image with an EFI System Partition, a read-only
   root filesystem, its dm-verity hash tree, and no mutable boot/config
   partition. Put the kernel, initramfs, fixed command line, OS release, and the
   dm-verity root hash in one Unified Kernel Image so these inputs cannot be
   independently substituted. `systemd-stub` defines the UKI sections and
   systemd's verity generator supports a root hash supplied from authenticated
   boot material.
   [systemd-stub](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html),
   [systemd-veritysetup-generator](https://www.freedesktop.org/software/systemd/man/latest/systemd-veritysetup-generator.html),
   [dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html)
   Configure exactly one UKI profile. The ESP contains no companion credential,
   system-extension, configuration-extension, addon EFI, alternate profile, or
   extra initrd/microcode input, and the guest contains no consumer for those
   extension mechanisms. Earlier boot stages must also be unable to append an
   initrd or command-line fragment. `systemd-stub` documents these automatic
   companion/addon inputs, so signing the primary UKI alone is insufficient.
3. Sign the boot artifact with an offline release key after reproducibility and
   review. Do not place that key, cloud credentials, or update credentials in
   the image or builder output. Publish the manifest, SBOM, signatures, image
   digest, and expected event-log replay inputs as release artifacts.
4. Import the disk as a custom Compute Engine Confidential VM image carrying
   the required TDX guest support: Linux 6.6 or newer, GVE, PCI MSI, SWIOTLB,
   NVMe boot drivers, UEFI compatibility, and the `TDX_CAPABLE` guest OS feature.
   Record the returned image
   numeric ID and source disk digest; deployment accepts those exact values,
   never a family or mutable name.
   [Custom Confidential VM images](https://cloud.google.com/confidential-computing/confidential-vm/docs/create-custom-confidential-vm-images),
   [Guest OS features](https://cloud.google.com/compute/docs/images/create-delete-deprecate-private-images#guest-os-features),
   [Confidential VM OS support](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-operating-systems)
5. Boot with TDX, `TERMINATE` maintenance, restart disabled, Secure Boot, vTPM,
   integrity monitoring, one known NVMe boot disk, no service account, and the
   closed metadata/network policy above. Resumed-memory snapshots are forbidden.
   Disk snapshot/restore remains forbidden until a verifier-owned monotonic
   state/rollback design exists.
6. Replay the CCEL and require its result to equal verifier-owned expected RTMR
   values for the signed release. Verify QuoteV4 signature, current collateral
   and revocation status, TDX type/vendor/attributes, platform TCB, MRTD and all
   RTMRs, then the v1 REPORT_DATA binding to the exact binary/config/profile,
   fresh challenge, and actual TLS peer SPKI. Expected values come from the
   reviewed release manifest and independently reproduced boot evidence, never
   from the guest being evaluated.
   Produce a reviewed component-to-register map showing how firmware,
   bootloader/UKI profile, kernel, initrd, command line, verity root, and fixed
   configuration affect quoted MRTD/RTMR values and the CCEL. systemd's
   documented PCR11/12/13 behavior is vTPM evidence and must not be assumed to
   reach TDX hardware RTMRs. vTPM PCR/event-log agreement cannot substitute for
   QuoteV4 RTMR and CCEL validation.
   [TDX measurement register contents](https://cloud.google.com/confidential-computing/confidential-vm/docs/measurement-register-contents)
7. Release query/bootstrap authority only over the retained TLS stream after
   quote acceptance and strict owner-derived bootstrap-context validation.
   Any reconnect starts with a new OS-generated 64-byte challenge and a new
   verification attempt.

## UKI and dm-verity feasibility on the selected target

The storage and kernel mechanisms are feasible in a Linux guest. Google
documents custom Shielded-image key enrollment through the `pk`, `kek`, `db`,
and `dbx` image-signature flags, with unspecified databases receiving Google
defaults. This does **not** yet establish that the resulting project-signed UKI
boots on the exact C3 TDX target, nor that its complete event sequence is stable
and documented enough for an RTMR allowlist.
[Creating Shielded images](https://cloud.google.com/compute/shielded-vm/docs/creating-shielded-images)
Stock
distro-signed shim/kernel may boot, but a mutable initramfs, command line, or
root hash would fail the accepted-image requirement.

Therefore the UKI/verity design is a bounded feasibility candidate, not the
selected production path. Before building the Zaino image, perform an isolated
no-secrets boot spike using the exact C3 TDX machine family and zone. It must
show: the enrolled offline-signed UKI is accepted with Secure Boot on; root verity is
enforced; a bounded full read of every verified root block completes before the
query listener opens, so changing any root byte prevents service start (without
that sweep, tests may claim only refusal when a corrupted boot/workload block is
later read); CCEL replay exactly
reproduces all quote RTMRs; and repeated clean boots of the identical image
produce the policy-defined stable measurements. If exact C3 TDX boot or stable
measured boot cannot be established from documented interfaces, reject
this path and evaluate a Google-supported signed boot chain plus an explicitly
measured immutable payload mechanism. Do not weaken Secure Boot or accept
measurements copied from the first successful guest.

The spike must also prove that the production quote path still works after PID
1 applies the final capability, device, mount, and syscall restrictions. Define
before boot a bounded evidence RPC that accepts only one fresh 64-byte
challenge, reads ConfigFS through the least-privileged fixed quote worker,
returns only the capped quote, fixed public CCEL ACPI table and event-log
artifacts, and public evidence
fields, and has no shell,
arbitrary path, command, upload, or debug operation. The diagnostic IAP
collector is not an acceptable production collection path.
The CCEL response has a fixed method, separate bounded byte lengths, validated
table format/checksum and declared log length, and no caller-supplied path so a
verifier can replay it independently. Both the ACPI table and event-log area
are required: the diagnostic retained only the latter. Register replay matches
event digests to quote RTMRs; an additional verifier-owned, type-aware event
policy must establish the accepted boot-component semantics.

## Required artifacts before approval

- reviewed threat model naming project administrators, Google control plane,
  guest root, build-system compromise, rollback, denial of service, and traffic
  observation;
- two-builder reproducibility records and complete source/package/toolchain
  provenance;
- signed release manifest, SBOM, Zaino binary/config/profile digests, UKI and
  disk digests, verity root, image numeric ID, and signing-key fingerprint;
- exact expected MRTD/RTMR/PZID and TDX attribute policy with a documented CCEL
  replay procedure and current Intel collateral policy;
- source audit proving removal of SSH, guest agent, metadata execution, shells,
  package/update services, crash/core capture, key persistence/export, and
  runtime code loading;
- immutable cloud manifest and verifier that fail closed on any unexpected
  metadata, account/scope, disk, NIC, firewall, scheduling, image-ID, or
  Shielded/TDX field;
- key-lifecycle analysis and tests showing the TLS private key and token/replay
  keys never cross the guest boundary; request/response keys cross only in the
  admitted ADR-0904 bootstrap response; all guest-held keys disappear on
  termination and are absent from logs, dumps, snapshots, and evidence;
- rollback design for any security-relevant persistent state. Until it exists,
  the accepted service must treat boot as a new lease and must not claim state
  freshness beyond the public finalized checkpoint bound in evidence/bootstrap.

## Mandatory negative gates

Acceptance requires automated evidence for every refusal below:

1. SSH, IAP TCP/22, serial console, getty, recovery/emergency shell, debug
   kernel, kexec, ptrace, core dump, guest agent, startup script, user-data,
   project SSH key, service account, or metadata outside the three exact
   control-plane flags is present.
2. The operator changes the binary, UKI, initramfs, kernel command line,
   dm-verity root, root filesystem byte, configuration, profile, image ID,
   signing key, Secure Boot setting, TDX type, debug/migratable attribute,
   firmware/TCB, MRTD, any RTMR, or CCEL event/order.
   Adding or renaming an ESP companion credential, sysext/confext image, addon
   EFI file, extra initrd/microcode, or alternate UKI profile must also prevent
   admission, even when the primary UKI file is unchanged.
3. Cloud preflight refuses an attached extra disk, replaced/restored/snapshotted
   boot or state disk, automatic restart/live migration, changed NIC/firewall,
   or boot-time workload/configuration URL when those facts are visible through
   the control-plane API. These are mutable provider assertions, not quote
   measurements; a client must not treat them as cryptographic attestation or
   assume an unobservable post-launch change is bound into REPORT_DATA.
4. The guest attempts outbound credential/metadata access, opens an admin
   listener, writes executable persistent state, exports the TLS private key or
   token/replay keys, releases envelope keys outside admitted bootstrap, emits secret
   bytes to logs/core dumps, or retains a prior lease key across reboot.
5. Quote collateral is missing, stale, revoked, or not UpToDate; the challenge,
   TLS SPKI, binary/config/profile/schema/key epoch, finalized checkpoint, or
   bootstrap context differs; the connection is retried/reconnected after
   evidence; or policy input is absent/unknown/duplicated.
6. Repeated identical-image boots do not match the documented measurement
   stability rule, CCEL replay does not reproduce the quote RTMRs, or a
   verifier cannot trace every accepted value to the reviewed release manifest.
   Admission also fails if the component-to-MRTD/RTMR/CCEL map cannot
   demonstrate coverage of the initrd, verity root, and fixed configuration, or
   if evidence relies only on vTPM PCRs.

Passing these gates would support an accepted-image experiment. It would still
not prove ORAM physical obliviousness, mainnet capacity, rollback resistance,
availability, or protection from malicious code intentionally approved in the
release manifest.
