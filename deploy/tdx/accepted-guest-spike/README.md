# Accepted-guest spike inputs

`upstream-selection.json` freezes the first upstream inputs for the
[reviewed boot spike](../../../docs/notes/oram-c3-no-secrets-boot-spike-plan.md).
It is deliberately a **partial upstream lock**, not the complete `inputs.json`
required by that plan. It cannot authorize image assembly, import, or admission.

The Ubuntu 24.04 amd64 root filesystem is the dated `release-20260826` artifact.
Its 228,994,404 downloaded bytes matched the retained signed checksum manifest.
The signature verified against fingerprint
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, published in
[Ubuntu's verification instructions](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/).
The stock root filesystem still contains administration and update software;
it is an input to the required removal and filesystem verification work.

The builder **base** is the selected Linux amd64 OCI manifest, referenced by
digest rather than the discovery tag. Retained raw manifests reproduce the
index-to-platform selection and content hashes. This verifies content identity
over public-registry HTTPS, not a publisher signature or a complete builder.
The final builder recipe, tools, and resulting image digest remain unpinned.

The [dated Ubuntu snapshot](https://snapshot.ubuntu.com/ubuntu/20260911T000000Z/)
has retained release metadata for noble, noble-updates, and noble-security.
All three archive signatures verified with the Ubuntu archive keyring extracted
from the verified root filesystem, under fingerprint
`F6ECB3762474EDA9D21B7022871920D1991BC93C`. The keyring is retained with the
metadata. This is a frozen historical snapshot, not a current-security-update
claim. The exact package closure, kernel configuration, and TDX compatibility
remain unverified; no package has been admitted by selecting this snapshot.

Run the read-only integrity check from this directory:

```sh
bash verify-upstream-selection.sh
bash verify-upstream-selection.sh /path/to/ubuntu-24.04-server-cloudimg-amd64-root.tar.xz
```

The optional argument also verifies downloaded root filesystem bytes. Neither
form downloads, extracts, executes, or builds the selected software. GnuPG uses
a temporary isolated public keyring. The second builder, Rust/vendor closure,
kernel/package pins, evidence agent, diagnostic client, offline signing inputs,
and deterministic filesystem/image settings remain explicit prerequisites.

`package-roots.json` freezes candidate guest-kernel roots separately from
builder tools. `resolve-package-closure.sh NEW_DIRECTORY` runs only on Linux
amd64 with the pinned APT version and an empty private APT state. It admits
indexes and packages only when their lengths and SHA-256 digests match the
retained signed snapshot metadata, downloads without installing, and emits a
canonical lock. `verify-package-closure.sh DIRECTORY` rechecks that closure
offline. The offline verifier authenticates package membership and bytes
against the retained signed indexes and requires every requested root; it does
not recompute the dependency graph. The pinned APT solve produces that graph,
and equal locks from two fresh runs show resolver determinism for those inputs.
Neither result establishes kernel suitability or image acceptance.
The current CI invokes APT 2.8.3 directly on GitHub's `ubuntu-24.04` runner;
it does not execute inside the selected OCI builder base and is not a hermetic
builder-identity claim.

The selected stock Linux 6.17 GCP kernel is a deliberate negative candidate.
Its package config contains the required TDX guest, ConfigFS TSM, GVE, NVMe,
SWIOTLB, EFI-stub, and dm-verity settings, but it also enables policy-prohibited
debug-kernel, kexec, hibernation, and sleep settings. The static
`verify-kernel-config.sh` gate therefore refuses it. `CONFIG_DEBUG_KERNEL` is
separate from the TDX DEBUG guest attribute. An acceptable custom kernel,
source/config/package digests, and review of the required TDX halt fixes remain
prerequisites.

`custom-kernel-tool-roots.json` is a separate builder-only request for the
compiler, binutils, Kbuild utilities, source extractor, and development
libraries. Its OpenSSL command and development packages are confined to the
network-disabled disposable kernel builder; they are not Zaino Rust/runtime or
guest-image dependencies. This scoped builder use does not relax the repository
ban on OpenSSL crates or OpenSSL packages in shipped runtime images.

`download-custom-kernel-source.sh` downloads only the three archives bound by
the retained signed source index. `build-custom-kernel-once.sh` then accepts
that directory, an offline closure resolved from `custom-kernel-tool-roots.json`,
the reviewed `custom-kernel.config`, a `run-1` or `run-2` label, and a new
output directory. It executes the selected OCI digest with networking disabled,
checks the installed package and compiler versions, extracts the authenticated
source, verifies the effective Kconfig, and builds `bzImage` and `vmlinux`.
The CI workflow runs this front door on two separate clean runners and compares
their artifact hashes. Matching builds establish this build-input experiment;
they do not establish boot, TDX, image-admission, or runtime suitability.
The builder marks its private `file:` APT repository as trusted only because
the outer gate has already authenticated every retained package against the
signed snapshot indexes. That adapter is not a new package-signature claim and
does not permit another source or network download.
