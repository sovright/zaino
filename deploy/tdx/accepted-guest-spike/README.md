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
