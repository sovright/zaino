# Offline workload build boundary

The first stage builds the GNU `tdx-evidence-agent` from the explicitly frozen
guest-confinement source commit `314b80ac1be55f0fb763587427f817d96c6803a1`,
which intentionally differs from the builder workflow commit, and records its complete
interpreter and shared-library closure on two independent Linux runners. The
selected Ubuntu OCI image executes with container networking disabled. Exact
Rust archives, authenticated workload-tool packages, the reviewed Git export,
Cargo lock, vendor file set, Cargo replacement config, builder scripts, and
outputs are retained in the run receipts.
`OUTPUT-SHA256SUMS` covers every other regular output, including the build-run
receipt and `OUTPUT-MODES.tsv`; consumers must verify both content and mode
manifests before copying the agent or runtime library closure.
The canonical runtime closure records each installed path, mode, and content
digest and is compared across runners. Raw `ldd` output and the linker map are
retained and individually hashed as diagnostics, but excluded from the
cross-runner equality check because they can contain ASLR addresses and
temporary linker paths. Small input identities remain resolvable through the
checked-in source and the hashes in `build-run.json`; their contents are not
copied into the uploaded output artifact.

The canonical retained vendor transport input is
`gs://sovright-oram-research-evidence/build-inputs/cargo-vendor/2fdeef5bb015c4f4b86867d07768e0e16b1592b20a576cbe7e3ccec8264477cb/`.
Its `vendor.tar.gz` is 189,862,954 bytes with SHA-256
`68cee248b20487524b29c53fa17cfe099584e439c8dc6502c1408d6ee9ef2a79`.
The retained directory also contains the file manifest, retention provenance,
Cargo lock, and original absolute-path config. That config is capture metadata;
the builder verifies cargo-vendor's source mappings and replaces only its local
directory with the fixed `/inputs/vendor` mount.

This stage deliberately does not emit `tdx-guest-init`. The init embeds the
exact root-image byte geometry, dm-verity UUID, and kernel command-line digest.
It can only be built after deterministic root construction freezes a reviewed
image-binding artifact. The intermediate agent output is not an image, boot
candidate, accepted guest, signature, attestation result, or TEE qualification.
