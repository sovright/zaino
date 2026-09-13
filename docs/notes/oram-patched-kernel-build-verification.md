# Patched TDX kernel: two-builder verification

The reviewed quote-status and bounded-length backport at source commit
`390880cb784fb3c19bf6d400bc4e14a3d742e36b` passed both independent builders and
comparison in [run 34728001247](https://github.com/sovright/zaino/actions/runs/34728001247).
Downloaded outputs were independently checked as described below. This clears
the patched kernel reproducibility input; boot, post-drop hardware access,
CCEL/RTMR replay, image admission, and workload privacy remain unqualified.
The [older retained kernels](oram-kernel-build-verification-2026-09-12.md) remain
historical pre-fix evidence and cannot substitute for this patched input.

## Download and payload verification

| Builder | GitHub artifact | ZIP bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| run-1 | `10309235277` | 253120937 | `a3f691205a2ee042766153d3d67ef787a58131d671d5b1437b7b75b5edbe7227` |
| run-2 | `10308641748` | 253120938 | `8fc85cc20fa2c0aa5f586fab26e6418968be81708f77d42c0159f95dd590a81c` |

Both downloaded ZIP hashes match public GitHub artifact metadata. All six
payload entries in each `SHA256SUMS` pass, and the complete artifact directories
compare byte for byte. The source archives also both match the pinned original
archive hash. Tool-version files match, and build receipts match after removing
only `run_label`.

| Reproduced payload | Bytes | SHA-256 |
| --- | ---: | --- |
| `bzImage` | 3408896 | `12e3b45a4bfe5b204cc4d05bb0269aa48decd08678a98549ee1d345ccef1d183` |
| `vmlinux` | 17180632 | `88f73cd5a055079b4af9e4553b67202fb29e8b9ad13694aded4247cea025f419` |
| `System.map` | 1111077 | `f9016d658184c72593125b3342bbc8e906a63b1dd9488792b1e9f6acd3995cff` |
| `config` and `embedded.config` (each) | 61200 | `5d516247b2d300ab0633b1d887dfd61c145810247902a04588b8b18bbd28400a` |
| `kernel-patches.json` | 992 | `fa4aa401443c303077fc1a434bb82c5fe558f44b5a62f4ca3d6534f649c2289a` |

Independent extraction using the selected source's `scripts/extract-ikconfig`
with `LC_ALL=C` reproduces `config` from both `bzImage` and `vmlinux` in both
builds. The merged requested/effective-config verifier passes on that config.
Neither kernel was booted during this verification.

## Source and builder binding

Both receipts identify source `390880cb...`, network-disabled compilation, the
selected OCI image and executed image ID, source/tool closure locks, requested
config, builder scripts, patch lock, artifact manifest, and tool versions.
The retained patch lock is byte-identical to the reviewed repository file.
Recomputing the builder-script digest from the clean reviewed checkout matches
both receipts: `753de39b66b8c72af059dddad7ed708cb120547a9075bd3307b9a131dc867ec7`.
The artifact manifest hash is
`c5d77ffb80865793c3d0bf1a453287a7aea176923e218453876ef406fc0e8acc`;
the tool-version hash is
`8187e654f399b1a64936a265c38a5c7c98099a501135aa31359e615947422618`.

The patch lock binds the reviewed upstream status and length fixes, the exact
combined 6.17 backport, original driver SHA-256 `06d50d736be3f708dd78654884b296b379736529f0a1cb73f7753e3f9e4fa078`,
and patched driver SHA-256 `ac7a2fed535b553fbd112bca77d42f7d734fa23e72341ce7437b853d311f582a`.
Strict application and pre/post-source checks passed independent review before
the builds. The individual builder receipts intentionally retain their
single-builder/unqualified scope; this cross-build report does not rewrite them.
