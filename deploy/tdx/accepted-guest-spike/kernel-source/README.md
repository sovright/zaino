# Custom kernel source input

The stock `6.17.0-1012-gcp` binary violates the reviewed configuration policy.
The custom build therefore selects a separate source package from the same
frozen Ubuntu snapshot: `linux-gcp-6.17` version `6.17.0-1022.25`. This is not
a reconstruction of the stock binary. The snapshot's source index contains
this source version; it does not contain the stock binary's older source
version. Selecting source does not establish kernel suitability or a build.

`custom-kernel-source.json` pins the source package and its three archives.
The retained `Sources.xz` is authenticated transitively by the already-retained
`noble-updates.InRelease` signature and its exact SHA-256/length entry. The
verifier then requires one matching package/version, its exact pool directory,
and all source-file SHA-256/length/name triples. Editing the source lock's own
hashes cannot replace that signature chain.

Run from the parent directory:

```console
bash verify-custom-kernel-source.sh
bash test-custom-kernel-source.sh
```

For archive-byte verification, supply a directory containing exactly the three
named regular files, with no symlinks or extra entries. Download each from
`snapshot + package.directory + "/" + files[].file`, using HTTPS and the pinned
byte limits. The download step is separate from these offline verifiers:

```console
bash verify-custom-kernel-source.sh /path/to/source-archives
bash test-custom-kernel-source.sh /path/to/source-archives
```

On 2026-09-12, all three actual archives were downloaded and passed the verifier
on macOS. No source was extracted or executed. Archive signatures here mean
the Ubuntu archive's signed index authenticates their bytes; this does not
claim an independent verification of the source maintainer's `.dsc` signature.
The metadata-only command explicitly leaves downloaded bytes unverified.

The next build must pin its compiler/tool closure, extract these verified
inputs into a fresh isolated builder with no network, produce and verify the
effective kernel configuration, and retain its exact kernel release and
outputs. Required drivers must be built in or included in the single verified
initramfs. The forbidden configuration settings must stay disabled after
Kconfig dependency resolution. Required TDX halt fixes, actual boot behavior,
and agreement between independent builds remain open.

Follow the kernel project's [reproducible-build guidance](https://cdn.kernel.org/doc/html/latest/kbuild/reproducible-builds.html)
for fixed timestamps, builder user/host, source/build path mapping, and
generated signing or randomization inputs. These controls must be verified
against this selected source and toolchain. No OCI image has yet executed the
custom kernel build, and no signing key or accepted guest is established.
