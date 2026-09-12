# Workload compiler and linker package roots

`workload-tool-roots.json` selects exact builder-only package roots for the
native init and evidence-agent compilation. It reuses the signed frozen
snapshot resolver and offline package verifier. There are no guest package
roots: these tools must not enter the verified runtime filesystem.

The signed noble amd64 universe index selects `musl-tools=1.2.4-2`, depending
on `musl-dev=1.2.4-2` and `musl=1.2.4-2`; the signed main index selects
`cmake=3.28.3-1build7`. Their index hashes and sizes were verified against the
retained InRelease files. The other roots use the already reviewed kernel
builder versions. The complete dependency set, not merely these root names,
must pass the resolver and actual-byte verifier before installation.

The workflow resolves twice from empty isolated APT state on one Linux
runner, compares canonical package locks, and runs the existing six tamper
cases with these roots. It retains one exact package directory, lock, and
signed-index proof set for later offline installation. This checks repeated
resolution; it is not two independent compiler executions.

The Rust host and musl-target components are pinned separately in
`rust-toolchain-inputs.json`. The later builder must install both verified
input sets in its pinned network-disabled container, select compiler/linker
paths explicitly, and record their actual versions. In particular, the
presence of distro musl libraries does not establish which CRT/libc inputs
Rust actually links; retain the effective linker inputs and verify the final
init ELF has neither an interpreter nor dynamic dependencies. Exact Cargo
vendor inputs, source/features, build flags, and independent binary comparison
remain required. This root selection grants no workload or guest admission.
