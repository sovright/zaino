# Frozen Rust compiler inputs

The adjacent lock selects Rust 1.96.0 for the Linux amd64 offline guest
builder: rustc, Cargo, the native standard library, and the separate musl
standard library needed for static native init. All four actual
archives were downloaded and matched to the retained release manifest before
selection. Their immutable dated URLs, byte lengths, and SHA-256 hashes are
recorded. The large archives are external inputs, not repository contents.

Run `bash ../verify-rust-toolchain-inputs.sh [archive-directory]` from this
directory. Without the optional directory, only the retained metadata is
checked. With it, exactly four regular, non-symlink archive files must match.
The verifier does not extract, install, or execute the archives.

Trust starts at the reviewed repository pins. Discovery used HTTPS from
static.rust-lang.org; no independent Rust publisher signature verification is
claimed. Manifest consistency and downloaded-byte identity do not establish
compiler correctness or a reproducible guest build.

The builder must still install these verified components in the pinned,
network-disabled Linux container and record actual `rustc -vV` and
`cargo --version` output. Rustup/channel resolution is not part of assembly.
The final reviewed source revision, Cargo.lock, hashed vendor closure,
explicit workload feature set, offline compilation, linked runtime libraries,
and independent binary comparison remain separate required inputs and gates.
The musl standard library does not supply the complete C/linker build closure;
the exact musl linker and tools must also be pinned before static-init builds.
