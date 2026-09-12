# Typed ORAM fixed-profile query path

The production projection builder already selects the typed `rostl` backend
and fails closed when that backend is unavailable. The remaining
qualification-memory seam is the portable wallet parity harness used for
answer-correctness tests.

This slice adds a private typed parity constructor in supported Linux x86-64
test builds with `rostl-experimental`. It drives the same small fixed profile through the typed worker,
finalized serving-store identity, record annotation pass, XChaCha20-Poly1305
request and response codec, existing replay journal, and generation
replacement behavior. The harness records its backend choice so republishing a
generation cannot silently return to qualification memory.

The Linux test must show ordinary-source answer parity across empty, single,
and multi-UTXO cases; replay refusal; bootstrap profile and key-epoch identity;
and refusal of a request sealed for a replaced generation.

Portable parity tests and strict Clippy passed locally. The new typed test
requires Linux x86-64 execution; a macOS test run does not execute it. This is
an engine integration test, not a typed-backend gRPC/TLS round trip.

This evidence is limited to a small volatile test shape. It does not qualify
mainnet capacity, persistent ORAM state, physical access traces or timing,
non-empty recent-chain capture, live subscriber refresh, rollback resistance,
or the upstream backend's obliviousness.
