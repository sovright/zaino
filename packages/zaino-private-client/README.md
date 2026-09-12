# Zaino private client evidence foundation

This non-published research crate parses canonical `EvidenceResponse` v1,
recomputes REPORT_DATA, checks verifier-owned workload fields, and correlates
the result of the pinned local Go quote verifier. Its opaque receipt is only a
quote, collateral, and supplied-field-policy result. It is not TLS-channel,
workload, bootstrap, or query admission.

The supported host platforms are Linux and macOS. The caller owns a fresh
64-byte challenge and the SPKI digest from the actual retained TLS stream. The
helper must be installed at an absolute, immutable path with a reviewed SHA-256
digest. The client host and filesystem are trusted; hash-then-spawn detects
accidental replacement but is not an atomic identity guarantee against a
hostile local OS. The pinned Go helper must not fork or daemonize.

Each invocation uses a mode-0700 temporary directory and mode-0600 files. The
client checks stdout and stderr sizes every 50 ms, kills and reaps the direct
child on the total deadline or when either exceeds 16 KiB, and accepts at most
16 KiB from each output. This is an enforcement boundary for the trusted
helper process, not a filesystem quota.

Bootstrap validation and construction of a production query codec are a
separate layer. This crate currently creates no same-stream capability or
admission state.

`ValidatedBootstrap` checks the owner-issued context against the supplied
accepted evidence and expected network, including the compiled 24,576-byte
envelope width and explicit hash byte order. It builds the production
`MainnetClientSession`, which seals first-page queries and refuses responses
with a different checkpoint or a continuation. The caller must keep the exact
verified evidence immutable; these public parsing helpers do not enforce
connection ownership or authorize a query.

The codec dependency currently enables `zaino-oram/corpus-zaino` and includes
the chain-index and native database dependency closure. This is a research
integration, not yet a minimal wallet dependency. Complete pagination, cover
rounds, retained-connection admission, and an accepted guest image remain open.
