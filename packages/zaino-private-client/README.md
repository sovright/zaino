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

`RetainedPrivateClient` owns one TLS stream and one absolute, nonrenewable
admission deadline beginning before connection setup. Admission requires a
nonzero client-selected maximum age. Before every private query, the client
runs the same pinned verifier over the immutable admitted quote and policy, so
collateral and CRLs are checked against trusted current client time at that
authorization. This does not fetch a fresh hardware quote, guarantee the most
recent collateral issuance, or continuously monitor revocation.

Every helper wait and RPC is capped by the remaining admission age. Expiry,
helper refusal, cancellation, or an RPC failure terminally closes the retained
socket and removes the codec; the client never reconnects or renews admission.
If an outer admission timeout drops a queued or running blocking verification,
its late result has no authority. A helper process already running still gets
its own bounded kill-and-reap deadline.

`ValidatedBootstrap` checks the owner-issued context against the supplied
accepted evidence and expected network, including the compiled 24,576-byte
envelope width and explicit hash byte order. It builds the production
`MainnetClientSession`, which seals first-page queries and refuses responses
with a different checkpoint or a continuation. The caller must keep the exact
verified evidence immutable; these public parsing helpers do not enforce
connection ownership or authorize a query.

The codec dependency enables only `zaino-oram/client-codec`. Its production
normal dependency graph excludes `zaino-state`, Zebra, LMDB, RocksDB, and the
server state closure. The broader research crate still compiles some modules
unrelated to wallet operation, so this extraction is a bounded closure
reduction rather than a claim that the whole crate is a minimal cryptographic
library. Complete pagination, cover rounds, external rollback freshness, and
an accepted guest image remain open. The retained TLS transport deliberately
uses the workspace's reviewed AWS-LC provider without reintroducing state or
database dependencies.
