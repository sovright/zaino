# Raw evidence interface v1

This is research evidence acquisition, not a verified private deployment.
`private serve --ephemeral-tls-identity --allow-unaudited-oram` remains loopback
only. `GetEvidence` uses the same in-process TLS identity as the query listener.
Persisted TLS identities cannot enable evidence. Bootstrap's legacy attestation
field stays empty. Neither an empty field nor successful raw acquisition means
that a quote was verified.

## Wire and transcript

`/zaino.private.v1.PrivateCompactTxStreamer/GetEvidence` accepts a protobuf
`EvidenceRequest` containing exactly 64 challenge bytes. The decoded protobuf
body cap is 66 bytes. There is one quote worker, separate from the query mutex;
busy requests fail and the public quote timeout is ten seconds. Timeout or
client cancellation keeps the permit held until the blocking worker exits.
Production Linux uses only `/sys/kernel/config/tsm/report` with the `tdx_guest`
provider; unsupported platforms and provider failures refuse evidence.

The response contains unverified claims and the raw quote. Recompute the
64-byte REPORT_DATA as SHA-512 of this exact concatenation:

| Offset | Width | Encoding |
| --- | --- | --- |
| 0 | 32 | ASCII `zaino-tdx-report-data-v1`, then eight zero bytes |
| 32 | 2 | Version 1, unsigned big-endian |
| 34 | 64 | Client challenge |
| 98 | 32 | SHA-256 of the live TLS SubjectPublicKeyInfo DER |
| 130 | 32 | SHA-256 of the executable file |
| 162 | 32 | SHA-256 of the public configuration allowlist below |
| 194 | 16 | Native compiled privacy profile identifier |
| 210 | 4 | Schema version, unsigned big-endian |
| 214 | 8 | Live key epoch, unsigned big-endian |
| 222 | 4 | Served finalized checkpoint height, unsigned big-endian |
| 226 | 32 | Canonical internal block hash bytes, not reversed display hex |

The 258-byte preimage has no variable-width fields. The checkpoint comes from
the finalized generation that runtime refresh accepted; the current listener
does not refresh again during serving. This checkpoint identifies a public
block, not an authenticated ORAM-state root. It does not establish rollback
protection or externally witnessed chain freshness.

On Linux the executable file is opened through `/proc/self/exe`. This is a
workload claim; hashing a file is not measurement of all loaded process memory.
The verifier must separately enforce a measured-image and runtime-launch policy.

## Public configuration allowlist

Concatenate these ASCII strings, each followed by one zero byte:

1. `zaino-private-evidence-config-v1`
2. `mainnet`
3. `ephemeral-tls`
4. `loopback`
5. `unaudited-research`
6. `single-worker`
7. `frozen-finalized-generation`
8. `direct` or `rpc-external-authority`, taken from the actual configured backend

Append schema version 1 as four unsigned big-endian bytes, then the native
16-byte compiled profile identifier. SHA-256 the result. For `direct` and a
profile consisting of sixteen `07` bytes, the digest is
`ace5fcdaa6b588e962d44df2fd8ae2d56e36c59eaffbb335d8e3f30231f8c82a`.

This allowlist describes this research serving mode. It excludes credentials,
paths, and serialized operator configuration. It does not assert guest admin,
boot, debug, network-source correctness, or production image policy. Those
require separate verifier-owned evidence and policy; `direct` alone is not a
claim that the node is inside the measured trust boundary.

## Acceptance still required

A client may use provisional TLS only to obtain evidence while still checking
TLS proof of possession. Before bootstrap or a wallet query it must validate
the hardware quote, current collateral/TCB status, platform provenance, allowed
guest measurement and runtime policy, REPORT_DATA, and the actual peer SPKI.
Its challenge must be fresh, pending, and consumed once. A server-provided
`verified` boolean can never authorize that transition.

This change does not implement that complete client verifier, an immutable
operator-inaccessible guest, authenticated ORAM-state roots, external rollback
witnesses, or full wallet API qualification. The production NO-GO in
[ADR 0903](../adr/0903-operator-privacy-scope-and-tdx-experiment.md) remains in force.
