# TDX file verifier experiment

This standalone client-side helper accepts one raw QuoteV4 file and one
verifier-owned closed policy file. It retrieves current Intel collateral over
a bounded, exact-endpoint HTTPS client, verifies the quote with revocation and
TCB checks enabled, requires both returned TDX and QE statuses to be
`UpToDate`, and applies every supplied field expectation to the same parsed
quote.

Build with the reviewed toolchain and static target:

```console
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
```

Invoke locally:

```console
tdx-verifier -quote quote.bin -policy accepted-image-policy.json
```

An explicit diagnostic mode additionally validates a bounded CCEL ACPI table,
strictly parses and replays its SHA-384 crypto-agile event log, and compares all
four lanes with the RTMRs from the same already-verified quote:

```console
tdx-verifier -mode ccel-diagnostic \
  -quote quote.bin -policy diagnostic-policy.json \
  -ccel-table CCEL -ccel-log ccel.bin
```

Both CCEL inputs are mandatory in this mode. The table is capped at 4 KiB and
the log at 1 MiB. The parser requires the TDX table label, exact table and log
lengths, a valid ACPI checksum, one SHA-384 digest per event, CC measurement
register indices 1 through 4 for measured events, no more than 4,096 events,
canonical all-`0xff` padding, and exact replay equality for all four RTMRs. A
lane with no measured event must equal the SHA-384 initial zero value. The
implementation does not invoke upstream replay workarounds.

Event-type numbers and event payloads remain opaque, untrusted diagnostic data
in this mode. Unknown event-type numbers are accepted into the digest chain but
are never interpreted, emitted, or used for policy. This is deliberate: type
and payload semantics belong to the later independently reviewed image policy.

This mode emits the distinct scope
`tdx_quote_ccel_digest_replay_diagnostic_v1`. The Rust trusted-client parser
rejects that scope. Digest replay does not authenticate every event's label or
raw payload, identify a UKI or workload, establish measurement coverage, or
approve an image. A later semantic policy requires an independently built image
manifest and component-mutation evidence; it must never be derived from a
received diagnostic log.

The JSON policy requires exactly these case-sensitive keys:
`report_data`, `minimum_qe_svn`, `minimum_pce_svn`,
`minimum_tee_tcb_svn`, `mr_seam`, `mr_signer_seam`, `seam_attributes`,
`td_attributes`, `xfam`, `mr_td`, `mr_config_id`, `mr_owner`,
`mr_owner_config`, and `rt_mrs`. Binary values are hex; the four `rt_mrs`
entries are each 48 bytes. DEBUG and MIGRATABLE are always rejected. The
trusted policy must come from an independently approved image process; never
populate it from the quote being evaluated.

Success covers quote signature, current fetched collateral and revocation
state, both strict TCB statuses, and the supplied field policy. It is not a TLS
binding, workload identity, GCP instance-provenance result, private-query
admission token, state-freshness proof, or operator-exclusion proof.
