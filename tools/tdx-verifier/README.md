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
