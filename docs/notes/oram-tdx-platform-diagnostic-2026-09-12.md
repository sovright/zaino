# Intel TDX platform diagnostic evidence — 2026-09-12

This note records a raw platform and quote-acquisition diagnostic. It does not
qualify an accepted Zaino image, exclude an administrator, validate quote
collateral, bind TLS, or exercise a private query.

Run 3 used manifest
`/private/tmp/zaino-tdx-platform-20260912-run3/manifest.json`, run ID
`20260912153826-e0e460c9`, instance ID `6433496150661713093`, boot disk ID
`7963980748426890437`, and pinned Ubuntu image ID
`6257327608773510097`. The enforcing cloud check passed for TDX type, private
networking, IAP-only TCP 22, no service account, the one-disk NVMe layout,
Shielded VM settings, and the 21,600-second delete policy. The last recorded
start was `2026-09-12T15:39:34.939Z`, making the no-restart runtime deadline
approximately `2026-09-12T21:39:34.939Z`; Compute Engine did not return a
separate `terminationTimestamp`. The manifest-guarded manual teardown completed
at `2026-09-12T16:12:33Z`, deleting the recorded instance, boot disk, firewall,
subnet, and network. Its receipt is retained beside the manifest as
`teardown-verified.txt`.

The successful second collection round is retained at
`/private/tmp/zaino-tdx-platform-20260912-run3/baseline-quote-round2`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `quote.bin` | 8,000 | `6385dfeba9b6c48ce175682add1458ca20ed9102a0620e351b6d70185eea7c35` |
| `report-data.bin` | 64 | `e7ea0e4b9c03dfbfe5b7bd97bab9c681079ea4e9262b82bf1e252b3fb49d4991` |
| `ccel.bin` | 262,144 | `71c67bb8d325c3adf02d6b207cb6a76248a4d117e57386661de2c4a4b08c7e00` |
| `guest-environment.txt` | 223 | `3287a7d1701c6b0c2ea746046712e1d53162c9564d1d9adc4221b1057bf7b519` |

The returned report-data file matched the locally generated public random
input byte for byte. Independently parsing the quote with Google's pinned
`go-tdx-guest` revision `48f3644ca143b4800def5f89dca819294606bf4e` also confirmed
that its embedded `TDQuoteBody.ReportData` equals those exact 64 bytes.
This parser check does not validate the signature or collateral. The quote
begins with the little-endian QuoteV4 version field. The guest reported
`tdx_guest=loaded`, Linux `7.0.0-1011-gcp`,
15,374,100 KiB total memory, and no swap.

Subsequent [client verifier work](https://github.com/sovright/zaino/pull/146)
verified this same signed quote with authenticated Intel collateral and a
diagnostic-derived test policy. The quote and signed collateral are retained
as deterministic test fixtures. That test policy qualifies cryptographic
plumbing only; it is not an approved image policy and supplies no private-query
admission. This later result does not change the limited scope of the original
acquisition diagnostic.

Run 1 and run 2 stopped on strict API-representation assertions before guest
access. Their guarded cleanup deleted each recorded instance, boot disk,
firewall, subnet, and network. Run 1 retains its manifest and recorded command
output; run 2 additionally retains sanitized snapshots and a teardown receipt
in its `/private/tmp/zaino-tdx-platform-20260912-run2` directory. Estimated
cumulative cost, including run 3's maximum lifetime, remains below the planned
`$2` diagnostic cap; this is an estimate, not a verified billing export.
