# Verifier test fixtures

`signed-quote-v4.dat` is copied from the pinned Apache-2.0
`github.com/google/go-tdx-guest` module testdata at commit
`48f3644ca143b4800def5f89dca819294606bf4e`.

`gcp-diagnostic-quote-v4.bin` is the raw public-challenge diagnostic quote
collected from the bounded GCP TDX run on 2026-09-12. Its SHA-256 is
`6385dfeba9b6c48ce175682add1458ca20ed9102a0620e351b6d70185eea7c35`.
`gcp-diagnostic-derived-policy.json` is derived from that quote solely for a
cryptographic plumbing test. It is not an approved image policy and must never
authorize a workload or query. `gcp-diagnostic-collateral.json` contains the
Intel HTTPS responses authenticated by the successful online verification on
2026-09-12, retained so tests can repeat at their fixed historical validation
time. Refresh is a deliberate manual test operation.

The fixtures contain public attestation evidence and public Intel collateral;
they contain no credentials or private application data.
