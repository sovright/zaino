# Client-owned TDX verifier candidate review

Reviewed 2026-09-12. The bounded file-verification experiment is implemented in
[`tools/tdx-verifier`](../../tools/tdx-verifier/README.md). No workload has been
accepted and no private-query admission path uses this result yet.

## Recommendation

The experiment uses a client-owned Go helper with Google's `go-tdx-guest` full
`verify` and `validate` libraries and a closed Zaino policy wrapper. Production
Rust/OpenSSL policy is unchanged. Integration must launch a pinned local
executable from the trusted client; output received from the server operator is
not an attestation result.

Pin `github.com/google/go-tdx-guest` to `v0.3.2-0.20260908172713-48f3644ca143`, source commit `48f3644ca143b4800def5f89dca819294606bf4e`. Go's checksum verification returned module sum `h1:3sKT3xene704hofiysISVsb3a5qENxfWBd49/GyCxeY=` and go.mod sum `h1:uHy3VaNXNXhl0fiPxKqTxieeouqQmW6A0EfLcaeCYBk=`. This is a pinned candidate revision, not a claim that an unpinned main branch is acceptable.

## Verified closure and limits

For `verify`, `validate`, and `gce`, Linux amd64 with `CGO_ENABLED=0` resolves 248 packages with no CgoFiles and builds successfully. The nonstandard runtime module closure is the pinned TDX module plus:

| Module | Version | Go module checksum |
| --- | --- | --- |
| github.com/google/go-configfs-tsm | v0.3.2 | h1:ZYmHkdQavfsvVGDtX7RRda0gamelUNUhu0A9fbiuLmE= |
| github.com/google/logger | v1.1.1 | h1:+6Z2geNxc9G+4D4oDO9njjjn2d0wN5d7uOo0vOIW1NQ= |
| go.uber.org/multierr | v1.11.0 | h1:blXXJkSxSSfBVBlC76pxqeO+LN3aDfLQo+309xJstO0= |
| golang.org/x/crypto | v0.17.0 | h1:r8bRNjWL3GshPW3gkd+RpvzWrZAwPS49OmTGZ/uhM4k= |
| golang.org/x/sys | v0.19.0 | h1:q5f1RH2jigJ1MoAWp2KTp3gm5zAGFUTarQZ5U386+4o= |
| google.golang.org/protobuf | v1.34.2 | h1:6xV6lTsCfpGD21XK49h7MhtcApnLqkfYgPcdHftf6hg= |

Upstream `abi`, `verify`, `validate`, and `gce` tests passed locally. `govulncheck` v1.8.0 with Linux amd64/CGO disabled reported zero reachable vulnerabilities and zero vulnerabilities in imported packages; it reported 23 advisories elsewhere in required modules. This does not audit future helper imports, prove equivalence to Intel QVL, or replace live quote qualification. Pin and record the Go toolchain and final helper build metadata/SBOM separately when building the actual artifact.

## Required wrapper behavior

1. Parse bounded raw evidence once. The implemented helper accepts only QuoteV4;
   QuoteV5 remains unqualified and is refused. Use the same parsed object for
   cryptographic verification, status checks, provenance, and field policy.
2. Construct `verify.Options` internally with `GetCollateral=true`, `CheckRevocations=true`, `DisableTcbStatusCheck=false`, pinned Intel roots, and a single trusted-client time copied into all TimeSet fields. Do not accept server-supplied time, trust anchors, relaxed flags, or verification options. Treat every network/CRL error as refusal.
3. Supply a bounded `ContextHTTPSGetter`. The upstream default uses unbounded `io.ReadAll` and an HTTP client with automatic redirects. Restrict schemes, endpoints, redirects, response sizes, request count, and total duration. Certificate-derived fetch URLs are untrusted inputs. Cache only authenticated collateral within its validity and re-evaluate against current trusted time.
4. After successful `verify.TdxQuoteContext`, call `SupportedTcbLevelsFromCollateral` with the same quote and options. Require both returned matched statuses to be exactly `UpToDate`. At the reviewed revision the ordinary verification path requires platform status UpToDate but checks a separate module status only through selected relaunch cases. The additional returned-status checks are necessary for our strict current-TCB policy. For nondefault modules the returned first status is the module status; the earlier verification already checks the platform status. Cover this with adverse-status fixtures.
5. Construct a complete `validate.Options` internally: REPORT_DATA64, approved MRTD/MRSEAM and other required launch measurements, all four RTMR entries each exactly48 bytes, expected owner/config identity as applicable, DEBUG disabled and MIGRATABLE disabled, reviewed SVN minima and attribute/XFAM policy. Upstream intentionally skips nil/empty expectations; an incomplete policy must fail before any library call. Its `MinimumTeeTcbSvn2` is also used as an exact-byte match on TDX1.5 quotes, so do not assume this field is solely a lower bound.
6. Use verifier-owned expected GCP project/zone/instance policy for PZID/MR_OWNER, and authenticated Google host-registry provenance for the PPID extracted from the verified PCK certificate. Do not call the upstream unbounded provenance HTTP fetcher unchanged; use the same bounded endpoint policy. Provenance alone does not qualify the workload.
7. The trusted Rust client retains the completed TLS connection, checks handshake proof of key possession, extracts that connection's actual peer leaf SPKI, owns the fresh pending challenge, and independently reconstructs the canonical REPORT_DATA. A successful helper result is correlated to the exact quote digest, request nonce, policy digest, and invocation; only the local trusted caller can create the capability allowing BootstrapSession/QueryPage on that same connection. A new connection/reconnect requires revalidation. Do not authorize from an unsolicited server JSON result.
8. Fixed RTMR expectations can be an initial strict allowlist. If CCEL replay is used, validate the replay against quote RTMRs and separately evaluate all measured launch components against policy; replay alone proves no workload authorization. Adding `go-eventlog` changes the closure and needs its own review.

The current admin Ubuntu diagnostic image is a workload-policy rejection fixture. A valid signature, current TCB, Google provenance and matching REPORT_DATA do not remove admin access or establish Zaino launch provenance. Fresh attestation also does not establish chain/ORAM-state freshness or rollback resistance.

## Why not silently adopt Intel QVL now

The official Intel Rust candidates are `intel-tee-quote-verification-rs`0.4.0 and `-sys`0.3.0. Published sys0.3.0 was inspected and includes newtype output enums that safely represent unknown native status values. It dynamically links `sgx_dcap_quoteverify` and generates bindings against installed headers. Native DCAP_1.27.1 source links OpenSSL `-lcrypto`, SGXSSL, and WAMR/QAL. Cargo-deny would not expose this entire native crypto closure. Therefore using it in existing production packaging without an explicit policy and artifact review would bypass the repository's intended OpenSSL exclusion.

A separately scoped client-owned Intel reference verifier remains a possible independent qualification oracle after explicit native-policy review and artifact/SBOM pinning. No native package SHA, precise dynamic-versus-embedded dependency claim, or equivalence claim has been established here. An in-process Intel integration needs a deliberate policy revision, not a hidden transitive library.

## Primary sources

- [Pinned Google verifier](https://github.com/google/go-tdx-guest/blob/48f3644ca143b4800def5f89dca819294606bf4e/verify/verify.go)
- [Pinned Google field policy](https://github.com/google/go-tdx-guest/blob/48f3644ca143b4800def5f89dca819294606bf4e/validate/validate.go)
- [Pinned Google network getter](https://github.com/google/go-tdx-guest/blob/48f3644ca143b4800def5f89dca819294606bf4e/verify/trust/trust.go)
- [Google TDX provenance and its limitations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance)
- [Google attestation overview](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation-overview)
- [Intel DCAP1.27.1 Linux verifier link closure](https://github.com/intel/confidential-computing.tee.dcap/blob/DCAP_1.27.1/QuoteVerification/dcap_quoteverify/linux/Makefile)
- [Intel Rust verifier wrapper](https://github.com/intel/confidential-computing.tee.dcap/blob/DCAP_1.27.1/QuoteVerification/dcap_quoteverify/sgx-dcap-quoteverify-rs/src/lib.rs)
