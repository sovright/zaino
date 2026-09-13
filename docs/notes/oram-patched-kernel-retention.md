# Patched kernel retention

The two independently verified patched builds from run `34728001247` are
retained in the dedicated ORAM project's private evidence bucket. The
[verification report](oram-patched-kernel-build-verification.md) records source,
patch, configuration, and payload identities and the remaining admission gates.

```text
gs://sovright-oram-research-evidence/builds/kernel/12e3b45a4bfe5b204cc4d05bb0269aa48decd08678a98549ee1d345ccef1d183/github-34728001247/
```

| Object | Bytes | Generation | CRC32C (base64) |
| --- | ---: | --- | --- |
| `zaino-kernel-patched-run1.zip` | 253120937 | `1789260014312335` | `ceOsqQ==` |
| `zaino-kernel-patched-run2.zip` | 253120938 | `1789260014808717` | `ApA0TA==` |
| `zaino-kernel-patched-github-artifacts.json` | 1443 | `1789260001899249` | `HsHraw==` |
| `oram-patched-kernel-build-verification.md` | 3413 | `1789260001893448` | `M8M4eQ==` |

Uploads used generation-zero preconditions. The exact remote object set and
all CRC32C values match locally computed hashes; all remote sizes match the
local files. Both ZIPs are composite objects, so they have no server MD5; the
metadata and report also match their local MD5 values. ZIP SHA-256 identities
are in the verification report. The metadata SHA-256 is
`41583c02a6c953cc2722c9a033c8644fd652fd11ae434857c730a975ee48810c`;
the retained report SHA-256 is
`ca774c22ca5a560d3bc1a0d01a87a2e3a06cbcf6843cd27f0bf4f9cdf121b8c9`.
Public-access prevention and uniform bucket-level access were verified in this
session. All uploaded payloads are public GitHub build artifacts or their
source-verification records. Retention does not imply boot or TEE admission.
