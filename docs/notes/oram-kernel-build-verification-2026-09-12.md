# Custom kernel artifact verification (2026-09-12)

Runs `34724637816` (PR 166 at `c7c1b2a4`) and `34724917455`
(integration at `3eb9d5a5`) both passed two builds and their comparison.
Downloaded artifact IDs were `10308045453`, `10307906104`, `10307781763`,
and `10307053534`. Their zip sizes were 253,120,191; 253,120,192;
253,120,190; and 253,120,190 bytes. Zip SHA-256 values, which include archive
packaging metadata and therefore are not expected to match, were respectively:

- `571a2b859469b13e4a91edf6494b4560e9687b73656c84390e09963287685a81`
- `730ad7cf76ce0b61d9a5942e54a18f9a1f0bb7d7fe2fc760f30ade93bff05b61`
- `56d995f2d290a8c44043e5b8a5b984fee2e006a5738c4d5ddcae3e20b1365e69`
- `38c1d16c0ba50f22e08b3cf5ea92bf3ea8b834f57aa7ed490f732c08f11957f5`

Every retained `SHA256SUMS` entry verified. Payload files were byte-identical
across all four artifacts:

| File | Bytes | SHA-256 |
|---|---:|---|
| `config` | 61,200 | `5d516247b2d300ab0633b1d887dfd61c145810247902a04588b8b18bbd28400a` |
| `embedded.config` | 61,200 | `5d516247b2d300ab0633b1d887dfd61c145810247902a04588b8b18bbd28400a` |
| `bzImage` | 3,408,896 | `6d17aa5310756b41405c5e2ea79f416f284f0612142deeb6ef0bbb1c123b7aef` |
| `vmlinux` | 17,180,632 | `6de6f8ecd125598ed7fa14ac613e097c4e2bec88c8b2b4da610c9304d57636a5` |
| `System.map` | 1,111,077 | `e8b8c87fa748210ef015d0cd3ac10224709f4ef6c50590de9407729f8a0f61a2` |
| source archive | 248,671,329 | `a5623ec5af79da8807e1467e43a1888461c7a445fb1e17533fe45f0fdf4394e3` |

The pinned Linux 6.17 `scripts/extract-ikconfig` independently extracted each
`vmlinux` and `bzImage` config under `LC_ALL=C`; every extraction matched both
`config` and `embedded.config` byte for byte. The verifier's 4 MiB per-config input cap was
respected. Each effective config passed the requested-fragment and static
policy verifier. Explicit checks confirmed `MULTIUSER`, `SHMEM`, `TMPFS`,
`PROC_FS`, `PROC_SYSCTL`, `SYSCTL`, `CONFIGFS_FS`, TDX guest/TSM, seccomp,
security, performance-framework, ELF, devtmpfs, and IPv4 requirements. TTY,
modules, scripts, BPF syscalls, debugfs, KGDB, kprobes, and ftrace were disabled.

All provenance records use builder base
`docker.io/library/ubuntu@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61`
and executed image `sha256:b2b7ea366714195a1e1c5b2b578ece85c0b3920381a8654d038d9684f009613c`.
They agree on source lock
`f3db605039f19f581a46e45881f05fa26f96c5b2d48ad6dc6adbe1ec63813e6d`,
tool closure
`0e29196a62fd8c8e5a28baf49b2b9d618f6bc18b20f4ca9fff0441c9b93a8753`,
requested config
`9da0252c9402ad21895c5e00bcd16289397660036bb5591178f8174c161740c9`,
builder scripts
`bb412a1f5faf0c65cc92c07a15caafc5403ed2c2b211084e57a848fe5e70f1a5`,
artifact manifest
`5c10e3619236588609cc3e6e36b4b010e2dc4e5a06f08a831505c5eb36b2e0e2`,
and tool versions
`8187e654f399b1a64936a265c38a5c7c98099a501135aa31359e615947422618`.
The expected run label and repository revision differ.
Network during each build is recorded as disabled.

This verifies reproducible kernel bytes and embedded/effective configuration.
It does not establish boot, measured image admission, post-drop ConfigFS access,
host PMU closure, or actual C3 runtime suitability.

## Durable retention

The two original PR166 ZIPs, `zaino-kernel-artifact-verification.md`, and
`zaino-kernel-c7-github-artifacts.json` are retained under:

```text
gs://sovright-oram-research-evidence/builds/kernel/6d17aa5310756b41405c5e2ea79f416f284f0612142deeb6ef0bbb1c123b7aef/github-34724637816/
```

The ZIP object names are `kernel-artifact-10308045453.zip` (generation
`1789255888114066`, CRC32C `ZiP1eg==`) and
`kernel-artifact-10307906104.zip` (generation `1789255888518752`, CRC32C
`YeHbeQ==`). Their SHA-256 values above match GitHub's artifact API digests.
Remote sizes and CRC32C values were independently compared with the local
ZIPs after upload. Composite objects do not carry an MD5 checksum.
The two accompanying records have generations `1789255875940694` and
`1789255875944602`; their remote sizes and MD5 checksums match local files.
Uploads required generation zero and therefore could not overwrite existing
objects. The dedicated bucket enforces public-access prevention and uniform
bucket-level access. Retention does not qualify execution or image admission.
