# Unqualified codegen diagnostic retention, 2026-09-12

[Native run 34722711445](https://github.com/sovright/zaino/actions/runs/34722711445)
completed its native tests and release build, retained a static diagnostic,
passed the access-path guard, and failed the exact-upsert guard. The fixed-page
guard and checked-runner packaging were skipped. The retained binary is
**unqualified**, is for static inspection, and has not been admitted for a
research run or TEE execution.

GitHub artifact `10307681807`, named
`oram-codegen-UNQUALIFIED-34722711445-1`, is a 67,542,806-byte ZIP with SHA-256
`8ce77073fdeddb49aafa162ceb01a38876d9ea2031ef9adcb11ebd3e9121131f`.
The downloaded ZIP matches the API-reported digest. Its exact ten-file set
contains the manifest and nine payload files; every manifest entry verifies.
The 38,485,544-byte `runner.UNQUALIFIED` has SHA-256
`f5cc1c3fbd21b97d0e3882261813ab8632cb698c1111a73c285cddba892a398d`.

The diagnostic records actual merge commit
`1621440510ccbd01ee961cc8ec30985096cff9ea`, tree
`eb2f45f395c2ce633b55cde7ea4e20a9fbe771a9`. Independent Git API inspection
confirms the merge parents and that the tree equals reviewed branch head
`f5742cb69e12b7e9a958739daeb1130ebed58a21`. It records Rust 1.96.0,
compiler source `ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`, LLVM 22.1.2,
and GNU binutils 2.42. Symbol lists, full disassembly and relocations are
retained alongside the ELF for complete machine-code review. Symbol hash drift
alone does not justify updating a codegen guard.

The private evidence prefix explicitly preserves the qualification status:

```text
gs://sovright-oram-research-evidence/builds/codegen-unqualified/f5cc1c3fbd21b97d0e3882261813ab8632cb698c1111a73c285cddba892a398d/github-34722711445/
```

| Object | Bytes | Generation |
| --- | ---: | --- |
| `zaino-codegen-f574-diagnostic.zip` | 67542806 | `1789255952418797` |
| `zaino-codegen-f574-github-artifacts.json` | 761 | `1789255950174861` |
| `zaino-codegen-f574-builder-commit.json` | 2575 | `1789255950160834` |

Uploads required generation zero. After upload, the exact object set and every
remote size and MD5 were checked against local files. The metadata record
SHA-256 values are, respectively,
`f9cfe3acb578538fe69521769ce7c0e636488c3cc7ee33cc2ec8fcdb81cb8f05`
and `10be52b7273c9798e27f6412a5f272b8b893475b25ff69324f01b7b21d87d8d5`.
The bucket enforces public-access prevention and uniform bucket-level access.

## Second integration diagnostic

Run `34724917398`, artifact `10308220938`, is also retained. The public GitHub
artifact metadata's ZIP SHA-256 matches the downloaded bytes:
`01985b4edf283aa1c827224739af349865bf4b547b8422f7431315d8391503ce`.
All nine payload manifest entries verify. The embedded source merge is
`a13646e816e3ffa240bfdef608894de83cdefef3`; its tree independently matches
integration `3eb9d5a538d8740dc27972fee745e46f6201403c`. Static-check results and
their limits are in the [repair review](oram-codegen-identity-and-mask-review-2026-09-12.md).
The ELF remains unqualified and was not executed.

Private retention prefix:

```text
gs://sovright-oram-research-evidence/builds/codegen-unqualified/56fab4e51e2e11f68d3df57a44795f94ec89dd33834d449271b71a62b4a89264/github-34724917398/
```

| Object | Bytes | Generation | SHA-256 |
| --- | ---: | --- | --- |
| `zaino-codegen-3eb9-diagnostic.zip` | 67451784 | `1789259569297119` | `01985b4edf283aa1c827224739af349865bf4b547b8422f7431315d8391503ce` |
| `zaino-codegen-3eb9-github-artifact.json` | 728 | `1789259566978324` | `ed0f690f74e0020ad1954c30987ddc42604099e1ff58553dded8a972ef47d176` |
| `zaino-codegen-3eb9-builder-commit.json` | 72199 | `1789259566978123` | `63a7bd6ad414cd7b0c280ae28e03e73d16775eaf887bb2ed67841043c011781f` |

These uploads also required generation zero. The remote object set, all three
sizes and MD5 checksums match the local files. Public-access prevention and
uniform bucket-level access were rechecked before this upload. The larger
commit record is the full public GitHub commit API response, not an ELF or a
qualification receipt.
