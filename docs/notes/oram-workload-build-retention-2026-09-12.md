# Offline workload build retention, 2026-09-12

Two independent offline builds in [run 34724627228](https://github.com/sovright/zaino/actions/runs/34724627228)
produced identical canonical agent and runtime outputs. Both builds and the
comparison passed. This establishes reproducibility for this pinned workload
construction; it does not qualify a rootfs, native init, UKI, boot, attestation,
or private query service.

The actual builder checkout was PR merge
`1a215a3f40752639a2d9a274fe86aae213b4a7a1`, tree
`bf25093c75311cce0f566da26c19da1788bf8279`, equal to the tree of builder head
`f6860414cd57a41dd81d1100d86966362a5778b1`.
The independently pinned workload source was
`ef4d81b9bc7c68ef03a73730caf42781b3f1cd21`, tree
`725be84be56cb6b51074ba81c8860523a91dbffd`.
It is distinct from the builder checkout.

Both outputs contain 15 files. Independent verification checked the complete
file set, every outer and inner manifest entry, declared modes, source and
builder identities, and canonical equality. The 6,414,552-byte agent has SHA-256
`95671d547e6226e34d0e26705795560c4e2ae9f2df06846afcf06a064cb41d0e`.
Raw linker/loader diagnostics and the run label differ as expected and are
excluded from canonical equality. GitHub ZIP transport normalizes file modes;
consumers must authenticate the mode manifest and restore approved modes during
construction. A deferred native init is required at this stage and is not a
completed final image.

## Durable copies

The following objects were retained in the existing private evidence bucket
with an upload precondition forbidding overwrite. The common prefix is:

```text
gs://sovright-oram-research-evidence/builds/workload/95671d547e6226e34d0e26705795560c4e2ae9f2df06846afcf06a064cb41d0e/github-34724627228/
```

| Object | Bytes | Generation | SHA-256 |
| --- | ---: | --- | --- |
| `zaino-workload-f686-run1.zip` | 5451865 | `1789255654429220` | `68c5df8110f77a768078df609307db2ddc2cc00415c5d408d9a60028bd2d91ce` |
| `zaino-workload-f686-run2.zip` | 5451870 | `1789255654543959` | `3b4de4f969060b55ad48bc16f69cef79b4af9377f6f2ce5478f90065a28d05f8` |
| `zaino-workload-f686-independent-verification.json` | 6946 | `1789255654001707` | `d401b3e6c5a5b2c430ab08d9a508f2b2dd4258f3e37ac22241de4894a1725636` |
| `zaino-workload-f686-github-artifacts.json` | 1451 | `1789255653919672` | `878e5610e85ce817b1a711d1fc236acfa67530a0fd1a592ed096d60310e5de9e` |
| `zaino-workload-f686-github-run.json` | 287 | `1789255653920928` | `8c883fbaaf474ab406891b77bcfa8469cdb89e2f281dc1c471898d9d468696c1` |
| `zaino-workload-f686-builder-commit.json` | 2575 | `1789255654040285` | `f213da959e9bd9dfa183fadbe5aeb368423df5ab120329f2ad515baa3e60fab0` |
| `source.json` | 651 | `1789255654025108` | `5f7a38ed2a13ea361b59fbc4e080f89057ab63237bbd8a6598ff31091881f4bc` |

The original ZIPs match GitHub artifact IDs `10306838736` and `10307526781`,
including their API-reported SHA-256 digests. After upload, the exact remote
seven-object set, every remote size, and every remote MD5 were compared with
the local files. The SHA-256 values above are independently calculated local
digests. Public-access prevention was enforced and uniform bucket-level access
enabled at verification time. The project is `sovright-oram-research`, number
`486673347298`.

The receipts are unsigned build provenance. Storage retention does not make
these artifacts an accepted-image policy or authorize an image launch.
