# Mainnet capture recovery and retention

On 2026-09-12, historical session transcripts identified the original capture
in project `sovright-testnet`, rather than the configured default project.
Read-only inspection confirmed the running builder `zaino-oram-build-20260713`
(instance ID `1882885340293317688`, zone `us-central1-a`) and this directory:

```text
/mnt/zaino-oram-mainnet/direct-mainnet-d35d158a-h3425046-c16
```

The three aggregate artifacts were recovered without changing the historical
VMs or disks. Local SHA-256 digests matched the builder:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| measurement.json | 24592554 | 46a53a2fe3e824f0cfa3831a9ddd8ce35d5247721a8acc0f2287491e75ea54a4 |
| measurement.txt | 2213769 | 1856187a63f991c54a118486efe09a77aeb9ad4253fe6820ffc3cae15180994b |
| provenance.json | 460 | baae4fe1c9e056e22b37bbe39095e5f555ab770ffbd299a6ca33f5ce5cf9dfce |

The compact canonical JSON of the whole `MeasurementArtifactV1` wrapper has
BLAKE2s-256 digest
`aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127`,
matching the July ledger. Hashing only its nested measurement produces a
different digest and is not the artifact identity.

The artifact declares schema `zaino-oram-mainnet-measurement-v1`, mainnet
checkpoint height `3425046`, hash
`0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`,
`3425047` blocks and `9193009` distinct addresses.

## Durable location for future work

The exact three files were uploaded using a create-only generation precondition
to the new research project `sovright-oram-research`:

```text
gs://sovright-oram-research-evidence/corpus/mainnet/h3425046/aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127/
```

Cloud listing confirmed all three objects and their sizes after upload. The
bucket is in `us-central1`, with uniform bucket-level access and public-access
prevention enforced. It contains aggregate measurements and public provenance;
no wallet inputs, daemon configurations, or credentials were copied. Downloads
must verify the file hashes above before use.

This establishes artifact availability and byte/canonical identity. Current
Rust-reader semantic revalidation and reproduction of the historical sizing
result remain separate checks. Recovery does not establish current chain
coverage, physical ORAM capacity, TDX performance, or accepted-image privacy.

All new ORAM cloud work uses the new project explicitly. Historical manifests
retain their original project and resource identities; do not rewrite them or
move/delete historical disks as part of this routing change.
