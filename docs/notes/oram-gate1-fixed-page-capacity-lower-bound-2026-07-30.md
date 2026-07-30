# Gate 1 fixed-page capacity lower bound

## Decision

The admitted `16`-entry, `288`-block provisional logical finalist is **not
rejected by the retained-memory floor of the modeled one-base, one-active-add,
one-active-spend topology alone**.

Pinned Rostl revision
`8c3a12d2febf17b024f2e949428b3bc526d74172` requires at least
`22,020,227,816` retained bytes (`20.507935 GiB`) for one base table at the
final checkpoint and one active add and spend table at their maximum observed
generation demands.

This is not a Gate 1 GO, a target-RSS pass, or a complete physical layout. The
calculation excludes the address directory and manifests, approved growth,
old/new generation overlap, rebuild workspace, allocator metadata and
over-allocation, transient construction allocations, the rest of the process,
stash-failure qualification, and all service latency. Gate 1 therefore remains
**NO-GO**.

## Source and implementation binding

The analyzer consumed the retained
[`hybrid-mainnet-2316644-h3425046-v1`](../evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/)
bundle using its externally retained canonical BLAKE2s-256:

```text
2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828
```

It revalidated the exact three-file set, strict typed JSON, canonical text,
internal source/checkpoint consistency, the provenance-to-artifact digest
link, and the supplied external artifact digest before deriving capacity. The
runner-version field in provenance is not authenticated by that external
digest and is not used by this calculation. The calculation uses the compiled
1,208-byte base/add/spend record types and pinned Rostl `Block`, `Bucket`,
stash, tree, and recursive-position-map geometry.

The command fails closed unless compiled for Linux x86-64. It is read-only and
emits no qualification artifact:

```text
cargo run -p zainod-oram --features typed-qualification --bin zainod-oram -- \
  qualification fixed-page-capacity \
  --hybrid-sizing-dir docs/evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1 \
  --expected-hybrid-sizing-blake2s256 \
    2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828
```

## Capacity result

One mandatory public spare record is added to the immutable base demand.
Two are added to each mutable delta demand because Rostl's upsert preflight
requires public occupancy to remain strictly below `capacity - 1`, including
when an existing page is updated at peak occupancy. Each result is then rounded
to the smallest power of two accepted by Zaino's Rostl adapter. The base row is
the final-checkpoint page count; the add and spend rows are maximum generation
page counts:

| Table | Source maximum | Minimum with spare | Rostl capacity | Capacity slack |
| --- | ---: | ---: | ---: | ---: |
| immutable base | 2,388,477 | 2,388,478 | 4,194,304 | 1,805,826 |
| active add | 69,233 | 69,235 | 131,072 | 61,837 |
| active spend | 92,186 | 92,188 | 131,072 | 38,884 |

On the modeled Linux x86-64 ABI, a 1,208-byte page produces a 1,224-byte Rostl
block and a 2,448-byte two-block bucket. For a power-of-two capacity `C`:

```text
height = log2(C) + 1
tree buckets = 2C - 1
stash blocks = 20 + 2 * height
```

Each table also owns an independent recursive position map. Production Rostl
uses 16 positions per 64-byte internal node, a 128-node linear root, and bare
internal-node Circuit ORAM levels beginning at capacities 2,048, 32,768, and
524,288 as required.

| Table | Main ORAM bytes | Position-map bytes | Table object bytes | Retained lower bound |
| --- | ---: | ---: | ---: | ---: |
| base | 20,535,390,720 | 178,933,712 | 168 | 20,714,324,600 |
| add | 641,794,608 | 11,156,832 | 168 | 652,951,608 |
| spend | 641,794,608 | 11,156,832 | 168 | 652,951,608 |
| **total** |  |  |  | **22,020,227,816** |

The three-table floor is `20.507935 GiB`, or 16.65% of the proposed
`123.2 GiB` maximum whole-process RSS budget on a 176-GiB guest. Because every
excluded component is nonnegative, this comparison can reject this explicit
one-table-per-class topology if its floor exceeds the budget; it cannot reject
the logical tuple across every possible topology or establish that this
topology fits. Sharding changes power-of-two rounding and must be modeled
separately.

The logical hot-address floor remains 27,159 page reads per request. This
capacity result says nothing about whether that access count can satisfy the
proposed latency or throughput targets.

## Next gate

The next high-information work is:

1. freeze a source-bound growth horizon and simultaneous-generation/rebuild
   overlap policy;
2. add the directory/manifest table geometry to obtain a complete steady-state
   allocation bound;
3. initialize the exact compiled topology on the proposed target class and
   measure construction peak and steady whole-process RSS with zero swap; and
4. measure exact fixed-page access latency before treating the 27,159-page hot
   tail as serviceable.

Any capacity change forced by growth or overlap must be rerun through this
power-of-two model rather than applying a linear multiplier to the current
result.
