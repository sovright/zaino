# Architecture decision records

Two sets of ADRs live here, and they are numbered from different sources.

## Inherited from upstream

`0001`-`0006`, and any later record that arrives through a sync with
`zingolabs/zaino`, are upstream's. They keep upstream's numbers so a sync stays
a clean merge.

## Fork-specific: use `0900` and up

ADRs that exist only in this fork — the private-query and ORAM work — take
numbers from `0900` upward.

The reserved range exists because upstream keeps allocating in the low range
and cannot know what this fork has used. That already collided once, and the
collision is still visible below.

## The existing collision

`docs/adr/` currently contains two `0007`s:

| File | Origin |
| --- | --- |
| `0007-block-persistence-is-a-row-set-boundary.md` | upstream |
| `0007-private-query-service-and-leakage-model.md` | this fork |

They are left as they are, deliberately. Renumbering the fork's `0007`-`0010`
would touch 25 references across 11 files and break every link that already
points at them from merged commit messages, pull requests, and the issues
tracking the private-query work — permanent breakage to fix a cosmetic clash.
The filenames differ, so links resolve correctly today.

The fork's low-numbered records are therefore grandfathered:

- `0007-private-query-service-and-leakage-model.md`
- `0008-private-query-xchacha-protection-primitive.md`
- `0009-private-query-runtime-security-state-owner.md`
- `0010-interim-honest-but-curious-deployment-posture.md`

Upstream may yet ship its own `0008`, `0009`, or `0010` — their zcashd-removal
work already claims `0008`. If that lands, the duplicate is expected and this
table is where to look. Do not resolve it by renumbering the fork's records
after the fact; that trades a cosmetic problem for broken references.

## Adding one

- Upstream-relevant decision: take the next free low number and expect it to
  travel upstream.
- Fork-only decision: take the next free number at `0900` or above.

Give the record a `## Status` line, and say what it supersedes or is superseded
by. `0010` is an example of a record that deliberately narrows another without
replacing it.
