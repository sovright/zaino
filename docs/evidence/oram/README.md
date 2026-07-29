# Checked-in ORAM evidence

`docs/evidence/oram/` preserves final machine-readable ORAM research evidence
only when the complete published bundle is small, sanitized, and directly
relevant to a documented gate decision. Large corpus captures, intermediate
results, staging directories, runtime logs, and machine-local diagnostics
remain outside Git.

Each leaf directory is an immutable copy of one atomically published artifact
bundle:

- preserve the published filenames and bytes exactly;
- keep explanatory prose in a dated file under `docs/notes/`;
- record the executed source revision and external run context in that note,
  rather than claiming the artifact provenance binds facts it does not;
- create a new sibling directory for every rerun; and
- never replace or reformat an existing bundle.

Run-directory names encode enough public context to distinguish evidence
without adding host identity. For example,
`insertion-mainnet-a4c55992-h3425046-p4-s8-b0` records the executed source
short hash, checkpoint height, probe count, deterministic schedule count, and
sampled failure budget in basis points.

The first bundle admitted under this convention is the
[Gate 1 current-layout insertion result](gate1/insertion-mainnet-a4c55992-h3425046-p4-s8-b0/).
Its human-readable context and claim boundary are in the
[dated evidence log](../../notes/oram-gate1-mainnet-insertion-bound-log-2026-07-27.md).
