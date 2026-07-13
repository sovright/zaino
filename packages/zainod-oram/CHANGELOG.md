# Changelog

## Unreleased

- Add listener-free `corpus capture` over one indexed non-finalized mainnet
  snapshot, with optional explicit height/hash selection and atomic,
  read-back-verified measurement artifacts.
- Separate observed corpus measurements from growth, capacity, backend, memory,
  and TDX sizing assumptions so one capture can be qualified offline under
  multiple models.
- Add fully offline `corpus size` with eleven required model inputs, validated
  capture consumption, deterministic typed qualification/provenance digests,
  source-bound qualification recomputation, bounded no-follow artifact reads,
  and dirfd-relative crash-durable no-clobber three-file publication.
