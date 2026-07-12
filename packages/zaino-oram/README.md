# zaino-oram

`zaino-oram` is the internal research library for Zaino's proposed
host-oblivious private-query service.

This first foundation contains only deterministic, dependency-free models:

- fixed transparent-UTXO and envelope shapes;
- compiled privacy-profile validation;
- an internal store interface and bounded plaintext mock implementation;
- exact logical store-call schedules and schedule-equivalence tests.

It does **not** contain a real ORAM, encryption, persistence, TDX attestation,
protobufs, or a network listener, and it makes no production privacy claim.
The schedule model does not establish equal instruction, memory, allocation,
page, timing, or packet behavior.
Those components remain gated by ADR-0007 and the feasibility criteria in
`docs/notes/oram-enabled-zaino-plan.md`.
