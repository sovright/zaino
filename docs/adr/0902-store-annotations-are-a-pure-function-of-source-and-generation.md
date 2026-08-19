# 0902 - Store annotations are a pure function of (source, generation)

## Status

Accepted (contract). Implemented in part: this record lands with the store
update primitive, the annotation field on the event page, and the mutation
mode that carries a write. The annotation *computation* and the
publication-time pass are deliberately not in this change; §"Obligations on
the annotation pass" below is what they must satisfy.

Fork-only record, allocated from the reserved `0900+` range per
`docs/adr/README.md`. Supersedes nothing. Extends, without weakening, the
source-bound rebuild claim implemented by
`projection_owner::cold_rebuild::TypedWorkerColdRebuildReport` and published
through `checkpoint::ProjectionEventLogRoot`. The sizing argument that makes
the annotation necessary is `docs/notes/recent-snapshot-scan-width.md` §C.

## Context

### What the store contract says today

The private projection store is volatile by design. Every restart rebuilds it
from the authoritative finalized chain, and nothing about the previous
process's tables is restored. Two mechanisms make that safe:

- `checkpoint::ProjectionEventLogRoot` is a hash chain over
  `persistent_utxo_event_commitment(event)` for every finalized projection
  event, in apply order, seeded by network, schema version and key epoch
  (`projection::ProjectionEventLogAccumulator`). It is published in the
  authenticated manifest.
- `projection_owner::cold_rebuild` replays a source-bound block sequence from
  genesis into a fresh typed worker, recomputes the source measurement, and
  reports `semantic_event_log_root_blake2s256` — that same root — for the
  rebuilt store.

Together they assert one property: **the store's event content is a pure
function of its source.** A rebuild that reaches the same checkpoint over the
same blocks produces the same root, and a host that tampered with either would
have to move the root to hide it.

Note what this is *not*. It is not a claim about the store's bytes. Physical
slot occupancy in the ORAM is randomized on every access
(`RostlTable::sample_new_position`), so two rebuilds of the same source are
already not physically identical, and the contract never claimed they were.
The identity is at the level of the logical record set and the event log root
over it.

### Why that contract is now insufficient

The private query's last quadratic term is `finalized_snapshot_relation`, at
`store_reads · N` per query. It is not query-dependent:
`read_slot(query.address_key(), slot)` returns the record at *that address's*
slot, so for any occupied slot the address argument is the candidate's own
owner, and both outputs are masked away otherwise. The pair
`(survives, valid)` is therefore a function of `(record, its owner, the
published recent snapshot)` — public per-generation data — and can be computed
once at publication and stored on the record, making the per-query join
`O(1)`. `docs/notes/recent-snapshot-scan-width.md` shows this is not a nice
optimisation but the difference between 1,130x over the per-query budget and
9.93% over it.

That requires writing to a published record. The store was insert-once:
`UniqueTable` exposed `capacity`, `read`, `occupied_records`, `insert_unique`
and no update primitive, and a "record" is folded from an append-only
`UtxoEvent` history by `records::finalized_live_utxo_at`. Adding an update is
a contract decision about the store, not a refactor, because the two
mechanisms above assume the store is a pure function of its source and an
in-place mutation is exactly the thing that could stop being one.

## Decision

### 1. The extended contract

> **The store's event content remains a pure function of its source. The store
> union its annotations is a pure function of `(source, generation)`.**

`generation` is the published projection generation — the rebuild interval
whose recent snapshot the annotation answers about. Two consequences:

- A rebuilt store, plus a re-run annotation pass for generation *g*, reproduces
  the same logical record set, annotations included. Recovery is unchanged in
  kind: replay the source, then re-run one pass.
- An annotation is never an input to itself. Nothing derives generation *g*'s
  annotation from generation *g−1*'s, so there is no accumulated state that a
  rebuild would have to reconstruct by replaying every prior generation.

### 2. Annotations are outside the event log root, and stay outside

`ProjectionEventLogAccumulator::append` hashes a `PersistentUtxoEvent`
commitment. The annotation is not part of a `UtxoEvent` and is not appended,
so it cannot move the root. This is deliberate and is the reason the extension
does not weaken the existing claim: the root keeps meaning exactly what it
meant — *the source produced these events, in this order* — and the annotation
rides beside it under a separate, weaker, generation-scoped claim.

The alternative — folding annotations into the root — was rejected. It would
make the root change every generation without any new event, breaking the
lineage the manifest and the rollback detection are built on, to authenticate
data that is derived from public inputs anyone can recompute.

### 3. Annotations are outside replay identity

`AddressEventPage`'s `PartialEq` is hand-written to compare event, directory
slot and event ordinal, and to ignore the annotation. Replay identity is
decided in `atomic_store::execute_inner` against the *appended event*
(`AtomicMutation::appended_event`), never against a stored page, so
`AppendDisposition::ExactReplay` and the at-most-one-duplicate uniqueness check
keep their current meaning across a re-annotation. Byte-exact comparison still
exists where it is needed: `PersistentAddressEventPage` keeps its derived
`PartialEq`, and the backend's compare-and-set reads every byte of the record.

### 4. The annotation occupies spare flag bits, not new payload bytes

`PERSISTENT_ADDRESS_EVENT_PAGE_BYTES` stays at 82. The annotation is three
bits in the existing address-cell flag byte: annotated, survives, valid. The
record width is an input to the ORAM block size, the fixed-page codegen
guard's `$0x52,%rax` `Cmov` loop bound (ADR 0901), the committed corpus
`record_sizes` manifest line, and every timing figure measured against them.
Growing the record to carry two bits would invalidate all of that for no gain.

The three bits are validated as a unit: `survives`/`valid` without `annotated`
is `NoncanonicalAnnotation`, not a silently-unannotated record; an annotated
dummy cell is rejected; and the directory cell — which defines none of these
bits — rejects all three, because `decode_address_cell_header` now takes the
caller's complete legal flag set instead of assuming the occupancy bit is the
only one.

### 5. `profile_id` does not move

`profile::derive_profile_id` hashes access-budget dimensions, concurrency and
replay policy tags, the runtime schedule version, envelope tag, continuation
TTL and timeout bucket. No persistent record shape enters it. Two prior
attempts at this hoist disagreed about that, so
`profile::tests::annotating_a_stored_record_does_not_move_the_profile_identifier`
pins it: it exhibits two stored records differing only in the annotation and
re-asserts the pinned mainnet identifier across them.

## Verifying the contract against the actual rebuild qualification

This section is the check the decision above depends on, done against the code
rather than assumed.

**The rebuild reproduces the logical record set.** `cold_rebuild` derives the
layout seed deterministically from the source binding (`derive_layout_seed`),
replays blocks genesis-forward, and every slot is chosen by
`FixedProbeLayout::probe_slots` — a keyed hash of the table kind and the
logical identity under the profile binding. Same source, same seed, same
insertion order, same logical→physical map. Confirmed.

**The annotation targets the slot the scan matched.** `EventScan::Found` now
carries a `BoundEventPage` with the physical slot the probe hit, and
`prepare_event_annotation` writes to exactly that slot with the exact prior
bytes as the compare operand. It cannot address a slot the read schedule did
not visit. Confirmed.

**The annotated value is order-independent and idempotent.** Each write targets
a distinct `(address, ordinal)` cell and overwrites the annotation bits
wholesale — there is no read-modify-accumulate, so no write depends on another
write's result. Re-running a pass with the same generation writes the same
bytes; the executor reports `AnnotationDisposition::Unchanged` and still
performs the write, so idempotence costs nothing in schedule uniformity.
Confirmed.

**The generation input is itself deterministic.** The recent snapshot is
published per generation with a content digest, and its publication sort is
documented as total with an ordinal tiebreak
(`recent_snapshot.rs`), so the snapshot a pass reads is a function of the
generation's public blocks. Confirmed.

**The event log root is unaffected.** Confirmed by inspection of
`ProjectionEventLogAccumulator::append`, per §2.

So the contract extension holds. Two things it does *not* cover, stated rather
than papered over:

- **Physical identity was never claimed and still is not.** "Bit-identical"
  holds for the logical record set and its encoded bytes, not for the ORAM's
  physical arrangement, which is randomized per access. This is unchanged by
  this record.
- **A partial pass is not a function of `(source, generation)`.** A store
  interrupted mid-pass carries a mix of generation *g−1* and *g* annotations.
  That mixed state satisfies no version of the claim, which is why the next
  section makes completeness an obligation on the pass rather than a property
  of the store.

## Obligations on the annotation pass (PR 2)

The contract is only true if the pass satisfies all of these. They are stated
here so the pass can be reviewed against them.

1. **The annotation is a pure function of `(record, its owner, the published
   snapshot for the generation)`.** No clock, no iteration order, no
   host-supplied input, no prior annotation.
2. **The pass is generation-scoped and all-or-nothing at publication.** A
   generation's annotations become readable only through a publication that
   names the generation the pass completed for. An interrupted pass publishes
   nothing and the previous generation stays current.
3. **The pass must not be a query.** It runs at publication over public data.
   Its access pattern may depend on the generation's public shape; it must not
   depend on any client input, because there is none.
4. **The event table's admission limit must be at most `capacity − 2`.**
   `admit_exact_upsert` reserves one spare slot so that an unexpected absence
   can materialize a record before post-schedule classification fails the
   generation closed. A profile sized at exactly `capacity − 1` would admit
   every insert and then refuse every annotation with `UpsertReserveExhausted`.

   **Enforced, not merely documented** (revised 2026-08-19). This ADR
   originally left the bound to whoever sized the profile. That was wrong: a
   precondition whose own validator permits violating it fails silently at the
   first annotation write rather than loudly at configuration.
   `validate_admission_limit` now rejects it, via `reserved_slots(kind)` — the
   event table reserves two slots, the directory table one, because the
   directory holds no annotations and is never upserted. The rejection is a
   distinct `LayoutConfigError::AdmissionLimitLeavesNoUpsertReserve` so the
   reserve violation is not confused with the plain below-capacity bound.

   Consequence: the smallest valid event table is now capacity 4. A two-slot
   event table cannot admit a record and keep the reserve, so it is rejected
   at construction.
5. **A failed annotation write discards the generation.** Already enforced:
   `ExclusiveTwoTableExecutor::update_event` discards on backend failure or
   panic exactly as `insert_event` does, because after either the stored record
   is of uncertain content.
6. **The pass must visit `addresses(snapshot_g) ∪ addresses(snapshot_g−1) ∪
   addresses appended since the last completed pass`** (added 2026-08-19).

   The cost model in `scan_width.rs` scopes one pass to
   `distinct_addresses * store_reads` — the addresses a generation *touches*,
   not every stored address. That scope is what makes the hoist affordable, but
   the naive reading of "touched" — addresses in the generation's finalized
   delta — is not sufficient, and the gap is silent:

   > Address A holds finalized record R. Generation *g−1*'s snapshot contained
   > a spend of R, so R was annotated `survives = false`. In generation *g*
   > that spend is reorged away. It never finalizes, so it produces no
   > finalized delta event for A. If A is not otherwise touched, R keeps
   > `survives = false` and stays invisible to its owner until unrelated
   > activity happens to touch A.

   The union above closes it, and it is complete by construction. An
   annotation is a pure function of `(record, owner, snapshot)` (obligation 1),
   so for a record already annotated at *g−1* the value can differ at *g* only
   if the snapshot's content for that owner differs. Any owner whose content
   differs between the two snapshots appears in at least one of them, because
   `RecentSnapshotSlot` carries the owning `AddressKey` on every occupied slot.
   The third term covers records that had no annotation at *g−1* because they
   were not yet in the finalized store.

   This does not widen the budget. Both snapshot terms are bounded by the
   snapshot's slot count `N`, and the append term is the finalized delta the
   cost model already counts. Deriving the touched set from the snapshots
   themselves — rather than from the finalized delta alone — is what makes the
   pass correct at no extra order of cost.

   Reorg-dropped entries are the motivating case, but the union is stated over
   the snapshots rather than over reorgs specifically, so it holds for any
   reason a snapshot entry disappears without finalizing.

## Consequences

- `UniqueTable` gains `update_present`, a compare-and-set on an occupied slot.
  It is the store's only mutation of a published record, and the history it
  folds from stays append-only.
- The `rostl` backend routes it through the already-qualified
  `fixed_exact_upsert` schedule, which the `fixed-exact-upsert` gate in
  `check-oram-codegen` disassembles and pins. That schedule was already present
  and anchored; this change makes it reachable from real code without adding a
  monomorphization.
- The qualification-memory backend implements the same signature with the same
  *shape* — one slot access, one unconditional store of a selected value,
  classification afterwards — while making no physical-obliviousness claim, as
  it never did.
- Recovery gains one step: replay the source, then re-run one annotation pass
  per current generation. It does not gain a durable-state requirement, and
  `durable_oram_state: false` in the cold-rebuild evidence scope is unchanged.
- The cold-rebuild report is unchanged and still validates, because its
  identity field is the event log root, which annotations do not enter.
