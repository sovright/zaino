# 0901 - ORAM codegen guards identify symbols by path and complete instantiation set

## Status

Accepted (design), with **decision 2 withdrawn**: its qualification experiment
was run and refuted the hypothesis it was conditional on. Decisions 1, 3 and 4
stand; their implementation remains pending a Linux x86-64 qualification run.
See "Event 4, resolved".

Fork-only record, allocated from the reserved `0900+` range per
`docs/adr/README.md`. Supersedes nothing. The detailed argument and the
churn evidence are in
`docs/notes/oram-codegen-guard-churn-2026-08-11.md`.

## Context

Two guards protect the ORAM constant-time work:

**`check-oram-codegen`** exists because Phase 0 kill-gate 2 failed. The secret
hit/miss boolean returned by `read_and_remap` drove a conditional jump before
the second ORAM access, so at the occupancy boundaries the ORAM access schedule
depended on whether the key was present. The remediation routes that boolean
through `Cmov` and arithmetic only. The guard is a structural regression check
on that remediation, admitting only the measured `Cmov` byte-loop motif, the
RNG refcount drop, and an exact multiplicity-checked set of call targets.

**`check-oram-page-codegen`** exists because a branch-only check is
insufficient for the fixed-page transforms. A compiler may legally replace the
source's sixteen fixed candidate-selection passes with a branchless
**occupancy-indexed memory access** — data-dependent addressing with no branch
to detect. Catching that requires knowing the addressing mode of every memory
operand, which is why the guard compares every normalized instruction against a
reviewed whole-symbol profile.

Both justifications are sound and both are retained in full.

Over five recorded events the guards failed for reasons unrelated to the
property they protect:

1. an upstream dependency sync moved the `random_range` and `CircuitORAM`
   mangled symbol hashes;
2. adding `rcgen`/`yasna` moved all five pinned identities again;
3. a branch three commits behind `main` produced a spurious
   `fixed_add_page_append` size mismatch that a rebase fixed;
4. a branch adding `release_schedule.rs` to `zainod-oram` produced a genuine
   448-byte growth in `fixed_add_page_append` whose own source was untouched;
   **as first recorded this was misleading** — see "Event 4, resolved" below:
   `records.rs` was untouched but its *crate* was not, and the growth is
   ordinary same-crate optimisation, not the cross-crate mystery this wording
   implies;
5. `random_range` was pinned as one identity while two instantiations exist.

Events 1 and 2 share a cause: mangled hashes embed a disambiguator derived from
the instantiating crate's `-C metadata`, which cargo computes from the
dependency graph. Event 5 is not noise but a soundness hole — the guard
quantifies over the symbols it pins, not over the binary, so an unpinned
instantiation is tolerated silently.

Two of the five ended in a wrong conclusion being drawn and reported: once
genuine drift was called churn, once the reverse. **A guard whose failures are
routinely noise trains its readers to wave through the signal.** That, not CI
time, is the cost this record addresses.

## Decision

### 1. Identify pinned callees by mangled path prefix plus a complete, asserted instantiation count

Stop pinning full mangled identities including the `17h<hash>` disambiguator.
Pin instead `(path_prefix, expected_instantiation_count)`, and require that the
binary contains exactly that many defined text instantiations of the path, with
every one of their addresses classified to the target.

The disambiguator is not load-bearing as a discriminator. Both
`CircuitORAM::read` instantiations already map to the same
`ExactDirectCallTarget`; the guard asks whether a call target is an approved
read, never which read. Legacy mangling drops generic parameters, so the two
share a demangled path and the value type that genuinely distinguishes them is
absent from the symbol entirely — the hash was a proxy for it, and one that the
dependency graph reassigns. The existing `DIRECTORY`/`EVENT` split in the
constant names records an attribution the code does not implement; the guard's
own header already says to treat it as historical.

This removes the cause of events 1 and 2, and **closes** event 5's hole: an
unexpected extra instantiation now fails the guard instead of passing silently.
This is the only change here that makes a guard reject something it currently
accepts.

The path-prefix extraction must handle both legacy (`17h…`) and v0
(`_RNv…Cs…_`) mangling — `core::panicking::panic_in_cleanup` is already
v0-mangled and carries its `-C metadata` disambiguator as a crate hash. One
shared function serves both guards.

Adopting `-C symbol-mangling-version=v0` to recover real per-instantiation
attribution is recorded as a follow-up, not adopted: it does not by itself
remove the churn, and it would invalidate and require re-review of all three
page profiles.

### 2. Pin the codegen-unit partition rather than adding inlining boundaries — REFUTED, NOT ADOPTED

**The qualification experiment this decision was conditional on has been run,
and it does not support the decision. `codegen-units = 1` is not adopted.** The
reasoning below is retained as the record of what was believed and why; the
verdict is in "Event 4, resolved".

`#[inline(never)]` is already present on all five guarded functions, so event 4
occurred despite it and more of it is not the remedy. The guarded page symbols
are thin wrappers whose entire body arrives from `#[inline(always)]`
`fixed_page_append` and its callees; the remaining unforced inlining decisions
lie below that, in `Cmov` and `core` machinery, and are a function of codegen
unit partitioning. The workspace declares no `[profile.release]`, so release
builds use `codegen-units = 16`.

Set `[profile.release] codegen-units = 1` at workspace scope, conditional on a
qualification experiment confirming the partition hypothesis (added dead code
volume perturbs symbol size at 16 units and does not at 1). This preserves
byte-exact strictness and removes the churn, which is strictly better than
loosening the profile.

It is explicitly **not** decided to add `#[inline(never)]` below
`fixed_page_append`. Doing so would move the transform body out of the guarded
symbols, leaving the guard inspecting forwarding stubs and guarding nothing
while still reporting green.

Accepted costs: slower, less parallel release builds; and a one-time
re-emission of all three page profiles, which **must** be reviewed as assembly
before admission. Regenerating and committing profiles without that review
would launder unknown codegen into the approved baseline and is forbidden.

### 3. Make guard failures self-describing, and refuse a stale base

Guards print a provenance block on success and failure: commit under test, base
branch tip, merge-base distance, `rustc -Vv`, and a `Cargo.lock` hash. These
are real inputs to the verdict — `Cargo.lock` determines the dependency graph
behind events 1 and 2. They are passed in as arguments by the workflow rather
than shelled out for, keeping the guards pure functions of an artifact plus
declared context.

CI gains a step, before the build, that fails when the merge-base of head and
base is not the base tip, with a message naming it a precondition failure
rather than a codegen failure. Event 3's damage was that a base problem wore a
codegen problem's clothes; a separately named early step makes them impossible
to confuse. This can only refuse to produce a verdict, never produce a passing
one.

### 4. Derive `EXPECTED_SYMBOL_SIZE`, `EXPECTED_BRANCHES` and `EXPECTED_RETURNS` from the profile

These three page-guard constants are already fully determined by the reviewed
profile, which records `offset:len:mnemonic:operands` for all 733 instructions:
size is the last offset plus its length, and the two counts are mnemonic
tallies. A whole-symbol profile match is a strict superset of all three checks,
so deriving them loses no detection ability — this is true by construction, not
a judgement call.

They are also actively harmful as separate pins. `EXPECTED_SYMBOL_SIZE` is
checked during symbol parsing, before any disassembly, so real drift surfaces
as "size 0xe69, expected 0xca9" — a changed number with no indication of what
changed. Events 3 and 4 both presented this way, and both were misdiagnosed.
Reporting the profile diff first, with derived scalars as supporting detail,
would have shown event 4 as a block of extra instructions in a specific region.

Deriving rather than deleting keeps a cheap pre-disassembly shape check while
leaving exactly one source of truth, the reviewed `.asm` file, and avoids the
duplicated counting logic that the duplicate-logic lint would reject.

## Event 4, resolved

Run `31953340068` executed the decision-2 experiment on Linux x86-64 via
`tools/scripts/codegen-guard-stability-experiment.sh`: build, measure the
guarded symbols, add inert reachable code volume, rebuild, measure again, diff
— strictly within each `codegen-units` setting, never against pins generated at
a different one.

**Result: stable at 16 and stable at 1.** Injected volume did not move the
guarded symbols at either setting. By this record's own rule that refutes the
partition hypothesis, so decision 2 is withdrawn rather than adopted on faith,
and the diagnosis reopens here.

**The premise was wrong, not just the conclusion.** Event 4 was recorded as
`release_schedule.rs` being added to `zainod-oram` while `records.rs` was
untouched — which reads as unrelated code in a *different crate* perturbing the
symbol. But the same branch adds 176 lines to `zaino-oram`, the crate
`records.rs` lives in, 149 of them in `inner_codec/runtime.rs`. The experiment
perturbed `zainod-oram`, following this record's framing, and correctly found
no effect: cross-crate volume is not what moved anything.

**What actually happened**, from the disassembly of all three symbols:

- All three grew identically to `0xe69`, not just `fixed_add_page_append`. The
  guard aborts on the first symbol, which is why this looked isolated.
- Branches, returns and calls are unchanged: exactly 26, 1 and 4, matching
  `EXPECTED_BRANCHES`, `EXPECTED_RETURNS` and `LibcCall::EXPECTED`. The growth
  is entirely straight-line.
- The new instructions are a vectorised byte-wise record serialisation:
  constant shifts (`shr $0x28/$0x30/$0x38`, `psrld $0x8/$0x10/$0x18`) split 64-
  and 32-bit fields into bytes, and a `punpcklbw` → `punpcklwd` → `punpckldq` →
  `punpcklqdq` ladder reassembles them into 128-bit vectors. Shift counts are
  immediates; memory operands are constant displacements from a base register.
  Nothing is indexed, shifted or branched on by data.

So new code in `zaino-oram` changed the optimiser's cost decisions for that
crate and enabled auto-vectorisation of loops in `records.rs`. That is ordinary
same-crate behaviour, not partition instability, and it is **benign** under the
property these guards protect.

Two consequences that are not benign, and remain open:

1. The vectorised code loads a **third** RIP-relative constant — `movd`, 4
   bytes, into `%xmm9`, from an anonymous LLVM constant pool. The guard admits
   RIP-relative data loads only as `pand` into `%xmm3`/`%xmm7` reading 16
   bytes, and `validate_measured_shape` asserts `masks == [FIRST_MASK,
   SECOND_MASK]` — exactly two, exactly those values. Admitting a third
   constant means generalising that invariant to N constants of declared width,
   each with pinned bytes and the same read-only, relocation-free provenance
   proof. That is a change to the mechanism proving the SIMD constants have not
   moved, and it needs its own reviewed change.
2. `MEASURED_MNEMONICS` gains `pandn`, `pslld`, `punpckldq` and `punpcklwd`,
   all data-independent by construction: counts and permutations come from
   immediates or the opcode, never from an operand that could carry secret
   data. `pshufb`, whose mask is register-supplied, stays out — that is the
   line. Three entries (`cmpq`, `pinsrw`, `psllq`) no longer appear and must be
   removed to preserve the allowlist's set-equality with the profiles.

A follow-up experiment perturbing `zaino-oram` rather than `zainod-oram` would
confirm the same-crate explanation directly. It has not been run: the
disassembly already establishes the growth is benign, so its value is
explanatory rather than gating.

## What remains deliberately strict

Nothing below is relaxed, and no proposal that would relax it may be adopted on
churn-reduction grounds:

- **The complete per-instruction page profile** — every register, immediate,
  stack offset, and memory base/index/scale/displacement, in order. This is the
  only thing that can catch an occupancy-indexed memory access, which has no
  branch. It is not made order-insensitive and not reduced to a mnemonic
  histogram.
- `MEASURED_MNEMONICS` as a closed allowlist, with every instruction
  classified before any other check runs.
- The exact `Cmov` loop bounds `$0x26,%rax` and `$0x52,%rax`, and the
  requirement of exactly one 38-byte and one 82-byte record loop. With mangled
  hashes gone, these are what tie the guarded symbols to the two real record
  types.
- `EXPECTED_MONOMORPHIZATIONS = 2` and the "cannot pass vacuously" failure —
  the protection against the check silently evaporating. More important under
  decision 2, not less.
- Exact call-target multiplicity per monomorphization. Decision 1 changes how a
  target is identified, never how many times it may be called.
- Byte-range coverage with no gaps, overlaps, duplicates, or inferred final
  instruction boundary.
- Relocation-proven resolution of indirect calls, and the exact SIMD mask bytes
  drawn only from loaded, allocated, relocation-free read-only data.
- `#[inline(never)]` on all five guarded functions.
- Rejection of the historical failure shape — a forward jump on a compare
  against the returned boolean — and the unit test covering it.

Neither guard becomes semantic taint analysis. Both remain fail-closed
structural regression profiles, and libc dispatch remains an explicit
transitive assumption.

## Consequences

- Events 1, 2 and 5 are eliminated by decision 1, with 5 additionally becoming
  a detected failure rather than a silent pass.
- Event 3 becomes a distinct, early, correctly named CI failure.
- Event 4 is **not** eliminated: the experiment did not reproduce the
  hypothesis, decision 2 is withdrawn, and the cause is instead ordinary
  same-crate optimisation enabling auto-vectorisation. Build settings are
  unchanged as a result.
- A one-time cost stands regardless, for a different reason: all three page
  profiles must be re-emitted and re-reviewed as assembly, because the
  vectorised codegen is the new baseline. The assembly review is done; the
  profiles cannot be admitted until the third RIP-relative constant is
  representable.
- Re-pinning after a dependency bump stops being routine work, so a guard
  failure again carries information.

## Open items before implementation

The instantiation counts asserted by decision 1 must be read off a real
qualifying Linux x86-64 build, never assumed from the current pin list —
assuming them would repeat exactly the mistake event 5 records.

The partition experiment for decision 2 **has now been run** (run
`31953340068`) and refuted the hypothesis; decision 2 is withdrawn and nothing
remains open under it.

What replaces it, before the page profiles can be regenerated: generalise the
RIP-relative constant mechanism from exactly two 16-byte `pand` masks to N
constants of declared width, each with pinned bytes and the existing
provenance proof. Until that exists, `--emit-profiles` cannot produce an
admissible profile for the vectorised codegen, and `check-oram-page-codegen`
correctly fails on any branch carrying it.
