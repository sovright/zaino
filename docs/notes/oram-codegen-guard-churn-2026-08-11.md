# Codegen-guard churn: diagnosis and proposed remedy

Date: 2026-08-11
Status: proposal, for review. No guard code is changed by this note.
Guards in scope:

- `tools/workbench/src/bin/check-oram-codegen.rs` (the access-path guard)
- `tools/workbench/src/bin/check-oram-page-codegen.rs` (the page guard)

## The cost being paid

Five churn events are on record. Two of them ended in a wrong conclusion being
drawn and reported: once a genuine drift was written off as churn, once the
reverse. That is the cost that matters. CI minutes are cheap; a guard whose
failures are routinely noise teaches its readers to wave through the signal,
and at that point the guard has negative value — it costs build time and
supplies false assurance.

So the objective is not "fewer failures". It is **every failure means
something**. A change that removes a failure mode by removing detection is a
regression even though the churn number goes down. Each proposal below is
therefore checked against the question: *could the original kill-gate-2 failure
still be caught?*

## What each guard is actually protecting

**`check-oram-codegen`.** Phase 0 kill-gate 2 failed because the secret
hit/miss boolean returned by `read_and_remap` drove a conditional jump before
the second ORAM access. At the occupancy boundaries the *access schedule*
depended on whether the key was present. The remediation routes that boolean
through `Cmov` and arithmetic only. The guard is a structural regression check
on that remediation: it admits only the measured `Cmov` byte-loop motif, the
RNG refcount drop, and an exact, multiplicity-checked set of call targets, and
rejects everything else. The historical shape — `cmp $0x0,%al` then `je` — is
rejected and covered by a unit test.

**`check-oram-page-codegen`.** A branch-only check is explicitly insufficient
here. A compiler is free to replace the source's sixteen fixed
candidate-selection passes with a branchless **occupancy-indexed memory
access**: data-dependent addressing, no branch to detect. Detecting that
requires knowing the addressing mode of every memory operand, which is why the
guard compares every normalized instruction — including base/index/scale/
displacement — against a reviewed whole-symbol profile.

Both justifications are sound and neither is weakened below.

## 1. Symbol identification: pin the path and the complete instantiation set

### The defect

`check-oram-codegen` pins five raw mangled identities, e.g.

```
_ZN10rostl_oram12circuit_oram20CircuitORAM$LT$V$GT$4read17h18365c90d6304c81E
```

The trailing `17h<hash>` is a compiler disambiguator derived from the
instantiating crate's `-C metadata`, which cargo computes from the dependency
graph. Any change to the dependency graph moves it. That is churn 1 (an
upstream dependency sync) and churn 2 (adding `rcgen`/`yasna`) — in both cases
*every* pinned identity moved at once, which is the signature of a `-C
metadata` change rather than a codegen change. The guard cannot tell those two
apart, so a maintainer must rebuild and re-pin to find out. Nothing about the
guarded property changed in either event.

Churn 5 is worse, and is a soundness hole rather than noise. `random_range` was
pinned as one identity while two instantiations exist. The resolution loop in
`parse_exact_direct_call_symbols` iterates over *pinned* symbols and asserts
each resolves to exactly one address:

```rust
for raw_symbol in target.raw_symbols() {
    let addresses = /* addresses whose name == raw_symbol */;
    let [address] = addresses.as_slice() else { /* mismatch */ };
```

The quantifier runs over the pin, not over the binary. So the message
`"expected exactly one defined raw text identity"` describes the pin. An
instantiation that is present but unpinned is tolerated **silently** — the
guard never looks at it, and a call to it would be classified against whichever
pinned target happens to share its address, or not at all. The header comment
at lines 78-81 concedes the guard cannot decide whether the second
`random_range` was new or always there. That is a subset check presented as an
exact check.

### What the hash is actually load-bearing for

This has to be settled before changing anything, because the guard's own
fixture has two `CircuitORAM::read` instantiations distinguishable *only* by
hash — so "just use the demangled name" is not automatically safe.

Reading the code, it is safe here, for a specific reason. Both read
instantiations map to the **same** classification:

```rust
const fn raw_symbols(self) -> &'static [&'static str] {
    Self::CircuitRead => CIRCUIT_READ_RAW_SYMBOLS,  // both hashes
```

and both are inserted against `ExactDirectCallTarget::CircuitRead`. The guard
never asks *which* read a given call site targets; it asks only whether the
target is one of the approved reads. The hash is therefore **not load-bearing
as a discriminator**. It is load-bearing only as an *existence* assertion —
"this exact thing is present" — and it is precisely that assertion which the
dependency graph invalidates.

This is confirmed by the header comment at lines 82-86, which already admits
the DIRECTORY/EVENT split in the constant names cannot be re-confirmed by the
guard and should be "treated as historical". The names imply an attribution the
code does not implement.

Note also that legacy mangling *drops generic parameters*. `CircuitORAM<V>::read`
for the 38-byte directory record and for the 82-byte event record produce the
same demangled path and the same mangled prefix. The thing that genuinely
distinguishes them — the value type `V` — is not in the symbol at all. The hash
is a proxy for it, and a proxy that is reassigned on every dependency-graph
change is not an identity.

### Proposal 1a — match on the path, assert the complete set

Replace "this exact mangled string exists exactly once" with:

> the mangled **path prefix** (everything up to the `17h` disambiguator) has
> exactly *N* defined text instantiations in this binary, and all *N* addresses
> classify to target *T*.

Concretely, the equivalence class the guard already computes in
`same_path_instantiations` becomes the matching key rather than a diagnostic,
and the pinned data becomes `(path_prefix, expected_instantiation_count)`
instead of a list of full mangled strings.

This is **strictly stronger** than today, in two ways:

1. It closes churn 5's subset hole. A third `random_range` instantiation
   appearing is now a *failure* ("expected 2 instantiations of this path,
   found 3"), not silent tolerance. Today it passes.
2. Every address of the path is registered in `ExactDirectCallSymbols`, so a
   direct call to a previously-unpinned instantiation is classified rather than
   falling through to "unknown call target".

And it is immune to churn 1, 2 and 5's shared cause: the disambiguator is no
longer part of the key, so a `-C metadata` move is invisible.

**What is lost.** Nothing that the guard uses. The two things worth stating
explicitly:

- *Attribution* (which instantiation serves which record type) is lost — but
  the guard never had it. The header already says so. If we want it, see 1b.
- *Cardinality of a specific hash* is lost, replaced by cardinality of the
  path, which is the quantity the guard actually needs and currently gets
  wrong.

The hash is **not** load-bearing anywhere else in either guard. The
`FixedCallTarget` identities (`ThreadRng`, `RcDropSlow`, `PositionMapAccess`,
`PanicInCleanup`) are matched the same way, against `nm` names, and are used
only to resolve `R_X86_64_RELATIVE` addends to a known target — again an
existence-and-classification use, not a discriminator use. The same treatment
applies to them.

One implementation trap to record: `same_path_instantiations` splits on
`rfind("17h")`, which is legacy-mangling-specific. `PanicInCleanup` is already
**v0**-mangled (`_RNvNtCs27Vx93FoQ6z_4core9panicking16panic_in_cleanup`) and
carries its `-C metadata` disambiguator as the `Cs27Vx93FoQ6z_` crate hash
instead. The current helper returns nothing for it, so if that identity moves,
the diagnostic is worse than for the others. Any prefix-extraction function
must handle both mangling schemes, and it should be one shared `fn` used by
both guards rather than two copies — the duplicate-logic lint will require that
anyway.

### Proposal 1b — optional, and probably not now: v0 mangling

`-C symbol-mangling-version=v0` encodes generic parameters in the symbol, so
the two `CircuitORAM::read` instantiations would become distinguishable *by
name* and the DIRECTORY/EVENT attribution would become real rather than
historical. That is a genuine strengthening.

It is not proposed for now, for three reasons: v0 still embeds a crate
disambiguator, so it does not by itself remove churn (the prefix rule above is
still needed); changing the mangling scheme changes every symbol in the binary
and would require re-reviewing and re-emitting all three page profiles; and it
is a build-flag change whose effect on the guarded codegen has to be
re-qualified. Recorded as a follow-up, not folded into this change.

## 2. Stability of the pinned symbols

### `#[inline(never)]` is already there — and did not prevent churn 4

The task suggested adding explicit inlining boundaries. Reading the source,
they are already present, which changes the diagnosis substantially:

```rust
#[cfg(feature = "rostl-experimental")]
#[inline(never)]
fn fixed_add_page_append(...)          // records.rs:1701
```

All three page transforms carry `#[inline(never)]`, and so do
`fixed_unique_insert` (rostl.rs:132) and `fixed_exact_upsert` (rostl.rs:278).
So churn 4 — a genuine 448-byte growth of `fixed_add_page_append` after
`release_schedule.rs` was added to `zainod-oram`, with the transform's own
source untouched — happened **despite** the outermost boundary being pinned.
Adding `#[inline(never)]` where it already exists cannot be the remedy.

### Where the variance actually comes from

The three guarded symbols are thin wrappers. Each calls one shared generic:

```rust
fn fixed_add_page_append(...) -> ... {
    let transition = fixed_page_append(prior.0, found, request.0, ...);
```

and `fixed_page_append` is `#[inline(always)]` (records.rs:1775), as are
`fixed_page_candidate_is_valid` (1823), `fixed_page_u32` (1903) and
`fixed_page_event_ordered` (1915). That is why all three symbols have the same
size and share `EXPECTED_SYMBOL_SIZE = 0xca9`: the guarded body *is* the
inlined transform.

So the first two levels are already forced. What is **not** forced is
everything below: `Cmov::cmov`, which comes from the external
`rostl_primitives` crate, plus whatever `core` slice/iterator machinery the
`zip` and range loops lower through. Those have no explicit attribute here, so
rustc's cost-based inliner decides, and that decision is a function of codegen
unit partitioning.

The workspace sets no `[profile.release]` overrides (only `[profile.test]
opt-level = 3`), so release builds use the defaults: `codegen-units = 16`,
`lto = false`. Under those settings the set of functions available for local
inlining in a given CGU depends on how the crate's code is partitioned across
16 units, and that partition shifts when total code volume shifts. "Unrelated
code volume in the same binary changed the partition" is exactly the mechanism
churn 4's report suspected, and the profile settings are consistent with it.

**This is a hypothesis, not a verified claim.** It is consistent with
everything readable in the tree, but the tree cannot confirm it from a
darwin/arm64 host. See the experiment below.

### Proposal 2 — pin the partition, not more inline attributes

Two candidate remedies, in preference order:

**2a. `codegen-units = 1` for the release profile.** If the partition is the
cause, fixing it at one unit removes the variable entirely: there is no
cross-CGU inlining decision left to shift, and unrelated code volume elsewhere
in the crate can no longer move it. This preserves byte-exact strictness and
removes the churn, which is strictly better than loosening the profile.

Costs, stated honestly:
- Release build time goes up, and loses parallelism within the crate. This
  binary is built once per guard CI run; that is an acceptable trade for a
  deterministic profile.
- It **will itself change the qualified codegen**, almost certainly. The
  existing three profiles were emitted under `codegen-units = 16` and would
  have to be re-emitted with `--emit-profiles` and **re-reviewed by hand** —
  the emit path deliberately prints "emitted profiles require manual assembly
  review before admission", and that review is the whole basis of the guard. So
  this is a one-time re-qualification cost, not a free switch. It must not be
  done by regenerating and committing without review; that would silently
  launder whatever the new codegen is into the approved baseline.
- It must be scoped so the guarded binary and the CI-built binary agree. A
  workspace-level `[profile.release] codegen-units = 1` is the simplest way to
  guarantee that; a target-specific setting risks the guard and the shipped
  artifact diverging.

**2b. `#[inline(never)]` on `Cmov` call sites — rejected.** Worth recording
why, because it is the obvious reading of "add inlining boundaries to the
callees" and it is a trap. The guarded symbols' entire contents arrive by
inlining. Forcing a boundary *below* the wrapper would move the transform body
out of the guarded symbol, leaving the guard inspecting three trivial
forwarding stubs and **guarding nothing** — a silent, total loss of detection
that would still show a green check. If any inline attribute is added below
`fixed_page_append`, the guard must simultaneously gain an assertion that the
guarded symbol still contains the sixteen-pass structure. Simpler not to.

**Experiment that decides between them.** On Linux x86-64, at a single commit:

1. `cargo build -p zainod-oram --all-features --locked --release`, then
   `--emit-profiles` to a scratch directory. Record the three symbol sizes.
2. Add a source file of comparable volume to `release_schedule.rs` to
   `zainod-oram` — dead code, not referenced from the guarded path. Rebuild and
   re-emit. Record sizes again.
3. Repeat both steps with `[profile.release] codegen-units = 1`.

Decision rule: if step 2 reproduces a size change at `codegen-units = 16` and
step 3 shows **no** change at `codegen-units = 1`, the partition hypothesis is
confirmed and 2a is adopted. If step 2 does not reproduce, churn 4 had another
cause — most likely an inlining cost-model input other than partitioning — and
2a should not be adopted on faith; re-open the diagnosis. If step 2 reproduces
but step 3 *also* changes, `codegen-units = 1` is insufficient and the next
candidate is pinning `-C llvm-args` inline thresholds or accepting a
per-instruction profile that tolerates a bounded epilogue.

This experiment must run in CI or on a Linux x86-64 host. It cannot be run
here.

## 3. Stale-base failures

Churn 3: a branch three commits behind `main` produced a spurious
`fixed_add_page_append` size mismatch that a rebase fixed. A stale base alone
can fake a constant-time-guard failure — and, symmetrically, can mask one.

The workflow triggers on `pull_request` with `actions/checkout@v7` and no
explicit `ref`, so it builds the PR **merge** ref, not the head. That usually
means the base is current. But merge refs are computed by GitHub and can lag,
and the workflow's `paths:` filter means a base change that would alter the
guarded codegen does not necessarily re-trigger the job on open PRs. Either way
the important defect is different and simpler:

**the guard reports nothing about what it built against, so a reader cannot
tell.** A failure message today is a size or a diff. It carries no base SHA, no
merge-base distance, no toolchain version, no `Cargo.lock` identity. Faced with
one, the only way to find out whether the base is implicated is to rebase and
rebuild — which is what happened, and which is exactly the ritual that trains
people to assume "rebase and it'll go away".

### Proposal 3 — make every failure self-describing, and fail closed on staleness

Two parts:

**3a. Provenance in the report.** Both guards should print, on success and on
failure, a provenance block: the commit under test, the base branch tip, the
merge-base distance between them, `rustc -Vv`, and a hash of `Cargo.lock`.
These are inputs the guard's result genuinely depends on — `Cargo.lock`
determines the dependency graph that moves disambiguators (churn 1 and 2), and
the toolchain determines the codegen. Emitting them costs nothing and turns
"size mismatch" into "size mismatch, built 3 commits behind base, Cargo.lock
changed since the profile was qualified", which is a diagnosis rather than a
prompt to guess.

The guard binaries should take these as explicit arguments supplied by the
workflow rather than shelling out to `git` themselves — that keeps them pure
functions of an artifact plus declared context, and keeps them runnable against
a downloaded binary.

**3b. CI refuses to run the guard on a stale base.** Add a step before the
build that fails with a clear message if the merge-base of the PR head and the
base branch is not the base tip. The message must say that this is a
*precondition* failure, not a codegen failure — the reader's problem in churn 3
was that a base problem wore a codegen problem's clothes. Failing early, in a
step whose name says "base is current", makes the two impossible to confuse.

This is a fail-closed addition: it can only refuse to produce a verdict, never
produce a passing one it should not have.

## 4. What the guards should not pin

One clear case, in the page guard. Three constants:

```rust
const EXPECTED_SYMBOL_SIZE: u64 = 0xca9;
const EXPECTED_BRANCHES: usize = 26;
const EXPECTED_RETURNS: usize = 1;
```

All three are **already fully determined by the reviewed profile**. Each
profile file is 733 lines of `offset:len:mnemonic:operands`:

```
0000:01:push:%rbp
0001:02:push:%r15
000a:07:sub:$0xe98,%rsp
```

The symbol size is the last offset plus its length. The branch count is the
number of branch mnemonics. The return count is the number of `ret`s. A
whole-symbol profile match is a strict superset of all three checks: no
instruction sequence can satisfy the profile and violate any of them.

Removing them therefore loses **no detection ability whatsoever** — this is
provable by construction, not a judgement call. The occupancy-indexed memory
access the guard exists to catch is caught by the per-instruction operand
comparison, which is untouched.

They are worse than merely redundant. `EXPECTED_SYMBOL_SIZE` is checked in
`parse_guarded_symbols` at line 388, **before** any disassembly happens. So
when the codegen drifts, the first and often only thing the reader sees is

> `fixed_add_page_append` has size 0xe69, expected exactly 0xca9

which says a number changed and nothing about *what* changed. Both churn 3 and
churn 4 presented this way. Had the profile diff been shown instead, churn 4's
448 bytes would have been visibly a block of extra instructions in a specific
region — much closer to the inlining diagnosis — and churn 3's would have been
visibly identical-except-for-layout.

**Proposal 4.** Delete the three constants as independently maintained values
and derive them from the parsed profile at startup, then compare the binary
against the derived values. The invariants stay; they simply stop being a
second place that has to be updated by hand and stop pre-empting the useful
diagnostic. Ordering changes so the profile diff is reported first, with the
derived scalar mismatches as supporting detail.

Deriving rather than deleting matters: it keeps a cheap early check that the
symbol is the right shape before spending time on disassembly, while ensuring
there is exactly one source of truth — the reviewed `.asm` file. That also
satisfies the duplicate-logic lint, which a copy of the counting logic in both
guards would trip.

**What must stay pinned.** Everything else. Specifically and deliberately:

- The complete per-instruction profile, including every register, immediate,
  stack offset, and memory base/index/scale/displacement. This is the only
  thing that can catch an occupancy-indexed memory access, which has no branch.
  Not relaxed, not made order-insensitive, not reduced to a mnemonic histogram.
- `MEASURED_MNEMONICS` as a closed allowlist, and the rule that every
  instruction must be classified before any other check runs.
- The exact `Cmov` loop bounds `$0x26,%rax` and `$0x52,%rax`, and the
  requirement that exactly one 38-byte and one 82-byte record loop is present.
  These are what tie the guarded symbols to the two real record types now that
  the mangled names cannot.
- `EXPECTED_MONOMORPHIZATIONS = 2` and the "cannot pass vacuously" failure.
  This is the guard's protection against the whole check silently evaporating,
  and it becomes *more* important under proposal 2, not less.
- Exact call-target multiplicity per monomorphization
  (`expected_per_monomorphization`). Proposal 1 changes how a target is
  *identified*; it does not relax how many times it may be called.
- The byte-range coverage requirement: no gaps, overlaps, duplicates, or
  inferred final instruction boundary.
- The relocation-proven resolution of indirect calls and the exact SIMD mask
  bytes, including the requirement that the masks come from loaded, allocated,
  relocation-free read-only data.
- `#[inline(never)]` on all five guarded functions. Load-bearing: without it
  the symbols dissolve and there is nothing to inspect.

## Summary of the effect on the five churn events

| # | Cause | Addressed by | Effect |
| --- | --- | --- | --- |
| 1 | dependency sync moved disambiguators | 1a | eliminated |
| 2 | `rcgen`/`yasna` moved all five identities | 1a | eliminated |
| 3 | stale base faked a size mismatch | 3a + 3b | distinguishable; refused early |
| 4 | unrelated code volume grew a symbol | 2a (pending experiment) | eliminated if partition hypothesis holds |
| 5 | unpinned instantiation tolerated silently | 1a | **hole closed** — now fails |

Churn 5 is the one to note: it is the only event where the current guard's
behaviour was unsound rather than noisy, and proposal 1a is the only proposal
here that makes a guard reject something it currently accepts.

## Verification status

Verified by reading the tree on darwin/arm64:

- both guard module headers and their stated justifications;
- `parse_exact_direct_call_symbols` quantifies over pinned symbols, not over
  the binary — the source of churn 5's subset hole;
- both `CircuitORAM::read` instantiations map to the same
  `ExactDirectCallTarget`, so the hash is not used as a discriminator;
- `same_path_instantiations` splits on `17h` and does not handle the
  v0-mangled `PanicInCleanup` identity;
- all five guarded functions already carry `#[inline(never)]`;
- `fixed_page_append` and its callees are all `#[inline(always)]`, so the
  guarded symbol's body is the inlined transform;
- the workspace declares no `[profile.release]`, so release uses
  `codegen-units = 16`, `lto = false`;
- the three page profiles are 733 lines of `offset:len:mnemonic:operands`, from
  which symbol size, branch count and return count are all derivable;
- the workflow builds the PR merge ref and passes no provenance to the guards.

Not verified — requires a Linux x86-64 CI run:

- that `codegen-units = 1` actually stabilises the three page symbols against
  unrelated code volume (the experiment in section 2);
- that churn 4 reproduces at all under a controlled added-volume test;
- the new profile bytes under `codegen-units = 1`, which need manual assembly
  review before admission;
- that the proposed path-prefix matching resolves the same address sets as the
  current hash pins on a real binary, and that the asserted instantiation
  counts are 2, 2, 2 and not something else.

The last of these is a precondition for landing proposal 1a: the counts must be
read off a real qualifying build, not assumed from the current pin list —
assuming them would repeat exactly the mistake churn 5 records.
