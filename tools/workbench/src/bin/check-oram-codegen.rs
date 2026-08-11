//! Guard: the ORAM insertion access path matches one approved codegen profile.
//!
//! Phase 0 kill-gate 2 failed because the secret hit/miss boolean returned by
//! `read_and_remap` drove a conditional jump before the second ORAM access, so
//! at the occupancy boundaries the access schedule itself depended on whether
//! the key was present. The remediation routes that boolean into `Cmov` and
//! arithmetic only. This structural regression check rejects codegen outside
//! the exact reviewed profile; it is not semantic taint analysis and does not
//! prove that arbitrary callees or future compiler transformations are
//! oblivious.
//!
//! # Why this is not simply "no conditional jumps"
//!
//! The remediated *source* has no control flow, but its *codegen* does. Review
//! of the native x86_64 artifact admitted these two structural shapes:
//!
//! - `Cmov` on a record expands to a byte-wise loop whose trip count is the
//!   compile-time record width (`cmp $0x26,%rax` for the 38-byte directory
//!   record, `cmp $0x52,%rax` for the 82-byte event record). The secret feeds
//!   only the `cmovne` inside the loop; the bound is a constant.
//! - Releasing the thread-local RNG handle emits a refcount decrement and a
//!   drop-path jump (`decq 0x0(%r13)` then `jne`).
//! - The PIE linker lowers five calls per monomorphization through local GOT
//!   slots. Each slot must carry an `R_X86_64_RELATIVE` relocation to one
//!   exact, defined text symbol; register dispatch, unresolved slots, and
//!   dynamically resolved calls remain forbidden.
//!
//! Neither reviewed shape depends on the secret, so rejecting every conditional
//! jump would reject the measured implementation. This check therefore permits
//! only their complete measured instruction motifs, requires their exact
//! multiplicity per monomorphization, and rejects everything else. Before
//! classification, every instruction must have an approved measured mnemonic
//! and its raw bytes must cover the exact `nm` symbol range without gaps,
//! overlaps, duplicates, or an inferred final instruction boundary. The
//! `fixed-exact-upsert` profile additionally rejects every direct call except
//! four exact, multiplicity-checked dependency targets and `_Unwind_Resume@plt`.
//! This prevents a compiler-lowered `memcmp`/`bcmp` or an unknown helper from
//! moving uninspected control flow outside the symbol. Its indirect-call
//! allowances remain tied to exact relocation-proven fixed targets. The legacy
//! `fixed-unique-insert` profile retains its measured call policy unchanged.
//!
//! The historical failure — a *forward* jump immediately after a compare
//! against the returned boolean (`cmp $0x0,%al` then `je`) — matches neither
//! allowance and is still rejected. That case is covered by a unit test.
//!
//! `fixed_unique_insert` carries `#[inline(never)]` so each monomorphization
//! keeps its own symbol. That attribute is load-bearing for this check: without
//! it the function dissolves into its caller and there is nothing to inspect.
//!
//! Usage:
//!
//! - `check-oram-codegen <path-to-x86_64-elf>` guards `fixed_unique_insert`.
//! - `check-oram-codegen --profile fixed-exact-upsert <path-to-x86_64-elf>`
//!   guards `fixed_exact_upsert`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use workbench::{command as tool, encoded_byte_len, is_gnu_prefix, run};

/// The original access-path function whose body must match the approved
/// profile. These constants remain the default so the historical one-argument
/// invocation keeps the exact same guard.
const GUARDED: &str = "fixed_unique_insert";
const GUARDED_SYMBOL: &str = "zaino_oram::layout::atomic_store::worker::rostl::fixed_unique_insert";

const FIXED_EXACT_UPSERT: &str = "fixed_exact_upsert";
const FIXED_EXACT_UPSERT_SYMBOL: &str =
    "zaino_oram::layout::atomic_store::worker::rostl::fixed_exact_upsert";

// Re-pinned from the qualifying Linux x86_64 release build after the upstream
// sync. Every `17h<hash>` disambiguator moved at once, which is what a
// dependency-graph change does: cargo derives `-C metadata` from it.
//
// `read` and `write_or_insert` each had two instantiations before and have two
// now, so for them this is churn. `random_range` is different: only one
// identity was ever pinned while two are present, so the guard counted
// addresses for the pinned symbol alone. Whether the second appeared with this
// sync or was always there and unpinned is not decidable from what the guard
// reports, so both are pinned here and the question is left open rather than
// answered by assumption.
//
// The DIRECTORY/EVENT split in these names records the original qualification's
// attribution. This re-pin cannot re-confirm it: the guard reports which
// instantiations exist for a path, not which record type each serves, and both
// map to the same target either way. Treat the suffix as historical.
const RANDOM_RANGE_RAW_SYMBOL: &str = "_ZN4rand3rng3Rng12random_range17h43bc1d42da279629E";
const RANDOM_RANGE_SECOND_RAW_SYMBOL: &str = "_ZN4rand3rng3Rng12random_range17hb9510b448ebef3c3E";
const CIRCUIT_READ_RAW_SYMBOL: &str =
    "_ZN10rostl_oram12circuit_oram20CircuitORAM$LT$V$GT$4read17h18365c90d6304c81E";
const CIRCUIT_EVENT_READ_RAW_SYMBOL: &str =
    "_ZN10rostl_oram12circuit_oram20CircuitORAM$LT$V$GT$4read17h79d3bb87fa7ca204E";
const CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOL: &str =
    "_ZN10rostl_oram12circuit_oram20CircuitORAM$LT$V$GT$15write_or_insert17h1408426bfb5e61feE";
const CIRCUIT_EVENT_WRITE_OR_INSERT_RAW_SYMBOL: &str =
    "_ZN10rostl_oram12circuit_oram20CircuitORAM$LT$V$GT$15write_or_insert17ha119a6051f7d95a7E";
const UNWIND_DYNAMIC_SYMBOL: &str = "_Unwind_Resume@GCC_3.0";

const RANDOM_RANGE_RAW_SYMBOLS: &[&str] =
    &[RANDOM_RANGE_RAW_SYMBOL, RANDOM_RANGE_SECOND_RAW_SYMBOL];
const CIRCUIT_READ_RAW_SYMBOLS: &[&str] = &[CIRCUIT_READ_RAW_SYMBOL, CIRCUIT_EVENT_READ_RAW_SYMBOL];
const CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOLS: &[&str] = &[
    CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOL,
    CIRCUIT_EVENT_WRITE_OR_INSERT_RAW_SYMBOL,
];

/// Both record monomorphizations must be present: the 38-byte directory record
/// and the 82-byte event record. Finding fewer means the build did not select
/// the typed backend and the check would otherwise pass vacuously.
const EXPECTED_MONOMORPHIZATIONS: usize = 2;

/// Exact fixed-size `Cmov` loop bounds measured for the two guarded records.
const DIRECTORY_RECORD_LOOP_COMPARE: &str = "$0x26,%rax";
const EVENT_RECORD_LOOP_COMPARE: &str = "$0x52,%rax";

/// Exact thread-local RNG refcount decrement measured on the pinned toolchain.
const RNG_REFCOUNT_DECREMENT: &str = "0x0(%r13)";

fn main() {
    run("check-oram-codegen", check, |report: Report| {
        let guarded = report.profile.guarded();
        for symbol in &report.symbols {
            for allowed in &symbol.allowed {
                println!("check-oram-codegen: allowed — {allowed}");
            }
            println!(
                "check-oram-codegen: ok — {} instructions match the approved structural profile in {}",
                symbol.instructions, symbol.name
            );
        }
        println!(
            "check-oram-codegen: ok — {} `{guarded}` monomorphizations match the approved structural codegen profile",
            report.symbols.len()
        );
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardedProfile {
    FixedUniqueInsert,
    FixedExactUpsert,
}

impl GuardedProfile {
    fn from_selector(selector: &str) -> Option<Self> {
        match selector {
            "fixed-unique-insert" => Some(Self::FixedUniqueInsert),
            "fixed-exact-upsert" => Some(Self::FixedExactUpsert),
            _ => None,
        }
    }

    const fn guarded(self) -> &'static str {
        match self {
            Self::FixedUniqueInsert => GUARDED,
            Self::FixedExactUpsert => FIXED_EXACT_UPSERT,
        }
    }

    const fn guarded_symbol(self) -> &'static str {
        match self {
            Self::FixedUniqueInsert => GUARDED_SYMBOL,
            Self::FixedExactUpsert => FIXED_EXACT_UPSERT_SYMBOL,
        }
    }

    const fn expected_monomorphizations(self) -> usize {
        EXPECTED_MONOMORPHIZATIONS
    }
}

#[derive(Debug)]
struct Invocation {
    profile: GuardedProfile,
    artifact: std::path::PathBuf,
}

struct Report {
    profile: GuardedProfile,
    symbols: Vec<Inspected>,
}

struct Inspected {
    name: String,
    instructions: usize,
    allowed: Vec<String>,
    record_loop: RecordLoop,
}

/// One defined symbol with a known address and size.
struct Symbol {
    name: String,
    address: u64,
    size: u64,
}

/// One decoded instruction from an `objdump` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Instruction {
    address: u64,
    mnemonic: String,
    operands: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedInstruction {
    instruction: Instruction,
    encoded_len: Option<u64>,
}

impl Instruction {
    fn has_prefix(&self) -> bool {
        self.mnemonic.contains(' ')
    }

    fn bare_mnemonic(&self) -> &str {
        self.mnemonic
            .rsplit_once(' ')
            .map_or(self.mnemonic.as_str(), |(_, mnemonic)| mnemonic)
    }
}

/// What a single instruction means for the guarded property.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not a branch at all, or an unconditional direct jump.
    Branchless,
    /// A branch that is structurally independent of the secret.
    Allowed(Allowance),
    /// A branch that could carry the secret.
    Rejected(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Allowance {
    DirectoryRecordLoop,
    EventRecordLoop,
    DirectoryEqualityReduction,
    EventEqualityReduction,
    RngRefcountDrop,
    ExactCleanupJump,
    ExactDirectCall(ExactDirectCallTarget),
    FixedCall(FixedCallTarget),
}

impl Allowance {
    const fn description(self) -> &'static str {
        match self {
            Self::DirectoryRecordLoop => "38-byte record Cmov loop back-edge",
            Self::EventRecordLoop => "82-byte record Cmov loop back-edge",
            Self::DirectoryEqualityReduction => "38-byte fixed-width equality reduction",
            Self::EventEqualityReduction => "82-byte fixed-width equality reduction",
            Self::RngRefcountDrop => "thread-local RNG reference-count drop branch",
            Self::ExactCleanupJump => "exact-upsert cleanup jump to unwind",
            Self::ExactDirectCall(target) => target.description(),
            Self::FixedCall(target) => target.description(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactDirectCallTarget {
    RandomRange,
    CircuitRead,
    CircuitWriteOrInsert,
    UnwindResume,
}

impl ExactDirectCallTarget {
    const EXPECTED_ORDER: [Self; 5] = [
        Self::RandomRange,
        Self::CircuitRead,
        Self::RandomRange,
        Self::CircuitWriteOrInsert,
        Self::UnwindResume,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::RandomRange => "rand::rng::Rng::random_range",
            Self::CircuitRead => "rostl_oram::circuit_oram::CircuitORAM<V>::read",
            Self::CircuitWriteOrInsert => {
                "rostl_oram::circuit_oram::CircuitORAM<V>::write_or_insert"
            }
            Self::UnwindResume => "_Unwind_Resume@plt",
        }
    }

    const fn raw_symbols(self) -> &'static [&'static str] {
        match self {
            Self::RandomRange => RANDOM_RANGE_RAW_SYMBOLS,
            Self::CircuitRead => CIRCUIT_READ_RAW_SYMBOLS,
            Self::CircuitWriteOrInsert => CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOLS,
            Self::UnwindResume => &[],
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::RandomRange => "exact direct call to rand::rng::Rng::random_range",
            Self::CircuitRead => "exact direct call to CircuitORAM<V>::read",
            Self::CircuitWriteOrInsert => "exact direct call to CircuitORAM<V>::write_or_insert",
            Self::UnwindResume => "exact direct call to _Unwind_Resume@plt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedCallTarget {
    ThreadRng,
    RcDropSlow,
    PositionMapAccess,
    PanicInCleanup,
}

impl FixedCallTarget {
    const ALL: [Self; 4] = [
        Self::ThreadRng,
        Self::RcDropSlow,
        Self::PositionMapAccess,
        Self::PanicInCleanup,
    ];

    const fn identity(self) -> &'static str {
        match self {
            Self::ThreadRng => "_ZN4rand4rngs6thread3rng17h25d391ca23111651E",
            Self::RcDropSlow => {
                "_ZN5alloc2rc15Rc$LT$T$C$A$GT$9drop_slow17hc939a64f1143612fE"
            }
            Self::PositionMapAccess => {
                "_ZN10rostl_oram14recursive_oram20RecursivePositionMap15access_position17h56ba6b451895665bE"
            }
            Self::PanicInCleanup => "_RNvNtCs27Vx93FoQ6z_4core9panicking16panic_in_cleanup",
        }
    }

    const fn symbol(self) -> &'static str {
        match self {
            Self::ThreadRng => "rand::rngs::thread::rng",
            Self::RcDropSlow => "alloc::rc::Rc<T,A>::drop_slow",
            Self::PositionMapAccess => {
                "rostl_oram::recursive_oram::RecursivePositionMap::access_position"
            }
            Self::PanicInCleanup => "core::panicking::panic_in_cleanup",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::ThreadRng => "fixed relative call to rand::rngs::thread::rng",
            Self::RcDropSlow => "fixed relative call to alloc::rc::Rc<T,A>::drop_slow",
            Self::PositionMapAccess => {
                "fixed relative call to RecursivePositionMap::access_position"
            }
            Self::PanicInCleanup => "fixed relative call to core::panicking::panic_in_cleanup",
        }
    }

    const fn expected_per_monomorphization(self, profile: GuardedProfile) -> usize {
        match (profile, self) {
            (GuardedProfile::FixedUniqueInsert, Self::RcDropSlow) => 2,
            (
                GuardedProfile::FixedUniqueInsert,
                Self::ThreadRng | Self::PositionMapAccess | Self::PanicInCleanup,
            ) => 1,
            (GuardedProfile::FixedExactUpsert, Self::RcDropSlow) => 4,
            (
                GuardedProfile::FixedExactUpsert,
                Self::ThreadRng | Self::PositionMapAccess | Self::PanicInCleanup,
            ) => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicRelocation {
    kind: String,
    relative_target: Option<FixedCallTarget>,
    dynamic_symbol: Option<String>,
}

type DynamicRelocations = BTreeMap<u64, DynamicRelocation>;
type TextSymbols = BTreeMap<u64, Vec<String>>;
type ExactDirectCallSymbols = BTreeMap<u64, ExactDirectCallTarget>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordLoop {
    Directory,
    Event,
}

fn check() -> Result<Report, Vec<String>> {
    let invocation = invocation()?;
    let profile = invocation.profile;
    let artifact = invocation.artifact;
    let symbols = guarded_symbols(&artifact, profile)?;
    let text_symbols = defined_text_symbols(&artifact)?;
    let relocations = dynamic_relocations(&artifact, &text_symbols)?;
    let exact_direct_calls = match profile {
        GuardedProfile::FixedUniqueInsert => ExactDirectCallSymbols::new(),
        GuardedProfile::FixedExactUpsert => {
            exact_direct_call_symbols(&artifact, &text_symbols, &relocations)?
        }
    };

    let expected_monomorphizations = profile.expected_monomorphizations();
    if symbols.len() != expected_monomorphizations {
        let guarded = profile.guarded();
        return Err(vec![
            format!(
                "found {} `{guarded}` symbol(s) in {}, expected exactly {expected_monomorphizations}",
                symbols.len(),
                artifact.display()
            ),
            "this check cannot pass vacuously: build with the typed rostl backend \
             selected, and keep #[inline(never)] on the function"
                .to_string(),
        ]);
    }

    let mut inspected = Vec::new();
    let mut failures = Vec::new();
    for symbol in symbols {
        match inspect(
            &artifact,
            &symbol,
            &relocations,
            &exact_direct_calls,
            profile,
        ) {
            Ok(report) => inspected.push(report),
            Err(lines) => failures.extend(lines),
        }
    }
    if !failures.is_empty() {
        failures.push(
            "the ORAM access path does not match the approved structural codegen profile; \
             this checker is a regression profile, not semantic taint proof"
                .to_string(),
        );
        return Err(failures);
    }

    let directory = inspected
        .iter()
        .filter(|symbol| symbol.record_loop == RecordLoop::Directory)
        .count();
    let event = inspected
        .iter()
        .filter(|symbol| symbol.record_loop == RecordLoop::Event)
        .count();
    if directory != 1 || event != 1 {
        return Err(vec![format!(
            "guarded symbols did not contain exactly one 38-byte and one 82-byte record loop; \
             found directory={directory}, event={event}"
        )]);
    }
    Ok(Report {
        profile,
        symbols: inspected,
    })
}

fn invocation() -> Result<Invocation, Vec<String>> {
    let invocation = parse_invocation(std::env::args_os().skip(1).collect())?;
    if !invocation.artifact.is_file() {
        return Err(vec![format!(
            "not a file: {}",
            invocation.artifact.display()
        )]);
    }
    Ok(invocation)
}

fn parse_invocation(args: Vec<OsString>) -> Result<Invocation, Vec<String>> {
    const USAGE: &str = "usage: check-oram-codegen <path-to-x86_64-elf>";
    const PROFILE_USAGE: &str = "usage: check-oram-codegen --profile \
                                 <fixed-unique-insert|fixed-exact-upsert> \
                                 <path-to-x86_64-elf>";

    match args.as_slice() {
        [] => Err(vec![USAGE.to_string()]),
        [flag] if flag == "--profile" => Err(vec![PROFILE_USAGE.to_string()]),
        [artifact] => Ok(Invocation {
            profile: GuardedProfile::FixedUniqueInsert,
            artifact: artifact.into(),
        }),
        [flag, selector, artifact] if flag == "--profile" => {
            let selector = selector
                .to_str()
                .ok_or_else(|| vec!["codegen profile selector is not utf-8".to_string()])?;
            let profile = GuardedProfile::from_selector(selector).ok_or_else(|| {
                vec![
                    format!("unknown ORAM codegen profile: {selector}"),
                    PROFILE_USAGE.to_string(),
                ]
            })?;
            Ok(Invocation {
                profile,
                artifact: artifact.into(),
            })
        }
        _ => Err(vec![PROFILE_USAGE.to_string()]),
    }
}

/// Every defined, sized text symbol with the exact guarded demangled name.
///
/// Legacy symbol mangling drops generic parameters, so the monomorphizations
/// are distinguished by count and size rather than by record type name.
fn guarded_symbols(artifact: &Path, profile: GuardedProfile) -> Result<Vec<Symbol>, Vec<String>> {
    let listing = tool(
        "nm",
        &["-nSC", "--defined-only", &artifact.display().to_string()],
    )?;
    parse_guarded_symbols_for_profile(&listing, profile)
}

#[cfg(test)]
fn parse_guarded_symbols(listing: &str) -> Result<Vec<Symbol>, Vec<String>> {
    parse_guarded_symbols_for_profile(listing, GuardedProfile::FixedUniqueInsert)
}

fn parse_guarded_symbols_for_profile(
    listing: &str,
    profile: GuardedProfile,
) -> Result<Vec<Symbol>, Vec<String>> {
    let guarded = profile.guarded();
    let guarded_symbol = profile.guarded_symbol();
    let mut symbols = Vec::new();
    for line in listing.lines() {
        if !line.contains(guarded) {
            continue;
        }
        // `<address> <size> <type> <name>`; unsized symbols have three fields
        // and cannot establish a safe disassembly range.
        let mut fields = line.split_whitespace();
        let (Some(address), Some(size), Some(kind)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(vec![format!("malformed `{guarded}` symbol line: {line}")]);
        };
        let name = fields.collect::<Vec<_>>().join(" ");
        if !matches!(kind, "T" | "t") {
            return Err(vec![format!("`{guarded}` symbol is not text: {line}")]);
        }
        if name != guarded_symbol {
            return Err(vec![format!(
                "unexpected demangled `{guarded}` symbol identity: {line}"
            )]);
        }
        let address = u64::from_str_radix(address, 16)
            .map_err(|_| vec![format!("invalid `{guarded}` symbol address: {line}")])?;
        let size = u64::from_str_radix(size, 16)
            .map_err(|_| vec![format!("invalid `{guarded}` symbol size: {line}")])?;
        if size == 0 {
            return Err(vec![format!("zero-sized `{guarded}` symbol: {line}")]);
        }
        address
            .checked_add(size)
            .ok_or_else(|| vec![format!("`{guarded}` symbol range overflows: {line}")])?;
        symbols.push(Symbol {
            name,
            address,
            size,
        });
    }
    symbols.sort_by_key(|symbol| symbol.address);
    for adjacent in symbols.windows(2) {
        let previous_end = adjacent[0]
            .address
            .checked_add(adjacent[0].size)
            .ok_or_else(|| {
                vec![format!(
                    "`{guarded}` symbol range overflows: {}",
                    adjacent[0].name
                )]
            })?;
        if adjacent[1].address < previous_end {
            return Err(vec![format!(
                "overlapping `{guarded}` symbols: {} and {}",
                adjacent[0].name, adjacent[1].name
            )]);
        }
    }
    Ok(symbols)
}

/// Dynamic relocation slots, with `R_X86_64_RELATIVE` addends resolved only
/// when they name one of the exact defined text symbols in the fixed-call
/// profile.
fn dynamic_relocations(
    artifact: &Path,
    text_symbols: &TextSymbols,
) -> Result<DynamicRelocations, Vec<String>> {
    let listing = tool("objdump", &["-R", &artifact.display().to_string()])?;
    parse_dynamic_relocations(&listing, text_symbols)
}

fn defined_text_symbols(artifact: &Path) -> Result<TextSymbols, Vec<String>> {
    let listing = tool(
        "nm",
        &["-nS", "--defined-only", &artifact.display().to_string()],
    )?;
    parse_defined_text_symbols(&listing)
}

fn parse_defined_text_symbols(listing: &str) -> Result<TextSymbols, Vec<String>> {
    let mut symbols = TextSymbols::new();
    let mut expected_addresses = BTreeMap::<&'static str, u64>::new();
    for line in listing.lines() {
        let expected_in_line = FixedCallTarget::ALL
            .into_iter()
            .find(|target| line.contains(target.identity()));
        let mut fields = line.split_whitespace();
        let (Some(address), Some(size), Some(kind)) = (fields.next(), fields.next(), fields.next())
        else {
            if expected_in_line.is_some() {
                return Err(vec![format!("malformed expected text symbol: {line}")]);
            }
            continue;
        };
        let name = fields.collect::<Vec<_>>().join(" ");
        let expected = FixedCallTarget::ALL
            .into_iter()
            .find(|target| name == target.identity());
        if !matches!(kind, "T" | "t") {
            if expected.is_some() {
                return Err(vec![format!("expected symbol is not text: {line}")]);
            }
            continue;
        }
        let Ok(address) = u64::from_str_radix(address, 16) else {
            if expected.is_some() {
                return Err(vec![format!(
                    "invalid expected text-symbol address: {line}"
                )]);
            }
            continue;
        };
        let Ok(size) = u64::from_str_radix(size, 16) else {
            if expected.is_some() {
                return Err(vec![format!("invalid expected text-symbol size: {line}")]);
            }
            continue;
        };
        if let Some(target) = expected {
            if size == 0 {
                return Err(vec![format!("zero-sized expected text symbol: {line}")]);
            }
            if expected_addresses
                .insert(target.identity(), address)
                .is_some()
            {
                return Err(vec![format!(
                    "expected text symbol identity appears multiple times: {}",
                    target.identity()
                )]);
            }
        }
        if !name.is_empty() {
            symbols.entry(address).or_default().push(name);
        }
    }
    Ok(symbols)
}

fn parse_dynamic_relocations(
    listing: &str,
    text_symbols: &TextSymbols,
) -> Result<DynamicRelocations, Vec<String>> {
    let mut relocations = DynamicRelocations::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(slot), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !kind.starts_with("R_X86_64_") {
            continue;
        }
        let slot = u64::from_str_radix(slot, 16)
            .map_err(|_| vec![format!("invalid dynamic-relocation slot: {line}")])?;
        let payload = fields.collect::<Vec<_>>();
        let relative_target = if kind == "R_X86_64_RELATIVE" {
            let addend = payload
                .first()
                .copied()
                .and_then(parse_relative_addend)
                .ok_or_else(|| vec![format!("invalid relative-relocation addend: {line}")])?;
            let candidates = text_symbols
                .get(&addend)
                .map(|names| {
                    FixedCallTarget::ALL
                        .into_iter()
                        .filter(|target| names.iter().any(|name| name == target.identity()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            match candidates.as_slice() {
                [] => None,
                [target] => Some(*target),
                _ => {
                    return Err(vec![format!(
                        "ambiguous expected text targets for relocation slot {slot:x}: {line}"
                    )]);
                }
            }
        } else {
            None
        };
        let dynamic_symbol = if kind == "R_X86_64_RELATIVE" || payload.is_empty() {
            None
        } else {
            Some(payload.join(" "))
        };
        let previous = relocations.insert(
            slot,
            DynamicRelocation {
                kind: kind.to_string(),
                relative_target,
                dynamic_symbol,
            },
        );
        if previous.is_some() {
            return Err(vec![format!(
                "duplicate dynamic-relocation slot {slot:x}: {line}"
            )]);
        }
    }
    Ok(relocations)
}

fn parse_relative_addend(value: &str) -> Option<u64> {
    let value = value.strip_prefix("*ABS*+0x")?;
    u64::from_str_radix(value, 16).ok()
}

fn exact_direct_call_symbols(
    artifact: &Path,
    text_symbols: &TextSymbols,
    relocations: &DynamicRelocations,
) -> Result<ExactDirectCallSymbols, Vec<String>> {
    let unwind_listing = tool(
        "objdump",
        &[
            "-d",
            "--insn-width=16",
            "--disassemble=_Unwind_Resume@plt",
            &artifact.display().to_string(),
        ],
    )?;
    parse_exact_direct_call_symbols(text_symbols, relocations, &unwind_listing)
}

/// Symbols sharing `pinned`'s demangled path but not its disambiguator hash.
///
/// Diagnostic only: it reports what a stale pin should be updated to. Matching
/// itself stays exact, because one path can have several legitimate
/// instantiations that only the hash tells apart.
fn same_path_instantiations(text_symbols: &TextSymbols, pinned: &str) -> Vec<String> {
    let Some(prefix_end) = pinned.rfind("17h") else {
        return Vec::new();
    };
    let prefix = &pinned[..prefix_end];
    let mut found = text_symbols
        .values()
        .flatten()
        .filter(|name| name.starts_with(prefix) && name.as_str() != pinned)
        .cloned()
        .collect::<Vec<_>>();
    found.sort();
    found.dedup();
    found
}

fn parse_exact_direct_call_symbols(
    text_symbols: &TextSymbols,
    relocations: &DynamicRelocations,
    unwind_listing: &str,
) -> Result<ExactDirectCallSymbols, Vec<String>> {
    let mut resolved = ExactDirectCallSymbols::new();
    // Collect every mismatch rather than returning on the first. Re-pinning
    // after a toolchain or dependency-graph move otherwise costs one full
    // release build per identity to discover the next one.
    let mut mismatches: Vec<String> = Vec::new();
    for target in [
        ExactDirectCallTarget::RandomRange,
        ExactDirectCallTarget::CircuitRead,
        ExactDirectCallTarget::CircuitWriteOrInsert,
    ] {
        for raw_symbol in target.raw_symbols() {
            let addresses = text_symbols
                .iter()
                .filter_map(|(address, names)| {
                    names
                        .iter()
                        .any(|name| name == raw_symbol)
                        .then_some(*address)
                })
                .collect::<Vec<_>>();
            let [address] = addresses.as_slice() else {
                // Name the instantiations that DO exist for this path. The
                // trailing `17h<hash>` is a compiler disambiguator, so it moves
                // when the toolchain or dependency graph does. Without this
                // list, re-qualifying means guessing the new value. The hash is
                // still matched exactly: distinct instantiations of one path are
                // distinguished by it and nothing else.
                let present = same_path_instantiations(text_symbols, raw_symbol);
                let found = if present.is_empty() {
                    "none".to_string()
                } else {
                    present.join(", ")
                };
                mismatches.push(format!(
                    "expected exactly one defined raw text identity `{raw_symbol}`; \
                     found {}. Instantiations present for this path: {found}",
                    addresses.len()
                ));
                continue;
            };
            insert_exact_direct_target(&mut resolved, *address, target)?;
        }
    }
    if !mismatches.is_empty() {
        return Err(mismatches);
    }
    let unwind = parse_unwind_plt_address(unwind_listing, relocations)?;
    insert_exact_direct_target(&mut resolved, unwind, ExactDirectCallTarget::UnwindResume)?;
    Ok(resolved)
}

fn insert_exact_direct_target(
    resolved: &mut ExactDirectCallSymbols,
    address: u64,
    target: ExactDirectCallTarget,
) -> Result<(), Vec<String>> {
    if let Some(previous) = resolved.insert(address, target) {
        return Err(vec![format!(
            "direct-call address {address:x} resolves ambiguously to {previous:?} and {target:?}"
        )]);
    }
    Ok(())
}

fn parse_unwind_plt_address(
    listing: &str,
    relocations: &DynamicRelocations,
) -> Result<u64, Vec<String>> {
    let addresses = listing
        .lines()
        .filter_map(|line| parse_symbol_header(line, "_Unwind_Resume@plt"))
        .collect::<Vec<_>>();
    let [address] = addresses.as_slice() else {
        return Err(vec![format!(
            "expected exactly one `_Unwind_Resume@plt` symbol; found {}",
            addresses.len()
        )]);
    };
    let mut decoded = Vec::new();
    for line in listing.lines() {
        match parse_instruction(line) {
            Ok(Some(instruction)) => decoded.push(instruction),
            Ok(None) => {}
            Err(reason) => {
                return Err(vec![format!(
                    "_Unwind_Resume@plt: {reason}: {}",
                    line.trim()
                )]);
            }
        }
    }
    let entries = decoded
        .iter()
        .filter(|instruction| instruction.instruction.address == *address)
        .collect::<Vec<_>>();
    let [entry] = entries.as_slice() else {
        return Err(vec![
            "_Unwind_Resume@plt does not have exactly one decoded entry instruction".to_string(),
        ]);
    };
    if entry.instruction.has_prefix() || entry.instruction.mnemonic != "jmp" {
        return Err(vec![
            "_Unwind_Resume@plt entry is not the measured direct GOT jump".to_string(),
        ]);
    }
    let next_address = entry
        .encoded_len
        .and_then(|length| address.checked_add(length))
        .ok_or_else(|| vec!["_Unwind_Resume@plt entry has no safe byte length".to_string()])?;
    let slot = rip_relative_slot(&entry.instruction.operands, next_address)
        .map_err(|reason| vec![format!("_Unwind_Resume@plt: {reason}")])?;
    let Some(relocation) = relocations.get(&slot) else {
        return Err(vec![format!(
            "_Unwind_Resume@plt GOT slot {slot:x} has no dynamic relocation"
        )]);
    };
    if relocation.kind != "R_X86_64_JUMP_SLOT"
        || relocation.dynamic_symbol.as_deref() != Some(UNWIND_DYNAMIC_SYMBOL)
    {
        return Err(vec![format!(
            "_Unwind_Resume@plt GOT slot {slot:x} is not the exact \
             `{UNWIND_DYNAMIC_SYMBOL}` jump slot"
        )]);
    }
    Ok(*address)
}

fn parse_symbol_header(line: &str, expected: &str) -> Option<u64> {
    let line = line.trim();
    let suffix = format!(" <{expected}>:");
    let address = line.strip_suffix(&suffix)?;
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(address, 16).ok()
}

/// Disassembles one symbol and enforces the approved structural profile.
fn inspect(
    artifact: &Path,
    symbol: &Symbol,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
    profile: GuardedProfile,
) -> Result<Inspected, Vec<String>> {
    let symbol_end = symbol
        .address
        .checked_add(symbol.size)
        .ok_or_else(|| vec![format!("{}: symbol range overflows", symbol.name)])?;
    let disassembly = tool(
        "objdump",
        &[
            "-dC",
            "--insn-width=16",
            &format!("--start-address=0x{:x}", symbol.address),
            &format!("--stop-address=0x{symbol_end:x}"),
            &artifact.display().to_string(),
        ],
    )?;

    let scanned = scan_with_range(
        &disassembly,
        &symbol.name,
        relocations,
        exact_direct_calls,
        profile,
        Some((symbol.address, symbol_end)),
    );

    if scanned.instructions == 0 {
        return Err(vec![format!(
            "{}: disassembled to no instructions; the symbol range looks wrong",
            symbol.name
        )]);
    }
    if !scanned.failures.is_empty() {
        return Err(scanned.failures);
    }
    let record_loop = validate_allowances_for_profile(&scanned, &symbol.name, profile)?;
    Ok(Inspected {
        name: symbol.name.clone(),
        instructions: scanned.instructions,
        allowed: scanned.allowed,
        record_loop,
    })
}

struct Scan {
    instructions: usize,
    allowed: Vec<String>,
    allowances: Vec<Allowance>,
    failures: Vec<String>,
}

/// Scans a disassembly listing. Pure, so it is unit-tested against the exact
/// instruction shapes measured on the x86_64 builder.
#[cfg(test)]
fn scan(disassembly: &str, symbol: &str, relocations: &DynamicRelocations) -> Scan {
    scan_for_profile(
        disassembly,
        symbol,
        relocations,
        GuardedProfile::FixedUniqueInsert,
    )
}

#[cfg(test)]
fn scan_for_profile(
    disassembly: &str,
    symbol: &str,
    relocations: &DynamicRelocations,
    profile: GuardedProfile,
) -> Scan {
    scan_for_profile_with_direct_calls(
        disassembly,
        symbol,
        relocations,
        &ExactDirectCallSymbols::new(),
        profile,
    )
}

#[cfg(test)]
fn scan_for_profile_with_direct_calls(
    disassembly: &str,
    symbol: &str,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
    profile: GuardedProfile,
) -> Scan {
    scan_with_range(
        disassembly,
        symbol,
        relocations,
        exact_direct_calls,
        profile,
        None,
    )
}

fn scan_with_range(
    disassembly: &str,
    symbol: &str,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
    profile: GuardedProfile,
    symbol_range: Option<(u64, u64)>,
) -> Scan {
    let mut allowed = Vec::new();
    let mut allowances = Vec::new();
    let mut failures = Vec::new();
    let mut parsed = Vec::new();
    for line in disassembly.lines() {
        match parse_instruction(line) {
            Ok(Some(instruction)) => parsed.push(instruction),
            Ok(None) => {}
            Err(reason) => failures.push(format!("{symbol}: {reason}: {}", line.trim())),
        }
    }

    let instructions = parsed.len();
    if let Some((symbol_start, symbol_end)) = symbol_range {
        if !failures.is_empty() {
            return Scan {
                instructions,
                allowed,
                allowances,
                failures,
            };
        }
        if let Err(reason) = validate_instruction_coverage(&parsed, symbol_start, symbol_end) {
            failures.push(format!("{symbol}: {reason}"));
            return Scan {
                instructions,
                allowed,
                allowances,
                failures,
            };
        }
    }

    let mut decoded = parsed
        .into_iter()
        .map(|parsed| parsed.instruction)
        .collect::<Vec<_>>();
    if let Some((_, symbol_end)) = symbol_range {
        decoded.push(Instruction {
            address: symbol_end,
            mnemonic: "<symbol-end>".to_string(),
            operands: String::new(),
        });
    }
    if profile == GuardedProfile::FixedExactUpsert {
        if let Some((allowance, address)) =
            exact_equality_reduction_motif(&decoded[..instructions], exact_direct_calls)
        {
            allowances.push(allowance);
            allowed.push(format!(
                "{symbol}: {} ending at {address:x}",
                allowance.description()
            ));
        }
    }
    for (index, current) in decoded.iter().take(instructions).enumerate() {
        match classify(&decoded, index, relocations, exact_direct_calls, profile) {
            Verdict::Branchless => {}
            Verdict::Allowed(allowance) => {
                allowances.push(allowance);
                allowed.push(format!(
                    "{symbol}: {} at {:x}: {} {}",
                    allowance.description(),
                    current.address,
                    current.mnemonic,
                    current.operands
                ));
            }
            Verdict::Rejected(reason) => failures.push(format!(
                "{symbol}: {reason} at {:x}: {} {}",
                current.address, current.mnemonic, current.operands
            )),
        }
    }

    Scan {
        instructions,
        allowed,
        allowances,
        failures,
    }
}

fn validate_instruction_coverage(
    instructions: &[ParsedInstruction],
    symbol_start: u64,
    symbol_end: u64,
) -> Result<(), &'static str> {
    if symbol_start >= symbol_end {
        return Err("invalid guarded symbol range");
    }
    let mut expected = symbol_start;
    for parsed in instructions {
        let instruction = &parsed.instruction;
        if instruction.address < symbol_start || instruction.address >= symbol_end {
            return Err("instruction address is outside the guarded symbol range");
        }
        if instruction.address < expected {
            return Err("instruction coverage overlaps or is not strictly monotonic");
        }
        if instruction.address > expected {
            return Err("instruction coverage has a gap");
        }
        let encoded_len = parsed
            .encoded_len
            .ok_or("instruction is missing raw encoded bytes")?;
        if encoded_len == 0 {
            return Err("instruction has no raw encoded bytes");
        }
        expected = instruction
            .address
            .checked_add(encoded_len)
            .ok_or("instruction range overflows")?;
        if expected > symbol_end {
            return Err("instruction extends beyond the guarded symbol range");
        }
    }
    if expected != symbol_end {
        return Err("instruction coverage does not reach the guarded symbol end");
    }
    Ok(())
}

#[cfg(test)]
fn validate_allowances(scanned: &Scan, symbol: &str) -> Result<RecordLoop, Vec<String>> {
    validate_allowances_for_profile(scanned, symbol, GuardedProfile::FixedUniqueInsert)
}

fn validate_allowances_for_profile(
    scanned: &Scan,
    symbol: &str,
    profile: GuardedProfile,
) -> Result<RecordLoop, Vec<String>> {
    let directory_loops = scanned
        .allowances
        .iter()
        .filter(|allowance| **allowance == Allowance::DirectoryRecordLoop)
        .count();
    let event_loops = scanned
        .allowances
        .iter()
        .filter(|allowance| **allowance == Allowance::EventRecordLoop)
        .count();
    let refcount_drops = scanned
        .allowances
        .iter()
        .filter(|allowance| **allowance == Allowance::RngRefcountDrop)
        .count();

    let record_loop = match (directory_loops, event_loops) {
        (1, 0) => RecordLoop::Directory,
        (0, 1) => RecordLoop::Event,
        _ => {
            return Err(vec![format!(
                "{symbol}: expected exactly one known fixed-record Cmov loop; \
                 found directory={directory_loops}, event={event_loops}"
            )]);
        }
    };
    let expected_refcount_drops = match profile {
        GuardedProfile::FixedUniqueInsert => 2,
        GuardedProfile::FixedExactUpsert => 4,
    };
    if refcount_drops != expected_refcount_drops {
        return Err(vec![format!(
            "{symbol}: expected exactly {expected_refcount_drops} known thread-local RNG refcount branches; \
             found {refcount_drops}"
        )]);
    }
    validate_profile_specific_allowances(scanned, symbol, profile, record_loop)?;
    for target in FixedCallTarget::ALL {
        let actual = scanned
            .allowances
            .iter()
            .filter(|allowance| **allowance == Allowance::FixedCall(target))
            .count();
        let expected = target.expected_per_monomorphization(profile);
        if actual != expected {
            return Err(vec![format!(
                "{symbol}: expected {expected} relocation-proven call(s) to {}; found {actual}",
                target.symbol()
            )]);
        }
    }
    Ok(record_loop)
}

fn validate_profile_specific_allowances(
    scanned: &Scan,
    symbol: &str,
    profile: GuardedProfile,
    record_loop: RecordLoop,
) -> Result<(), Vec<String>> {
    let directory_equalities = allowance_count(scanned, Allowance::DirectoryEqualityReduction);
    let event_equalities = allowance_count(scanned, Allowance::EventEqualityReduction);
    let cleanup_jumps = allowance_count(scanned, Allowance::ExactCleanupJump);
    let direct_calls = scanned
        .allowances
        .iter()
        .filter_map(|allowance| match allowance {
            Allowance::ExactDirectCall(target) => Some(*target),
            _ => None,
        })
        .collect::<Vec<_>>();

    match profile {
        GuardedProfile::FixedUniqueInsert => {
            if directory_equalities != 0
                || event_equalities != 0
                || cleanup_jumps != 0
                || !direct_calls.is_empty()
            {
                return Err(vec![format!(
                    "{symbol}: exact-upsert allowances appeared in the legacy insert profile"
                )]);
            }
        }
        GuardedProfile::FixedExactUpsert => {
            let expected_equalities = match record_loop {
                RecordLoop::Directory => (1, 0),
                RecordLoop::Event => (0, 1),
            };
            if (directory_equalities, event_equalities) != expected_equalities {
                return Err(vec![format!(
                    "{symbol}: expected one width-matched fixed equality reduction; \
                     found directory={directory_equalities}, event={event_equalities}"
                )]);
            }
            if cleanup_jumps != 1 {
                return Err(vec![format!(
                    "{symbol}: expected exactly one measured cleanup jump; found {cleanup_jumps}"
                )]);
            }
            if direct_calls != ExactDirectCallTarget::EXPECTED_ORDER {
                return Err(vec![format!(
                    "{symbol}: exact direct-call order or multiplicity changed; \
                     found {direct_calls:?}"
                )]);
            }
        }
    }
    Ok(())
}

fn allowance_count(scanned: &Scan, expected: Allowance) -> usize {
    scanned
        .allowances
        .iter()
        .filter(|allowance| **allowance == expected)
        .count()
}

/// Classifies one instruction in its complete decoded-symbol context.
///
/// Branch allowances require their complete measured motifs. Fixed calls
/// require an exact unprefixed RIP-relative operand whose slot is recomputed
/// from the following instruction address and independently proven by the
/// dynamic relocation table.
fn classify(
    instructions: &[Instruction],
    index: usize,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
    profile: GuardedProfile,
) -> Verdict {
    let current = &instructions[index];
    let mnemonic = current.bare_mnemonic();
    if current.has_prefix() && is_control_mnemonic(mnemonic) {
        return Verdict::Rejected("prefixed control transfer");
    }
    if mnemonic.starts_with("loop") {
        return Verdict::Rejected("looping branch");
    }
    if mnemonic.starts_with("call") {
        if !is_approved_mnemonic(mnemonic, profile) {
            return Verdict::Rejected("mnemonic is outside the approved structural profile");
        }
        if current.operands.starts_with('*') {
            let Some(next) = instructions.get(index + 1) else {
                return Verdict::Rejected("indirect call has no following instruction boundary");
            };
            return match fixed_call_target(current, next.address, relocations) {
                Ok(target) => Verdict::Allowed(Allowance::FixedCall(target)),
                Err(reason) => Verdict::Rejected(reason),
            };
        }
        return match profile {
            GuardedProfile::FixedUniqueInsert => Verdict::Branchless,
            GuardedProfile::FixedExactUpsert => {
                match exact_direct_call_target(current, exact_direct_calls) {
                    Ok(target) => Verdict::Allowed(Allowance::ExactDirectCall(target)),
                    Err(reason) => Verdict::Rejected(reason),
                }
            }
        };
    }
    if mnemonic.starts_with('j') {
        if mnemonic == "jmp" {
            if profile == GuardedProfile::FixedExactUpsert
                && exact_cleanup_jump_motif(instructions, index, relocations, exact_direct_calls)
            {
                return Verdict::Allowed(Allowance::ExactCleanupJump);
            }
            return Verdict::Rejected("unapproved unconditional jump");
        }
        if mnemonic != "jne" {
            return Verdict::Rejected("conditional jump");
        }
        if rng_drop_motif(
            instructions,
            index,
            relocations,
            exact_direct_calls,
            profile,
        ) {
            return Verdict::Allowed(Allowance::RngRefcountDrop);
        }
        if let Some(allowance) = record_loop_motif(instructions, index, profile) {
            return Verdict::Allowed(allowance);
        }
        return Verdict::Rejected("conditional jump");
    }
    if !is_approved_mnemonic(mnemonic, profile) {
        return Verdict::Rejected("mnemonic is outside the approved structural profile");
    }
    Verdict::Branchless
}

fn exact_direct_call_target(
    instruction: &Instruction,
    exact_direct_calls: &ExactDirectCallSymbols,
) -> Result<ExactDirectCallTarget, &'static str> {
    if instruction.has_prefix()
        || !instruction.bare_mnemonic().starts_with("call")
        || instruction.operands.starts_with('*')
    {
        return Err("exact direct-call proof was requested for a non-direct call");
    }
    let mut fields = instruction.operands.split_whitespace();
    let address = fields
        .next()
        .ok_or("exact direct call is missing its target address")?;
    if address.is_empty()
        || !address.bytes().all(|byte| byte.is_ascii_hexdigit())
        || u64::from_str_radix(address, 16).is_err()
    {
        return Err("exact direct call has an invalid target address");
    }
    let label = fields
        .next()
        .ok_or("exact direct call is missing its resolved target label")?;
    if fields.next().is_some() {
        return Err("exact direct call has unexpected operand text");
    }
    let label_target = ExactDirectCallTarget::EXPECTED_ORDER
        .into_iter()
        .find(|target| label == format!("<{}>", target.label()))
        .ok_or("direct call target is outside the fixed-exact-upsert profile")?;
    let address = u64::from_str_radix(address, 16)
        .map_err(|_| "exact direct call has an invalid target address")?;
    match exact_direct_calls.get(&address) {
        Some(resolved) if *resolved == label_target => Ok(label_target),
        Some(_) => Err("direct call label conflicts with its raw symbol identity"),
        None => Err("direct call address has no approved raw symbol identity"),
    }
}

fn fixed_call_target(
    instruction: &Instruction,
    next_address: u64,
    relocations: &DynamicRelocations,
) -> Result<FixedCallTarget, &'static str> {
    if instruction.has_prefix()
        || !instruction.bare_mnemonic().starts_with("call")
        || !instruction.operands.starts_with('*')
    {
        return Err("fixed-call proof was requested for a non-call instruction");
    }
    let slot = rip_relative_slot(&instruction.operands, next_address)?;
    let Some(relocation) = relocations.get(&slot) else {
        return Err("indirect call through an unresolved slot");
    };
    if relocation.kind != "R_X86_64_RELATIVE" {
        return Err("indirect call is not fixed by R_X86_64_RELATIVE");
    }
    relocation
        .relative_target
        .ok_or("relative call target is not an expected defined text symbol")
}

fn rng_drop_motif(
    instructions: &[Instruction],
    branch_index: usize,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
    profile: GuardedProfile,
) -> bool {
    match profile {
        GuardedProfile::FixedUniqueInsert => {
            legacy_rng_drop_motif(instructions, branch_index, relocations)
        }
        GuardedProfile::FixedExactUpsert => {
            exact_rng_drop_motif(instructions, branch_index, relocations, exact_direct_calls)
        }
    }
}

fn legacy_rng_drop_motif(
    instructions: &[Instruction],
    branch_index: usize,
    relocations: &DynamicRelocations,
) -> bool {
    if !rng_r13_provenance(instructions, branch_index, relocations) {
        return false;
    }
    let Some(decrement) = branch_index
        .checked_sub(1)
        .and_then(|index| instructions.get(index))
    else {
        return false;
    };
    let Some(move_argument) = instructions.get(branch_index + 1) else {
        return false;
    };
    let Some(drop_call) = instructions.get(branch_index + 2) else {
        return false;
    };
    let Some(branch_target) = instructions.get(branch_index + 3) else {
        return false;
    };
    let Some(branch) = instructions.get(branch_index) else {
        return false;
    };
    !decrement.has_prefix()
        && decrement.mnemonic == "decq"
        && decrement.operands == RNG_REFCOUNT_DECREMENT
        && !move_argument.has_prefix()
        && move_argument.mnemonic == "mov"
        && move_argument.operands == "%rsp,%rdi"
        && jump_target(&branch.operands) == Some(branch_target.address)
        && fixed_call_target(drop_call, branch_target.address, relocations)
            == Ok(FixedCallTarget::RcDropSlow)
}

fn exact_rng_drop_motif(
    instructions: &[Instruction],
    branch_index: usize,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
) -> bool {
    if !exact_rng_handle_provenance(instructions, relocations, exact_direct_calls) {
        return false;
    }
    exact_rng_drop_branch_shape(instructions, branch_index, relocations).is_some()
}

/// Returns whether this measured drop path needs the extra cleanup jump.
fn exact_rng_drop_branch_shape(
    instructions: &[Instruction],
    branch_index: usize,
    relocations: &DynamicRelocations,
) -> Option<bool> {
    let decrement = branch_index
        .checked_sub(1)
        .and_then(|index| instructions.get(index))?;
    let drop_argument = instructions.get(branch_index + 1)?;
    let drop_call = instructions.get(branch_index + 2)?;
    let after_drop = instructions.get(branch_index + 3)?;
    let branch = instructions.get(branch_index)?;
    let branch_target = jump_target(&branch.operands)?;
    let falls_through_to_target = after_drop.address == branch_target;
    let cleanup_jumps_to_target =
        after_drop.mnemonic == "jmp" && jump_target(&after_drop.operands) == Some(branch_target);

    let exact = !decrement.has_prefix()
        && decrement.mnemonic == "decq"
        && decrement.operands == "(%rbx)"
        && !branch.has_prefix()
        && branch.mnemonic == "jne"
        && !drop_argument.has_prefix()
        && drop_argument.mnemonic == "lea"
        && matches!(
            drop_argument.operands.as_str(),
            "0x8(%rsp),%rdi" | "0x10(%rsp),%rdi"
        )
        && fixed_call_target(drop_call, after_drop.address, relocations)
            == Ok(FixedCallTarget::RcDropSlow)
        && falls_through_to_target != cleanup_jumps_to_target;
    exact.then_some(cleanup_jumps_to_target)
}

fn exact_rng_handle_provenance(
    instructions: &[Instruction],
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
) -> bool {
    let rng_calls = instructions
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            (fixed_call_target(&pair[0], pair[1].address, relocations)
                == Ok(FixedCallTarget::ThreadRng))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let [first_rng_call, second_rng_call] = rng_calls.as_slice() else {
        return false;
    };
    let assignments = [first_rng_call + 1, second_rng_call + 1];
    if assignments.iter().any(|index| {
        let assignment = &instructions[*index];
        assignment.has_prefix()
            || assignment.mnemonic != "mov"
            || assignment.operands != "%rax,%rbx"
    }) || instructions
        .iter()
        .filter(|instruction| {
            !instruction.has_prefix()
                && instruction.mnemonic == "mov"
                && instruction.operands == "%rax,%rbx"
        })
        .count()
        != 2
    {
        return false;
    }

    let random_range_calls = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (exact_direct_call_target(instruction, exact_direct_calls)
                == Ok(ExactDirectCallTarget::RandomRange))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let [first_random_range, second_random_range] = random_range_calls.as_slice() else {
        return false;
    };
    let returns = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            matches!(instruction.bare_mnemonic(), "ret" | "retq").then_some(index)
        })
        .collect::<Vec<_>>();
    let [return_index] = returns.as_slice() else {
        return false;
    };
    let decrements = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (!instruction.has_prefix()
                && instruction.mnemonic == "decq"
                && instruction.operands == "(%rbx)")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let [first_normal_drop, second_normal_drop, first_cleanup_drop, second_cleanup_drop] =
        decrements.as_slice()
    else {
        return false;
    };
    if !(*first_rng_call < assignments[0]
        && assignments[0] < *first_random_range
        && *first_random_range < *first_normal_drop
        && *first_normal_drop < *second_rng_call
        && *second_rng_call < assignments[1]
        && assignments[1] < *second_random_range
        && *second_random_range < *second_normal_drop
        && *second_normal_drop < *return_index
        && *return_index < *first_cleanup_drop
        && *first_cleanup_drop < *second_cleanup_drop)
    {
        return false;
    }

    let Some(first_slot) = rng_handle_stack_slot(instructions, assignments[0]) else {
        return false;
    };
    let Some(second_slot) = rng_handle_stack_slot(instructions, assignments[1]) else {
        return false;
    };
    for (assignment, normal_drop) in [
        (assignments[0], *first_normal_drop),
        (assignments[1], *second_normal_drop),
    ] {
        if instructions[assignment + 1..normal_drop]
            .iter()
            .any(writes_rbx)
        {
            return false;
        }
    }

    // Unwind cleanups are laid out in reverse lifetime order: the second RNG
    // lifetime reaches the first landing pad, and the first reaches the last.
    for (drop, slot) in [
        (*first_normal_drop, first_slot),
        (*second_normal_drop, second_slot),
        (*first_cleanup_drop, second_slot),
        (*second_cleanup_drop, first_slot),
    ] {
        if !rng_drop_uses_stack_slot(instructions, drop, slot) {
            return false;
        }
    }
    for cleanup_drop in [*first_cleanup_drop, *second_cleanup_drop] {
        let Some(landing) = cleanup_drop
            .checked_sub(1)
            .and_then(|index| instructions.get(index))
        else {
            return false;
        };
        if landing.has_prefix() || landing.mnemonic != "mov" || landing.operands != "%rax,%r14" {
            return false;
        }
    }

    exact_rng_drop_branch_shape(instructions, first_normal_drop + 1, relocations) == Some(false)
        && exact_rng_drop_branch_shape(instructions, second_normal_drop + 1, relocations)
            == Some(false)
        && exact_rng_drop_branch_shape(instructions, first_cleanup_drop + 1, relocations)
            == Some(true)
        && exact_rng_drop_branch_shape(instructions, second_cleanup_drop + 1, relocations)
            == Some(false)
}

fn rng_handle_stack_slot(instructions: &[Instruction], assignment_index: usize) -> Option<&str> {
    let store = instructions.get(assignment_index + 1)?;
    if store.has_prefix() || store.mnemonic != "mov" {
        return None;
    }
    match store.operands.as_str() {
        "%rax,0x8(%rsp)" => Some("0x8(%rsp)"),
        "%rax,0x10(%rsp)" => Some("0x10(%rsp)"),
        _ => None,
    }
}

fn rng_drop_uses_stack_slot(
    instructions: &[Instruction],
    decrement_index: usize,
    slot: &str,
) -> bool {
    let Some(argument) = instructions.get(decrement_index + 2) else {
        return false;
    };
    !argument.has_prefix()
        && argument.mnemonic == "lea"
        && argument.operands == format!("{slot},%rdi")
}

fn writes_rbx(instruction: &Instruction) -> bool {
    if matches!(
        instruction.bare_mnemonic(),
        "call" | "callq" | "cmp" | "jmp" | "jne" | "push" | "ret" | "retq" | "test"
    ) {
        return false;
    }
    instruction
        .operands
        .split_once('#')
        .map_or(instruction.operands.as_str(), |(operands, _)| operands)
        .rsplit(',')
        .next()
        .map(str::trim)
        .is_some_and(|destination| matches!(destination, "%rbx" | "%ebx" | "%bx" | "%bl"))
}

fn exact_cleanup_jump_motif(
    instructions: &[Instruction],
    jump_index: usize,
    relocations: &DynamicRelocations,
    exact_direct_calls: &ExactDirectCallSymbols,
) -> bool {
    let Some(jump) = instructions.get(jump_index) else {
        return false;
    };
    let Some(drop_call) = jump_index
        .checked_sub(1)
        .and_then(|index| instructions.get(index))
    else {
        return false;
    };
    let Some(target_address) = jump_target(&jump.operands) else {
        return false;
    };
    let Some(target_index) = instructions
        .iter()
        .position(|instruction| instruction.address == target_address)
    else {
        return false;
    };
    let Some(move_exception) = instructions.get(target_index) else {
        return false;
    };
    let Some(unwind_call) = instructions.get(target_index + 1) else {
        return false;
    };

    jump.address < target_address
        && fixed_call_target(drop_call, jump.address, relocations)
            == Ok(FixedCallTarget::RcDropSlow)
        && !move_exception.has_prefix()
        && move_exception.mnemonic == "mov"
        && move_exception.operands == "%r14,%rdi"
        && exact_direct_call_target(unwind_call, exact_direct_calls)
            == Ok(ExactDirectCallTarget::UnwindResume)
}

fn rng_r13_provenance(
    instructions: &[Instruction],
    branch_index: usize,
    relocations: &DynamicRelocations,
) -> bool {
    let rng_calls = instructions
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            (fixed_call_target(&pair[0], pair[1].address, relocations)
                == Ok(FixedCallTarget::ThreadRng))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let [rng_call] = rng_calls.as_slice() else {
        return false;
    };
    let assignment_index = rng_call + 1;
    let assignment = &instructions[assignment_index];
    if assignment.has_prefix() || assignment.mnemonic != "mov" || assignment.operands != "%rax,%r13"
    {
        return false;
    }

    let drops = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (instruction.mnemonic == "decq" && instruction.operands == RNG_REFCOUNT_DECREMENT)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let [normal_drop, unwind_drop] = drops.as_slice() else {
        return false;
    };
    if branch_index != normal_drop + 1 && branch_index != unwind_drop + 1 {
        return false;
    }

    let Some(return_index) = instructions
        .iter()
        .enumerate()
        .skip(assignment_index + 1)
        .find_map(|(index, instruction)| {
            (instruction.bare_mnemonic().starts_with("ret")).then_some(index)
        })
    else {
        return false;
    };
    if !(*normal_drop < return_index && return_index < *unwind_drop) {
        return false;
    }
    for (index, instruction) in instructions
        .iter()
        .enumerate()
        .take(*unwind_drop + 1)
        .skip(assignment_index)
    {
        if !mentions_r13_family(instruction) {
            continue;
        }
        let is_assignment = index == assignment_index;
        let is_drop_read = (index == *normal_drop || index == *unwind_drop)
            && instruction.mnemonic == "decq"
            && instruction.operands == RNG_REFCOUNT_DECREMENT;
        let is_normal_epilogue_restore = index < return_index
            && instruction.mnemonic == "pop"
            && instruction.operands == "%r13"
            && instructions[index + 1..return_index]
                .iter()
                .all(|tail| tail.mnemonic == "pop");
        if !(is_assignment || is_drop_read || is_normal_epilogue_restore) {
            return false;
        }
    }

    let Some(landing_pad) = unwind_drop
        .checked_sub(1)
        .and_then(|index| instructions.get(index))
    else {
        return false;
    };
    !landing_pad.has_prefix()
        && landing_pad.mnemonic == "mov"
        && landing_pad.operands == "%rax,%rbx"
}

fn mentions_r13_family(instruction: &Instruction) -> bool {
    ["%r13", "%r13d", "%r13w", "%r13b"]
        .into_iter()
        .any(|register| instruction.operands.contains(register))
}

fn record_loop_motif(
    instructions: &[Instruction],
    branch_index: usize,
    profile: GuardedProfile,
) -> Option<Allowance> {
    match profile {
        GuardedProfile::FixedUniqueInsert => legacy_record_loop_motif(instructions, branch_index),
        GuardedProfile::FixedExactUpsert => exact_record_loop_motif(instructions, branch_index),
    }
}

fn legacy_record_loop_motif(
    instructions: &[Instruction],
    branch_index: usize,
) -> Option<Allowance> {
    let start = branch_index.checked_sub(7)?;
    let motif = instructions.get(start..=branch_index)?;
    if motif.iter().any(Instruction::has_prefix) {
        return None;
    }
    let (allowance, source, bound, padding_mnemonic) = match motif[6].operands.as_str() {
        DIRECTORY_RECORD_LOOP_COMPARE => (
            Allowance::DirectoryRecordLoop,
            "0x40(%rsp,%rax,1),%ecx",
            DIRECTORY_RECORD_LOOP_COMPARE,
            "nopw",
        ),
        EVENT_RECORD_LOOP_COMPARE => (
            Allowance::EventRecordLoop,
            "0x70(%rsp,%rax,1),%ecx",
            EVENT_RECORD_LOOP_COMPARE,
            "data16 cs nopw",
        ),
        _ => return None,
    };
    let expected = [
        ("movzbl", source),
        ("movzbl", "0x10(%rsp,%rax,1),%edx"),
        ("test", "%rbx,%rbx"),
        ("cmovne", "%ecx,%edx"),
        ("mov", "%dl,0x10(%rsp,%rax,1)"),
        ("inc", "%rax"),
        ("cmp", bound),
    ];
    if motif[..7]
        .iter()
        .zip(expected)
        .any(|(instruction, (mnemonic, operands))| {
            instruction.mnemonic != mnemonic || instruction.operands != operands
        })
    {
        return None;
    }
    let found_to_rbx = start
        .checked_sub(3)
        .and_then(|index| instructions.get(index))?;
    let zero_index = instructions.get(start - 2)?;
    let padding = instructions.get(start - 1)?;
    if found_to_rbx.has_prefix()
        || found_to_rbx.mnemonic != "movzbl"
        || found_to_rbx.operands != "%al,%ebx"
        || zero_index.has_prefix()
        || zero_index.mnemonic != "xor"
        || zero_index.operands != "%eax,%eax"
        || padding.mnemonic != padding_mnemonic
    {
        return None;
    }
    let branch = &motif[7];
    (branch.mnemonic == "jne" && jump_target(&branch.operands) == Some(motif[0].address))
        .then_some(allowance)
}

fn exact_record_loop_motif(instructions: &[Instruction], branch_index: usize) -> Option<Allowance> {
    let start = branch_index.checked_sub(7)?;
    let motif = instructions.get(start..=branch_index)?;
    if motif.iter().any(Instruction::has_prefix) {
        return None;
    }
    let (allowance, source, prior, output, bound) = match motif[6].operands.as_str() {
        "$0x26,%rcx" => (
            Allowance::DirectoryRecordLoop,
            "0x27(%rbp,%rcx,1),%edx",
            "0x70(%rsp,%rcx,1),%esi",
            "%sil,0x70(%rsp,%rcx,1)",
            "$0x26,%rcx",
        ),
        "$0x52,%rcx" => (
            Allowance::EventRecordLoop,
            "0x53(%r13,%rcx,1),%edx",
            "0x90(%rsp,%rcx,1),%esi",
            "%sil,0x90(%rsp,%rcx,1)",
            "$0x52,%rcx",
        ),
        _ => return None,
    };
    let expected = [
        ("movzbl", source),
        ("movzbl", prior),
        ("test", "%rax,%rax"),
        ("cmovne", "%edx,%esi"),
        ("mov", output),
        ("inc", "%rcx"),
        ("cmp", bound),
    ];
    if motif[..7]
        .iter()
        .zip(expected)
        .any(|(instruction, (mnemonic, operands))| {
            instruction.mnemonic != mnemonic || instruction.operands != operands
        })
    {
        return None;
    }
    let found_to_index = start
        .checked_sub(3)
        .and_then(|index| instructions.get(index))?;
    let zero_index = instructions.get(start - 2)?;
    let padding = instructions.get(start - 1)?;
    if found_to_index.has_prefix()
        || found_to_index.mnemonic != "movzbl"
        || found_to_index.operands != "%al,%eax"
        || zero_index.has_prefix()
        || zero_index.mnemonic != "xor"
        || zero_index.operands != "%ecx,%ecx"
        || padding.mnemonic != "data16 data16 data16 cs nopw"
        || padding.operands != "0x0(%rax,%rax,1)"
    {
        return None;
    }
    let branch = &motif[7];
    (branch.mnemonic == "jne" && jump_target(&branch.operands) == Some(motif[0].address))
        .then_some(allowance)
}

fn exact_equality_reduction_motif(
    instructions: &[Instruction],
    exact_direct_calls: &ExactDirectCallSymbols,
) -> Option<(Allowance, u64)> {
    let read_calls = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (exact_direct_call_target(instruction, exact_direct_calls)
                == Ok(ExactDirectCallTarget::CircuitRead))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let [read_index] = read_calls.as_slice() else {
        return None;
    };
    let record_loops = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            exact_record_loop_motif(instructions, index).map(|allowance| (index, allowance))
        })
        .collect::<Vec<_>>();
    let [(branch_index, record_loop)] = record_loops.as_slice() else {
        return None;
    };
    let reduction_end = branch_index.checked_sub(10)?;
    let reduction = instructions.get(read_index + 1..reduction_end)?;
    let anchor = reduction.last()?.address;

    let equality = match record_loop {
        Allowance::DirectoryRecordLoop if directory_equality_reduction(reduction) => {
            Allowance::DirectoryEqualityReduction
        }
        Allowance::EventRecordLoop if event_equality_reduction(reduction) => {
            Allowance::EventEqualityReduction
        }
        _ => return None,
    };
    Some((equality, anchor))
}

const EVENT_EQUALITY_REDUCTION: &str = "\
mov %eax,%r12d
movdqu 0x41(%r13),%xmm5
movdqa 0x70(%rsp),%xmm0
movdqu 0x31(%r13),%xmm6
movdqa 0x30(%rsp),%xmm1
movdqa 0x40(%rsp),%xmm2
movdqa 0x50(%rsp),%xmm3
movdqa 0x60(%rsp),%xmm4
pxor %xmm4,%xmm6
movdqu 0x11(%r13),%xmm7
pxor %xmm2,%xmm7
por %xmm6,%xmm7
movdqu 0x21(%r13),%xmm6
pxor %xmm3,%xmm6
movdqu 0x1(%r13),%xmm8
pxor %xmm1,%xmm8
por %xmm6,%xmm8
por %xmm7,%xmm8
pshufd $0xee,%xmm8,%xmm6
por %xmm8,%xmm6
pshufd $0x55,%xmm6,%xmm7
por %xmm6,%xmm7
movdqa %xmm7,%xmm6
psrld $0x10,%xmm6
por %xmm7,%xmm6
movdqa %xmm6,%xmm7
psrlw $0x8,%xmm7
por %xmm6,%xmm7
pand (%rip),%xmm7
pxor %xmm0,%xmm5
por %xmm5,%xmm7
pshufd $0xee,%xmm7,%xmm5
por %xmm7,%xmm5
pshufd $0x55,%xmm5,%xmm6
por %xmm5,%xmm6
movdqa %xmm6,%xmm5
psrld $0x10,%xmm5
por %xmm6,%xmm5
movdqa %xmm5,%xmm6
psrlw $0x8,%xmm6
por %xmm5,%xmm6
movd %xmm6,%eax
movzbl 0x51(%r13),%ecx
xor 0x80(%rsp),%cl
or %al,%cl
movzbl 0x52(%r13),%ebp
xor 0x81(%rsp),%bpl
or %cl,%bpl
sete %al
mov %r12b,0x7(%rsp)
xor $0x1,%r12b
movzbl 0x0(%r13),%r15d
and %r15b,%al
or %r12b,%al
movzwl 0x80(%rsp),%ecx
mov %cx,0xe0(%rsp)
movdqa %xmm0,0xd0(%rsp)
movdqa %xmm4,0xc0(%rsp)
movdqa %xmm3,0xb0(%rsp)
movdqa %xmm2,0xa0(%rsp)
movdqa %xmm1,0x90(%rsp)
";

const DIRECTORY_EQUALITY_REDUCTION: &str = "\
mov %al,0xd(%rsp)
movzbl 0x1(%rbp),%eax
movzbl 0x2(%rbp),%ecx
movzbl 0x3(%rbp),%edx
movzbl 0x4(%rbp),%esi
movzbl 0x5(%rbp),%edi
xor 0x21(%rsp),%cl
xor 0x20(%rsp),%al
movzbl 0x6(%rbp),%r8d
or %cl,%al
xor 0x22(%rsp),%dl
xor 0x23(%rsp),%sil
or %dl,%sil
or %al,%sil
xor 0x24(%rsp),%dil
xor 0x25(%rsp),%r8b
or %sil,%dil
or %dil,%r8b
sete 0xe(%rsp)
movdqu 0x26(%rsp),%xmm0
movdqu 0x7(%rbp),%xmm1
pcmpeqb %xmm0,%xmm1
pmovmskb %xmm1,%ebx
test %bx,%bx
sets 0xf(%rsp)
mov %ebx,%ecx
shr $0xe,%ecx
mov %ebx,%edi
shr $0xd,%edi
mov %ebx,%r8d
shr $0xc,%r8d
mov %ebx,%r9d
shr $0xb,%r9d
mov %ebx,%r10d
shr $0xa,%r10d
mov %ebx,%esi
shr $0x9,%esi
mov %ebx,%edx
shr $0x8,%edx
test %bl,%bl
sets %r15b
mov %ebx,%r11d
mov %ebx,%r12d
mov %ebx,%r14d
mov %ebx,%eax
mov %ebx,%r13d
shr $1,%r13b
and %bl,%r13b
shr $0x6,%bl
shr $0x5,%r11b
and %bl,%r11b
and %r15b,%r11b
shr $0x3,%r14b
shr $0x2,%al
and %r14b,%al
movzbl 0x0(%rbp),%ebx
movdqu 0x36(%rsp),%xmm0
movdqu 0x17(%rbp),%xmm1
pcmpeqb %xmm0,%xmm1
pmovmskb %xmm1,%r15d
shr $0x4,%r12b
and %r12b,%al
and 0xe(%rsp),%r13b
and %al,%r13b
and %dl,%r11b
and %r13b,%r11b
and %r10b,%sil
and %r9b,%sil
and %r8b,%sil
and %dil,%sil
and %r11b,%sil
and 0xf(%rsp),%cl
and %r15b,%cl
mov %r15d,%eax
shr $1,%al
and %cl,%al
mov %r15d,%ecx
shr $0x2,%cl
and %al,%cl
and %sil,%cl
mov %r15d,%eax
shr $0x3,%al
mov %r15d,%edx
shr $0x4,%dl
and %al,%dl
mov %r15d,%eax
shr $0x5,%al
and %dl,%al
mov %r15d,%edx
shr $0x6,%dl
and %al,%dl
mov %r15d,%eax
shr $0x8,%eax
mov %r15d,%esi
shr $0x7,%sil
and %dl,%sil
and %al,%sil
mov %r15d,%eax
shr $0x9,%eax
and %sil,%al
and %cl,%al
mov %r15d,%ecx
shr $0xa,%ecx
mov %r15d,%edx
shr $0xb,%edx
and %cl,%dl
mov %r15d,%ecx
shr $0xc,%ecx
and %dl,%cl
mov %r15d,%edx
shr $0xd,%edx
and %cl,%dl
mov %r15d,%ecx
shr $0xe,%ecx
and %dl,%cl
shr $0xf,%r15d
and %cl,%r15b
and %al,%r15b
movzbl 0xd(%rsp),%r14d
xor $0x1,%r14b
mov %r15d,%eax
mov %ebx,%r12d
and %bl,%al
or %r14b,%al
movaps 0x30(%rsp),%xmm0
movaps %xmm0,0x80(%rsp)
mov 0x3e(%rsp),%rcx
mov %rcx,0x8e(%rsp)
movaps 0x20(%rsp),%xmm0
movaps %xmm0,0x70(%rsp)
";

fn directory_equality_reduction(instructions: &[Instruction]) -> bool {
    normalized_instruction_range(instructions) == DIRECTORY_EQUALITY_REDUCTION
}

fn event_equality_reduction(instructions: &[Instruction]) -> bool {
    normalized_instruction_range(instructions) == EVENT_EQUALITY_REDUCTION
}

fn normalized_instruction_range(instructions: &[Instruction]) -> String {
    let mut normalized = String::new();
    for instruction in instructions {
        normalized.push_str(normalized_exact_mnemonic(&instruction.mnemonic));
        normalized.push(' ');
        normalized.push_str(&normalized_exact_operands(&instruction.operands));
        normalized.push('\n');
    }
    normalized
}

fn normalized_exact_mnemonic(mnemonic: &str) -> &str {
    match mnemonic {
        "movb" | "movl" | "movq" => "mov",
        "xorb" | "xorl" => "xor",
        "orb" => "or",
        "andb" => "and",
        "shrb" | "shrl" => "shr",
        "testb" | "testw" | "testq" => "test",
        _ => mnemonic,
    }
}

fn normalized_exact_operands(operands: &str) -> String {
    let operands = operands
        .split_once('#')
        .map_or(operands, |(before, _)| before);
    let mut compact = operands
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if let Some(rip) = compact.find("(%rip)") {
        let displacement = &compact[..rip];
        if displacement.is_empty() || parse_signed_hex(displacement).is_some() {
            compact.replace_range(..rip, "");
        }
    }
    compact
}

/// The exact unsegmented GNU operand `*0xDISP(%rip) # SLOT`, independently
/// recomputed from the following instruction boundary.
fn rip_relative_slot(operands: &str, next_address: u64) -> Result<u64, &'static str> {
    let (operand, resolved) = operands
        .split_once('#')
        .ok_or("indirect call lacks an objdump-resolved slot")?;
    if resolved.contains('#') {
        return Err("indirect call has an invalid resolved-slot comment");
    }
    let operand = operand.trim();
    let displacement = operand
        .strip_prefix('*')
        .and_then(|value| value.strip_suffix("(%rip)"))
        .ok_or("indirect call is not exact unsegmented RIP-relative syntax")?;
    if displacement.is_empty()
        || displacement.contains(char::is_whitespace)
        || displacement.contains(['(', ')', '%', '{', '}', ':'])
    {
        return Err("indirect call is not exact unsegmented RIP-relative syntax");
    }
    let displacement = parse_signed_hex(displacement)
        .ok_or("indirect call has an invalid RIP-relative displacement")?;
    let computed = i128::from(next_address)
        .checked_add(i128::from(displacement))
        .and_then(|address| u64::try_from(address).ok())
        .ok_or("indirect call RIP-relative slot overflows")?;
    let reported = resolved
        .split_whitespace()
        .next()
        .and_then(|address| u64::from_str_radix(address, 16).ok())
        .ok_or("indirect call has an invalid resolved-slot comment")?;
    if computed != reported {
        return Err("indirect call resolved-slot comment mismatches instruction");
    }
    Ok(computed)
}

fn parse_signed_hex(value: &str) -> Option<i64> {
    let (negative, digits) = match value.strip_prefix('-') {
        Some(rest) => (true, rest.strip_prefix("0x")?),
        None => (false, value.strip_prefix("0x")?),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let magnitude = i128::from(u64::from_str_radix(digits, 16).ok()?);
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).ok()
}

/// The absolute address a jump operand names, if it names one directly.
fn jump_target(operands: &str) -> Option<u64> {
    let first = operands.split_whitespace().next()?;
    u64::from_str_radix(first, 16).ok()
}

/// Decodes both test listings without raw bytes and production `objdump`
/// listings with one raw-byte column. GNU instruction prefixes remain exposed
/// in the mnemonic so control-transfer classification can reject them.
fn parse_instruction(line: &str) -> Result<Option<ParsedInstruction>, &'static str> {
    let Some((address, rest)) = line.split_once(':') else {
        return Ok(None);
    };
    let address = address.trim();
    if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let address = u64::from_str_radix(address, 16).map_err(|_| "invalid instruction address")?;
    let columns = rest
        .split('\t')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .collect::<Vec<_>>();
    let (encoded_len, instruction_text) = match columns.as_slice() {
        [] => return Err("instruction has no mnemonic"),
        [text] if encoded_byte_len(text).is_some() => {
            return Err("instruction has raw bytes but no mnemonic");
        }
        [text] => (None, *text),
        [bytes, text] => (
            Some(encoded_byte_len(bytes).ok_or("invalid raw instruction bytes")?),
            *text,
        ),
        _ => return Err("instruction has unexpected objdump columns"),
    };
    let parts = instruction_text.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return Err("instruction has no mnemonic");
    }
    let known_prefixes = parts.iter().take_while(|part| is_gnu_prefix(part)).count();
    let mnemonic_index = parts
        .iter()
        .enumerate()
        .skip(known_prefixes)
        .find_map(|(index, part)| is_control_mnemonic(part).then_some(index))
        .unwrap_or(known_prefixes);
    let mnemonic = parts
        .get(mnemonic_index)
        .ok_or("missing instruction after prefix")?;
    let prefixes = &parts[..mnemonic_index];
    let mnemonic = if prefixes.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{} {mnemonic}", prefixes.join(" "))
    };
    Ok(Some(ParsedInstruction {
        instruction: Instruction {
            address,
            mnemonic,
            operands: parts[mnemonic_index + 1..].join(" "),
        },
        encoded_len,
    }))
}

fn is_control_mnemonic(value: &str) -> bool {
    matches!(
        value,
        "call"
            | "callq"
            | "iret"
            | "iretq"
            | "ret"
            | "retq"
            | "syscall"
            | "sysenter"
            | "sysexit"
            | "sysret"
    ) || value.starts_with('j')
        || value.starts_with("loop")
}

fn is_approved_mnemonic(value: &str, profile: GuardedProfile) -> bool {
    legacy_mnemonic(value)
        || profile == GuardedProfile::FixedExactUpsert
            && matches!(
                value,
                "and"
                    | "movd"
                    | "movdqa"
                    | "movdqu"
                    | "nopl"
                    | "or"
                    | "pand"
                    | "pcmpeqb"
                    | "pmovmskb"
                    | "por"
                    | "pshufd"
                    | "psrld"
                    | "psrlw"
                    | "pxor"
                    | "sete"
                    | "sets"
                    | "shr"
            )
}

fn legacy_mnemonic(value: &str) -> bool {
    matches!(
        value,
        "add"
            | "call"
            | "cmovne"
            | "cmp"
            | "decq"
            | "inc"
            | "int3"
            | "jne"
            | "lea"
            | "mov"
            | "movaps"
            | "movq"
            | "movups"
            | "movw"
            | "movzbl"
            | "movzwl"
            | "nopw"
            | "pop"
            | "push"
            | "ret"
            | "sub"
            | "test"
            | "xor"
            | "xorps"
    )
}

/// Runs a binutils tool, turning a missing tool or non-zero exit into a
/// diagnostic rather than a silent pass.
#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the Phase 0 kill-gate report recorded: the hit/miss boolean
    /// returned in AL drives a conditional jump between the two ORAM accesses.
    const FAILING: &str = "\
00000000007ade10 <fixed_unique_insert>:
  7ade98:\tcall   7a1120 <read_and_remap>
  7adead:\tcmp    $0x0,%al
  7adeb2:\tje     7adec7 <fixed_unique_insert+0xb7>
  7adec7:\tcall   7a1450 <write_or_insert_and_remap>
  7adee0:\tret
";

    /// The remediated 38-byte directory monomorphization, transcribed from the
    /// x86_64 builder: a fixed-count `Cmov` loop and two refcount drop paths.
    const MEASURED: &str = "\
0000000000a98ef0 <fixed_unique_insert>:
  a98f52:\tmovzbl %al,%ebx
  a98f55:\txor    %eax,%eax
  a98f57:\tnopw   0x0(%rax,%rax,1)
  a98f60:\tmovzbl 0x40(%rsp,%rax,1),%ecx
  a98f65:\tmovzbl 0x10(%rsp,%rax,1),%edx
  a98f6a:\ttest   %rbx,%rbx
  a98f6d:\tcmovne %ecx,%edx
  a98f70:\tmov    %dl,0x10(%rsp,%rax,1)
  a98f74:\tinc    %rax
  a98f77:\tcmp    $0x26,%rax
  a98f7b:\tjne    a98f60 <fixed_unique_insert+0x70>
  a98f85:\tcall   *0xf12245(%rip) # 19ab1d0 <_DYNAMIC+0x2688>
  a98f8b:\tmov    %rax,%r13
  a98fa0:\tcall   a924e0 <rand::rng::Rng::random_range>
  a98fa5:\tmov    %eax,%ebp
  a98fa7:\tdecq   0x0(%r13)
  a98fab:\tjne    a98fb6 <fixed_unique_insert+0xc6>
  a98fad:\tmov    %rsp,%rdi
  a98fb0:\tcall   *0xf12222(%rip) # 19ab1d8 <_DYNAMIC+0x2690>
  a98fb6:\tlea    0x50(%r12),%rdi
  a98fc0:\tcall   *0xf1221a(%rip) # 19ab1e0 <_DYNAMIC+0x2698>
  a98fc6:\tlea    0x10(%rsp),%r8
  a98fd5:\tcall   abdca0 <CircuitORAM<V>::write_or_insert>
  a9900a:\tret
  a9900b:\tmov    %rax,%rbx
  a9900e:\tdecq   0x0(%r13)
  a99012:\tjne    a9901d <fixed_unique_insert+0x12d>
  a99014:\tmov    %rsp,%rdi
  a99017:\tcall   *0xf121bb(%rip) # 19ab1d8 <_DYNAMIC+0x2690>
  a9901d:\tmov    %rbx,%rdi
  a99020:\tcall   18edca0 <_Unwind_Resume@plt>
  a99025:\tcall   *0xf0fd8d(%rip) # 19a8db8 <_DYNAMIC+0x270>
  a9902b:\tint3
";

    const TEXT_SYMBOLS: &str = "\
0000000000ad4c30 00000000000007a4 T _ZN10rostl_oram14recursive_oram20RecursivePositionMap15access_position17h56ba6b451895665bE
0000000000ad7ba0 0000000000000020 T _ZN5alloc2rc15Rc$LT$T$C$A$GT$9drop_slow17hc939a64f1143612fE
0000000000ad80a0 0000000000000048 T _ZN4rand4rngs6thread3rng17h25d391ca23111651E
00000000018df84b 0000000000000014 T _RNvNtCs27Vx93FoQ6z_4core9panicking16panic_in_cleanup
";

    const RELOCATIONS: &str = "\
00000000019a8db8 R_X86_64_RELATIVE  *ABS*+0x00000000018df84b
00000000019ab1d0 R_X86_64_RELATIVE  *ABS*+0x0000000000ad80a0
00000000019ab1d8 R_X86_64_RELATIVE  *ABS*+0x0000000000ad7ba0
00000000019ab1e0 R_X86_64_RELATIVE  *ABS*+0x0000000000ad4c30
";

    fn measured_relocations() -> DynamicRelocations {
        let symbols =
            parse_defined_text_symbols(TEXT_SYMBOLS).expect("measured text symbols are valid");
        parse_dynamic_relocations(RELOCATIONS, &symbols)
            .expect("measured dynamic relocations are valid")
    }

    fn exact_direct_text_symbols() -> TextSymbols {
        TextSymbols::from([
            (0x600, vec![RANDOM_RANGE_RAW_SYMBOL.to_string()]),
            (0x601, vec![RANDOM_RANGE_SECOND_RAW_SYMBOL.to_string()]),
            (0x610, vec![CIRCUIT_READ_RAW_SYMBOL.to_string()]),
            (0x611, vec![CIRCUIT_EVENT_READ_RAW_SYMBOL.to_string()]),
            (0x620, vec![CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOL.to_string()]),
            (
                0x621,
                vec![CIRCUIT_EVENT_WRITE_OR_INSERT_RAW_SYMBOL.to_string()],
            ),
        ])
    }

    fn unwind_jump_slot(dynamic_symbol: &str) -> DynamicRelocations {
        DynamicRelocations::from([(
            0x800,
            DynamicRelocation {
                kind: "R_X86_64_JUMP_SLOT".to_string(),
                relative_target: None,
                dynamic_symbol: Some(dynamic_symbol.to_string()),
            },
        )])
    }

    const UNWIND_PLT: &str = "\
0000000000000700 <_Unwind_Resume@plt>:
 700:\tff 25 fa 00 00 00\tjmp *0xfa(%rip) # 800 <_Unwind_Resume@GCC_3.0>
";

    fn classify_without_relocations(
        previous: Option<&Instruction>,
        current: &Instruction,
    ) -> Verdict {
        classify_for_profile_without_relocations(
            GuardedProfile::FixedUniqueInsert,
            previous,
            current,
        )
    }

    fn classify_for_profile_without_relocations(
        profile: GuardedProfile,
        previous: Option<&Instruction>,
        current: &Instruction,
    ) -> Verdict {
        classify_for_profile_with_direct_calls(
            profile,
            previous,
            current,
            &ExactDirectCallSymbols::new(),
        )
    }

    fn classify_for_profile_with_direct_calls(
        profile: GuardedProfile,
        previous: Option<&Instruction>,
        current: &Instruction,
        exact_direct_calls: &ExactDirectCallSymbols,
    ) -> Verdict {
        let mut instructions = previous.into_iter().cloned().collect::<Vec<_>>();
        instructions.push(current.clone());
        classify(
            &instructions,
            instructions.len() - 1,
            &DynamicRelocations::new(),
            exact_direct_calls,
            profile,
        )
    }

    fn classify_with_next(
        current: Instruction,
        next_address: u64,
        relocations: &DynamicRelocations,
    ) -> Verdict {
        classify_for_profile_with_next(
            GuardedProfile::FixedUniqueInsert,
            current,
            next_address,
            relocations,
        )
    }

    fn classify_for_profile_with_next(
        profile: GuardedProfile,
        current: Instruction,
        next_address: u64,
        relocations: &DynamicRelocations,
    ) -> Verdict {
        let next = Instruction {
            address: next_address,
            mnemonic: "ret".to_string(),
            operands: String::new(),
        };
        classify(
            &[current, next],
            0,
            relocations,
            &ExactDirectCallSymbols::new(),
            profile,
        )
    }

    fn rip_call(slot: u64, next_address: u64) -> Instruction {
        let displacement = slot
            .checked_sub(next_address)
            .expect("test slot follows the instruction");
        Instruction {
            address: next_address - 6,
            mnemonic: "call".to_string(),
            operands: format!("*0x{displacement:x}(%rip) # {slot:x} <_DYNAMIC>"),
        }
    }

    fn relocation(slot: u64, kind: &str, target: Option<FixedCallTarget>) -> DynamicRelocations {
        DynamicRelocations::from([(
            slot,
            DynamicRelocation {
                kind: kind.to_string(),
                relative_target: target,
                dynamic_symbol: None,
            },
        )])
    }

    fn instruction(address: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction {
            address,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        }
    }

    fn exact_direct_calls(entries: &[(u64, ExactDirectCallTarget)]) -> ExactDirectCallSymbols {
        entries.iter().copied().collect()
    }

    fn canonical_equality_fixture(motif: &str) -> Vec<Instruction> {
        motif
            .lines()
            .enumerate()
            .map(|(index, line)| {
                let (mnemonic, operands) = line
                    .split_once(' ')
                    .expect("canonical equality instruction has operands");
                instruction(
                    0x100 + u64::try_from(index).expect("test fixture index fits u64"),
                    mnemonic,
                    operands,
                )
            })
            .collect()
    }

    #[test]
    fn cli_without_a_profile_selector_keeps_the_insert_guard() {
        let invocation = parse_invocation(vec![OsString::from("target/release/zainod-oram")])
            .expect("legacy one-argument invocation is valid");

        assert_eq!(invocation.profile, GuardedProfile::FixedUniqueInsert);
        assert_eq!(
            invocation.artifact,
            std::path::PathBuf::from("target/release/zainod-oram")
        );
    }

    #[test]
    fn cli_explicitly_selects_each_guarded_profile() {
        for (selector, expected) in [
            ("fixed-unique-insert", GuardedProfile::FixedUniqueInsert),
            ("fixed-exact-upsert", GuardedProfile::FixedExactUpsert),
        ] {
            let invocation = parse_invocation(vec![
                OsString::from("--profile"),
                OsString::from(selector),
                OsString::from("zainod-oram"),
            ])
            .expect("documented profile invocation is valid");

            assert_eq!(invocation.profile, expected, "{selector}");
            assert_eq!(
                invocation.artifact,
                std::path::PathBuf::from("zainod-oram"),
                "{selector}"
            );
        }
    }

    #[test]
    fn cli_profile_selection_fails_closed() {
        assert_eq!(
            parse_invocation(Vec::new())
                .expect_err("missing artifact must retain the legacy usage error"),
            vec!["usage: check-oram-codegen <path-to-x86_64-elf>".to_string()]
        );

        for args in [
            vec![OsString::from("--profile")],
            vec![
                OsString::from("--profile"),
                OsString::from("fixed-exact-upsert"),
            ],
            vec![OsString::from("first"), OsString::from("second")],
        ] {
            assert!(parse_invocation(args).is_err());
        }

        let unknown = parse_invocation(vec![
            OsString::from("--profile"),
            OsString::from("unknown"),
            OsString::from("zainod-oram"),
        ])
        .expect_err("unknown profiles must not fall back to the insert guard");
        assert_eq!(unknown[0], "unknown ORAM codegen profile: unknown");
    }

    #[test]
    fn both_profiles_require_two_record_width_monomorphizations() {
        assert_eq!(
            GuardedProfile::FixedUniqueInsert.expected_monomorphizations(),
            2
        );
        assert_eq!(
            GuardedProfile::FixedExactUpsert.expected_monomorphizations(),
            2
        );
    }

    #[test]
    fn the_recorded_gate_two_failure_is_rejected() {
        let scanned = scan(FAILING, "event", &DynamicRelocations::new());
        assert_eq!(scanned.failures.len(), 1);
        assert!(
            scanned.failures[0].contains("conditional jump at 7adeb2"),
            "unexpected diagnostic: {}",
            scanned.failures[0]
        );
    }

    /// The real remediated codegen must pass, with each benign branch reported.
    #[test]
    fn the_measured_remediated_codegen_is_accepted() {
        let scanned = scan(MEASURED, "directory", &measured_relocations());
        assert_eq!(scanned.failures, Vec::<String>::new());
        assert_eq!(scanned.allowed.len(), 8);
        assert!(scanned.allowed[0].contains("38-byte record Cmov loop back-edge"));
        assert!(scanned
            .allowed
            .iter()
            .any(|line| line.contains("fixed relative call to rand::rngs::thread::rng")));
        assert_eq!(
            scanned
                .allowed
                .iter()
                .filter(|line| line.contains("fixed relative call to alloc::rc::Rc"))
                .count(),
            2
        );
        assert_eq!(
            validate_allowances(&scanned, "directory"),
            Ok(RecordLoop::Directory)
        );
    }

    /// A compare and backward edge alone are insufficient: the full measured
    /// loop body is required.
    #[test]
    fn bare_compare_bounded_jumps_are_rejected() {
        let previous = Instruction {
            address: 0x100,
            mnemonic: "cmp".to_string(),
            operands: "$0x26,%rax".to_string(),
        };
        let backward = Instruction {
            address: 0x104,
            mnemonic: "jne".to_string(),
            operands: "f0 <sym+0x10>".to_string(),
        };
        let forward = Instruction {
            address: 0x104,
            mnemonic: "jne".to_string(),
            operands: "120 <sym+0x30>".to_string(),
        };
        assert_eq!(
            classify_without_relocations(Some(&previous), &backward),
            Verdict::Rejected("conditional jump")
        );
        assert_eq!(
            classify_without_relocations(Some(&previous), &forward),
            Verdict::Rejected("conditional jump")
        );
    }

    /// The allowances require their specific preceding instruction, so a bare
    /// conditional jump cannot slip through either of them.
    #[test]
    fn allowances_require_their_preceding_instruction() {
        let unrelated = Instruction {
            address: 0x100,
            mnemonic: "test".to_string(),
            operands: "%al,%al".to_string(),
        };
        let jump = Instruction {
            address: 0x104,
            mnemonic: "je".to_string(),
            operands: "f0 <sym+0x10>".to_string(),
        };
        assert_eq!(
            classify_without_relocations(Some(&unrelated), &jump),
            Verdict::Rejected("conditional jump")
        );
        assert_eq!(
            classify_without_relocations(None, &jump),
            Verdict::Rejected("conditional jump")
        );

        // A register-to-register compare is not a constant bound.
        let register_compare = Instruction {
            address: 0x100,
            mnemonic: "cmp".to_string(),
            operands: "%rcx,%rax".to_string(),
        };
        assert_eq!(
            classify_without_relocations(Some(&register_compare), &jump),
            Verdict::Rejected("conditional jump")
        );

        // A register decrement is not the measured RNG refcount drop.
        let register_decrement = Instruction {
            address: 0x100,
            mnemonic: "dec".to_string(),
            operands: "%rax".to_string(),
        };
        assert_eq!(
            classify_without_relocations(Some(&register_decrement), &jump),
            Verdict::Rejected("conditional jump")
        );

        // Neither a different immediate nor a secret-carrying register may
        // borrow the known fixed-record loop allowance.
        for operands in ["$0x1,%rax", "$0x26,%rbx", "$0x52,%al"] {
            let near_miss = Instruction {
                address: 0x100,
                mnemonic: "cmp".to_string(),
                operands: operands.to_string(),
            };
            assert_eq!(
                classify_without_relocations(Some(&near_miss), &jump),
                Verdict::Rejected("conditional jump"),
                "{operands}"
            );
        }

        // A decrement through arbitrary memory is not enough: the allowance
        // is tied to the exact TLS refcount instruction in the pinned build.
        for operands in ["-0x8(%rsp)", "0x0(%r12)", "(%rax)"] {
            let near_miss = Instruction {
                address: 0x100,
                mnemonic: "decq".to_string(),
                operands: operands.to_string(),
            };
            assert_eq!(
                classify_without_relocations(Some(&near_miss), &jump),
                Verdict::Rejected("conditional jump"),
                "{operands}"
            );
        }
    }

    #[test]
    fn every_conditional_jump_mnemonic_is_rejected_without_an_allowance() {
        for mnemonic in [
            "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js",
            "jns", "jo", "jno", "jp", "jnp", "jrcxz",
        ] {
            let jump = Instruction {
                address: 0x104,
                mnemonic: mnemonic.to_string(),
                operands: "120 <sym>".to_string(),
            };
            assert_eq!(
                classify_without_relocations(None, &jump),
                Verdict::Rejected("conditional jump"),
                "{mnemonic} was not rejected"
            );
        }
    }

    #[test]
    fn legacy_profile_accepts_non_control_instructions_and_direct_calls() {
        for mnemonic in [
            "add", "call", "cmovne", "cmp", "decq", "inc", "int3", "lea", "mov", "movaps", "movq",
            "movups", "movw", "movzbl", "movzwl", "nopw", "pop", "push", "ret", "sub", "test",
            "xor", "xorps",
        ] {
            let instruction = Instruction {
                address: 0x100,
                mnemonic: mnemonic.to_string(),
                operands: "%rax,%rdx".to_string(),
            };
            assert_eq!(
                classify_without_relocations(None, &instruction),
                Verdict::Branchless,
                "{mnemonic}"
            );
        }
        let direct = Instruction {
            address: 0x100,
            mnemonic: "jmp".to_string(),
            operands: "120 <sym>".to_string(),
        };
        assert_eq!(
            classify_without_relocations(None, &direct),
            Verdict::Rejected("unapproved unconditional jump")
        );
    }

    #[test]
    fn exact_upsert_rejects_direct_calls_to_branchy_or_unknown_callees() {
        for operands in [
            "120 <memcmp@plt>",
            "120 <bcmp@plt>",
            "120 <unknown_local_helper>",
        ] {
            let call = Instruction {
                address: 0x100,
                mnemonic: "call".to_string(),
                operands: operands.to_string(),
            };
            assert_eq!(
                classify_for_profile_without_relocations(
                    GuardedProfile::FixedExactUpsert,
                    None,
                    &call,
                ),
                Verdict::Rejected("direct call target is outside the fixed-exact-upsert profile"),
                "{operands}"
            );
            assert_eq!(
                classify_for_profile_without_relocations(
                    GuardedProfile::FixedUniqueInsert,
                    None,
                    &call,
                ),
                Verdict::Branchless,
                "legacy insert policy changed for {operands}"
            );
        }
    }

    #[test]
    fn exact_upsert_scan_rejects_a_compiler_lowered_byte_comparison_call() {
        for callee in ["memcmp@plt", "bcmp@plt"] {
            let disassembly = format!("  100:\tcall 120 <{callee}>\n");
            let scanned = scan_for_profile(
                &disassembly,
                "exact-upsert",
                &DynamicRelocations::new(),
                GuardedProfile::FixedExactUpsert,
            );

            assert_eq!(scanned.failures.len(), 1, "{callee}");
            assert!(
                scanned.failures[0]
                    .contains("direct call target is outside the fixed-exact-upsert profile"),
                "{}",
                scanned.failures[0]
            );
        }
    }

    #[test]
    fn exact_upsert_direct_calls_require_exact_address_and_label_syntax() {
        for target in [
            ExactDirectCallTarget::RandomRange,
            ExactDirectCallTarget::CircuitRead,
            ExactDirectCallTarget::CircuitWriteOrInsert,
            ExactDirectCallTarget::UnwindResume,
        ] {
            let call = instruction(0x100, "call", &format!("120 <{}>", target.label()));
            let exact_direct_calls = exact_direct_calls(&[(0x120, target)]);
            assert_eq!(
                classify_for_profile_with_direct_calls(
                    GuardedProfile::FixedExactUpsert,
                    None,
                    &call,
                    &exact_direct_calls,
                ),
                Verdict::Allowed(Allowance::ExactDirectCall(target))
            );
        }

        let exact_direct_calls = exact_direct_calls(&[(0x120, ExactDirectCallTarget::RandomRange)]);
        for operands in [
            "0x120 <rand::rng::Rng::random_range>",
            "120 rand::rng::Rng::random_range",
            "120 <rand::rng::Rng::random_range> trailing",
            "not-hex <rand::rng::Rng::random_range>",
            "120 <rand::rng::Rng::random_range::lookalike>",
        ] {
            let call = instruction(0x100, "call", operands);
            assert!(matches!(
                classify_for_profile_with_direct_calls(
                    GuardedProfile::FixedExactUpsert,
                    None,
                    &call,
                    &exact_direct_calls,
                ),
                Verdict::Rejected(_)
            ));
        }

        let conflicting = instruction(
            0x100,
            "call",
            "120 <rostl_oram::circuit_oram::CircuitORAM<V>::read>",
        );
        assert_eq!(
            classify_for_profile_with_direct_calls(
                GuardedProfile::FixedExactUpsert,
                None,
                &conflicting,
                &exact_direct_calls,
            ),
            Verdict::Rejected("direct call label conflicts with its raw symbol identity")
        );
    }

    #[test]
    fn exact_direct_call_addresses_require_raw_symbol_and_unwind_plt_identities() {
        let symbols = exact_direct_text_symbols();
        let relocations = unwind_jump_slot(UNWIND_DYNAMIC_SYMBOL);
        let resolved = parse_exact_direct_call_symbols(&symbols, &relocations, UNWIND_PLT)
            .expect("raw symbols and unwind jump slot are exact");

        assert_eq!(
            resolved,
            ExactDirectCallSymbols::from([
                (0x600, ExactDirectCallTarget::RandomRange),
                (0x601, ExactDirectCallTarget::RandomRange),
                (0x610, ExactDirectCallTarget::CircuitRead),
                (0x611, ExactDirectCallTarget::CircuitRead),
                (0x620, ExactDirectCallTarget::CircuitWriteOrInsert),
                (0x621, ExactDirectCallTarget::CircuitWriteOrInsert),
                (0x700, ExactDirectCallTarget::UnwindResume),
            ])
        );

        for missing in [0x600, 0x601, 0x610, 0x611, 0x620, 0x621] {
            let mut incomplete = symbols.clone();
            incomplete.remove(&missing);
            assert!(
                parse_exact_direct_call_symbols(&incomplete, &relocations, UNWIND_PLT).is_err(),
                "missing exact direct-call identity at {missing:x} passed"
            );
        }

        let mut colliding = symbols.clone();
        colliding
            .get_mut(&0x600)
            .expect("random_range address exists")
            .push(CIRCUIT_READ_RAW_SYMBOL.to_string());
        colliding.remove(&0x610);
        assert!(
            parse_exact_direct_call_symbols(&colliding, &relocations, UNWIND_PLT).is_err(),
            "two approved raw identities at one address must be ambiguous"
        );

        // One identity at two addresses is ambiguous even when every other
        // required identity is present, so the second `random_range`
        // instantiation is still supplied at its own address below.
        let duplicated = TextSymbols::from([
            (0x600, vec![RANDOM_RANGE_RAW_SYMBOL.to_string()]),
            (0x601, vec![RANDOM_RANGE_RAW_SYMBOL.to_string()]),
            (0x602, vec![RANDOM_RANGE_SECOND_RAW_SYMBOL.to_string()]),
            (0x610, vec![CIRCUIT_READ_RAW_SYMBOL.to_string()]),
            (0x611, vec![CIRCUIT_EVENT_READ_RAW_SYMBOL.to_string()]),
            (0x620, vec![CIRCUIT_WRITE_OR_INSERT_RAW_SYMBOL.to_string()]),
            (
                0x621,
                vec![CIRCUIT_EVENT_WRITE_OR_INSERT_RAW_SYMBOL.to_string()],
            ),
        ]);
        assert!(
            parse_exact_direct_call_symbols(&duplicated, &relocations, UNWIND_PLT).is_err(),
            "one raw identity at two addresses must be ambiguous"
        );
    }

    #[test]
    fn unwind_plt_requires_the_exact_jump_slot_symbol_and_shape() {
        let symbols = exact_direct_text_symbols();
        for relocations in [
            DynamicRelocations::new(),
            unwind_jump_slot("_Unwind_Resume"),
            DynamicRelocations::from([(
                0x800,
                DynamicRelocation {
                    kind: "R_X86_64_GLOB_DAT".to_string(),
                    relative_target: None,
                    dynamic_symbol: Some(UNWIND_DYNAMIC_SYMBOL.to_string()),
                },
            )]),
        ] {
            assert!(
                parse_exact_direct_call_symbols(&symbols, &relocations, UNWIND_PLT).is_err(),
                "{relocations:?}"
            );
        }

        let relocation = unwind_jump_slot(UNWIND_DYNAMIC_SYMBOL);
        for listing in [
            UNWIND_PLT.replace("jmp *0xfa", "call *0xfa"),
            UNWIND_PLT.replace("# 800", "# 801"),
            format!("{UNWIND_PLT}0000000000000710 <_Unwind_Resume@plt>:\n"),
        ] {
            assert!(
                parse_exact_direct_call_symbols(&symbols, &relocation, &listing).is_err(),
                "{listing}"
            );
        }
    }

    #[test]
    fn equality_mnemonics_are_scoped_to_the_exact_upsert_profile() {
        for mnemonic in [
            "and", "movd", "movdqa", "movdqu", "nopl", "or", "pand", "pcmpeqb", "pmovmskb", "por",
            "pshufd", "psrld", "psrlw", "pxor", "sete", "sets", "shr",
        ] {
            let instruction = instruction(0x100, mnemonic, "%rax,%rdx");
            assert_eq!(
                classify_for_profile_without_relocations(
                    GuardedProfile::FixedExactUpsert,
                    None,
                    &instruction,
                ),
                Verdict::Branchless,
                "exact profile rejected {mnemonic}"
            );
            assert_eq!(
                classify_without_relocations(None, &instruction),
                Verdict::Rejected("mnemonic is outside the approved structural profile"),
                "legacy profile admitted {mnemonic}"
            );
        }
    }

    #[test]
    fn every_unmeasured_or_pseudo_mnemonic_is_rejected() {
        for mnemonic in [
            "cmove",
            "cmovb",
            "sete",
            "setne",
            "lcall",
            "ljmp",
            "xbegin",
            "(bad)",
            "future-computed-transfer",
        ] {
            let instruction = Instruction {
                address: 0x100,
                mnemonic: mnemonic.to_string(),
                operands: "*%rax".to_string(),
            };
            assert_eq!(
                classify_without_relocations(None, &instruction),
                Verdict::Rejected("mnemonic is outside the approved structural profile"),
                "{mnemonic}"
            );
        }
    }

    /// A jump table is a branch on a computed value even though `jmp` itself is
    /// unconditional.
    #[test]
    fn indirect_jumps_are_rejected() {
        for operands in ["*%rax", "*0x18(%rip)"] {
            let indirect = Instruction {
                address: 0x100,
                mnemonic: "jmp".to_string(),
                operands: operands.to_string(),
            };
            assert_eq!(
                classify_without_relocations(None, &indirect),
                Verdict::Rejected("unapproved unconditional jump")
            );
        }
    }

    #[test]
    fn indirect_calls_are_rejected() {
        for operands in ["*%rax", "*0x18(%rip)"] {
            let indirect = Instruction {
                address: 0x100,
                mnemonic: "call".to_string(),
                operands: operands.to_string(),
            };
            assert!(matches!(
                classify_with_next(indirect, 0x106, &DynamicRelocations::new()),
                Verdict::Rejected(_)
            ));
        }
    }

    #[test]
    fn only_relocation_proven_rip_relative_calls_are_accepted() {
        let fixed = rip_call(0x120, 0x106);
        let relocations = relocation(0x120, "R_X86_64_RELATIVE", Some(FixedCallTarget::ThreadRng));
        assert_eq!(
            classify_with_next(fixed, 0x106, &relocations),
            Verdict::Allowed(Allowance::FixedCall(FixedCallTarget::ThreadRng))
        );

        for operands in [
            "*%rax",
            "*0x18(%rax) # 19ab1d0 <_DYNAMIC+0x2688>",
            "*0x18(%rip)",
        ] {
            let not_proven = Instruction {
                address: 0x100,
                mnemonic: "call".to_string(),
                operands: operands.to_string(),
            };
            assert!(matches!(
                classify_with_next(not_proven, 0x106, &relocations),
                Verdict::Rejected(_)
            ));
        }
    }

    #[test]
    fn exact_upsert_accepts_only_a_relocation_proven_fixed_call_target() {
        let call = rip_call(0x120, 0x106);
        let relocations = relocation(
            0x120,
            "R_X86_64_RELATIVE",
            Some(FixedCallTarget::PositionMapAccess),
        );
        assert_eq!(
            classify_for_profile_with_next(
                GuardedProfile::FixedExactUpsert,
                call.clone(),
                0x106,
                &relocations,
            ),
            Verdict::Allowed(Allowance::FixedCall(FixedCallTarget::PositionMapAccess))
        );

        let unresolved = DynamicRelocations::new();
        assert_eq!(
            classify_for_profile_with_next(
                GuardedProfile::FixedExactUpsert,
                call,
                0x106,
                &unresolved,
            ),
            Verdict::Rejected("indirect call through an unresolved slot")
        );
    }

    #[test]
    fn symbol_end_is_the_boundary_after_a_terminal_fixed_call() {
        let relocations = relocation(0x120, "R_X86_64_RELATIVE", Some(FixedCallTarget::ThreadRng));
        let scanned = scan_with_range(
            "  100:\tff 15 1a 00 00 00\tcall *0x1a(%rip) # 120 <_DYNAMIC>\n",
            "terminal",
            &relocations,
            &ExactDirectCallSymbols::new(),
            GuardedProfile::FixedUniqueInsert,
            Some((0x100, 0x106)),
        );

        assert!(scanned.failures.is_empty());
        assert_eq!(scanned.instructions, 1);
        assert_eq!(
            scanned.allowances,
            vec![Allowance::FixedCall(FixedCallTarget::ThreadRng)]
        );
    }

    #[test]
    fn production_range_requires_exact_contiguous_raw_byte_coverage() {
        let exact = "\
  100:\t90\tnopw 0x0(%rax)
  101:\tc3\tret
";
        let scanned = scan_with_range(
            exact,
            "coverage",
            &DynamicRelocations::new(),
            &ExactDirectCallSymbols::new(),
            GuardedProfile::FixedUniqueInsert,
            Some((0x100, 0x102)),
        );
        assert!(scanned.failures.is_empty());
        assert_eq!(scanned.instructions, 2);

        for malformed in [
            // Missing initial coverage.
            "  101:\tc3\tret\n",
            // Gap between decoded instructions.
            "  100:\t90\tnopw 0x0(%rax)\n  102:\tc3\tret\n",
            // Overlap and duplicate address.
            "  100:\t90 90\tnopw 0x0(%rax)\n  101:\tc3\tret\n",
            "  100:\t90\tnopw 0x0(%rax)\n  100:\tc3\tret\n",
            // Out of range.
            "  ff:\t90\tnopw 0x0(%rax)\n  100:\tc3\tret\n",
            // Missing and malformed raw bytes.
            "  100:\tnopw 0x0(%rax)\n  101:\tret\n",
            "  100:\tzz\tnopw 0x0(%rax)\n  101:\tc3\tret\n",
            // Short and overlong final coverage.
            "  100:\t90\tnopw 0x0(%rax)\n",
            "  100:\t90 90 90\tnopw 0x0(%rax)\n",
        ] {
            let scanned = scan_with_range(
                malformed,
                "coverage",
                &DynamicRelocations::new(),
                &ExactDirectCallSymbols::new(),
                GuardedProfile::FixedUniqueInsert,
                Some((0x100, 0x102)),
            );
            assert!(
                !scanned.failures.is_empty(),
                "malformed range unexpectedly passed: {malformed}"
            );
            assert!(scanned.allowances.is_empty(), "{malformed}");
        }
    }

    #[test]
    fn decoded_bad_instruction_is_rejected_even_with_complete_coverage() {
        let scanned = scan_with_range(
            "  100:\t0f 0b\t(bad)\n",
            "bad",
            &DynamicRelocations::new(),
            &ExactDirectCallSymbols::new(),
            GuardedProfile::FixedUniqueInsert,
            Some((0x100, 0x102)),
        );
        assert_eq!(
            scanned.failures,
            vec![
                "bad: mnemonic is outside the approved structural profile at 100: (bad) "
                    .to_string()
            ]
        );
    }

    #[test]
    fn unresolved_and_dynamic_linker_slots_are_rejected() {
        let indirect = rip_call(0x120, 0x106);
        assert_eq!(
            classify_with_next(indirect.clone(), 0x106, &DynamicRelocations::new()),
            Verdict::Rejected("indirect call through an unresolved slot")
        );

        for kind in ["R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"] {
            let relocations = relocation(0x120, kind, None);
            assert_eq!(
                classify_with_next(indirect.clone(), 0x106, &relocations),
                Verdict::Rejected("indirect call is not fixed by R_X86_64_RELATIVE"),
                "{kind}"
            );
        }
    }

    #[test]
    fn relative_addends_must_resolve_to_an_expected_defined_text_symbol() {
        assert!(parse_defined_text_symbols(&format!(
            "0000000000000100 0000000000000010 D {}\n",
            FixedCallTarget::ThreadRng.identity()
        ))
        .is_err());
        let symbols =
            parse_defined_text_symbols("0000000000000200 0000000000000010 T unexpected::call\n")
                .expect("test text symbols are valid");
        let relocations = parse_dynamic_relocations(
            "0000000000002000 R_X86_64_RELATIVE *ABS*+0x0000000000000200\n",
            &symbols,
        )
        .expect("test relocations are valid");

        let indirect = rip_call(0x2000, 0x106);
        assert_eq!(
            classify_with_next(indirect, 0x106, &relocations),
            Verdict::Rejected("relative call target is not an expected defined text symbol")
        );
    }

    #[test]
    fn relocation_parser_resolves_only_exact_text_targets() {
        let symbols =
            parse_defined_text_symbols(TEXT_SYMBOLS).expect("test text symbols are valid");
        let relocations = parse_dynamic_relocations(
            &format!(
                "{RELOCATIONS}\
00000000019ab200 R_X86_64_GLOB_DAT rand::rngs::thread::rng\n"
            ),
            &symbols,
        )
        .expect("test relocations are valid");

        assert_eq!(
            relocations.get(&0x19ab1d0),
            Some(&DynamicRelocation {
                kind: "R_X86_64_RELATIVE".to_string(),
                relative_target: Some(FixedCallTarget::ThreadRng),
                dynamic_symbol: None,
            })
        );
        assert_eq!(
            relocations.get(&0x19ab200),
            Some(&DynamicRelocation {
                kind: "R_X86_64_GLOB_DAT".to_string(),
                relative_target: None,
                dynamic_symbol: Some("rand::rngs::thread::rng".to_string()),
            })
        );
    }

    #[test]
    fn prefixed_control_transfers_are_exposed_and_rejected() {
        let relocations = relocation(0x120, "R_X86_64_RELATIVE", Some(FixedCallTarget::ThreadRng));
        for instruction in [
            "  100:\tnotrack call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\tbnd call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\taddr32 call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\tfs call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\tgs call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\trex.WB call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\tfuture-prefix call *0x1a(%rip) # 120 <_DYNAMIC>\n  106:\tret",
            "  100:\tdata16 jne 80 <sym>\n  106:\tret",
        ] {
            let scanned = scan(instruction, "prefixed", &relocations);
            assert!(
                scanned
                    .failures
                    .iter()
                    .any(|failure| failure.contains("prefixed control transfer")),
                "{instruction}: {:?}",
                scanned.failures
            );
        }
    }

    #[test]
    fn rip_relative_operand_is_exact_and_recomputed() {
        assert_eq!(
            rip_relative_slot("*0x1a(%rip) # 120 <_DYNAMIC>", 0x106),
            Ok(0x120)
        );
        assert_eq!(
            rip_relative_slot("*-0x1a(%rip) # 106 <_DYNAMIC>", 0x120),
            Ok(0x106)
        );
        for operands in [
            "*0x1a(%rax) # 120 <_DYNAMIC>",
            "*%fs:0x1a(%rip) # 120 <_DYNAMIC>",
            "*%gs:0x1a(%rip) # 120 <_DYNAMIC>",
            "*0x1a(%rip){1to8} # 120 <_DYNAMIC>",
            "*0x1a (%rip) # 120 <_DYNAMIC>",
            "*0x1a(%rip)",
            "*0x1a(%rip) # 121 <_DYNAMIC>",
            "*0x1a(%rip) # 120 # 120",
        ] {
            assert!(rip_relative_slot(operands, 0x106).is_err(), "{operands}");
        }
    }

    #[test]
    fn complete_loop_motif_is_required() {
        let exact = "\
  f0:\tmovzbl %al,%ebx
  f3:\txor %eax,%eax
  f5:\tnopw 0x0(%rax,%rax,1)
  100:\tmovzbl 0x40(%rsp,%rax,1),%ecx
  105:\tmovzbl 0x10(%rsp,%rax,1),%edx
  10a:\ttest %rbx,%rbx
  10d:\tcmovne %ecx,%edx
  110:\tmov %dl,0x10(%rsp,%rax,1)
  114:\tinc %rax
  117:\tcmp $0x26,%rax
  11b:\tjne 100 <sym>
";
        let scanned = scan(exact, "loop", &DynamicRelocations::new());
        assert_eq!(scanned.allowances, vec![Allowance::DirectoryRecordLoop]);
        assert!(scanned.failures.is_empty());

        for changed in [
            exact.replace("cmovne", "cmove"),
            exact.replace("jne 100", "je 100"),
            exact.replace("jne 100", "jne 105"),
            exact.replace("inc %rax", "inc %rbx"),
            exact.replace("xor %eax,%eax", "mov $0x1,%eax"),
            exact.replace("movzbl %al,%ebx", "movzbl %al,%ecx"),
            exact.replace("nopw 0x0", "data16 nopw 0x0"),
        ] {
            let scanned = scan(&changed, "loop", &DynamicRelocations::new());
            assert!(scanned.allowances.is_empty(), "{changed}");
            assert!(!scanned.failures.is_empty(), "{changed}");
        }
    }

    #[test]
    fn exact_upsert_requires_its_width_specific_selection_loops() {
        let directory = "\
  f0:\tmovzbl %al,%eax
  f3:\txor %ecx,%ecx
  f5:\tdata16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  100:\tmovzbl 0x27(%rbp,%rcx,1),%edx
  105:\tmovzbl 0x70(%rsp,%rcx,1),%esi
  10a:\ttest %rax,%rax
  10d:\tcmovne %edx,%esi
  110:\tmov %sil,0x70(%rsp,%rcx,1)
  114:\tinc %rcx
  117:\tcmp $0x26,%rcx
  11b:\tjne 100 <sym>
";
        let event = "\
  f0:\tmovzbl %al,%eax
  f3:\txor %ecx,%ecx
  f5:\tdata16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  100:\tmovzbl 0x53(%r13,%rcx,1),%edx
  105:\tmovzbl 0x90(%rsp,%rcx,1),%esi
  10a:\ttest %rax,%rax
  10d:\tcmovne %edx,%esi
  110:\tmov %sil,0x90(%rsp,%rcx,1)
  114:\tinc %rcx
  117:\tcmp $0x52,%rcx
  11b:\tjne 100 <sym>
";

        for (listing, expected) in [
            (directory, Allowance::DirectoryRecordLoop),
            (event, Allowance::EventRecordLoop),
        ] {
            let scanned = scan_for_profile(
                listing,
                "exact-loop",
                &DynamicRelocations::new(),
                GuardedProfile::FixedExactUpsert,
            );
            assert!(scanned.failures.is_empty(), "{:?}", scanned.failures);
            assert!(scanned.allowances.contains(&expected));
        }

        for changed in [
            directory.replace("0x27(%rbp", "0x28(%rbp"),
            directory.replace("%sil,0x70", "%dl,0x70"),
            directory.replace("data16 data16 data16 cs nopw", "data16 data16 cs nopw"),
            event.replace("$0x52,%rcx", "$0x26,%rcx"),
            event.replace("0x90(%rsp", "0x80(%rsp"),
        ] {
            let scanned = scan_for_profile(
                &changed,
                "exact-loop-near-miss",
                &DynamicRelocations::new(),
                GuardedProfile::FixedExactUpsert,
            );
            assert!(
                !scanned.allowances.iter().any(|allowance| matches!(
                    allowance,
                    Allowance::DirectoryRecordLoop | Allowance::EventRecordLoop
                )),
                "{changed}"
            );
            assert!(!scanned.failures.is_empty(), "{changed}");
        }
    }

    #[test]
    fn exact_upsert_directory_equality_requires_the_canonical_instruction_fingerprint() {
        let exact = canonical_equality_fixture(DIRECTORY_EQUALITY_REDUCTION);
        assert!(directory_equality_reduction(&exact));
        assert!(!event_equality_reduction(&exact));

        let mut reordered = exact.clone();
        let first_fold = reordered
            .iter()
            .position(|instruction| instruction.mnemonic == "pcmpeqb")
            .expect("fixture contains pcmpeqb");
        reordered.swap(first_fold, first_fold + 1);
        assert!(!directory_equality_reduction(&reordered));

        let mut mutated_operand = exact.clone();
        let input = mutated_operand
            .iter_mut()
            .find(|instruction| instruction.operands == "0x17(%rbp),%xmm1")
            .expect("fixture contains second SIMD input");
        input.operands = "0x18(%rbp),%xmm1".to_string();
        assert!(!directory_equality_reduction(&mutated_operand));

        let mut extra_approved_instruction = exact.clone();
        extra_approved_instruction.insert(1, instruction(0x101, "mov", "%rax,%rax"));
        assert!(!directory_equality_reduction(&extra_approved_instruction));

        let mut extra_approved_call = exact;
        extra_approved_call.insert(
            1,
            instruction(
                0x101,
                "call",
                "120 <rostl_oram::circuit_oram::CircuitORAM<V>::read>",
            ),
        );
        assert!(!directory_equality_reduction(&extra_approved_call));
    }

    #[test]
    fn exact_upsert_event_equality_requires_the_canonical_instruction_fingerprint() {
        let exact = canonical_equality_fixture(EVENT_EQUALITY_REDUCTION);
        assert!(event_equality_reduction(&exact));
        assert!(!directory_equality_reduction(&exact));

        let mut reordered = exact.clone();
        let first_reduce = reordered
            .iter()
            .position(|instruction| instruction.mnemonic == "por")
            .expect("fixture contains por");
        reordered.swap(first_reduce, first_reduce + 1);
        assert!(!event_equality_reduction(&reordered));

        let mut mutated_operand = exact.clone();
        let tail = mutated_operand
            .iter_mut()
            .find(|instruction| instruction.operands == "0x52(%r13),%ebp")
            .expect("fixture contains final scalar input");
        tail.operands = "0x53(%r13),%ebp".to_string();
        assert!(!event_equality_reduction(&mutated_operand));

        let mut extra_approved_instruction = exact.clone();
        extra_approved_instruction.insert(1, instruction(0x101, "mov", "%rax,%rax"));
        assert!(!event_equality_reduction(&extra_approved_instruction));

        let mut extra_approved_call = exact;
        extra_approved_call.insert(
            1,
            instruction(
                0x101,
                "call",
                "120 <rostl_oram::circuit_oram::CircuitORAM<V>::read>",
            ),
        );
        assert!(!event_equality_reduction(&extra_approved_call));
    }

    #[test]
    fn complete_drop_motif_is_required() {
        let exact = "\
  80:\tcall *0xfa(%rip) # 180 <_DYNAMIC>
  86:\tmov %rax,%r13
  90:\tdecq 0x0(%r13)
  94:\tjne a0 <sym>
  96:\tmov %rsp,%rdi
  99:\tcall *0x160(%rip) # 200 <_DYNAMIC>
  a0:\tret
  a1:\tmov %rax,%rbx
  a4:\tdecq 0x0(%r13)
  a8:\tjne b4 <sym>
  aa:\tmov %rsp,%rdi
  ad:\tcall *0x14c(%rip) # 200 <_DYNAMIC>
  b4:\tret
";
        let relocations = DynamicRelocations::from([
            (
                0x180,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::ThreadRng),
                    dynamic_symbol: None,
                },
            ),
            (
                0x200,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::RcDropSlow),
                    dynamic_symbol: None,
                },
            ),
        ]);
        let scanned = scan(exact, "drop", &relocations);
        assert_eq!(
            scanned
                .allowances
                .iter()
                .filter(|allowance| **allowance == Allowance::RngRefcountDrop)
                .count(),
            2
        );
        assert!(scanned.failures.is_empty());

        for changed in [
            exact.replace("jne a0", "jnz a0"),
            exact.replace("jne a0", "jne 99"),
            exact.replace("mov %rsp,%rdi", "mov %rsp,%rsi"),
            exact.replace("decq 0x0(%r13)", "decq 0x0(%r12)"),
            exact.replace("mov %rax,%r13", "mov %rax,%r12"),
            exact.replace("mov %rax,%rbx", "mov %rax,%r13"),
            exact.replace(
                "  90:\tdecq 0x0(%r13)",
                "  88:\tmov %rax,%r13\n  90:\tdecq 0x0(%r13)",
            ),
            exact.replace(
                "  90:\tdecq 0x0(%r13)",
                "  88:\tmov %eax,%r13d\n  90:\tdecq 0x0(%r13)",
            ),
            exact.replace(
                "  90:\tdecq 0x0(%r13)",
                "  88:\txchg %r13,%rax\n  90:\tdecq 0x0(%r13)",
            ),
        ] {
            let scanned = scan(&changed, "drop", &relocations);
            assert!(
                scanned
                    .failures
                    .iter()
                    .any(|failure| failure.contains("conditional jump")),
                "{changed}: {:?}",
                scanned.failures
            );
        }
    }

    #[test]
    fn exact_upsert_drop_and_cleanup_motifs_require_the_complete_unwind_shape() {
        let mut instructions = vec![
            rip_call(0x500, 0x106),
            instruction(0x106, "mov", "%rax,%rbx"),
            instruction(0x109, "mov", "%rax,0x8(%rsp)"),
            instruction(0x10e, "mov", "%rax,%rdi"),
            instruction(0x110, "call", "600 <rand::rng::Rng::random_range>"),
            instruction(0x115, "mov", "%eax,%ebp"),
            instruction(0x120, "decq", "(%rbx)"),
            instruction(0x123, "jne", "130 <sym>"),
            instruction(0x125, "lea", "0x8(%rsp),%rdi"),
            rip_call(0x510, 0x130),
            instruction(0x130, "mov", "%rdi,%rbx"),
            rip_call(0x508, 0x140),
            instruction(0x140, "mov", "%rax,%rbx"),
            instruction(0x143, "mov", "%rax,0x8(%rsp)"),
            instruction(0x148, "call", "600 <rand::rng::Rng::random_range>"),
            instruction(0x150, "decq", "(%rbx)"),
            instruction(0x153, "jne", "160 <sym>"),
            instruction(0x155, "lea", "0x8(%rsp),%rdi"),
            rip_call(0x518, 0x160),
            instruction(0x160, "mov", "%rax,%rax"),
            instruction(0x170, "ret", ""),
            instruction(0x180, "mov", "%rax,%r14"),
            instruction(0x183, "decq", "(%rbx)"),
            instruction(0x186, "jne", "1b0 <sym>"),
            instruction(0x188, "lea", "0x8(%rsp),%rdi"),
            rip_call(0x520, 0x190),
            instruction(0x190, "jmp", "1b0 <sym>"),
            instruction(0x198, "mov", "%rax,%r14"),
            instruction(0x19b, "decq", "(%rbx)"),
            instruction(0x19e, "jne", "1b0 <sym>"),
            instruction(0x1a0, "lea", "0x8(%rsp),%rdi"),
            rip_call(0x528, 0x1b0),
            instruction(0x1b0, "mov", "%r14,%rdi"),
            instruction(0x1b3, "call", "700 <_Unwind_Resume@plt>"),
        ];
        let relocations = DynamicRelocations::from([
            (
                0x500,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::ThreadRng),
                    dynamic_symbol: None,
                },
            ),
            (
                0x508,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::ThreadRng),
                    dynamic_symbol: None,
                },
            ),
            (
                0x510,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::RcDropSlow),
                    dynamic_symbol: None,
                },
            ),
            (
                0x518,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::RcDropSlow),
                    dynamic_symbol: None,
                },
            ),
            (
                0x520,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::RcDropSlow),
                    dynamic_symbol: None,
                },
            ),
            (
                0x528,
                DynamicRelocation {
                    kind: "R_X86_64_RELATIVE".to_string(),
                    relative_target: Some(FixedCallTarget::RcDropSlow),
                    dynamic_symbol: None,
                },
            ),
        ]);
        let exact_direct_calls = exact_direct_calls(&[
            (0x600, ExactDirectCallTarget::RandomRange),
            (0x700, ExactDirectCallTarget::UnwindResume),
        ]);

        let branches = instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| (instruction.mnemonic == "jne").then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(branches.len(), 4);
        assert!(branches.iter().all(|index| exact_rng_drop_motif(
            &instructions,
            *index,
            &relocations,
            &exact_direct_calls,
        )));
        let cleanup_jump = instructions
            .iter()
            .position(|instruction| instruction.mnemonic == "jmp")
            .expect("fixture contains cleanup jump");
        assert!(exact_cleanup_jump_motif(
            &instructions,
            cleanup_jump,
            &relocations,
            &exact_direct_calls,
        ));
        let exact_instructions = instructions.clone();

        instructions[cleanup_jump].operands = "1b1 <sym>".to_string();
        assert!(!exact_cleanup_jump_motif(
            &instructions,
            cleanup_jump,
            &relocations,
            &exact_direct_calls,
        ));
        instructions[cleanup_jump].operands = "1b0 <sym>".to_string();
        let decrement = instructions
            .iter_mut()
            .find(|instruction| instruction.mnemonic == "decq")
            .expect("fixture contains decrement");
        decrement.operands = "(%r13)".to_string();
        assert!(branches.iter().all(|index| !exact_rng_drop_motif(
            &instructions,
            *index,
            &relocations,
            &exact_direct_calls,
        )));

        let mut clobbered = exact_instructions;
        let first_random_range = clobbered
            .iter()
            .position(|instruction| {
                exact_direct_call_target(instruction, &exact_direct_calls)
                    == Ok(ExactDirectCallTarget::RandomRange)
            })
            .expect("fixture contains random_range");
        clobbered.insert(first_random_range, instruction(0x10f, "mov", "%rdi,%rbx"));
        let clobbered_branches = clobbered
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| (instruction.mnemonic == "jne").then_some(index))
            .collect::<Vec<_>>();
        assert!(clobbered_branches.iter().all(|index| !exact_rng_drop_motif(
            &clobbered,
            *index,
            &relocations,
            &exact_direct_calls,
        )));
    }

    #[test]
    fn relocation_parsing_rejects_duplicates_and_ambiguous_targets() {
        let symbols =
            parse_defined_text_symbols(TEXT_SYMBOLS).expect("test text symbols are valid");
        let duplicate = format!(
            "{RELOCATIONS}\
00000000019ab1d0 R_X86_64_RELATIVE *ABS*+0x0000000000ad80a0\n"
        );
        assert!(parse_dynamic_relocations(&duplicate, &symbols).is_err());

        let ambiguous = TextSymbols::from([(
            0xad80a0,
            vec![
                FixedCallTarget::ThreadRng.identity().to_string(),
                FixedCallTarget::RcDropSlow.identity().to_string(),
            ],
        )]);
        assert!(parse_dynamic_relocations(
            "00000000019ab1d0 R_X86_64_RELATIVE *ABS*+0x0000000000ad80a0\n",
            &ambiguous
        )
        .is_err());
        assert!(parse_dynamic_relocations(
            "00000000019ab1d0 R_X86_64_RELATIVE malformed\n",
            &symbols
        )
        .is_err());

        let identity = FixedCallTarget::ThreadRng.identity();
        let duplicate_expected_name = format!(
            "0000000000000100 0000000000000010 T {identity}\n\
             0000000000000200 0000000000000010 T {identity}\n"
        );
        assert!(parse_defined_text_symbols(&duplicate_expected_name).is_err());
        let duplicate_expected_name_same_address = format!(
            "0000000000000100 0000000000000010 T {identity}\n\
             0000000000000100 0000000000000010 T {identity}\n"
        );
        assert!(parse_defined_text_symbols(&duplicate_expected_name_same_address).is_err());
        assert!(parse_defined_text_symbols(&format!(
            "0000000000000100 0000000000000000 T {identity}\n"
        ))
        .is_err());
        assert!(
            parse_defined_text_symbols(&format!("0000000000000100 malformed T {identity}\n"))
                .is_err()
        );
    }

    #[test]
    fn guarded_symbol_ranges_must_not_overlap() {
        let listing = format!(
            "0000000000000100 0000000000000020 t {GUARDED_SYMBOL}\n\
             0000000000000110 0000000000000020 t {GUARDED_SYMBOL}\n"
        );
        assert!(parse_guarded_symbols(&listing).is_err());
    }

    #[test]
    fn guarded_symbols_require_text_kind_and_exact_demangled_identity() {
        let exact = format!(
            "0000000000000100 0000000000000020 t {GUARDED_SYMBOL}\n\
             0000000000000120 0000000000000020 T {GUARDED_SYMBOL}\n"
        );
        let symbols = parse_guarded_symbols(&exact).expect("exact guarded symbols are valid");
        assert_eq!(symbols.len(), 2);

        let wrong_kind = format!("0000000000000100 0000000000000020 D {GUARDED_SYMBOL}\n");
        assert!(parse_guarded_symbols(&wrong_kind).is_err());
        let wrong_namespace = "0000000000000100 0000000000000020 t other::fixed_unique_insert\n";
        assert!(parse_guarded_symbols(wrong_namespace).is_err());
        let decorated =
            format!("0000000000000100 0000000000000020 t {GUARDED_SYMBOL}::unexpected\n");
        assert!(parse_guarded_symbols(&decorated).is_err());
    }

    #[test]
    fn upsert_profile_requires_its_exact_demangled_symbol_identity() {
        let exact = format!(
            "0000000000000100 0000000000000020 t {FIXED_EXACT_UPSERT_SYMBOL}\n\
             0000000000000120 0000000000000020 T {FIXED_EXACT_UPSERT_SYMBOL}\n"
        );
        let symbols = parse_guarded_symbols_for_profile(&exact, GuardedProfile::FixedExactUpsert)
            .expect("exact fixed-exact-upsert symbols are valid");
        assert_eq!(symbols.len(), 2);

        assert!(
            parse_guarded_symbols_for_profile(&exact, GuardedProfile::FixedUniqueInsert)
                .expect("an unrelated symbol is ignored")
                .is_empty()
        );

        let old_symbols = format!(
            "0000000000000100 0000000000000020 t {GUARDED_SYMBOL}\n\
             0000000000000120 0000000000000020 T {GUARDED_SYMBOL}\n"
        );
        assert!(
            parse_guarded_symbols_for_profile(&old_symbols, GuardedProfile::FixedExactUpsert)
                .expect("an unrelated symbol is ignored")
                .is_empty()
        );

        let wrong_namespace = "0000000000000100 0000000000000020 t other::fixed_exact_upsert\n";
        assert!(parse_guarded_symbols_for_profile(
            wrong_namespace,
            GuardedProfile::FixedExactUpsert
        )
        .is_err());
        let decorated = format!(
            "0000000000000100 0000000000000020 t {FIXED_EXACT_UPSERT_SYMBOL}::unexpected\n"
        );
        assert!(
            parse_guarded_symbols_for_profile(&decorated, GuardedProfile::FixedExactUpsert)
                .is_err()
        );
    }

    #[test]
    fn guarded_symbol_duplicate_ranges_are_rejected() {
        let listing = format!(
            "0000000000000100 0000000000000020 t {GUARDED_SYMBOL}\n\
             0000000000000100 0000000000000020 t {GUARDED_SYMBOL}\n"
        );
        assert!(parse_guarded_symbols(&listing).is_err());
    }

    #[test]
    fn an_incomplete_or_expanded_allowance_profile_is_rejected() {
        let missing_drop = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: vec![Allowance::DirectoryRecordLoop, Allowance::RngRefcountDrop],
            failures: Vec::new(),
        };
        assert!(validate_allowances(&missing_drop, "directory").is_err());

        let extra_loop = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: vec![
                Allowance::DirectoryRecordLoop,
                Allowance::EventRecordLoop,
                Allowance::RngRefcountDrop,
                Allowance::RngRefcountDrop,
            ],
            failures: Vec::new(),
        };
        assert!(validate_allowances(&extra_loop, "mixed").is_err());
    }

    #[test]
    fn fixed_call_profile_requires_the_exact_five_calls() {
        let mut allowances = vec![
            Allowance::DirectoryRecordLoop,
            Allowance::RngRefcountDrop,
            Allowance::RngRefcountDrop,
            Allowance::FixedCall(FixedCallTarget::ThreadRng),
            Allowance::FixedCall(FixedCallTarget::RcDropSlow),
            Allowance::FixedCall(FixedCallTarget::RcDropSlow),
            Allowance::FixedCall(FixedCallTarget::PositionMapAccess),
            Allowance::FixedCall(FixedCallTarget::PanicInCleanup),
        ];
        let complete = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: allowances.clone(),
            failures: Vec::new(),
        };
        assert_eq!(
            validate_allowances(&complete, "directory"),
            Ok(RecordLoop::Directory)
        );

        allowances.pop();
        let missing = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: allowances.clone(),
            failures: Vec::new(),
        };
        assert!(validate_allowances(&missing, "directory").is_err());

        allowances.push(Allowance::FixedCall(FixedCallTarget::PanicInCleanup));
        allowances.push(Allowance::FixedCall(FixedCallTarget::ThreadRng));
        let extra = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances,
            failures: Vec::new(),
        };
        assert!(validate_allowances(&extra, "directory").is_err());
    }

    #[test]
    fn exact_upsert_profile_requires_every_measured_multiplicity() {
        let mut allowances = vec![
            Allowance::DirectoryRecordLoop,
            Allowance::DirectoryEqualityReduction,
            Allowance::RngRefcountDrop,
            Allowance::RngRefcountDrop,
            Allowance::RngRefcountDrop,
            Allowance::RngRefcountDrop,
            Allowance::ExactCleanupJump,
        ];
        allowances.extend(
            ExactDirectCallTarget::EXPECTED_ORDER
                .into_iter()
                .map(Allowance::ExactDirectCall),
        );
        for target in FixedCallTarget::ALL {
            allowances.extend(std::iter::repeat_n(
                Allowance::FixedCall(target),
                target.expected_per_monomorphization(GuardedProfile::FixedExactUpsert),
            ));
        }
        let complete = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: allowances.clone(),
            failures: Vec::new(),
        };
        assert_eq!(
            validate_allowances_for_profile(
                &complete,
                "exact-directory",
                GuardedProfile::FixedExactUpsert,
            ),
            Ok(RecordLoop::Directory)
        );

        let mutation_indices = [
            allowances
                .iter()
                .position(|allowance| *allowance == Allowance::DirectoryEqualityReduction)
                .expect("fixture contains equality"),
            allowances
                .iter()
                .position(|allowance| *allowance == Allowance::ExactCleanupJump)
                .expect("fixture contains cleanup jump"),
            allowances
                .iter()
                .position(|allowance| {
                    *allowance == Allowance::ExactDirectCall(ExactDirectCallTarget::CircuitRead)
                })
                .expect("fixture contains direct read"),
            allowances
                .iter()
                .position(|allowance| {
                    *allowance == Allowance::FixedCall(FixedCallTarget::RcDropSlow)
                })
                .expect("fixture contains Rc drop"),
        ];
        for index in mutation_indices {
            let mut missing = allowances.clone();
            missing.remove(index);
            let scan = Scan {
                instructions: 1,
                allowed: Vec::new(),
                allowances: missing,
                failures: Vec::new(),
            };
            assert!(validate_allowances_for_profile(
                &scan,
                "exact-directory",
                GuardedProfile::FixedExactUpsert,
            )
            .is_err());
        }

        let mut wrong_order = allowances;
        let random = wrong_order
            .iter()
            .position(|allowance| {
                *allowance == Allowance::ExactDirectCall(ExactDirectCallTarget::RandomRange)
            })
            .expect("fixture contains random_range");
        let read = wrong_order
            .iter()
            .position(|allowance| {
                *allowance == Allowance::ExactDirectCall(ExactDirectCallTarget::CircuitRead)
            })
            .expect("fixture contains read");
        wrong_order.swap(random, read);
        let scan = Scan {
            instructions: 1,
            allowed: Vec::new(),
            allowances: wrong_order,
            failures: Vec::new(),
        };
        assert!(validate_allowances_for_profile(
            &scan,
            "exact-directory",
            GuardedProfile::FixedExactUpsert,
        )
        .is_err());
    }

    /// A refcount drop allowance must not launder a `loop` instruction.
    #[test]
    fn looping_instructions_are_rejected_even_after_a_decrement() {
        let decrement = Instruction {
            address: 0x100,
            mnemonic: "decq".to_string(),
            operands: "0x0(%r13)".to_string(),
        };
        let looping = Instruction {
            address: 0x104,
            mnemonic: "loopne".to_string(),
            operands: "f0 <sym>".to_string(),
        };
        assert_eq!(
            classify_without_relocations(Some(&decrement), &looping),
            Verdict::Rejected("looping branch")
        );
    }

    #[test]
    fn listing_headers_and_blank_lines_are_not_instructions() {
        assert_eq!(parse_instruction(""), Ok(None));
        assert_eq!(parse_instruction("Disassembly of section .text:"), Ok(None));
        assert_eq!(
            parse_instruction("00000000007ade10 <fixed_unique_insert>:"),
            Ok(None)
        );
        assert_eq!(
            parse_instruction("  7adeb2:\tje     7adec7 <sym>"),
            Ok(Some(ParsedInstruction {
                instruction: Instruction {
                    address: 0x7adeb2,
                    mnemonic: "je".to_string(),
                    operands: "7adec7 <sym>".to_string(),
                },
                encoded_len: None,
            }))
        );
        assert_eq!(
            parse_instruction("  7adeb2:\t75 13\tjne 7adec7 <sym>"),
            Ok(Some(ParsedInstruction {
                instruction: Instruction {
                    address: 0x7adeb2,
                    mnemonic: "jne".to_string(),
                    operands: "7adec7 <sym>".to_string(),
                },
                encoded_len: Some(2),
            }))
        );
        assert_eq!(
            parse_instruction("  7adeb2:\tnotrack"),
            Err("missing instruction after prefix")
        );
        assert_eq!(
            parse_instruction("  7adeb2:\t75 13"),
            Err("instruction has raw bytes but no mnemonic")
        );
        assert_eq!(
            parse_instruction("  7adeb2:\tgg\tjne 7adec7 <sym>"),
            Err("invalid raw instruction bytes")
        );
    }

    #[test]
    fn successful_tool_stderr_is_rejected() {
        let failure = tool("sh", &["-c", "printf warning >&2"])
            .expect_err("successful tool stderr must fail closed");
        assert!(failure[0].contains("wrote to stderr despite succeeding"));
    }
}
