//! Guard the complete optimized codegen of the three fixed-page transforms.
//!
//! A branch-only check is insufficient here: a compiler could replace the
//! source's sixteen fixed candidate-selection passes with a branchless,
//! occupancy-indexed memory access. This checker therefore compares every
//! normalized instruction against a reviewed whole-symbol profile. It
//! preserves instruction offsets and lengths, registers, immediates, stack
//! offsets, memory base/index/scale/displacement operands, and local branch
//! topology. Only linked-layout noise is normalized:
//!
//! - local branch targets become offsets from the guarded symbol;
//! - fixed indirect libc calls become their relocation-proven, versioned
//!   dynamic identities;
//! - each reviewed RIP-relative constant load becomes its exact referenced
//!   bytes, only when they come from loaded, allocated, relocation-free
//!   read-only data. The loads are pinned as an ordered sequence
//!   (`EXPECTED_RIP_CONSTANTS`) of mnemonic, destination register and exact
//!   bytes; a load with no entry at its position fails closed.
//!
//! The measured wrappers contain one fixed-size `memset` and three fixed-size
//! `memcpy` calls. Their caller-side argument setup is pinned by the complete
//! profiles and their targets by exact `R_X86_64_GLOB_DAT` relocations. Runtime
//! libc dispatch remains an explicit transitive assumption. This is a
//! fail-closed regression profile, not semantic taint analysis.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};
use workbench::{command as tool, encoded_byte_len, is_gnu_prefix, run};

const EXPECTED_SYMBOL_SIZE: u64 = 0xca9;
const EXPECTED_BRANCHES: usize = 26;
const EXPECTED_RETURNS: usize = 1;
const MEMCPY: &str = "memcpy@GLIBC_2.14";
const MEMSET: &str = "memset@GLIBC_2.2.5";
const FIRST_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
];
const SECOND_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// One reviewed RIP-relative constant load, pinned by position.
///
/// Every field is load-bearing. `bytes` pins the constant's value, and its
/// length is also the width the guard reads and therefore cannot be inferred
/// from the instruction — an attacker-chosen width would otherwise decide how
/// much of the constant gets compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RipConstant {
    mnemonic: &'static str,
    destination: &'static str,
    bytes: &'static [u8],
}

/// The complete, ordered set of RIP-relative constant loads the guarded
/// symbols may perform.
///
/// Previously this was two hard-coded 16-byte `pand` masks compared as
/// `masks == [FIRST_MASK, SECOND_MASK]`. Expressing it as a sequence lets a
/// reviewed symbol load constants of other widths through other instructions
/// -- auto-vectorisation introduces exactly that -- without loosening what is
/// checked. Each entry still pins mnemonic, destination register and every
/// byte, and a load with no entry at its position fails closed.
const EXPECTED_RIP_CONSTANTS: &[RipConstant] = &[
    RipConstant {
        mnemonic: "pand",
        destination: "%xmm7",
        bytes: &FIRST_MASK,
    },
    RipConstant {
        mnemonic: "pand",
        destination: "%xmm3",
        bytes: &SECOND_MASK,
    },
];
const MEASURED_MNEMONICS: &[&str] = &[
    "add",
    "and",
    "call",
    "cmovne",
    "cmp",
    "cmpb",
    "cmpq",
    "data16 data16 data16 cs nopw",
    "inc",
    "ja",
    "je",
    "jmp",
    "jne",
    "lea",
    "mov",
    "movabs",
    "movaps",
    "movd",
    "movdqa",
    "movdqu",
    "movq",
    "movsd",
    "movss",
    "movups",
    "movw",
    "movzbl",
    "movzwl",
    "nop",
    "nopl",
    "nopw",
    "not",
    "or",
    "orps",
    "packuswb",
    "pand",
    "pcmpeqb",
    "pinsrw",
    "pmovmskb",
    "pop",
    "por",
    "pshufd",
    "pshufhw",
    "pshuflw",
    "pslldq",
    "psllq",
    "psllw",
    "psrld",
    "psrldq",
    "psrlw",
    "punpckhbw",
    "punpcklbw",
    "punpcklqdq",
    "push",
    "pxor",
    "ret",
    "setae",
    "setb",
    "setbe",
    "sete",
    "setne",
    "shl",
    "shr",
    "shufps",
    "sub",
    "test",
    "xchg",
    "xor",
];

const BASE_PROFILE: &str = include_str!("../../codegen-profiles/fixed-page-append-v1/base.asm");
const ADD_PROFILE: &str = include_str!("../../codegen-profiles/fixed-page-append-v1/add.asm");
const SPEND_PROFILE: &str = include_str!("../../codegen-profiles/fixed-page-append-v1/spend.asm");

fn main() {
    run("check-oram-page-codegen", execute, |report| match report {
        Report::Checked(symbols) => {
            for symbol in symbols {
                println!(
                    "check-oram-page-codegen: ok — {} instructions match {}",
                    symbol.instructions,
                    symbol.kind.symbol()
                );
            }
            println!(
                "check-oram-page-codegen: ok — all three fixed-page transforms match the reviewed whole-symbol profile"
            );
        }
        Report::Emitted(paths) => {
            for path in paths {
                println!(
                    "check-oram-page-codegen: emitted unreviewed profile {}",
                    path.display()
                );
            }
            println!(
                "check-oram-page-codegen: warning — emitted profiles require manual assembly review before admission"
            );
        }
    })
}

#[derive(Debug)]
enum Report {
    Checked(Vec<CheckedSymbol>),
    Emitted(Vec<PathBuf>),
}

#[derive(Debug)]
struct CheckedSymbol {
    kind: PageKind,
    instructions: usize,
}

#[derive(Debug)]
enum Invocation {
    Check(PathBuf),
    Emit { artifact: PathBuf, output: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PageKind {
    Base,
    Add,
    Spend,
}

impl PageKind {
    const ALL: [Self; 3] = [Self::Base, Self::Add, Self::Spend];

    const fn fragment(self) -> &'static str {
        match self {
            Self::Base => "fixed_base_page_append",
            Self::Add => "fixed_add_page_append",
            Self::Spend => "fixed_spend_page_append",
        }
    }

    const fn symbol(self) -> &'static str {
        match self {
            Self::Base => "zaino_oram::records::fixed_base_page_append",
            Self::Add => "zaino_oram::records::fixed_add_page_append",
            Self::Spend => "zaino_oram::records::fixed_spend_page_append",
        }
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::Base => "base.asm",
            Self::Add => "add.asm",
            Self::Spend => "spend.asm",
        }
    }

    const fn profile(self) -> &'static str {
        match self {
            Self::Base => BASE_PROFILE,
            Self::Add => ADD_PROFILE,
            Self::Spend => SPEND_PROFILE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Symbol {
    kind: PageKind,
    address: u64,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Instruction {
    address: u64,
    encoded_len: u64,
    mnemonic: String,
    operands: String,
}

impl Instruction {
    fn bare_mnemonic(&self) -> &str {
        self.mnemonic
            .rsplit_once(' ')
            .map_or(self.mnemonic.as_str(), |(_, mnemonic)| mnemonic)
    }

    fn has_prefix(&self) -> bool {
        self.mnemonic.contains(' ')
    }

    fn next_address(&self) -> Option<u64> {
        self.address.checked_add(self.encoded_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicRelocation {
    kind: String,
    symbol: String,
}

type DynamicRelocations = BTreeMap<u64, DynamicRelocation>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    name: String,
    address: u64,
    size: u64,
    contents: bool,
    allocated: bool,
    loaded: bool,
    readonly: bool,
    code: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LibcCall {
    Memset,
    Memcpy,
}

impl LibcCall {
    const EXPECTED: [Self; 4] = [Self::Memset, Self::Memcpy, Self::Memcpy, Self::Memcpy];

    const fn symbol(self) -> &'static str {
        match self {
            Self::Memset => MEMSET,
            Self::Memcpy => MEMCPY,
        }
    }
}

#[derive(Debug)]
struct Normalized {
    text: String,
    instructions: usize,
}

/// Whether the exact-size pin is enforced or merely recorded.
///
/// `Check` enforces it: an unexpected size is the regression the guard exists
/// to catch, and it must fail closed.
///
/// `Emit` records it instead. Enforcing during emission would make the guard
/// unable to regenerate its own pins after a size change -- which is precisely
/// when regeneration is needed -- forcing whoever regenerates to edit the
/// constant blind, before ever seeing the assembly they are meant to review.
/// Emission produces candidate material for human review and admits nothing on
/// its own, so observing the size here weakens no check: every emitted profile
/// still has to pass `Check` once its pin is committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SizePolicy {
    Enforce,
    Observe,
}

fn execute() -> Result<Report, Vec<String>> {
    let invocation = parse_invocation(std::env::args_os().skip(1).collect())?;
    let (artifact, output, size_policy) = match &invocation {
        Invocation::Check(artifact) => (artifact, None, SizePolicy::Enforce),
        Invocation::Emit { artifact, output } => (artifact, Some(output), SizePolicy::Observe),
    };
    if !artifact.is_file() {
        return Err(vec![format!("not a file: {}", artifact.display())]);
    }

    let symbols = guarded_symbols(artifact, size_policy)?;
    let sections = artifact_sections(artifact)?;
    let relocations = dynamic_relocations(artifact)?;
    let mut normalized = Vec::with_capacity(PageKind::ALL.len());
    for symbol in &symbols {
        normalized.push((
            symbol.kind,
            inspect_symbol(artifact, symbol, &sections, &relocations)?,
        ));
    }

    if let Some(output) = output {
        fs::create_dir_all(output).map_err(|error| {
            vec![format!(
                "cannot create profile directory {}: {error}",
                output.display()
            )]
        })?;
        let mut paths = Vec::with_capacity(normalized.len());
        for (kind, inspected) in normalized {
            let path = output.join(kind.filename());
            fs::write(&path, inspected.text.as_bytes())
                .map_err(|error| vec![format!("cannot write {}: {error}", path.display())])?;
            paths.push(path);
        }
        return Ok(Report::Emitted(paths));
    }

    let mut checked = Vec::with_capacity(normalized.len());
    for (kind, inspected) in normalized {
        compare_profile(kind, kind.profile(), &inspected.text)?;
        checked.push(CheckedSymbol {
            kind,
            instructions: inspected.instructions,
        });
    }
    Ok(Report::Checked(checked))
}

fn parse_invocation(args: Vec<OsString>) -> Result<Invocation, Vec<String>> {
    const USAGE: &str = "usage: check-oram-page-codegen <path-to-x86_64-elf>\n       \
         check-oram-page-codegen --emit-profiles <path-to-x86_64-elf> <output-directory>";
    match args.as_slice() {
        [artifact] if artifact != "--emit-profiles" => Ok(Invocation::Check(artifact.into())),
        [flag, artifact, output] if flag == "--emit-profiles" => Ok(Invocation::Emit {
            artifact: artifact.into(),
            output: output.into(),
        }),
        _ => Err(vec![USAGE.to_string()]),
    }
}

fn guarded_symbols(artifact: &Path, size_policy: SizePolicy) -> Result<Vec<Symbol>, Vec<String>> {
    let listing = tool(
        "nm",
        &["-nSC", "--defined-only", &artifact.display().to_string()],
    )?;
    parse_guarded_symbols(&listing, size_policy)
}

fn parse_guarded_symbols(
    listing: &str,
    size_policy: SizePolicy,
) -> Result<Vec<Symbol>, Vec<String>> {
    let mut symbols = Vec::new();
    for line in listing.lines() {
        let matched = PageKind::ALL
            .into_iter()
            .find(|kind| line.contains(kind.fragment()));
        let Some(kind) = matched else {
            continue;
        };
        let mut fields = line.split_whitespace();
        let (Some(address), Some(size), Some(symbol_kind)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(vec![format!(
                "malformed `{}` symbol line: {line}",
                kind.fragment()
            )]);
        };
        let name = fields.collect::<Vec<_>>().join(" ");
        if name != kind.symbol() {
            return Err(vec![format!(
                "unexpected demangled `{}` identity: {line}",
                kind.fragment()
            )]);
        }
        if !matches!(symbol_kind, "T" | "t") {
            return Err(vec![format!(
                "`{}` symbol is not text: {line}",
                kind.fragment()
            )]);
        }
        let address = u64::from_str_radix(address, 16).map_err(|_| {
            vec![format!(
                "invalid `{}` symbol address: {line}",
                kind.fragment()
            )]
        })?;
        let size = u64::from_str_radix(size, 16)
            .map_err(|_| vec![format!("invalid `{}` symbol size: {line}", kind.fragment())])?;
        if size_policy == SizePolicy::Enforce && size != EXPECTED_SYMBOL_SIZE {
            return Err(vec![format!(
                "`{}` has size 0x{size:x}, expected exactly 0x{EXPECTED_SYMBOL_SIZE:x}",
                kind.fragment()
            )]);
        }
        address.checked_add(size).ok_or_else(|| {
            vec![format!(
                "`{}` symbol range overflows: {line}",
                kind.fragment()
            )]
        })?;
        symbols.push(Symbol {
            kind,
            address,
            size,
        });
    }

    for kind in PageKind::ALL {
        let count = symbols.iter().filter(|symbol| symbol.kind == kind).count();
        if count != 1 {
            return Err(vec![format!(
                "found {count} exact `{}` symbols, expected exactly one; the gate cannot pass vacuously",
                kind.symbol()
            )]);
        }
    }
    symbols.sort_by_key(|symbol| symbol.address);
    for adjacent in symbols.windows(2) {
        let previous_end = adjacent[0]
            .address
            .checked_add(adjacent[0].size)
            .ok_or_else(|| vec!["guarded symbol range overflows".to_string()])?;
        if adjacent[1].address < previous_end {
            return Err(vec![format!(
                "guarded symbols overlap or alias: {} and {}",
                adjacent[0].kind.symbol(),
                adjacent[1].kind.symbol()
            )]);
        }
    }
    Ok(symbols)
}

fn dynamic_relocations(artifact: &Path) -> Result<DynamicRelocations, Vec<String>> {
    let listing = tool("objdump", &["-R", &artifact.display().to_string()])?;
    parse_dynamic_relocations(&listing)
}

fn artifact_sections(artifact: &Path) -> Result<Vec<Section>, Vec<String>> {
    let listing = tool("objdump", &["-h", &artifact.display().to_string()])?;
    parse_sections(&listing)
}

fn parse_sections(listing: &str) -> Result<Vec<Section>, Vec<String>> {
    if !listing
        .lines()
        .any(|line| line.trim_end().ends_with("file format elf64-x86-64"))
    {
        return Err(vec![
            "artifact is not reported as exact elf64-x86-64".to_string()
        ]);
    }
    let mut sections = Vec::new();
    let mut indices = BTreeSet::new();
    let mut lines = listing.lines();
    while let Some(line) = lines.next() {
        let mut fields = line.split_whitespace();
        let Some(index) = fields.next().and_then(|field| field.parse::<usize>().ok()) else {
            continue;
        };
        let (Some(name), Some(size), Some(address)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(vec![format!("malformed objdump section row: {line}")]);
        };
        if !indices.insert(index) {
            return Err(vec![format!("duplicate objdump section index {index}")]);
        }
        let size = u64::from_str_radix(size, 16)
            .map_err(|_| vec![format!("invalid objdump section size: {line}")])?;
        let address = u64::from_str_radix(address, 16)
            .map_err(|_| vec![format!("invalid objdump section address: {line}")])?;
        address
            .checked_add(size)
            .ok_or_else(|| vec![format!("objdump section range overflows: {line}")])?;
        let flags_line = lines
            .next()
            .ok_or_else(|| vec![format!("missing flags for objdump section `{name}`")])?;
        let flags = flags_line
            .split(',')
            .map(str::trim)
            .collect::<BTreeSet<_>>();
        sections.push(Section {
            name: name.to_string(),
            address,
            size,
            contents: flags.contains("CONTENTS"),
            allocated: flags.contains("ALLOC"),
            loaded: flags.contains("LOAD"),
            readonly: flags.contains("READONLY"),
            code: flags.contains("CODE"),
        });
    }
    if sections.is_empty() {
        return Err(vec![
            "objdump did not provide any parseable section headers".to_string(),
        ]);
    }
    Ok(sections)
}

fn parse_dynamic_relocations(listing: &str) -> Result<DynamicRelocations, Vec<String>> {
    let mut relocations = DynamicRelocations::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let Some(slot) = fields.next() else {
            continue;
        };
        let Ok(slot) = u64::from_str_radix(slot, 16) else {
            continue;
        };
        let Some(kind) = fields.next() else {
            return Err(vec![format!(
                "dynamic relocation at 0x{slot:x} has no type: {line}"
            )]);
        };
        if !kind.starts_with("R_X86_64_") {
            return Err(vec![format!(
                "dynamic relocation at 0x{slot:x} has unsupported type `{kind}`"
            )]);
        }
        let symbol = fields.collect::<Vec<_>>().join(" ");
        if relocations
            .insert(
                slot,
                DynamicRelocation {
                    kind: kind.to_string(),
                    symbol,
                },
            )
            .is_some()
        {
            return Err(vec![format!(
                "duplicate dynamic-relocation slot {slot:x}: {line}"
            )]);
        }
    }
    Ok(relocations)
}

fn inspect_symbol(
    artifact: &Path,
    symbol: &Symbol,
    sections: &[Section],
    relocations: &DynamicRelocations,
) -> Result<Normalized, Vec<String>> {
    let symbol_end = symbol
        .address
        .checked_add(symbol.size)
        .ok_or_else(|| vec![format!("{}: symbol range overflows", symbol.kind.symbol())])?;
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
    let instructions = parse_instructions(&disassembly, symbol.kind.symbol())?;
    validate_instruction_coverage(&instructions, symbol.address, symbol_end)
        .map_err(|reason| vec![format!("{}: {reason}", symbol.kind.symbol())])?;
    normalize_instructions(
        symbol,
        &instructions,
        sections,
        relocations,
        |address, length| artifact_bytes(artifact, address, length),
    )
}

fn parse_instructions(listing: &str, symbol: &str) -> Result<Vec<Instruction>, Vec<String>> {
    let mut instructions = Vec::new();
    for line in listing.lines() {
        match parse_instruction(line) {
            Ok(Some(instruction)) => instructions.push(instruction),
            Ok(None) => {}
            Err(reason) => {
                return Err(vec![format!("{symbol}: {reason}: {}", line.trim())]);
            }
        }
    }
    if instructions.is_empty() {
        return Err(vec![format!(
            "{symbol}: disassembled to no instructions; the symbol range looks wrong"
        )]);
    }
    Ok(instructions)
}

fn parse_instruction(line: &str) -> Result<Option<Instruction>, &'static str> {
    let Some((address, rest)) = line.split_once(':') else {
        return Ok(None);
    };
    let address = address.trim();
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let address = u64::from_str_radix(address, 16).map_err(|_| "invalid instruction address")?;
    let columns = rest
        .split('\t')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .collect::<Vec<_>>();
    let [bytes, instruction] = columns.as_slice() else {
        return Err("instruction does not have exact raw-byte and mnemonic columns");
    };
    let encoded_len = encoded_byte_len(bytes).ok_or("invalid raw instruction bytes")?;
    let parts = instruction.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return Err("instruction has no mnemonic");
    }
    let prefixes = parts.iter().take_while(|part| is_gnu_prefix(part)).count();
    let mnemonic = parts
        .get(prefixes)
        .ok_or("missing instruction after prefix")?;
    let mnemonic = if prefixes == 0 {
        mnemonic.to_string()
    } else {
        format!("{} {mnemonic}", parts[..prefixes].join(" "))
    };
    Ok(Some(Instruction {
        address,
        encoded_len,
        mnemonic,
        operands: parts[prefixes + 1..].join(" "),
    }))
}

fn validate_instruction_coverage(
    instructions: &[Instruction],
    symbol_start: u64,
    symbol_end: u64,
) -> Result<(), &'static str> {
    if symbol_start >= symbol_end {
        return Err("invalid guarded symbol range");
    }
    let mut expected = symbol_start;
    for instruction in instructions {
        if instruction.address != expected {
            return Err("instruction bytes do not contiguously cover the guarded symbol");
        }
        expected = instruction
            .next_address()
            .ok_or("instruction range overflows")?;
        if expected > symbol_end {
            return Err("instruction extends beyond the guarded symbol");
        }
    }
    if expected != symbol_end {
        return Err("instruction coverage does not reach the guarded symbol end");
    }
    Ok(())
}

fn normalize_instructions(
    symbol: &Symbol,
    instructions: &[Instruction],
    sections: &[Section],
    relocations: &DynamicRelocations,
    mut read_bytes: impl FnMut(u64, usize) -> Result<Vec<u8>, Vec<String>>,
) -> Result<Normalized, Vec<String>> {
    let instruction_boundaries = instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<BTreeSet<_>>();
    let mut text = String::new();
    let mut calls = Vec::new();
    let mut branches = 0usize;
    let mut returns = 0usize;
    let mut rip_constants = 0usize;

    for instruction in instructions {
        if !is_measured_mnemonic(&instruction.mnemonic) {
            return Err(vec![format!(
                "{}: unmeasured instruction mnemonic `{}` at +0x{:x}",
                symbol.kind.symbol(),
                instruction.mnemonic,
                instruction.address.saturating_sub(symbol.address)
            )]);
        }
        let mnemonic = instruction.bare_mnemonic();
        let operands = if matches!(mnemonic, "call" | "callq") {
            if instruction.has_prefix() {
                return Err(vec![format!(
                    "{}: prefixed call at +0x{:x}",
                    symbol.kind.symbol(),
                    instruction.address - symbol.address
                )]);
            }
            let target = resolve_libc_call(instruction, relocations)?;
            calls.push(target);
            format!("*<{}>", target.symbol())
        } else if mnemonic.starts_with('j') {
            branches += 1;
            normalize_branch_target(symbol, instruction, &instruction_boundaries)?
        } else if matches!(mnemonic, "ret" | "retq") {
            if instruction.has_prefix() || !instruction.operands.is_empty() {
                return Err(vec![format!(
                    "{}: non-canonical return at +0x{:x}",
                    symbol.kind.symbol(),
                    instruction.address - symbol.address
                )]);
            }
            returns += 1;
            String::new()
        } else if instruction.operands.contains("%rip") {
            let normalized = normalize_rip_constant(
                instruction,
                rip_constants,
                sections,
                relocations,
                &mut read_bytes,
            )?;
            rip_constants += 1;
            normalized
        } else {
            if instruction.operands.contains('#') {
                return Err(vec![format!(
                    "{}: unreviewed symbolic operand at +0x{:x}",
                    symbol.kind.symbol(),
                    instruction.address - symbol.address
                )]);
            }
            instruction.operands.clone()
        };

        let offset = instruction
            .address
            .checked_sub(symbol.address)
            .ok_or_else(|| {
                vec![format!(
                    "{}: instruction precedes symbol start",
                    symbol.kind.symbol()
                )]
            })?;
        text.push_str(&format!(
            "{offset:04x}:{:02x}:{}",
            instruction.encoded_len, instruction.mnemonic
        ));
        if !operands.is_empty() {
            text.push(':');
            text.push_str(&operands);
        }
        text.push('\n');
    }

    validate_measured_shape(symbol.kind, &calls, branches, returns, rip_constants)?;

    Ok(Normalized {
        text,
        instructions: instructions.len(),
    })
}

fn is_measured_mnemonic(mnemonic: &str) -> bool {
    MEASURED_MNEMONICS.contains(&mnemonic)
}

fn normalize_branch_target(
    symbol: &Symbol,
    instruction: &Instruction,
    instruction_boundaries: &BTreeSet<u64>,
) -> Result<String, Vec<String>> {
    if instruction.has_prefix() || instruction.operands.starts_with('*') {
        return Err(vec![format!(
            "{}: indirect or prefixed jump at +0x{:x}",
            symbol.kind.symbol(),
            instruction.address.saturating_sub(symbol.address)
        )]);
    }
    let target = direct_target(&instruction.operands).ok_or_else(|| {
        vec![format!(
            "{}: jump has no exact numeric target at +0x{:x}",
            symbol.kind.symbol(),
            instruction.address.saturating_sub(symbol.address)
        )]
    })?;
    let symbol_end = symbol
        .address
        .checked_add(symbol.size)
        .ok_or_else(|| vec![format!("{}: symbol range overflows", symbol.kind.symbol())])?;
    if target < symbol.address || target >= symbol_end {
        return Err(vec![format!(
            "{}: external jump target 0x{target:x} at +0x{:x}",
            symbol.kind.symbol(),
            instruction.address.saturating_sub(symbol.address)
        )]);
    }
    if !instruction_boundaries.contains(&target) {
        return Err(vec![format!(
            "{}: jump target 0x{target:x} is not an instruction boundary",
            symbol.kind.symbol()
        )]);
    }
    Ok(format!("+0x{:x}", target - symbol.address))
}

fn validate_measured_shape(
    kind: PageKind,
    calls: &[LibcCall],
    branches: usize,
    returns: usize,
    rip_constants: usize,
) -> Result<(), Vec<String>> {
    if calls != LibcCall::EXPECTED {
        return Err(vec![format!(
            "{}: fixed libc call order or multiplicity changed; found {calls:?}",
            kind.symbol()
        )]);
    }
    if branches != EXPECTED_BRANCHES {
        return Err(vec![format!(
            "{}: expected exactly {EXPECTED_BRANCHES} reviewed internal branches; found {branches}",
            kind.symbol()
        )]);
    }
    if returns != EXPECTED_RETURNS {
        return Err(vec![format!(
            "{}: expected exactly one return; found {returns}",
            kind.symbol()
        )]);
    }
    if rip_constants != EXPECTED_RIP_CONSTANTS.len() {
        return Err(vec![format!(
            "{}: expected exactly {} reviewed RIP-relative constants; found {rip_constants}",
            kind.symbol(),
            EXPECTED_RIP_CONSTANTS.len()
        )]);
    }
    Ok(())
}

fn resolve_libc_call(
    instruction: &Instruction,
    relocations: &DynamicRelocations,
) -> Result<LibcCall, Vec<String>> {
    let next = instruction
        .next_address()
        .ok_or_else(|| vec!["call instruction range overflows".to_string()])?;
    let (operand, comment) = instruction.operands.split_once('#').ok_or_else(|| {
        vec!["fixed libc call is missing the objdump-resolved slot comment".to_string()]
    })?;
    let slot = rip_relative_target(operand.trim(), next, true)
        .map_err(|reason| vec![format!("fixed libc call: {reason}")])?;
    let (comment_address, comment_label) = comment_target(comment).ok_or_else(|| {
        vec!["fixed libc call has a malformed objdump-resolved slot comment".to_string()]
    })?;
    if comment_address != slot {
        return Err(vec![
            "fixed libc call comment address conflicts with its RIP-relative slot".to_string(),
        ]);
    }
    let relocation = relocations
        .get(&slot)
        .ok_or_else(|| vec![format!("fixed libc call slot 0x{slot:x} has no relocation")])?;
    if relocation.kind != "R_X86_64_GLOB_DAT" {
        return Err(vec![format!(
            "fixed libc call slot 0x{slot:x} uses {}, expected R_X86_64_GLOB_DAT",
            relocation.kind
        )]);
    }
    let target = match relocation.symbol.as_str() {
        MEMSET => LibcCall::Memset,
        MEMCPY => LibcCall::Memcpy,
        _ => {
            return Err(vec![format!(
                "fixed libc call slot 0x{slot:x} resolves to unapproved `{}`",
                relocation.symbol
            )]);
        }
    };
    if comment_label != target.symbol() {
        return Err(vec![format!(
            "fixed libc call label `{comment_label}` conflicts with relocation identity `{}`",
            target.symbol()
        )]);
    }
    Ok(target)
}

/// Normalize the `index`-th RIP-relative constant load in a guarded symbol.
///
/// The expected constant is selected by position, and its pinned length is the
/// number of bytes read and compared. A load beyond the reviewed sequence has
/// no entry and fails closed, so extra constants cannot slip in unmeasured.
fn normalize_rip_constant(
    instruction: &Instruction,
    index: usize,
    sections: &[Section],
    relocations: &DynamicRelocations,
    read_bytes: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, Vec<String>>,
) -> Result<String, Vec<String>> {
    let Some(expected) = EXPECTED_RIP_CONSTANTS.get(index) else {
        return Err(vec![format!(
            "RIP-relative constant #{index} at 0x{:x} is beyond the {} reviewed constants: {} {}",
            instruction.address,
            EXPECTED_RIP_CONSTANTS.len(),
            instruction.mnemonic,
            instruction.operands
        )]);
    };
    if instruction.has_prefix() || instruction.bare_mnemonic() != expected.mnemonic {
        return Err(vec![format!(
            "unapproved RIP-relative data instruction at 0x{:x}: {} {}, expected `{}`",
            instruction.address, instruction.mnemonic, instruction.operands, expected.mnemonic
        )]);
    }
    let next = instruction
        .next_address()
        .ok_or_else(|| vec!["RIP-relative instruction range overflows".to_string()])?;
    let (operand_text, comment) = instruction.operands.split_once('#').ok_or_else(|| {
        vec!["RIP-relative constant is missing the objdump-resolved target comment".to_string()]
    })?;
    let (source, destination) = operand_text.trim().rsplit_once(',').ok_or_else(|| {
        vec!["RIP-relative constant does not have exact source,destination operands".to_string()]
    })?;
    if destination != expected.destination {
        return Err(vec![format!(
            "RIP-relative constant #{index} has destination `{destination}`, expected `{}`",
            expected.destination
        )]);
    }
    let target = rip_relative_target(source, next, false)
        .map_err(|reason| vec![format!("RIP-relative constant: {reason}")])?;
    let (comment_address, _) = comment_target(comment).ok_or_else(|| {
        vec!["RIP-relative constant has a malformed objdump-resolved target comment".to_string()]
    })?;
    if comment_address != target {
        return Err(vec![
            "RIP-relative constant comment address conflicts with its encoded target".to_string(),
        ]);
    }
    let width = expected.bytes.len();
    let length = u64::try_from(width)
        .map_err(|_| vec!["reviewed constant width does not fit u64".to_string()])?;
    validate_readonly_constant_span(sections, relocations, target, length)?;
    let bytes = read_bytes(target, width)?;
    if bytes.len() != width {
        return Err(vec![format!(
            "RIP-relative constant #{index} read returned {} bytes, expected {width}",
            bytes.len()
        )]);
    }
    if bytes != expected.bytes {
        return Err(vec![format!(
            "RIP-relative constant #{index} is {}, expected {}",
            encode_hex(&bytes),
            encode_hex(expected.bytes)
        )]);
    }
    Ok(format!("<const:{}>,{destination}", encode_hex(&bytes)))
}

fn validate_readonly_constant_span(
    sections: &[Section],
    relocations: &DynamicRelocations,
    address: u64,
    length: u64,
) -> Result<(), Vec<String>> {
    let end = address
        .checked_add(length)
        .ok_or_else(|| vec!["RIP-relative constant range overflows".to_string()])?;
    let mut overlapping = Vec::new();
    for section in sections {
        let section_end = section
            .address
            .checked_add(section.size)
            .ok_or_else(|| vec![format!("section `{}` range overflows", section.name)])?;
        if section.size != 0 && section.address < end && address < section_end {
            overlapping.push((section, section_end));
        }
    }
    let [(section, section_end)] = overlapping.as_slice() else {
        return Err(vec![format!(
            "RIP-relative constant span 0x{address:x}..0x{end:x} intersects {} sections, expected exactly one",
            overlapping.len()
        )]);
    };
    if section.address > address || *section_end < end {
        return Err(vec![format!(
            "RIP-relative constant span is not fully contained by section `{}`",
            section.name
        )]);
    }
    if !(section.contents && section.allocated && section.loaded && section.readonly)
        || section.code
    {
        return Err(vec![format!(
            "RIP-relative constant span is in unapproved section `{}`; expected loaded, allocated, read-only data",
            section.name
        )]);
    }
    if let Some((slot, relocation)) = relocations.range(section.address..*section_end).next() {
        return Err(vec![format!(
            "RIP-relative constant section `{}` contains dynamic relocation at 0x{slot:x}: {} {}; relocation-free provenance is required",
            section.name, relocation.kind, relocation.symbol
        )]);
    }
    Ok(())
}

fn rip_relative_target(
    operand: &str,
    next_address: u64,
    indirect: bool,
) -> Result<u64, &'static str> {
    let operand = operand.trim();
    let operand = if indirect {
        operand
            .strip_prefix('*')
            .ok_or("expected an indirect RIP-relative operand")?
    } else {
        if operand.starts_with('*') {
            return Err("unexpected indirect RIP-relative operand");
        }
        operand
    };
    let displacement = operand
        .strip_suffix("(%rip)")
        .ok_or("operand is not exact disp(%rip)")?;
    let displacement = parse_signed_hex(displacement).ok_or("invalid RIP-relative displacement")?;
    if displacement >= 0 {
        next_address
            .checked_add(displacement.unsigned_abs())
            .ok_or("RIP-relative target overflows")
    } else {
        next_address
            .checked_sub(displacement.unsigned_abs())
            .ok_or("RIP-relative target underflows")
    }
}

fn parse_signed_hex(value: &str) -> Option<i64> {
    let (negative, digits) = if let Some(digits) = value.strip_prefix("-0x") {
        (true, digits)
    } else {
        (false, value.strip_prefix("0x")?)
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let magnitude = u64::from_str_radix(digits, 16).ok()?;
    let magnitude = i64::try_from(magnitude).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

fn comment_target(comment: &str) -> Option<(u64, &str)> {
    let mut fields = comment.split_whitespace();
    let address = fields.next()?;
    let label = fields.next()?;
    if fields.next().is_some()
        || address.is_empty()
        || !address.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let label = label.strip_prefix('<')?.strip_suffix('>')?;
    Some((u64::from_str_radix(address, 16).ok()?, label))
}

fn direct_target(operands: &str) -> Option<u64> {
    let mut fields = operands.split_whitespace();
    let target = fields.next()?;
    if target.is_empty() || !target.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(target, 16).ok()
}

fn artifact_bytes(artifact: &Path, address: u64, length: usize) -> Result<Vec<u8>, Vec<String>> {
    let length = u64::try_from(length)
        .map_err(|_| vec!["requested artifact-byte length does not fit u64".to_string()])?;
    let end = address
        .checked_add(length)
        .ok_or_else(|| vec!["requested artifact-byte range overflows".to_string()])?;
    let listing = tool(
        "objdump",
        &[
            "-s",
            &format!("--start-address=0x{address:x}"),
            &format!("--stop-address=0x{end:x}"),
            &artifact.display().to_string(),
        ],
    )?;
    parse_artifact_bytes(&listing, address, end)
}

fn parse_artifact_bytes(listing: &str, start: u64, end: u64) -> Result<Vec<u8>, Vec<String>> {
    let mut found = BTreeMap::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next() else {
            continue;
        };
        let Ok(mut address) = u64::from_str_radix(address, 16) else {
            continue;
        };
        for word in fields {
            if word.is_empty()
                || word.len() > 8
                || word.len() % 2 != 0
                || !word.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                break;
            }
            for index in (0..word.len()).step_by(2) {
                let byte = u8::from_str_radix(&word[index..index + 2], 16)
                    .map_err(|_| vec![format!("invalid objdump data byte: {word}")])?;
                if address >= start && address < end && found.insert(address, byte).is_some() {
                    return Err(vec![format!(
                        "duplicate objdump data byte at address 0x{address:x}"
                    )]);
                }
                address = address
                    .checked_add(1)
                    .ok_or_else(|| vec!["objdump data address overflows".to_string()])?;
            }
        }
    }
    let mut bytes = Vec::new();
    for address in start..end {
        bytes.push(*found.get(&address).ok_or_else(|| {
            vec![format!(
                "objdump did not provide requested data byte at 0x{address:x}"
            )]
        })?);
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn compare_profile(kind: PageKind, expected: &str, actual: &str) -> Result<(), Vec<String>> {
    if expected == actual {
        return Ok(());
    }
    let difference = first_difference(expected, actual);
    Err(vec![
        format!(
            "{} does not match its reviewed normalized whole-symbol profile",
            kind.symbol()
        ),
        difference,
        "do not auto-bless this drift: inspect the complete native disassembly before replacing the profile"
            .to_string(),
    ])
}

fn first_difference(expected: &str, actual: &str) -> String {
    let expected = expected.lines().collect::<Vec<_>>();
    let actual = actual.lines().collect::<Vec<_>>();
    let shared = expected.len().min(actual.len());
    for index in 0..shared {
        if expected[index] != actual[index] {
            return format!(
                "first difference at profile line {}: expected `{}`, found `{}`",
                index + 1,
                expected[index],
                actual[index]
            );
        }
    }
    format!(
        "profile line count changed: expected {}, found {}",
        expected.len(),
        actual.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction(address: u64, encoded_len: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction {
            address,
            encoded_len,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        }
    }

    fn readonly_data_section(address: u64, size: u64) -> Section {
        Section {
            name: ".rodata".to_string(),
            address,
            size,
            contents: true,
            allocated: true,
            loaded: true,
            readonly: true,
            code: false,
        }
    }

    #[test]
    fn cli_requires_an_explicit_check_or_emit_shape() {
        assert!(matches!(
            parse_invocation(vec![OsString::from("zainod-oram")]),
            Ok(Invocation::Check(_))
        ));
        assert!(matches!(
            parse_invocation(vec![
                OsString::from("--emit-profiles"),
                OsString::from("zainod-oram"),
                OsString::from("profiles"),
            ]),
            Ok(Invocation::Emit { .. })
        ));
        assert!(parse_invocation(Vec::new()).is_err());
        assert!(parse_invocation(vec![OsString::from("--emit-profiles")]).is_err());
    }

    /// Address of each guarded symbol in the synthetic `nm` listings below.
    ///
    /// The three symbols sit exactly adjacent, so every address is a function
    /// of [`EXPECTED_SYMBOL_SIZE`]. Deriving them rather than hard-coding hex
    /// is what keeps the range and overlap assertions meaningful when the
    /// pinned size is regenerated: a literal listing silently stops being
    /// adjacent the moment the constant moves.
    const FIRST_SYMBOL_ADDRESS: u64 = 0x100;

    fn symbol_address(index: u64) -> u64 {
        FIRST_SYMBOL_ADDRESS + index * EXPECTED_SYMBOL_SIZE
    }

    /// One `nm -nSC` line per guarded symbol, at the pinned size.
    fn expected_listing() -> String {
        [PageKind::Base, PageKind::Add, PageKind::Spend]
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                format!(
                    "{:016x} {EXPECTED_SYMBOL_SIZE:016x} t {}\n",
                    symbol_address(index as u64),
                    kind.symbol()
                )
            })
            .collect()
    }

    #[test]
    fn exact_three_symbols_are_required() {
        let listing = expected_listing();
        let parsed =
            parse_guarded_symbols(&listing, SizePolicy::Enforce).expect("exact symbols are valid");
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed.iter().map(|symbol| symbol.kind).collect::<Vec<_>>(),
            vec![PageKind::Base, PageKind::Add, PageKind::Spend]
        );

        let missing = listing.replace(
            &format!(
                "{:016x} {EXPECTED_SYMBOL_SIZE:016x} t {}\n",
                symbol_address(2),
                PageKind::Spend.symbol()
            ),
            "",
        );
        assert!(parse_guarded_symbols(&missing, SizePolicy::Enforce).is_err());
        let duplicate = format!("{listing}{listing}");
        assert!(parse_guarded_symbols(&duplicate, SizePolicy::Enforce).is_err());
    }

    #[test]
    fn symbol_identity_size_kind_and_ranges_fail_closed() {
        let good = expected_listing();
        assert!(parse_guarded_symbols(
            &good.replace(PageKind::Base.symbol(), "other::fixed_base_page_append"),
            SizePolicy::Enforce
        )
        .is_err());
        assert!(parse_guarded_symbols(&undersized(&good), SizePolicy::Enforce).is_err());
        assert!(
            parse_guarded_symbols(&good.replacen(" t ", " D ", 1), SizePolicy::Enforce).is_err()
        );
        // Moving the second symbol inside the first symbol's range must fail
        // closed: the guard requires three disjoint, ordered symbols.
        assert!(parse_guarded_symbols(
            &good.replace(
                &format!("{:016x}", symbol_address(1)),
                &format!("{:016x}", FIRST_SYMBOL_ADDRESS + 1)
            ),
            SizePolicy::Enforce
        )
        .is_err());
    }

    /// The same listing with the first symbol one byte short of the pin.
    fn undersized(listing: &str) -> String {
        listing.replacen(
            &format!("{EXPECTED_SYMBOL_SIZE:016x}"),
            &format!("{:016x}", EXPECTED_SYMBOL_SIZE - 1),
            1,
        )
    }

    /// Emission must not enforce the size pin, or the guard could never
    /// regenerate its own profiles after the size change that necessitates
    /// regeneration. `Enforce` must still reject the very same listing --
    /// otherwise this policy would be a hole rather than a mode.
    #[test]
    fn emission_observes_the_size_pin_that_checking_enforces() {
        let shrunk = undersized(&expected_listing());

        let observed = parse_guarded_symbols(&shrunk, SizePolicy::Observe)
            .expect("emission accepts a symbol whose size has moved");
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0].size, EXPECTED_SYMBOL_SIZE - 1);

        assert!(parse_guarded_symbols(&shrunk, SizePolicy::Enforce).is_err());
    }

    #[test]
    fn instruction_parser_requires_raw_bytes() {
        assert_eq!(
            parse_instruction("  100:\t75 02\tjne 104 <symbol+0x4>"),
            Ok(Some(instruction(0x100, 2, "jne", "104 <symbol+0x4>")))
        );
        assert!(parse_instruction("  100:\tjne 104 <symbol+0x4>").is_err());
        assert!(parse_instruction("  100:\tgg\tret").is_err());
    }

    #[test]
    fn instruction_coverage_rejects_gaps_overlap_and_short_tail() {
        let contiguous = vec![
            instruction(0x100, 2, "jne", "104 <symbol+0x4>"),
            instruction(0x102, 2, "nop", ""),
        ];
        assert_eq!(
            validate_instruction_coverage(&contiguous, 0x100, 0x104),
            Ok(())
        );
        let mut gap = contiguous.clone();
        gap[1].address = 0x103;
        assert!(validate_instruction_coverage(&gap, 0x100, 0x105).is_err());
        let mut overlap = contiguous.clone();
        overlap[1].address = 0x101;
        assert!(validate_instruction_coverage(&overlap, 0x100, 0x103).is_err());
        assert!(validate_instruction_coverage(&contiguous, 0x100, 0x105).is_err());
    }

    #[test]
    fn dynamic_relocations_require_unique_slots() {
        let listing = "\
0000000000000200 R_X86_64_GLOB_DAT  memcpy@GLIBC_2.14
0000000000000210 R_X86_64_GLOB_DAT  memset@GLIBC_2.2.5
";
        let parsed = parse_dynamic_relocations(listing).expect("relocations are valid");
        assert_eq!(parsed.len(), 2);
        assert!(parse_dynamic_relocations(&format!("{listing}{listing}")).is_err());
        assert!(parse_dynamic_relocations("0000000000000220 R_AARCH64_RELATIVE ignored").is_err());
    }

    #[test]
    fn section_parser_preserves_constant_security_flags() {
        let listing = "\
/tmp/zainod-oram:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
 10 .rodata       00000100  0000000000000200  0000000000000200  00000200  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 11 .data         00000100  0000000000000300  0000000000000300  00000300  2**4
                  CONTENTS, ALLOC, LOAD, DATA
";
        let sections = parse_sections(listing).expect("section table is valid");
        assert_eq!(sections.len(), 2);
        assert!(sections[0].readonly);
        assert!(!sections[0].code);
        assert!(!sections[1].readonly);
        assert!(parse_sections(&listing.replace("elf64-x86-64", "elf64-littleaarch64")).is_err());
    }

    #[test]
    fn libc_calls_require_recomputed_slot_kind_version_and_label() {
        let call = instruction(0x100, 6, "call", "*0xfa(%rip) # 200 <memcpy@GLIBC_2.14>");
        let relocations = DynamicRelocations::from([(
            0x200,
            DynamicRelocation {
                kind: "R_X86_64_GLOB_DAT".to_string(),
                symbol: MEMCPY.to_string(),
            },
        )]);
        assert_eq!(resolve_libc_call(&call, &relocations), Ok(LibcCall::Memcpy));

        let mut wrong_kind = relocations.clone();
        wrong_kind
            .get_mut(&0x200)
            .expect("fixture slot exists")
            .kind = "R_X86_64_JUMP_SLOT".to_string();
        assert!(resolve_libc_call(&call, &wrong_kind).is_err());
        let wrong_label = instruction(0x100, 6, "call", "*0xfa(%rip) # 200 <memset@GLIBC_2.2.5>");
        assert!(resolve_libc_call(&wrong_label, &relocations).is_err());
        let wrong_slot = instruction(0x100, 6, "call", "*0xfb(%rip) # 200 <memcpy@GLIBC_2.14>");
        assert!(resolve_libc_call(&wrong_slot, &relocations).is_err());
    }

    #[test]
    fn rip_constants_bind_exact_target_bytes_destination_and_position() {
        let sections = [readonly_data_section(0x200, 0x100)];
        let relocations = DynamicRelocations::new();

        // Constant 0 is pinned to `pand` into %xmm7 carrying FIRST_MASK, and
        // its pinned length is what gets read.
        let first = instruction(0x100, 8, "pand", "0xf8(%rip),%xmm7 # 200 <anonymous>");
        let normalized = normalize_rip_constant(
            &first,
            0,
            &sections,
            &relocations,
            &mut |address, length| {
                assert_eq!((address, length), (0x200, FIRST_MASK.len()));
                Ok(FIRST_MASK.to_vec())
            },
        )
        .expect("the reviewed first constant is valid");
        assert_eq!(normalized, "<const:ffffffffffffffffffffffffffff0000>,%xmm7");

        // Right instruction, wrong destination register.
        let wrong_destination = instruction(0x100, 8, "pand", "0xf8(%rip),%xmm2 # 200 <anonymous>");
        assert!(normalize_rip_constant(
            &wrong_destination,
            0,
            &sections,
            &relocations,
            &mut |_, _| Ok(FIRST_MASK.to_vec())
        )
        .is_err());

        // Right shape, wrong bytes: the value is pinned, not just the shape.
        assert!(
            normalize_rip_constant(&first, 0, &sections, &relocations, &mut |_, _| Ok(
                SECOND_MASK.to_vec()
            ))
            .is_err()
        );

        // The same instruction at the wrong position is rejected: constant 1
        // expects %xmm3 and SECOND_MASK.
        assert!(
            normalize_rip_constant(&first, 1, &sections, &relocations, &mut |_, _| Ok(
                FIRST_MASK.to_vec()
            ))
            .is_err()
        );

        // A load beyond the reviewed sequence has no entry and fails closed --
        // this is what stops an extra constant slipping in unmeasured.
        assert!(normalize_rip_constant(
            &first,
            EXPECTED_RIP_CONSTANTS.len(),
            &sections,
            &relocations,
            &mut |_, _| Ok(FIRST_MASK.to_vec())
        )
        .is_err());

        // A different mnemonic at a position pinned to `pand` is rejected, so
        // widening the guard to a new instruction requires a reviewed entry.
        let wrong_mnemonic = instruction(0x100, 8, "movd", "0xf8(%rip),%xmm7 # 200 <anonymous>");
        assert!(normalize_rip_constant(
            &wrong_mnemonic,
            0,
            &sections,
            &relocations,
            &mut |_, _| Ok(FIRST_MASK.to_vec())
        )
        .is_err());
    }

    #[test]
    fn rip_masks_require_readonly_relocation_free_data() {
        let address = 0x200;
        let mut writable = readonly_data_section(address, 0x100);
        writable.readonly = false;
        assert!(validate_readonly_constant_span(
            &[writable],
            &DynamicRelocations::new(),
            address,
            16
        )
        .is_err());

        let relocation = DynamicRelocations::from([(
            address + 0x80,
            DynamicRelocation {
                kind: "R_X86_64_RELATIVE".to_string(),
                symbol: String::new(),
            },
        )]);
        assert!(validate_readonly_constant_span(
            &[readonly_data_section(address, 0x100)],
            &relocation,
            address,
            16,
        )
        .is_err());

        let overlapping = [
            readonly_data_section(address, 0x100),
            readonly_data_section(address + 8, 0x100),
        ];
        assert!(validate_readonly_constant_span(
            &overlapping,
            &DynamicRelocations::new(),
            address,
            16,
        )
        .is_err());
    }

    #[test]
    fn artifact_data_parser_requires_complete_exact_bytes() {
        let listing = "\
Contents of section .rodata:
 0200 ffffffff ffffffff ffffffff ffff0000  ................
";
        assert_eq!(
            parse_artifact_bytes(listing, 0x200, 0x210).expect("data bytes are complete"),
            FIRST_MASK
        );
        assert!(parse_artifact_bytes(listing, 0x1ff, 0x210).is_err());
    }

    #[test]
    fn profile_comparison_detects_operand_and_line_mutations() {
        let expected = "0000:03:mov:0x10(%rsp,%rax,1),%edx\n0003:01:ret\n";
        assert!(compare_profile(PageKind::Base, expected, expected).is_ok());
        let secret_index = "0000:03:mov:0x10(%rsp,%rsi,1),%edx\n0003:01:ret\n";
        assert!(compare_profile(PageKind::Base, expected, secret_index).is_err());
        assert!(compare_profile(PageKind::Base, expected, "0000:01:ret\n").is_err());
    }

    #[test]
    fn local_targets_are_parsed_without_trusting_labels() {
        assert_eq!(direct_target("1ff <wrong-label+0xff>"), Some(0x1ff));
        assert_eq!(direct_target("*%rax"), None);
        assert_eq!(direct_target("outside"), None);
    }

    #[test]
    fn signed_rip_displacements_are_checked() {
        assert_eq!(rip_relative_target("0xfa(%rip)", 0x106, false), Ok(0x200));
        assert_eq!(rip_relative_target("-0x6(%rip)", 0x106, false), Ok(0x100));
        assert!(rip_relative_target("*0xfa(%rip)", 0x106, false).is_err());
        assert!(rip_relative_target("0xfa(%rip)", 0x106, true).is_err());
    }

    #[test]
    fn normalized_profile_retains_security_relevant_operands() {
        let instructions = vec![instruction(0x100, 3, "mov", "0x10(%rsp,%rax,1),%edx")];
        let symbol = Symbol {
            kind: PageKind::Base,
            address: 0x100,
            size: 3,
        };
        let result = normalize_instructions(
            &symbol,
            &instructions,
            &[],
            &DynamicRelocations::new(),
            |_, _| Ok(Vec::new()),
        )
        .expect_err("an incomplete control profile must fail");
        assert!(result[0].contains("fixed libc call order"));
    }

    #[test]
    fn measured_shape_rejects_call_branch_return_and_constant_drift() {
        let calls = LibcCall::EXPECTED;
        let constants = EXPECTED_RIP_CONSTANTS.len();
        assert!(validate_measured_shape(
            PageKind::Base,
            &calls,
            EXPECTED_BRANCHES,
            EXPECTED_RETURNS,
            constants,
        )
        .is_ok());

        assert!(validate_measured_shape(
            PageKind::Base,
            &calls[1..],
            EXPECTED_BRANCHES,
            EXPECTED_RETURNS,
            constants,
        )
        .is_err());
        assert!(validate_measured_shape(
            PageKind::Base,
            &calls,
            EXPECTED_BRANCHES - 1,
            EXPECTED_RETURNS,
            constants,
        )
        .is_err());
        assert!(
            validate_measured_shape(PageKind::Base, &calls, EXPECTED_BRANCHES, 0, constants)
                .is_err()
        );
        // Too few and too many reviewed constants must both fail closed.
        assert!(validate_measured_shape(
            PageKind::Base,
            &calls,
            EXPECTED_BRANCHES,
            EXPECTED_RETURNS,
            constants - 1,
        )
        .is_err());
        assert!(validate_measured_shape(
            PageKind::Base,
            &calls,
            EXPECTED_BRANCHES,
            EXPECTED_RETURNS,
            constants + 1,
        )
        .is_err());
    }

    #[test]
    fn control_transfer_mutations_are_rejected_before_profile_comparison() {
        let external = instruction(0x100, 5, "jmp", "200 <outside>");
        let symbol = Symbol {
            kind: PageKind::Base,
            address: 0x100,
            size: 5,
        };
        assert!(normalize_instructions(
            &symbol,
            &[external],
            &[],
            &DynamicRelocations::new(),
            |_, _| Ok(Vec::new()),
        )
        .is_err());

        let indirect = instruction(0x100, 2, "jmp", "*%rax");
        assert!(normalize_instructions(
            &symbol,
            &[indirect],
            &[],
            &DynamicRelocations::new(),
            |_, _| Ok(Vec::new()),
        )
        .is_err());
    }

    #[test]
    fn unmeasured_control_mnemonics_are_rejected_before_profile_emission() {
        for mnemonic in ["xbegin", "ljmp", "hlt"] {
            let symbol = Symbol {
                kind: PageKind::Base,
                address: 0x100,
                size: 1,
            };
            let unmeasured = instruction(0x100, 1, mnemonic, "");
            let error = normalize_instructions(
                &symbol,
                &[unmeasured],
                &[],
                &DynamicRelocations::new(),
                |_, _| Ok(Vec::new()),
            )
            .expect_err("unmeasured control instruction must fail");
            assert!(error[0].contains("unmeasured instruction mnemonic"));
        }
    }

    #[test]
    fn measured_mnemonic_allowlist_exactly_matches_committed_profiles() {
        let profiled = [BASE_PROFILE, ADD_PROFILE, SPEND_PROFILE]
            .into_iter()
            .flat_map(str::lines)
            .map(|line| {
                line.split(':')
                    .nth(2)
                    .expect("committed profile line has an exact mnemonic field")
            })
            .collect::<BTreeSet<_>>();
        let measured = MEASURED_MNEMONICS.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(measured, profiled);
    }

    #[test]
    fn branch_targets_must_land_on_instruction_boundaries() {
        let symbol = Symbol {
            kind: PageKind::Base,
            address: 0x100,
            size: 5,
        };
        let branch = instruction(0x100, 2, "jmp", "101 <middle>");
        let boundaries = BTreeSet::from([0x100, 0x102]);
        assert!(normalize_branch_target(&symbol, &branch, &boundaries).is_err());
    }
}
