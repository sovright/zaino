//! Guard: no secret-dependent branch in the ORAM insertion access path.
//!
//! Phase 0 kill-gate 2 failed because the secret hit/miss boolean returned by
//! `read_and_remap` drove a conditional jump before the second ORAM access, so
//! at the occupancy boundaries the access schedule itself depended on whether
//! the key was present. The remediation routes that boolean into `Cmov` and
//! arithmetic only; this turns the property into a build failure rather than
//! something a future refactor can silently undo.
//!
//! # Why this is not simply "no conditional jumps"
//!
//! The remediated *source* has no control flow, but its *codegen* does, and
//! measurement on the native x86_64 builder proved both shapes are benign:
//!
//! - `Cmov` on a record expands to a byte-wise loop whose trip count is the
//!   compile-time record width (`cmp $0x26,%rax` for the 38-byte directory
//!   record, `cmp $0x52,%rax` for the 82-byte event record). The secret feeds
//!   only the `cmovne` inside the loop; the bound is a constant.
//! - Releasing the thread-local RNG handle emits a refcount decrement and a
//!   drop-path jump (`decq 0x0(%r13)` then `jne`).
//!
//! Neither depends on the secret, so rejecting every conditional jump would
//! reject a correct implementation. This check therefore permits exactly those
//! two structurally-identified shapes and rejects everything else.
//!
//! The historical failure — a *forward* jump immediately after a compare
//! against the returned boolean (`cmp $0x0,%al` then `je`) — matches neither
//! allowance and is still rejected. That case is covered by a unit test.
//!
//! `fixed_unique_insert` carries `#[inline(never)]` so each monomorphization
//! keeps its own symbol. That attribute is load-bearing for this check: without
//! it the function dissolves into its caller and there is nothing to inspect.
//!
//! Usage: `check-oram-codegen <path-to-x86_64-elf>`

use std::path::Path;
use std::process::Command;
use workbench::run;

/// The access-path function whose compiled body must carry no secret branch.
const GUARDED: &str = "fixed_unique_insert";

/// Both record monomorphizations must be present: the 38-byte directory record
/// and the 82-byte event record. Finding fewer means the build did not select
/// the typed backend and the check would otherwise pass vacuously.
const EXPECTED_MONOMORPHIZATIONS: usize = 2;

fn main() {
    run("check-oram-codegen", check, |report: Report| {
        for symbol in &report.symbols {
            for allowed in &symbol.allowed {
                println!("check-oram-codegen: allowed — {allowed}");
            }
            println!(
                "check-oram-codegen: ok — {} instructions, no secret-dependent branch in {}",
                symbol.instructions, symbol.name
            );
        }
        println!(
            "check-oram-codegen: ok — {} `{GUARDED}` monomorphizations carry no secret branch",
            report.symbols.len()
        );
    })
}

struct Report {
    symbols: Vec<Inspected>,
}

struct Inspected {
    name: String,
    instructions: usize,
    allowed: Vec<String>,
}

/// One defined symbol with a known address and size.
struct Symbol {
    name: String,
    address: u64,
    size: u64,
}

/// One decoded instruction from an `objdump` listing.
#[derive(Debug, PartialEq, Eq)]
struct Instruction {
    address: u64,
    mnemonic: String,
    operands: String,
}

/// What a single instruction means for the guarded property.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not a branch at all, or an unconditional direct jump.
    Branchless,
    /// A branch that is structurally independent of the secret.
    Allowed(&'static str),
    /// A branch that could carry the secret.
    Rejected(&'static str),
}

fn check() -> Result<Report, Vec<String>> {
    let artifact = artifact_path()?;
    let symbols = guarded_symbols(&artifact)?;

    if symbols.len() < EXPECTED_MONOMORPHIZATIONS {
        return Err(vec![
            format!(
                "found {} `{GUARDED}` symbol(s) in {}, expected at least {EXPECTED_MONOMORPHIZATIONS}",
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
        match inspect(&artifact, &symbol) {
            Ok(report) => inspected.push(report),
            Err(lines) => failures.extend(lines),
        }
    }
    if !failures.is_empty() {
        failures.push(
            "a secret-dependent branch in the ORAM access path re-fails Phase 0 kill-gate 2; \
             keep the hit/miss result in Cmov and arithmetic only"
                .to_string(),
        );
        return Err(failures);
    }
    Ok(Report { symbols: inspected })
}

fn artifact_path() -> Result<std::path::PathBuf, Vec<String>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| vec!["usage: check-oram-codegen <path-to-x86_64-elf>".to_string()])?;
    let path = std::path::PathBuf::from(path);
    if !path.is_file() {
        return Err(vec![format!("not a file: {}", path.display())]);
    }
    Ok(path)
}

/// Every defined, sized symbol whose demangled name mentions [`GUARDED`].
///
/// Legacy symbol mangling drops generic parameters, so the monomorphizations
/// are distinguished by count and size rather than by record type name.
fn guarded_symbols(artifact: &Path) -> Result<Vec<Symbol>, Vec<String>> {
    let listing = tool(
        "nm",
        &["-nSC", "--defined-only", &artifact.display().to_string()],
    )?;
    let mut symbols = Vec::new();
    for line in listing.lines() {
        // `<address> <size> <type> <name>`; unsized symbols have three fields
        // and are skipped.
        let mut fields = line.split_whitespace();
        let (Some(address), Some(size), Some(_kind)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let name = fields.collect::<Vec<_>>().join(" ");
        if !name.contains(GUARDED) {
            continue;
        }
        let (Ok(address), Ok(size)) = (
            u64::from_str_radix(address, 16),
            u64::from_str_radix(size, 16),
        ) else {
            continue;
        };
        if size > 0 {
            symbols.push(Symbol {
                name,
                address,
                size,
            });
        }
    }
    Ok(symbols)
}

/// Disassembles one symbol and rejects any branch that could carry the secret.
fn inspect(artifact: &Path, symbol: &Symbol) -> Result<Inspected, Vec<String>> {
    let disassembly = tool(
        "objdump",
        &[
            "-dC",
            "--no-show-raw-insn",
            &format!("--start-address=0x{:x}", symbol.address),
            &format!("--stop-address=0x{:x}", symbol.address + symbol.size),
            &artifact.display().to_string(),
        ],
    )?;

    let scanned = scan(&disassembly, &symbol.name);

    if scanned.instructions == 0 {
        return Err(vec![format!(
            "{}: disassembled to no instructions; the symbol range looks wrong",
            symbol.name
        )]);
    }
    if !scanned.failures.is_empty() {
        return Err(scanned.failures);
    }
    Ok(Inspected {
        name: symbol.name.clone(),
        instructions: scanned.instructions,
        allowed: scanned.allowed,
    })
}

struct Scan {
    instructions: usize,
    allowed: Vec<String>,
    failures: Vec<String>,
}

/// Scans a disassembly listing. Pure, so it is unit-tested against the exact
/// instruction shapes measured on the x86_64 builder.
fn scan(disassembly: &str, symbol: &str) -> Scan {
    let mut instructions = 0;
    let mut allowed = Vec::new();
    let mut failures = Vec::new();
    let mut previous: Option<Instruction> = None;

    for line in disassembly.lines() {
        let Some(current) = parse_instruction(line) else {
            continue;
        };
        instructions += 1;
        match classify(previous.as_ref(), &current) {
            Verdict::Branchless => {}
            Verdict::Allowed(reason) => allowed.push(format!(
                "{symbol}: {reason} at {:x}: {} {}",
                current.address, current.mnemonic, current.operands
            )),
            Verdict::Rejected(reason) => failures.push(format!(
                "{symbol}: {reason} at {:x}: {} {}",
                current.address, current.mnemonic, current.operands
            )),
        }
        previous = Some(current);
    }

    Scan {
        instructions,
        allowed,
        failures,
    }
}

/// Classifies one instruction, given the instruction immediately before it.
///
/// The two allowances are deliberately narrow and structural: each requires a
/// specific preceding instruction, so a secret-carrying branch cannot fall into
/// them by accident.
fn classify(previous: Option<&Instruction>, current: &Instruction) -> Verdict {
    if current.mnemonic.starts_with("loop") {
        return Verdict::Rejected("looping branch");
    }
    if !current.mnemonic.starts_with('j') {
        return Verdict::Branchless;
    }
    if current.mnemonic == "jmp" {
        // A direct tail jump is unconditional and carries no secret. An
        // indirect one implies a jump table, i.e. a branch on a computed value.
        return if current.operands.starts_with('*') {
            Verdict::Rejected("indirect jump (jump table)")
        } else {
            Verdict::Branchless
        };
    }

    let Some(previous) = previous else {
        return Verdict::Rejected("conditional jump");
    };

    // A refcount decrement drives the drop path, not the secret.
    if previous.mnemonic.starts_with("dec") && previous.operands.contains('(') {
        return Verdict::Allowed("reference-count drop branch");
    }

    // A backward jump bounded by a compare against an immediate is a loop with
    // a compile-time trip count, such as the byte-wise `Cmov` over a record.
    if previous.mnemonic == "cmp" && previous.operands.starts_with('$') {
        if let Some(target) = jump_target(&current.operands) {
            if target < current.address {
                return Verdict::Allowed("fixed-count loop back-edge");
            }
        }
    }

    Verdict::Rejected("conditional jump")
}

/// The absolute address a jump operand names, if it names one directly.
fn jump_target(operands: &str) -> Option<u64> {
    let first = operands.split_whitespace().next()?;
    u64::from_str_radix(first, 16).ok()
}

/// Decodes `  a8e32b:\tjne    a8e310 <sym+0x70>` into its parts.
fn parse_instruction(line: &str) -> Option<Instruction> {
    let (address, rest) = line.split_once(':')?;
    let address = address.trim();
    if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let address = u64::from_str_radix(address, 16).ok()?;
    let rest = rest.trim();
    let mut parts = rest.split_whitespace();
    let mnemonic = parts.next()?.to_string();
    Some(Instruction {
        address,
        mnemonic,
        operands: parts.collect::<Vec<_>>().join(" "),
    })
}

/// Runs a binutils tool, turning a missing tool or non-zero exit into a
/// diagnostic rather than a silent pass.
fn tool(program: &str, args: &[&str]) -> Result<String, Vec<String>> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| vec![format!("failed to run {program}: {e}")])?;
    if !output.status.success() {
        return Err(vec![format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )]);
    }
    String::from_utf8(output.stdout).map_err(|e| vec![format!("{program} output not utf-8: {e}")])
}

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
0000000000a8e2a0 <fixed_unique_insert>:
  a8e2e0:\tcall   a8eab0 <read_and_remap>
  a8e302:\tmovzbl %al,%ebx
  a8e310:\tmovzbl 0x40(%rsp,%rax,1),%ecx
  a8e31a:\ttest   %rbx,%rbx
  a8e31d:\tcmovne %ecx,%edx
  a8e324:\tinc    %rax
  a8e327:\tcmp    $0x26,%rax
  a8e32b:\tjne    a8e310 <fixed_unique_insert+0x70>
  a8e350:\tcall   a9d4a0 <rand::rng::Rng::random_range>
  a8e357:\tdecq   0x0(%r13)
  a8e35b:\tjne    a8e366 <fixed_unique_insert+0xc6>
  a8e385:\tcall   abdca0 <CircuitORAM<V>::write_or_insert>
  a8e3be:\tdecq   0x0(%r13)
  a8e3c2:\tjne    a8e3cd <fixed_unique_insert+0x12d>
  a8e3ba:\tret
";

    #[test]
    fn the_recorded_gate_two_failure_is_rejected() {
        let scanned = scan(FAILING, "event");
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
        let scanned = scan(MEASURED, "directory");
        assert_eq!(scanned.failures, Vec::<String>::new());
        assert_eq!(scanned.allowed.len(), 3);
        assert!(scanned.allowed[0].contains("fixed-count loop back-edge"));
        assert!(scanned.allowed[1].contains("reference-count drop branch"));
        assert!(scanned.allowed[2].contains("reference-count drop branch"));
    }

    /// A forward jump after a compare is the failing shape, not a loop, even
    /// though a backward one after the same compare is allowed.
    #[test]
    fn only_backward_compare_bounded_jumps_are_treated_as_loops() {
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
            classify(Some(&previous), &backward),
            Verdict::Allowed("fixed-count loop back-edge")
        );
        assert_eq!(
            classify(Some(&previous), &forward),
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
            classify(Some(&unrelated), &jump),
            Verdict::Rejected("conditional jump")
        );
        assert_eq!(classify(None, &jump), Verdict::Rejected("conditional jump"));

        // A register-to-register compare is not a constant bound.
        let register_compare = Instruction {
            address: 0x100,
            mnemonic: "cmp".to_string(),
            operands: "%rcx,%rax".to_string(),
        };
        assert_eq!(
            classify(Some(&register_compare), &jump),
            Verdict::Rejected("conditional jump")
        );

        // A register decrement is not a refcount drop through memory.
        let register_decrement = Instruction {
            address: 0x100,
            mnemonic: "dec".to_string(),
            operands: "%rax".to_string(),
        };
        assert_eq!(
            classify(Some(&register_decrement), &jump),
            Verdict::Rejected("conditional jump")
        );
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
                classify(None, &jump),
                Verdict::Rejected("conditional jump"),
                "{mnemonic} was not rejected"
            );
        }
    }

    #[test]
    fn branchless_and_unconditional_instructions_are_accepted() {
        for mnemonic in [
            "mov", "cmp", "test", "call", "ret", "cmove", "cmovne", "cmovb", "sete", "setne",
            "xor", "add", "lea", "push", "pop",
        ] {
            let instruction = Instruction {
                address: 0x100,
                mnemonic: mnemonic.to_string(),
                operands: "%rax,%rdx".to_string(),
            };
            assert_eq!(
                classify(None, &instruction),
                Verdict::Branchless,
                "{mnemonic}"
            );
        }
        let direct = Instruction {
            address: 0x100,
            mnemonic: "jmp".to_string(),
            operands: "120 <sym>".to_string(),
        };
        assert_eq!(classify(None, &direct), Verdict::Branchless);
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
                classify(None, &indirect),
                Verdict::Rejected("indirect jump (jump table)")
            );
        }
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
            classify(Some(&decrement), &looping),
            Verdict::Rejected("looping branch")
        );
    }

    #[test]
    fn listing_headers_and_blank_lines_are_not_instructions() {
        assert_eq!(parse_instruction(""), None);
        assert_eq!(parse_instruction("Disassembly of section .text:"), None);
        assert_eq!(
            parse_instruction("00000000007ade10 <fixed_unique_insert>:"),
            None
        );
        assert_eq!(
            parse_instruction("  7adeb2:\tje     7adec7 <sym>"),
            Some(Instruction {
                address: 0x7adeb2,
                mnemonic: "je".to_string(),
                operands: "7adec7 <sym>".to_string(),
            })
        );
    }
}
