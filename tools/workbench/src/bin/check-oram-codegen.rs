//! Guard: the ORAM insertion access path must compile to branchless code.
//!
//! Phase 0 kill-gate 2 failed because the secret hit/miss boolean returned by
//! `read_and_remap` drove a conditional jump before the second ORAM access, so
//! at the occupancy boundaries the access schedule itself depended on whether
//! the key was present. The remediation removed all control flow from
//! `fixed_unique_insert`; this turns that property into a build failure rather
//! than something a future refactor can silently undo.
//!
//! The rule is deliberately absolute and needs no judgement call: the function
//! provably has no control flow, so *any* conditional jump in its compiled body
//! is a regression. `cmov` and `set<cc>` are branchless and therefore allowed.
//!
//! `fixed_unique_insert` carries `#[inline(never)]` so each monomorphization
//! keeps its own symbol. That attribute is load-bearing for this check: without
//! it the function dissolves into its caller and there is nothing to inspect.
//!
//! Usage: `check-oram-codegen <path-to-x86_64-elf>`

use std::path::Path;
use std::process::Command;
use workbench::run;

/// The access-path function whose compiled body must contain no branches.
const GUARDED: &str = "fixed_unique_insert";

/// Both record monomorphizations must be present: the 38-byte directory record
/// and the 82-byte event record. Finding fewer means the build did not select
/// the typed backend and the check would otherwise pass vacuously.
const EXPECTED_MONOMORPHIZATIONS: usize = 2;

fn main() {
    run("check-oram-codegen", check, |report: Report| {
        for symbol in &report.symbols {
            println!(
                "check-oram-codegen: ok — {} instructions, no conditional jumps in {}",
                symbol.instructions, symbol.name
            );
        }
        println!(
            "check-oram-codegen: ok — {} `{GUARDED}` monomorphizations are branchless",
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
}

/// One defined symbol with a known address and size.
struct Symbol {
    name: String,
    address: u64,
    size: u64,
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

/// Disassembles one symbol and rejects any branch in its body.
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

    let Scan {
        instructions,
        failures,
    } = scan(&disassembly, &symbol.name);

    if instructions == 0 {
        return Err(vec![format!(
            "{}: disassembled to no instructions; the symbol range looks wrong",
            symbol.name
        )]);
    }
    if !failures.is_empty() {
        return Err(failures);
    }
    Ok(Inspected {
        name: symbol.name.clone(),
        instructions,
    })
}

struct Scan {
    instructions: usize,
    failures: Vec<String>,
}

/// Scans a disassembly listing for branches. Pure, so it is unit-tested against
/// the exact instruction shapes the kill-gate report recorded.
fn scan(disassembly: &str, symbol: &str) -> Scan {
    let mut instructions = 0;
    let mut failures = Vec::new();
    for line in disassembly.lines() {
        let Some((address, rest)) = instruction(line) else {
            continue;
        };
        instructions += 1;
        let mut parts = rest.split_whitespace();
        let Some(mnemonic) = parts.next() else {
            continue;
        };
        let operands = parts.collect::<Vec<_>>().join(" ");
        if let Some(reason) = branch_reason(mnemonic, &operands) {
            failures.push(format!(
                "{symbol}: {reason} at {address}: {mnemonic} {operands}"
            ));
        }
    }
    Scan {
        instructions,
        failures,
    }
}

/// Splits `  4011a6:\tje     4011c0 <…>` into its address and instruction text.
fn instruction(line: &str) -> Option<(&str, &str)> {
    let (address, rest) = line.split_once(':')?;
    let address = address.trim();
    if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let rest = rest.trim();
    (!rest.is_empty()).then_some((address, rest))
}

/// Why this instruction is a branch, or `None` if it is branchless.
///
/// `cmov*` and `set*` are the branchless primitives the access path is built
/// from and are deliberately permitted.
fn branch_reason(mnemonic: &str, operands: &str) -> Option<&'static str> {
    if mnemonic.starts_with("loop") {
        return Some("looping branch");
    }
    if !mnemonic.starts_with('j') {
        return None;
    }
    if mnemonic == "jmp" {
        // A direct tail jump is unconditional and carries no secret. An
        // indirect one implies a jump table, i.e. a branch on a computed value.
        return operands
            .starts_with('*')
            .then_some("indirect jump (jump table)");
    }
    Some("conditional jump")
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

    /// The shape the Phase 0 kill-gate report recorded at the 82-byte event
    /// record: the hit/miss boolean returned in AL drives a conditional jump
    /// between the two ORAM accesses.
    const FAILING: &str = "\
00000000007ade10 <fixed_unique_insert>:
  7ade98:\tcall   7a1120 <read_and_remap>
  7adead:\tcmp    $0x0,%al
  7adeb2:\tje     7adec7 <fixed_unique_insert+0xb7>
  7adec7:\tcall   7a1450 <write_or_insert_and_remap>
  7adee0:\tret
";

    /// The remediated shape: the secret reaches only a conditional move.
    const PASSING: &str = "\
00000000007ade10 <fixed_unique_insert>:
  7ade98:\tcall   7a1120 <read_and_remap>
  7adead:\ttest   %al,%al
  7adeb2:\tcmovne %rcx,%rdx
  7adec7:\tcall   7a1450 <write_or_insert_and_remap>
  7adee0:\tret
";

    #[test]
    fn the_recorded_gate_two_failure_is_rejected() {
        let scanned = scan(FAILING, "event");
        assert_eq!(scanned.instructions, 5);
        assert_eq!(scanned.failures.len(), 1);
        assert!(
            scanned.failures[0].contains("conditional jump at 7adeb2"),
            "unexpected diagnostic: {}",
            scanned.failures[0]
        );
    }

    #[test]
    fn the_remediated_shape_is_accepted() {
        let scanned = scan(PASSING, "event");
        assert_eq!(scanned.instructions, 5);
        assert_eq!(scanned.failures, Vec::<String>::new());
    }

    #[test]
    fn every_conditional_jump_mnemonic_is_rejected() {
        for mnemonic in [
            "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js",
            "jns", "jo", "jno", "jp", "jnp", "jrcxz",
        ] {
            assert_eq!(
                branch_reason(mnemonic, "7adec7"),
                Some("conditional jump"),
                "{mnemonic} was not rejected"
            );
        }
        assert_eq!(branch_reason("loop", "7adec7"), Some("looping branch"));
        assert_eq!(branch_reason("loopne", "7adec7"), Some("looping branch"));
    }

    #[test]
    fn branchless_and_unconditional_instructions_are_accepted() {
        for mnemonic in [
            "mov", "cmp", "test", "call", "ret", "cmove", "cmovne", "cmovb", "sete", "setne",
            "xor", "add", "lea", "push", "pop",
        ] {
            assert_eq!(branch_reason(mnemonic, "%rax,%rdx"), None, "{mnemonic}");
        }
        assert_eq!(branch_reason("jmp", "7adec7 <sym>"), None);
    }

    /// A jump table is a branch on a computed value even though `jmp` itself is
    /// unconditional.
    #[test]
    fn indirect_jumps_are_rejected() {
        assert_eq!(
            branch_reason("jmp", "*%rax"),
            Some("indirect jump (jump table)")
        );
        assert_eq!(
            branch_reason("jmp", "*0x18(%rip)"),
            Some("indirect jump (jump table)")
        );
    }

    #[test]
    fn listing_headers_and_blank_lines_are_not_instructions() {
        assert_eq!(instruction(""), None);
        assert_eq!(instruction("Disassembly of section .text:"), None);
        assert_eq!(instruction("00000000007ade10 <fixed_unique_insert>:"), None);
        assert_eq!(
            instruction("  7adeb2:\tje     7adec7 <sym>"),
            Some(("7adeb2", "je     7adec7 <sym>"))
        );
    }
}
