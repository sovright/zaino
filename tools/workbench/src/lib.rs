//! Shared helpers for the the workbench tooling crate (one binary per `src/bin/*.rs`).
//!
//! Every tool follows the same shape — resolve something under the repo root,
//! then either print a result or emit one-or-more `"{prog}: {line}"`
//! diagnostics and exit non-zero. [`run`] centralises that `main()` shape;
//! [`repo_root`], [`git`], and [`toolchain_channel`] are the shared primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

/// Run a tool `body`, reporting diagnostics as `"{prog}: {line}"` to stderr and
/// exiting `1` on error; on success runs `on_ok` (e.g. to print a result) and
/// exits `0`. This is the single `main()` shape shared by every binary.
pub fn run<T>(
    prog: &str,
    body: impl FnOnce() -> Result<T, Vec<String>>,
    on_ok: impl FnOnce(T),
) -> ! {
    match body() {
        Ok(value) => {
            on_ok(value);
            exit(0);
        }
        Err(lines) => {
            for line in lines {
                eprintln!("{prog}: {line}");
            }
            exit(1);
        }
    }
}

/// Run `git <args>` and return its stdout, or a one-line diagnostic on failure.
pub fn git(args: &[&str]) -> Result<String, Vec<String>> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| vec![format!("failed to run git: {e}")])?;
    if !output.status.success() {
        return Err(vec![format!("`git {}` failed", args.join(" "))]);
    }
    String::from_utf8(output.stdout).map_err(|e| vec![format!("git output not utf-8: {e}")])
}

/// Run a command that must succeed silently on stderr and return UTF-8 stdout.
pub fn command(program: &str, args: &[&str]) -> Result<String, Vec<String>> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| vec![format!("failed to run {program}: {error}")])?;
    if !output.status.success() {
        return Err(vec![format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )]);
    }
    if !output.stderr.is_empty() {
        return Err(vec![format!(
            "`{program} {}` wrote to stderr despite succeeding: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )]);
    }
    String::from_utf8(output.stdout)
        .map_err(|error| vec![format!("{program} output is not valid UTF-8: {error}")])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub contents: bool,
    pub allocated: bool,
    pub loaded: bool,
    pub readonly: bool,
    pub code: bool,
}

pub fn artifact_sections(artifact: &Path) -> Result<Vec<ElfSection>, Vec<String>> {
    parse_elf_sections(&command(
        "objdump",
        &["-h", &artifact.display().to_string()],
    )?)
}

pub fn parse_elf_sections(listing: &str) -> Result<Vec<ElfSection>, Vec<String>> {
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
        let flags = lines
            .next()
            .ok_or_else(|| vec![format!("missing flags for objdump section `{name}`")])?
            .split(',')
            .map(str::trim)
            .collect::<BTreeSet<_>>();
        sections.push(ElfSection {
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
    (!sections.is_empty())
        .then_some(sections)
        .ok_or_else(|| vec!["objdump did not provide any parseable section headers".to_string()])
}

pub fn rip_relative_target(
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
    let magnitude = i64::try_from(u64::from_str_radix(digits, 16).ok()?).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

pub fn comment_target(comment: &str) -> Option<(u64, &str)> {
    let mut fields = comment.split_whitespace();
    let address = fields.next()?;
    let label = fields.next()?;
    if fields.next().is_some()
        || address.is_empty()
        || !address.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u64::from_str_radix(address, 16).ok()?,
        label.strip_prefix('<')?.strip_suffix('>')?,
    ))
}

pub fn validate_readonly_constant_span(
    sections: &[ElfSection],
    relocation_addresses: impl IntoIterator<Item = u64>,
    address: u64,
    length: u64,
) -> Result<(), Vec<String>> {
    if length == 0 {
        return Err(vec![
            "RIP-relative constant length must be nonzero".to_string()
        ]);
    }
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
    if let Some(slot) = relocation_addresses
        .into_iter()
        .find(|slot| section.address <= *slot && *slot < *section_end)
    {
        return Err(vec![format!(
            "RIP-relative constant section `{}` contains dynamic relocation at 0x{slot:x}; relocation-free provenance is required",
            section.name
        )]);
    }
    Ok(())
}

/// Read an exact virtual-address byte range from an ELF through `objdump`.
pub fn artifact_bytes(
    artifact: &Path,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, Vec<String>> {
    let length = u64::try_from(length)
        .map_err(|_| vec!["requested artifact-byte length does not fit u64".to_string()])?;
    let end = address
        .checked_add(length)
        .ok_or_else(|| vec!["requested artifact-byte range overflows".to_string()])?;
    let listing = command(
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
        let Some(field) = fields.next() else {
            continue;
        };
        let Ok(mut address) = u64::from_str_radix(field, 16) else {
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
    (start..end)
        .map(|address| {
            found.get(&address).copied().ok_or_else(|| {
                vec![format!(
                    "objdump did not provide requested data byte at 0x{address:x}"
                )]
            })
        })
        .collect()
}

#[cfg(test)]
mod elf_tests {
    use super::*;

    #[test]
    fn artifact_data_parser_refuses_missing_and_duplicate_bytes() {
        let complete = " 0200 ffffffff ffffffff ffffffff ffff0000  ................\n";
        assert_eq!(
            parse_artifact_bytes(complete, 0x200, 0x210).expect("fixture range is complete"),
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0, 0,
            ]
        );
        assert!(parse_artifact_bytes(complete, 0x1ff, 0x210).is_err());
        let duplicate = " 0200 ffffffff\n 0200 ffffffff\n";
        assert!(parse_artifact_bytes(duplicate, 0x200, 0x204).is_err());
    }

    #[test]
    fn rip_targets_accept_checked_positive_and_negative_displacements() {
        assert_eq!(rip_relative_target("0xfa(%rip)", 0x106, false), Ok(0x200));
        assert_eq!(rip_relative_target("-0x6(%rip)", 0x106, false), Ok(0x100));
        assert!(rip_relative_target("0xffffffffffffffff(%rip)", 0x106, false).is_err());
        assert!(rip_relative_target("-0xffffffffffffffff(%rip)", 0x106, false).is_err());
    }

    #[test]
    fn readonly_span_refuses_zero_length_and_section_range_overflow() {
        let section = ElfSection {
            name: ".rodata".to_string(),
            address: 0x200,
            size: 0x100,
            contents: true,
            allocated: true,
            loaded: true,
            readonly: true,
            code: false,
        };
        assert!(validate_readonly_constant_span(&[section], [], 0x200, 0).is_err());
        let overflowing = ElfSection {
            name: ".rodata".to_string(),
            address: u64::MAX,
            size: 2,
            contents: true,
            allocated: true,
            loaded: true,
            readonly: true,
            code: false,
        };
        assert!(validate_readonly_constant_span(&[overflowing], [], u64::MAX, 1).is_err());
    }
}

/// Repository root via `git rev-parse --show-toplevel`.
pub fn repo_root() -> Result<PathBuf, Vec<String>> {
    Ok(PathBuf::from(
        git(&["rev-parse", "--show-toplevel"])?.trim(),
    ))
}

/// Read `path` to a string, or a one-line `cannot read …` diagnostic.
pub fn read(path: &Path) -> Result<String, Vec<String>> {
    std::fs::read_to_string(path).map_err(|e| vec![format!("cannot read {}: {e}", path.display())])
}

/// The pinned, validated rustc channel from `<root>/rust-toolchain.toml`.
///
/// Single source of truth for `RUST_VERSION`. Rejects any non-numeric channel
/// (`stable` / `nightly` / dated pins) so the CI image tag stays reproducible.
pub fn toolchain_channel(root: &Path) -> Result<String, Vec<String>> {
    let path = root.join("rust-toolchain.toml");
    let contents = read(&path)?;

    let Some(channel) = contents.lines().find_map(channel_value) else {
        return Err(vec![format!(
            "no [toolchain].channel in {}",
            path.display()
        )]);
    };

    if !is_concrete_numeric(&channel) {
        return Err(vec![
            format!("channel '{channel}' is not a concrete numeric version (e.g. 1.95 or 1.95.0)"),
            format!(
                "a pinned rustc is required; set channel = \"<x.y[.z]>\" in {}",
                path.display()
            ),
        ]);
    }
    Ok(channel)
}

/// The zebra repository probed by `get-zebra-git-ref`.
pub const ZEBRA_REPO_URL: &str = "https://github.com/ZcashFoundation/zebra";

/// The `git ls-remote` refs to probe for a `ZEBRA_VERSION` value: its
/// `v`-prefixed release tag, a bare tag, and a branch, in that precedence.
pub fn zebra_ref_probes(version: &str) -> [String; 3] {
    [
        format!("refs/tags/v{version}"),
        format!("refs/tags/{version}"),
        format!("refs/heads/{version}"),
    ]
}

/// Resolve `ZEBRA_VERSION` to the git ref the zebra source build checks out,
/// given the `git ls-remote` output for [`zebra_ref_probes`].
///
/// `ZEBRA_VERSION` is canonically the Docker Hub image tag (bare, e.g.
/// "6.0.0-rc.0"), but zebra's git release tags carry a `v` prefix, so a
/// release version maps to `v{version}`. A branch or plain-tag pin resolves
/// as-is, and a commit SHA passes through (`ls-remote` matches ref names, not
/// commits). Anything else is an error — reported at resolve time instead of
/// surfacing as a checkout pathspec error after the container build stage has
/// cloned the whole zebra repo.
pub fn zebra_git_ref(version: &str, ls_remote_output: &str) -> Result<String, Vec<String>> {
    let v_tag = format!("refs/tags/v{version}");
    let matches_v_tag = ls_remote_output
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .any(|r| r == v_tag);

    let some_ref_matched = ls_remote_output.lines().any(|l| !l.trim().is_empty());
    if matches_v_tag {
        Ok(format!("v{version}"))
    } else if some_ref_matched || is_commit_sha_shaped(version) {
        Ok(version.to_string())
    } else {
        Err(vec![format!(
            "ZEBRA_VERSION={version} matches no zebra tag (v-prefixed or bare), \
branch, or commit-SHA shape"
        )])
    }
}

/// 7 to 40 lowercase-hex characters — an abbreviated or full git commit SHA.
fn is_commit_sha_shaped(version: &str) -> bool {
    (7..=40).contains(&version.len())
        && version
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Value of a `channel = "..."` line, mirroring `^[[:space:]]*channel[[:space:]]*=`.
/// `None` for comments, other keys, or a line without a double-quoted value.
fn channel_value(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("channel")?.trim_start();
    let value = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

/// `^[0-9]+\.[0-9]+(\.[0-9]+)?$` — two or three dot-separated all-digit parts.
fn is_concrete_numeric(channel: &str) -> bool {
    let parts: Vec<&str> = channel.split('.').collect();
    matches!(parts.len(), 2 | 3)
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Length in bytes of a whitespace-separated hex-byte encoding, if well formed.
///
/// Shared by the ORAM codegen guards; see `check-oram-codegen` and
/// `check-oram-page-codegen`.
pub fn encoded_byte_len(value: &str) -> Option<u64> {
    let bytes = value.split_whitespace().collect::<Vec<_>>();
    if bytes.is_empty()
        || bytes.len() > 15
        || bytes
            .iter()
            .any(|byte| byte.len() != 2 || !byte.bytes().all(|part| part.is_ascii_hexdigit()))
    {
        return None;
    }
    u64::try_from(bytes.len()).ok()
}

/// True for GNU-syntax instruction prefixes that carry no opcode of their own.
pub fn is_gnu_prefix(value: &str) -> bool {
    value == "rex"
        || value.starts_with("rex.")
        || matches!(
            value,
            "addr16"
                | "addr32"
                | "bnd"
                | "cs"
                | "data16"
                | "data32"
                | "ds"
                | "es"
                | "fs"
                | "gs"
                | "lock"
                | "notrack"
                | "rep"
                | "repe"
                | "repne"
                | "repnz"
                | "repz"
                | "ss"
                | "xacquire"
                | "xrelease"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_value_recognises_only_quoted_assignments() {
        assert_eq!(
            channel_value("channel = \"1.96.0\"").as_deref(),
            Some("1.96.0")
        );
        assert_eq!(channel_value("  channel=\"1.95\"").as_deref(), Some("1.95"));
        assert_eq!(channel_value("# channel = \"x\""), None);
        assert_eq!(channel_value("components = [\"clippy\"]"), None);
        assert_eq!(channel_value("[toolchain]"), None);
    }

    #[test]
    fn zebra_git_ref_prefers_the_v_tag() {
        // Annotated tags also list a peeled `^{}` line; the plain ref wins.
        let out = "abc123\trefs/tags/v6.0.0-rc.0\nabc456\trefs/tags/v6.0.0-rc.0^{}\n";
        assert_eq!(
            zebra_git_ref("6.0.0-rc.0", out).as_deref(),
            Ok("v6.0.0-rc.0")
        );
    }

    #[test]
    fn zebra_git_ref_passes_branches_and_bare_tags_through() {
        let out = "abc123\trefs/heads/main\n";
        assert_eq!(zebra_git_ref("main", out).as_deref(), Ok("main"));
    }

    #[test]
    fn zebra_git_ref_passes_sha_shapes_through_unprobed() {
        assert_eq!(
            zebra_git_ref("15d578362448fb8c4a5d29a00dcfe8adb5184082", "").as_deref(),
            Ok("15d578362448fb8c4a5d29a00dcfe8adb5184082")
        );
        assert_eq!(zebra_git_ref("15d5783", "").as_deref(), Ok("15d5783"));
    }

    #[test]
    fn zebra_git_ref_rejects_unresolvable_values() {
        assert!(zebra_git_ref("not-a-real-ref", "").is_err());
        // Short-hex-lookalike below the 7-char floor is rejected too.
        assert!(zebra_git_ref("abc", "").is_err());
    }

    #[test]
    fn numeric_validation_matches_x_y_z() {
        assert!(is_concrete_numeric("1.96.0"));
        assert!(is_concrete_numeric("1.96"));
        assert!(!is_concrete_numeric("stable"));
        assert!(!is_concrete_numeric("nightly"));
        assert!(!is_concrete_numeric("1"));
        assert!(!is_concrete_numeric("1.96.0.1"));
        assert!(!is_concrete_numeric("1..0"));
    }
}
