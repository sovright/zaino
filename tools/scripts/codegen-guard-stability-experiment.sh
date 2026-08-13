#!/usr/bin/env bash
#
# ADR 0901's codegen-guard stability experiment.
#
# Churn event 4: adding `release_schedule.rs` to `zainod-oram` grew
# `fixed_add_page_append` by 448 bytes, though `records.rs` was untouched. All
# five guarded functions already carry `#[inline(never)]`, so that is not the
# remedy. The workspace declares no `[profile.release]`, so release runs at
# `codegen-units = 16`. The hypothesis under test: codegen-unit partition
# instability is what lets unrelated code volume perturb a guarded symbol.
#
# METHOD. For each `codegen-units` setting, build, measure the guarded symbols,
# add inert-but-reachable code volume elsewhere in the crate, rebuild, measure
# again, and diff. Stability is measured strictly *within* a setting.
#
# THE CONFOUND THIS AVOIDS: changing `codegen-units` itself changes the emitted
# code, so a guard failure against the committed pins (generated at 16) is not
# evidence either way. Nothing here is ever compared against those pins.
#
# INSTRUMENTS, in order of authority:
#
#   1. Symbol sizes, read directly with `nm -nSC`. This is the primary
#      measurement, because the churn event WAS a size change, and because
#      `check-oram-page-codegen` enforces its exact-size pin before it will
#      emit anything — so under real churn the emit path fails rather than
#      producing a profile to diff. An emit failure here is therefore a
#      result, not a script error, and is reported as such.
#   2. Normalized profile text, via `--emit-profiles`. Secondary: it catches
#      a same-size body whose instructions moved. Only available when the
#      size pin still holds.
#
# SCOPE. This measures the three fixed-page symbols that `check-oram-page-codegen`
# guards, which is where the churn appeared. It says nothing directly about the
# two symbols guarded by `check-oram-codegen`, which has no emit mode.
#
# Decision rule, from ADR 0901. Apply as written; do not adopt on faith:
#
#   moves at 16, stable at 1  -> hypothesis holds, adopt codegen-units = 1
#   stable at both            -> hypothesis is WRONG. Do not adopt. Churn 4
#                                came from something else; reopen the diagnosis
#   moves at both             -> insufficient. Next step is inline-threshold
#                                pinning, per the ADR
#   moves at 1, stable at 16  -> unexpected; report before acting on it
#
# Emitted profiles are EVIDENCE, not an admission. ADR 0901 is explicit that
# new profiles require manual assembly review before they can be pinned.
#
# Requires Linux x86-64: the guards read x86-64 ELF release output.

set -euo pipefail

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "refusing to run on $(uname -sm): the guards read x86-64 ELF release output" >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "refusing to run with a dirty tree: this script edits the source and restores it" >&2
    exit 1
fi

WORK="$(mktemp -d)"
PERTURBATION="packages/zainod-oram/src/codegen_stability_perturbation.rs"
MAIN="packages/zainod-oram/src/main.rs"
ARTIFACT="target/release/zainod-oram"

restore() {
    rm -f "$PERTURBATION"
    git checkout -- "$MAIN" 2>/dev/null || true
}
trap restore EXIT

# Inert volume comparable to `release_schedule.rs`, and deliberately
# *reachable*: unreachable code can be eliminated before it ever reaches
# codegen-unit partitioning, which would make the perturbation a no-op and the
# whole experiment silently vacuous.
perturb() {
    {
        echo "//! Inert volume for the ADR 0901 stability experiment. Never shipped."
        echo "#[inline(never)]"
        echo "pub(crate) fn perturbation(seed: u64) -> u64 {"
        echo "    let mut acc = seed;"
        for i in $(seq 1 400); do
            echo "    acc = acc.rotate_left($((i % 63))).wrapping_add(0x${i}9e3779b9);"
        done
        echo "    acc"
        echo "}"
    } > "$PERTURBATION"
    printf '\nmod codegen_stability_perturbation;\n#[used]\nstatic PERTURBATION: fn(u64) -> u64 = codegen_stability_perturbation::perturbation;\n' \
        >> "$MAIN"
}

# Primary instrument: exact sizes of the three guarded symbols.
measure_sizes() {
    nm -nSC --defined-only "$ARTIFACT" \
        | grep -E 'fixed_(base|add|spend)_page_append' \
        | awk '{print $2, $NF}' \
        | sort
}

# Secondary instrument: normalized profile text. Fails by design when the
# size pin no longer holds; that failure is recorded, not swallowed.
emit_profiles() {
    local out="$1"
    mkdir -p "$out"
    if cargo run --locked --release --manifest-path tools/workbench/Cargo.toml \
        --bin check-oram-page-codegen -- --emit-profiles "$ARTIFACT" "$out" \
        > "$out/../$(basename "$out").emit-log" 2>&1
    then
        echo ok
    else
        echo "refused (size pin no longer holds, or tooling error — see $out.emit-log)"
    fi
}

build() {
    cargo build -p zainod-oram --all-features --locked --release >/dev/null
}

for UNITS in 16 1; do
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$UNITS"
    echo "=== codegen-units = $UNITS ==="

    restore
    build
    measure_sizes > "$WORK/cu$UNITS-before.sizes"
    echo "  before: emit $(emit_profiles "$WORK/cu$UNITS-before")"

    perturb
    build
    measure_sizes > "$WORK/cu$UNITS-after.sizes"
    echo "  after:  emit $(emit_profiles "$WORK/cu$UNITS-after")"
    restore

    SIZES_MOVED=no
    diff -q "$WORK/cu$UNITS-before.sizes" "$WORK/cu$UNITS-after.sizes" >/dev/null || SIZES_MOVED=yes

    PROFILES_MOVED=no
    diff -rq "$WORK/cu$UNITS-before" "$WORK/cu$UNITS-after" >/dev/null 2>&1 || PROFILES_MOVED=yes

    if [ "$SIZES_MOVED" = no ] && [ "$PROFILES_MOVED" = no ]; then
        echo "codegen-units=$UNITS: STABLE — unrelated volume did not move the guarded symbols"
    else
        echo "codegen-units=$UNITS: MOVED (sizes=$SIZES_MOVED profiles=$PROFILES_MOVED)"
        diff -u "$WORK/cu$UNITS-before.sizes" "$WORK/cu$UNITS-after.sizes" || true
    fi
    echo
done

echo "Apply ADR 0901's decision rule to the two results above."
echo "Artifacts in $WORK are evidence only; pinning any emitted profile"
echo "requires manual assembly review per ADR 0901."
