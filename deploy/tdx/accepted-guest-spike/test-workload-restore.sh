#!/usr/bin/env bash
# Prove that ZIP mode restoration is bound to a reviewer-accepted outer manifest.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "workload restore test failed: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: test-workload-restore.sh WORKLOAD EXPECTATIONS'
workload=$1 expectations=$2; scratch=$(mktemp -d); trap 'rm -rf -- "$scratch"' EXIT
bash "$root/restore-workload-output.sh" "$workload" "$expectations" "$scratch/restored"
cp -a "$workload" "$scratch/repaired"
awk -F '\t' 'BEGIN {OFS="\t"} $2=="./artifacts/tdx-evidence-agent" {$1="644"} {print}' "$scratch/repaired/OUTPUT-MODES.tsv" >"$scratch/repaired/OUTPUT-MODES.new"
mv "$scratch/repaired/OUTPUT-MODES.new" "$scratch/repaired/OUTPUT-MODES.tsv"
(cd "$scratch/repaired" && find . -type f ! -name OUTPUT-SHA256SUMS -print | sort | while read -r file; do digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done) >"$scratch/repaired-manifest"
mv "$scratch/repaired-manifest" "$scratch/repaired/OUTPUT-SHA256SUMS"
if bash "$root/restore-workload-output.sh" "$scratch/repaired" "$expectations" "$scratch/refused" >/dev/null 2>&1; then fail 'self-consistent repaired mode manifest accepted'; fi
echo 'Authenticated workload mode restoration passed and a repaired unaccepted manifest was refused.'
