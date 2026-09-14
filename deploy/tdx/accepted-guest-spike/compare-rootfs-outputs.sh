#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
fail() { echo "rootfs comparison refused: $*" >&2; exit 1; }
[[ $# == 7 ]] || fail 'usage: compare-rootfs-outputs.sh RUN_1 RUN_2 WORKLOAD_EXPECTATIONS TOOL_CLOSURE_1 TOOL_CLOSURE_2 WORKLOAD_1 WORKLOAD_2'
left=$(cd -- "$1" && pwd -P); right=$(cd -- "$2" && pwd -P); expectations=$3; closure_left=$4; closure_right=$5; workload_left=$6; workload_right=$7
bash "$(dirname -- "$0")/verify-rootfs-output.sh" "$left" "$workload_left" "$expectations" "$closure_left" >/dev/null
bash "$(dirname -- "$0")/verify-rootfs-output.sh" "$right" "$workload_right" "$expectations" "$closure_right" >/dev/null
for candidate in "$left" "$right"; do (cd "$candidate" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'candidate checksum mismatch'; done
[[ $(find "$left" -mindepth 1 -printf '%y %m %P\n' | sort) == $(find "$right" -mindepth 1 -printf '%y %m %P\n' | sort) ]] || fail 'restored file set or modes differ'
while IFS= read -r relative; do
  case "$relative" in build-run.json|OUTPUT-SHA256SUMS) continue ;; esac
  cmp -s "$left/$relative" "$right/$relative" || fail "output differs: $relative"
done < <(find "$left" -type f -printf '%P\n' | sort)
left_receipt=$(mktemp); right_receipt=$(mktemp); trap 'rm -f -- "$left_receipt" "$right_receipt"' EXIT
jq -S 'del(.run_label,.trusted_workload_output_sha256s_sha256)' "$left/build-run.json" > "$left_receipt"; jq -S 'del(.run_label,.trusted_workload_output_sha256s_sha256)' "$right/build-run.json" > "$right_receipt"
cmp -s "$left_receipt" "$right_receipt" || fail 'producer receipts differ'
echo 'Verified both complete per-run lineages and compared canonical rootfs/verity outputs.'
