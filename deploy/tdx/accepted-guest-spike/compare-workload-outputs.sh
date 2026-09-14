#!/usr/bin/env bash
set -euo pipefail
fail() { echo "workload output comparison refused: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: compare-workload-outputs.sh RUN_1 RUN_2'
left=$1 right=$2
for root in "$left" "$right"; do [[ -f "$root/OUTPUT-SHA256SUMS" ]] || fail 'missing output manifest'; (cd "$root" && sha256sum -c OUTPUT-SHA256SUMS >/dev/null) || fail 'output digest mismatch'; done
temporary=$(mktemp -d); trap 'rm -rf -- "$temporary"' EXIT
for pair in "left:$left" "right:$right"; do name=${pair%%:*}; root=${pair#*:}; grep -Ev '  \./(build-run.json|runtime-closure.txt|evidence-agent.link-map)$' "$root/OUTPUT-SHA256SUMS" > "$temporary/$name.outputs"; jq -S 'del(.run_label)' "$root/build-run.json" > "$temporary/$name.run"; done
cmp "$temporary/left.outputs" "$temporary/right.outputs" >/dev/null || fail 'canonical outputs differ'
cmp "$temporary/left.run" "$temporary/right.run" >/dev/null || fail 'build receipts differ'
echo 'Canonical workload outputs match; raw ldd/link-map diagnostics were verified but excluded.'
