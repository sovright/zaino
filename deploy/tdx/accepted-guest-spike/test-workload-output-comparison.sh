#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd); fixture=$(mktemp -d); trap 'rm -rf -- "$fixture"' EXIT
refresh() { local output=$1; (cd "$output" && for file in agent canonical-runtime-closure.tsv; do digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done > SHA256SUMS; find . -type f ! -name OUTPUT-SHA256SUMS -print | LC_ALL=C sort | while read -r file; do digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done > ../outer); mv "$output/../outer" "$output/OUTPUT-SHA256SUMS"; }
make_output() { local output=$1 run=$2 raw=$3; mkdir "$output"; printf 'agent\n' > "$output/agent"; printf 'canonical\n' > "$output/canonical-runtime-closure.tsv"; printf '%s\n' "$raw" > "$output/runtime-closure.txt"; printf '%s\n' "$raw" > "$output/evidence-agent.link-map"; jq -n --arg run "$run" '{run_label:$run,identity:"fixed"}' > "$output/build-run.json"; refresh "$output"; }
make_output "$fixture/one" run-1 raw-one; make_output "$fixture/two" run-2 raw-two
bash "$root/compare-workload-outputs.sh" "$fixture/one" "$fixture/two" >/dev/null
printf 'mutation\n' >> "$fixture/two/agent"; refresh "$fixture/two"
failure=$(mktemp); if bash "$root/compare-workload-outputs.sh" "$fixture/one" "$fixture/two" >/dev/null 2> "$failure"; then echo 'repaired canonical mutation accepted' >&2; exit 1; fi
grep -Fx 'workload output comparison refused: canonical outputs differ' "$failure" >/dev/null
cp -R "$fixture/one" "$fixture/identity"; jq '.identity="changed"' "$fixture/identity/build-run.json" > "$fixture/identity/run"; mv "$fixture/identity/run" "$fixture/identity/build-run.json"; refresh "$fixture/identity"
if bash "$root/compare-workload-outputs.sh" "$fixture/one" "$fixture/identity" >/dev/null 2> "$failure"; then echo 'repaired build identity mutation accepted' >&2; exit 1; fi
grep -Fx 'workload output comparison refused: build receipts differ' "$failure" >/dev/null; rm "$failure"
echo 'Diagnostic exclusion plus repaired canonical and identity mutation refusals passed.'
