#!/usr/bin/env bash
# Restore ZIP-lost modes into a new owned copy after authenticating the manifest.
set -euo pipefail
export LC_ALL=C
fail() { echo "workload restore refused: $*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'usage: ZIP_OUTPUT TRUSTED_EXPECTATIONS NEW_RESTORED_OUTPUT'
source=$(cd -- "$1" && pwd -P) || fail 'missing source'
expectations=$(cd -- "$(dirname -- "$2")" && pwd -P)/$(basename -- "$2")
destination=$3; [[ ! -e "$destination" ]] || fail 'destination exists'
[[ -f "$expectations" && ! -L "$expectations" ]] || fail 'missing trusted expectations'
for tool in find jq sha256sum sort tar; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if find "$source" -xdev ! -type d ! -type f -print -quit | grep -q .; then fail 'special source path'; fi
expected_roots=$(printf '%s\n' artifacts build-run.json canonical-runtime-closure.tsv evidence-agent.link-map init-status.txt native-tool-versions.txt OUTPUT-MODES.tsv OUTPUT-SHA256SUMS runtime-closure.txt runtime-libs rust-tool-versions.txt SHA256SUMS | sort)
[[ $(find "$source" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == "$expected_roots" ]] || fail 'unexpected source root'
for file in build-run.json canonical-runtime-closure.tsv evidence-agent.link-map init-status.txt native-tool-versions.txt OUTPUT-MODES.tsv OUTPUT-SHA256SUMS runtime-closure.txt rust-tool-versions.txt SHA256SUMS artifacts/tdx-evidence-agent; do [[ -f "$source/$file" && ! -L "$source/$file" ]] || fail "nonregular source file: $file"; done
[[ -d "$source/artifacts" && ! -L "$source/artifacts" && -d "$source/runtime-libs" && ! -L "$source/runtime-libs" ]] || fail 'invalid source directories'
for file in build-run.json canonical-runtime-closure.tsv init-status.txt native-tool-versions.txt OUTPUT-MODES.tsv OUTPUT-SHA256SUMS runtime-closure.txt rust-tool-versions.txt SHA256SUMS; do [[ $(stat -c %s "$source/$file") -le 65536 ]] || fail "oversized source metadata: $file"; done
run_label=$(jq -r '.run_label // empty' "$source/build-run.json")
[[ "$run_label" == run-1 || "$run_label" == run-2 ]] || fail 'invalid source run label'
outer_sha=$(sha256sum "$source/OUTPUT-SHA256SUMS" | awk '{print $1}')
[[ "$outer_sha" == "$(jq -r --arg run "$run_label" '.accepted_runs[] | select(.run_label==$run) | .output_sha256s_sha256' "$expectations")" ]] || fail 'source manifest is not reviewer accepted'
expected_files=$(find "$source" -type f ! -name OUTPUT-SHA256SUMS -printf './%P\n' | sort)
manifest_files=$(awk 'NF==2 && $1 ~ /^[0-9a-f]{64}$/ && $2 ~ /^\.\/[A-Za-z0-9+._\/-]+$/ && $2 !~ /\.\./ {print $2; next} {bad=1} END {if(bad) exit 1}' "$source/OUTPUT-SHA256SUMS" | sort) || fail 'unsafe source manifest'
[[ "$expected_files" == "$manifest_files" ]] || fail 'source manifest file set mismatch'
(cd "$source" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'source checksum mismatch'
mkdir -m 700 "$destination"
(cd "$source" && tar --create --format=posix --files-from=-) < <(cd "$source" && find . -mindepth 1 -print | sort) | (cd "$destination" && tar --extract --no-same-owner --no-same-permissions)
find "$destination" -type d -exec chmod 755 {} +
chmod 700 "$destination" "$destination/artifacts" "$destination/runtime-libs"
while IFS=$'\t' read -r mode relative; do
  [[ "$mode" =~ ^[0-7]{3,4}$ && "$relative" == ./* && "$relative" != *..* && -f "$destination/${relative#./}" && ! -L "$destination/${relative#./}" ]] || fail 'invalid authenticated mode row'
  chmod "$mode" "$destination/${relative#./}"
done < "$destination/OUTPUT-MODES.tsv"
expected=$(find "$destination" -type f ! -name OUTPUT-SHA256SUMS -printf './%P\n' | sort)
actual=$(cut -f2 "$destination/OUTPUT-MODES.tsv" | sort)
[[ "$expected" == "$actual" ]] || fail 'mode manifest file set mismatch'
(cd "$destination" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'restored checksum mismatch'
