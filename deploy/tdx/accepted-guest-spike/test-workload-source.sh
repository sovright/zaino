#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(git -C "$root" rev-parse --show-toplevel)
fixture=$(mktemp -d); trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/vendor" "$fixture/repository"
printf 'crate bytes\n' > "$fixture/vendor/lib.rs"
git -C "$repository_root" archive ef4d81b9bc7c68ef03a73730caf42781b3f1cd21 | tar -xf - -C "$fixture/repository"
git -C "$repository_root" show ef4d81b9bc7c68ef03a73730caf42781b3f1cd21:Cargo.lock > "$fixture/repository/Cargo.lock"
for link in AGENTS.md packages/zaino-proto/proto/compact_formats.proto packages/zaino-proto/proto/service.proto; do cp -L "$fixture/repository/$link" "$fixture/repository/$link.materialized"; rm "$fixture/repository/$link"; mv "$fixture/repository/$link.materialized" "$fixture/repository/$link"; done
cp "$root/workload-cargo-config.toml" "$fixture/config.toml"
hash() { local x; x=$(openssl dgst -sha256 -r "$1"); printf '%s' "${x%% *}"; }
manifest() { local directory=$1 output=$2; (cd "$directory" && find . -type f -print | LC_ALL=C sort | while read -r path; do printf '%s\t%s\n' "$(hash "$path")" "$path"; done) > "$output"; }
manifest "$fixture/vendor" "$fixture/vendor-files.tsv"; manifest "$fixture/repository" "$fixture/source-files.tsv"
jq -n --arg lock "$(hash "$fixture/repository/Cargo.lock")" --arg source "$(hash "$fixture/source-files.tsv")" --arg files "$(hash "$fixture/vendor-files.tsv")" --arg config "$(hash "$fixture/config.toml")" \
  '{schema:"zaino-workload-source-v1",repository_revision:"ef4d81b9bc7c68ef03a73730caf42781b3f1cd21",source_tree:"725be84be56cb6b51074ba81c8860523a91dbffd",cargo_lock_sha256:$lock,source_file_manifest_sha256:$source,vendor_file_manifest_sha256:$files,cargo_config_sha256:$config,scope:"reviewed-git-export-and-prefetched-cargo-source;compiler-and-build-unexecuted"}' > "$fixture/source.json"
failure=$(mktemp); trap 'rm -rf -- "$fixture"; rm -f -- "$failure"' EXIT
if bash "$root/verify-workload-source.sh" "$fixture" > /dev/null 2> "$failure"; then echo 'self-authored vendor manifest accepted' >&2; exit 1; fi
grep -Fx 'workload source refused: vendor differs from reviewed dependency capture manifest' "$failure" >/dev/null
printf 'Self-authored vendor receipt refusal passed; retained positive capture is exercised separately.\n'
