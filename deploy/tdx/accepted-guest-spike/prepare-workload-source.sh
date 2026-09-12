#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
fail() { echo "workload source preparation refused: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: prepare-workload-source.sh NEW_OUTPUT_DIRECTORY'
for tool in cargo git jq openssl tar; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
mv --help 2>&1 | grep -q -- '--no-target-directory' || fail 'GNU mv with no-target-directory is required'
out=$1; [[ ! -e "$out" ]] || fail 'output already exists'
parent=$(cd -- "$(dirname -- "$out")" && pwd -P); name=$(basename -- "$out")
stage=$(mktemp -d "$parent/.${name}.partial.XXXXXX"); moved=false
cleanup() { local s=$?; trap - EXIT; [[ $moved == true ]] || rm -rf -- "$stage"; exit "$s"; }; trap cleanup EXIT
revision=314b80ac1be55f0fb763587427f817d96c6803a1
tree=2b4b61857e009232dbcb37413f24f6b7ff68e6f8
[[ $(git rev-parse "$revision^{tree}") == "$tree" ]] || fail 'reviewed source commit is unavailable or changed'
mkdir "$stage/repository" "$stage/vendor"
git archive --format=tar "$revision" | tar -xf - -C "$stage/repository"
git show "$revision:Cargo.lock" > "$stage/repository/Cargo.lock"
materialize() { local link=$1 target=$2; [[ -L "$stage/repository/$link" && $(readlink "$stage/repository/$link") == "$target" ]] || fail 'reviewed export link changed'; cp -L "$stage/repository/$link" "$stage/repository/$link.materialized"; rm "$stage/repository/$link"; mv "$stage/repository/$link.materialized" "$stage/repository/$link"; }
materialize AGENTS.md CLAUDE.md
materialize packages/zaino-proto/proto/compact_formats.proto ../lightwallet-protocol/walletrpc/compact_formats.proto
materialize packages/zaino-proto/proto/service.proto ../lightwallet-protocol/walletrpc/service.proto
[[ -z $(find "$stage/repository" -type l -print) ]] || fail 'unexpected export link'
lock_sha=$(openssl dgst -sha256 -r "$stage/repository/Cargo.lock"); lock_sha=${lock_sha%% *}
[[ "$lock_sha" == 6cadfd92d011d36dfacb684fdeb7c1bc5edda06b581d1da5dec36fe8adf5b398 ]] || fail 'Cargo.lock differs from reviewed input'
cargo vendor --manifest-path "$stage/repository/Cargo.toml" --locked --versioned-dirs "$stage/vendor" > "$stage/generated-config.toml"
executable_list="$stage/executable-files"; regular_list="$stage/regular-files"; : > "$executable_list"; : > "$regular_list"
while IFS= read -r -d '' file; do if [[ -x "$file" ]]; then printf '%s\0' "$file" >> "$executable_list"; else printf '%s\0' "$file" >> "$regular_list"; fi; done < <(find "$stage/vendor" -type f -print0)
xargs -0 chmod 755 < "$executable_list"; xargs -0 chmod 644 < "$regular_list"; rm "$executable_list" "$regular_list"
cp "$(dirname "$0")/workload-cargo-config.toml" "$stage/config.toml"
escaped=${stage//\/\\}; escaped=${escaped//|/\|}
sed "s|directory = \"$escaped/vendor\"|directory = \"/inputs/vendor\"|" "$stage/generated-config.toml" > "$stage/generated-config.normalized.toml"
cmp "$stage/config.toml" "$stage/generated-config.normalized.toml" >/dev/null || fail 'cargo vendor mappings differ from reviewed config'
rm "$stage/generated-config.toml" "$stage/generated-config.normalized.toml"
manifest() {
  local directory=$1 output=$2
  (cd "$directory" && find . -type f -print | LC_ALL=C sort | while IFS= read -r path; do [[ "$path" =~ ^\./[A-Za-z0-9._/+~=@,()~-]+$ && "$path" != *../* ]] || fail 'unsafe manifest path'; printf '%s\0' "$path"; done | xargs -0 openssl dgst -sha256 -r | awk '{digest=$1; $1=""; sub(/^ \*/,""); print digest "\t" $0}') > "$output"
}
manifest "$stage/repository" "$stage/source-files.tsv"
manifest "$stage/vendor" "$stage/vendor-files.tsv"
source_manifest_sha=$(openssl dgst -sha256 -r "$stage/source-files.tsv"); source_manifest_sha=${source_manifest_sha%% *}
vendor_manifest_sha=$(openssl dgst -sha256 -r "$stage/vendor-files.tsv"); vendor_manifest_sha=${vendor_manifest_sha%% *}
config_sha=$(openssl dgst -sha256 -r "$stage/config.toml"); config_sha=${config_sha%% *}
jq -n --arg revision "$revision" --arg tree "$tree" --arg lock "$lock_sha" --arg source "$source_manifest_sha" --arg files "$vendor_manifest_sha" --arg config "$config_sha" \
  '{schema:"zaino-workload-source-v1",repository_revision:$revision,source_tree:$tree,cargo_lock_sha256:$lock,source_file_manifest_sha256:$source,vendor_file_manifest_sha256:$files,cargo_config_sha256:$config,scope:"reviewed-git-export-and-prefetched-cargo-source;compiler-and-build-unexecuted"}' > "$stage/source.json"
mv --no-clobber --no-target-directory -- "$stage" "$out"
[[ -d "$out" && -f "$out/source.json" && ! -e "$stage" && ! -e "$out/${stage##*/}" ]] || fail 'atomic publication failed'
moved=true
