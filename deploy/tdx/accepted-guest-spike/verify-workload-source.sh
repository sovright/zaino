#!/usr/bin/env bash
set -euo pipefail
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(git -C "$script_root" rev-parse --show-toplevel)
fail() { echo "workload source refused: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: verify-workload-source.sh SOURCE_DIRECTORY'
root=$1
for file in source.json config.toml source-files.tsv vendor-files.tsv; do [[ -f "$root/$file" && ! -L "$root/$file" ]] || fail "missing $file"; done
for directory in repository vendor; do [[ -d "$root/$directory" && ! -L "$root/$directory" ]] || fail "missing $directory"; done
entries=$(find "$root" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' '); [[ "$entries" == 6 ]] || fail 'unexpected source-input root entry'
jq -e '.schema=="zaino-workload-source-v1" and .scope=="reviewed-git-export-and-prefetched-cargo-source;compiler-and-build-unexecuted" and (.repository_revision|test("^[0-9a-f]{40}$")) and (.source_tree|test("^[0-9a-f]{40}$")) and (.cargo_lock_sha256|test("^[0-9a-f]{64}$")) and (.source_file_manifest_sha256|test("^[0-9a-f]{64}$")) and (.vendor_file_manifest_sha256|test("^[0-9a-f]{64}$")) and (.cargo_config_sha256|test("^[0-9a-f]{64}$"))' "$root/source.json" >/dev/null || fail 'source receipt rejected'
[[ $(jq -r .repository_revision "$root/source.json") == ef4d81b9bc7c68ef03a73730caf42781b3f1cd21 && $(jq -r .source_tree "$root/source.json") == 725be84be56cb6b51074ba81c8860523a91dbffd ]] || fail 'reviewed source identity mismatch'
[[ $(git -C "$repository_root" rev-parse 'ef4d81b9bc7c68ef03a73730caf42781b3f1cd21^{tree}') == 725be84be56cb6b51074ba81c8860523a91dbffd ]] || fail 'reviewed Git object unavailable'
hash() { local x; x=$(openssl dgst -sha256 -r "$1"); printf '%s\n' "${x%% *}"; }
cmp "$root/config.toml" "$script_root/workload-cargo-config.toml" >/dev/null || fail 'Cargo config differs from reviewed config'
[[ $(hash "$root/config.toml") == "$(jq -r .cargo_config_sha256 "$root/source.json")" ]] || fail 'config digest mismatch'
[[ $(hash "$root/repository/Cargo.lock") == 6cadfd92d011d36dfacb684fdeb7c1bc5edda06b581d1da5dec36fe8adf5b398 && $(hash "$root/repository/Cargo.lock") == "$(jq -r .cargo_lock_sha256 "$root/source.json")" ]] || fail 'Cargo.lock digest mismatch'
verify_tree() {
  local directory=$1 manifest=$2 expected_digest=$3 actual declared
  [[ $(hash "$manifest") == "$expected_digest" ]] || fail 'file manifest digest mismatch'
  find "$directory" ! -type f ! -type d -print | grep -q . && fail 'source tree contains a non-regular entry'
  actual=$(mktemp); declared=$(mktemp); trap 'rm -f -- "$actual" "$declared"' RETURN
  (cd "$directory" && find . -type f -print | LC_ALL=C sort) > "$actual"
  cut -f2 "$manifest" | LC_ALL=C sort > "$declared"
  [[ $(wc -l < "$declared") == $(LC_ALL=C sort -u "$declared" | wc -l) ]] || fail 'duplicate manifest path'
  cmp "$actual" "$declared" >/dev/null || fail 'file set mismatch'
  count=$(wc -l < "$actual" | tr -d ' ')
  if find "$directory" -type f -printf '' >/dev/null 2>&1; then total=$(find "$directory" -type f -printf '%s\n' | awk '{sum+=$1} END {printf "%.0f",sum}'); else total=$(find "$directory" -type f -exec stat -f %z {} + | awk '{sum+=$1} END {printf "%.0f",sum}'); fi
  [[ "$count" -gt 0 && "$count" -le 50000 && "$total" -le 2147483648 ]] || fail 'file-set bound exceeded'
  while IFS=$'\t' read -r digest relative extra; do
    [[ -z "$extra" && "$digest" =~ ^[0-9a-f]{64}$ && "$relative" =~ ^\./[A-Za-z0-9._/+~=@,()~-]+$ && "$relative" != *../* ]] || fail 'manifest entry rejected'
    file="$directory/${relative#./}"; [[ -f "$file" && ! -L "$file" ]] || fail 'manifest file mismatch'
  done < "$manifest"
  hashes=$(mktemp)
  (cd "$directory" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 openssl dgst -sha256 -r | awk '{digest=$1; $1=""; sub(/^ \*/,""); print digest "\t" $0}') > "$hashes"
  cmp "$manifest" "$hashes" >/dev/null || fail 'file digest mismatch'
  rm -f "$hashes"
  rm -f "$actual" "$declared"; trap - RETURN
}
verify_tree "$root/repository" "$root/source-files.tsv" "$(jq -r .source_file_manifest_sha256 "$root/source.json")"
[[ $(hash "$root/vendor-files.tsv") == 3990a280ca47809755e39ad5eeefe9c572fe8fc1eb57a7dae0edb4869694b225 ]] || fail 'vendor differs from reviewed dependency capture manifest'
verify_tree "$root/vendor" "$root/vendor-files.tsv" "$(jq -r .vendor_file_manifest_sha256 "$root/source.json")"
[[ $(wc -l < "$root/vendor-files.tsv" | tr -d ' ') == 33865 ]] || fail 'reviewed vendor file count mismatch'
vendor_modes=$(mktemp); vendor_classes=$(mktemp); trap 'rm -f -- "$vendor_modes" "$vendor_classes"' RETURN
if find "$root/vendor" -type f -printf '' >/dev/null 2>&1; then (cd "$root/vendor" && find . -type f -printf '%m|%p\n' | LC_ALL=C sort) > "$vendor_modes"; else (cd "$root/vendor" && find . -type f -exec stat -f '%Lp|%N' {} + | LC_ALL=C sort) > "$vendor_modes"; fi
awk -F '|' '$1=="755" {print "executable\t" $2; next} $1=="644" {print "nonexecutable\t" $2; next} {exit 1}' "$vendor_modes" > "$vendor_classes" || fail 'vendor mode outside reviewed 0644/0755 set'
LC_ALL=C sort -t $'\t' -k2,2 -o "$vendor_classes" "$vendor_classes"
[[ $(hash "$vendor_classes") == 32aaeb811dc98b5c6da4e46379fc41c9cf37eb31946710b444a743efbc10dd0a ]] || fail 'reviewed vendor modes differ'
rm -f "$vendor_modes" "$vendor_classes"; trap - RETURN
canonical_parent=$(mktemp -d); canonical="$canonical_parent/repository"; mkdir "$canonical"; trap 'rm -rf -- "$canonical_parent"' EXIT
git -C "$repository_root" archive ef4d81b9bc7c68ef03a73730caf42781b3f1cd21 | tar -xf - -C "$canonical"
git -C "$repository_root" show ef4d81b9bc7c68ef03a73730caf42781b3f1cd21:Cargo.lock > "$canonical/Cargo.lock"
materialize() { local link=$1 target=$2; [[ -L "$canonical/$link" && $(readlink "$canonical/$link") == "$target" ]] || fail 'reviewed canonical link changed'; cp -L "$canonical/$link" "$canonical/$link.materialized"; rm "$canonical/$link"; mv "$canonical/$link.materialized" "$canonical/$link"; }
materialize AGENTS.md CLAUDE.md
materialize packages/zaino-proto/proto/compact_formats.proto ../lightwallet-protocol/walletrpc/compact_formats.proto
materialize packages/zaino-proto/proto/service.proto ../lightwallet-protocol/walletrpc/service.proto
[[ -z $(find "$canonical" -type l -print) ]] || fail 'unexpected canonical link'
(cd "$canonical" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 openssl dgst -sha256 -r | awk '{digest=$1; $1=""; sub(/^ \*/,""); print digest "\t" $0}') > "$canonical_parent/source-files.tsv"
cmp "$root/source-files.tsv" "$canonical_parent/source-files.tsv" >/dev/null || fail 'archived source differs from reviewed Git tree'
actual_source_modes="$canonical_parent/actual-modes"; canonical_source_modes="$canonical_parent/canonical-modes"
if find "$root/repository" -type f -printf '' >/dev/null 2>&1; then (cd "$root/repository" && find . -type f -printf '%m|%p\n' | LC_ALL=C sort) > "$actual_source_modes"; (cd "$canonical" && find . -type f -printf '%m|%p\n' | LC_ALL=C sort) > "$canonical_source_modes"; else (cd "$root/repository" && find . -type f -exec stat -f '%Lp|%N' {} + | LC_ALL=C sort) > "$actual_source_modes"; (cd "$canonical" && find . -type f -exec stat -f '%Lp|%N' {} + | LC_ALL=C sort) > "$canonical_source_modes"; fi
cmp "$actual_source_modes" "$canonical_source_modes" >/dev/null || fail 'archived source modes differ'
echo 'Exact archived source and prefetched Cargo inputs verified; no compiler or guest claim.'
