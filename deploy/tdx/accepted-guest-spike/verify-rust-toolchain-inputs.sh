#!/usr/bin/env bash
# Check reviewed compiler archive identities; never install or execute them.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock="$root/rust-toolchain-inputs.json"
fail() { echo "Rust inputs refused: $*" >&2; exit 1; }
hash() {
  local result
  result=$(openssl dgst -sha256 -r "$1")
  printf '%s\n' "${result%% *}"
}
check_file() {
  [[ -f "$1" && ! -L "$1" ]] || fail 'missing regular input'
  [[ $(wc -c < "$1" | tr -d '[:space:]') == "$2" ]] || fail 'input size mismatch'
  [[ $(hash "$1") == "$3" ]] || fail 'input digest mismatch'
}
[[ $# -le 1 ]] || fail 'usage: verify-rust-toolchain-inputs.sh [archive-directory]'
[[ -f "$lock" && ! -L "$lock" && $(wc -c < "$lock") -le 16384 ]] || fail 'lock rejected'
jq -e '
  (keys | sort) == (["schema","scope","builder_execution_verified","version","target","release_date","source_commit","manifest","components"] | sort) and
  .schema == "zaino-boot-spike-rust-inputs-v1" and
  .scope == "compiler_archive_selection_only" and .builder_execution_verified == false and
  .version == "1.96.0" and .target == "x86_64-unknown-linux-gnu" and
  .release_date == "2026-05-28" and .source_commit == "ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96" and
  (.manifest | keys | sort) == (["file","url","bytes","sha256"] | sort) and
  .manifest.file == "rust-toolchain-inputs/channel-rust-1.96.0.toml" and
  .manifest.url == "https://static.rust-lang.org/dist/channel-rust-1.96.0.toml" and
  (.manifest.bytes | type == "number" and . == floor and . > 0 and . <= 2097152) and
  (.manifest.sha256 | test("^[0-9a-f]{64}$")) and
  (.components | type == "array" and length == 4) and
  ([.components[] | [.name,.target]] | sort) == [["cargo","x86_64-unknown-linux-gnu"],["rust-std","x86_64-unknown-linux-gnu"],["rust-std","x86_64-unknown-linux-musl"],["rustc","x86_64-unknown-linux-gnu"]] and
  all(.components[];
    (keys | sort) == (["name","target","file","url","bytes","sha256"] | sort) and
    .file == (.name + "-1.96.0-" + .target + ".tar.xz") and
    .url == ("https://static.rust-lang.org/dist/2026-05-28/" + .file) and
    (.bytes | type == "number" and . == floor and . > 0 and . <= 268435456) and
    (.sha256 | test("^[0-9a-f]{64}$")))
' "$lock" >/dev/null || fail 'lock schema rejected'
[[ -d "$root/rust-toolchain-inputs" && ! -L "$root/rust-toolchain-inputs" ]] || fail 'manifest directory rejected'
manifest="$root/rust-toolchain-inputs/channel-rust-1.96.0.toml"
check_file "$manifest" "$(jq -r '.manifest.bytes' "$lock")" "$(jq -r '.manifest.sha256' "$lock")"
while IFS=$'\t' read -r name target url digest; do
  # This is an exact section/value comparison against a hash-pinned manifest,
  # not a general TOML parser accepting arbitrary equivalent syntax.
  selected=$(awk -v section="[pkg.$name.target.$target]" '
    /^\[/ { active=($0 == section); if (active) sections++ }
    active && /^available = true$/ { available++ }
    active && /^xz_url = / { url=$0; urls++ }
    active && /^xz_hash = / { hash=$0; hashes++ }
    END {
      if (sections != 1 || available != 1 || urls != 1 || hashes != 1) exit 1
      print url; print hash
    }
  ' "$manifest") || fail 'manifest component missing or ambiguous'
  expected=$(printf 'xz_url = "%s"\nxz_hash = "%s"' "$url" "$digest")
  [[ "$selected" == "$expected" ]] || fail 'component differs from retained manifest'
done < <(jq -r '.components[] | [.name,.target,.url,.sha256] | @tsv' "$lock")
if [[ $# == 1 ]]; then
  archives=$1
  [[ -d "$archives" && ! -L "$archives" ]] || fail 'archive directory rejected'
  shopt -s nullglob dotglob
  entries=("$archives"/*)
  [[ ${#entries[@]} == 4 ]] || fail 'archive directory must contain exactly four files'
  while IFS=$'\t' read -r file bytes digest; do
    check_file "$archives/$file" "$bytes" "$digest"
  done < <(jq -r '.components[] | [.file,(.bytes|tostring),.sha256] | @tsv' "$lock")
fi
echo 'Rust compiler input identities verified; no builder execution or guest claim'
