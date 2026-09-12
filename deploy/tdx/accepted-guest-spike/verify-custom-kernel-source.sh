#!/usr/bin/env bash
# Authenticate the selected source package; never extract, build, or execute it.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock="$root/custom-kernel-source.json"
fail() { echo "custom kernel source refused: $*" >&2; exit 1; }
hash() {
  local result
  result=$(openssl dgst -sha256 -r "$1")
  printf '%s\n' "${result%% *}"
}
check_file() {
  local path=$1 bytes=$2 digest=$3
  [[ -f "$path" && ! -L "$path" ]] || fail 'missing regular input'
  [[ $(wc -c < "$path" | tr -d '[:space:]') == "$bytes" ]] || fail 'input size mismatch'
  [[ $(hash "$path") == "$digest" ]] || fail 'input digest mismatch'
}
[[ $# -le 1 ]] || fail 'usage: verify-custom-kernel-source.sh [downloaded-source-directory]'
[[ -f "$lock" && ! -L "$lock" ]] || fail 'missing regular source lock'
[[ $(wc -c < "$lock") -le 16384 ]] || fail 'source lock exceeds cap'
jq -e '
  (keys | sort) == (["schema","scope","kernel_build_complete","snapshot","index","package","files"] | sort) and
  .schema == "zaino-boot-spike-custom-kernel-source-v1" and
  .scope == "source_selection_only" and .kernel_build_complete == false and
  .snapshot == "https://snapshot.ubuntu.com/ubuntu/20260911T000000Z/" and
  (.index | keys | sort) == (["suite","path","file","bytes","sha256"] | sort) and
  .index.suite == "noble-updates" and .index.path == "main/source/Sources.xz" and
  .index.file == "kernel-source/noble-updates-main-Sources.xz" and
  (.index.bytes | type == "number" and . == floor and . > 0 and . <= 16777216) and
  (.index.sha256 | test("^[0-9a-f]{64}$")) and
  (.package | keys | sort) == (["name","version","directory"] | sort) and
  .package.name == "linux-gcp-6.17" and
  (.package.version | test("^[0-9][0-9A-Za-z.+~:-]{0,79}$")) and
  .package.directory == "pool/main/l/linux-gcp-6.17" and
  (.files | type == "array" and length == 3) and
  ([.files[].file] | unique | length) == 3 and
  all(.files[];
    (keys | sort) == (["file","bytes","sha256"] | sort) and
    (.file | test("^linux-gcp-6[.]17_[0-9A-Za-z.+~-]+[.](orig[.]tar[.]gz|diff[.]gz|dsc)$")) and
    (.bytes | type == "number" and . == floor and . > 0 and . <= 536870912) and
    (.sha256 | test("^[0-9a-f]{64}$")))
' "$lock" >/dev/null || fail 'source lock schema rejected'

# Reuse the retained archive-key and InRelease signature chain. The source
# lock cannot authenticate itself by changing its own expected hashes.
bash "$root/verify-upstream-selection.sh" >/dev/null
index="$root/$(jq -r '.index.file' "$lock")"
[[ -d "$root/kernel-source" && ! -L "$root/kernel-source" ]] || fail 'source index directory rejected'
release="$root/upstream/noble-updates.InRelease"
expected_index=$(awk '
  /^SHA256:$/ { in_hashes=1; next }
  in_hashes && /^[^ ]/ { in_hashes=0 }
  in_hashes && $3 == "main/source/Sources.xz" { print $1 " " $2; count++ }
  END { if (count != 1) exit 1 }
' "$release") || fail 'source index missing or duplicated in signed release'
[[ "$expected_index" == "$(jq -r '.index | .sha256 + " " + (.bytes|tostring)' "$lock")" ]] || fail 'source index does not match signed release'
check_file "$index" "$(jq -r '.index.bytes' "$lock")" "$(jq -r '.index.sha256' "$lock")"

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
chmod 700 "$temporary"
if ! xz --memlimit-decompress=128MiB -dc "$index" | head -c 33554433 > "$temporary/Sources"; then
  fail 'source index decompression rejected'
fi
[[ $(wc -c < "$temporary/Sources") -le 33554432 ]] || fail 'expanded source index exceeds cap'
awk -v wanted_package="$(jq -r '.package.name' "$lock")" \
    -v wanted_version="$(jq -r '.package.version' "$lock")" '
  BEGIN { RS=""; FS="\n" }
  {
    package=""; version=""
    for (i=1; i<=NF; i++) {
      if ($i ~ /^Package: /) package=substr($i,10)
      if ($i ~ /^Version: /) version=substr($i,10)
    }
    if (package == wanted_package && version == wanted_version) { print; count++ }
  }
  END { if (count != 1) exit 1 }
' "$temporary/Sources" > "$temporary/stanza" || fail 'selected source package missing or duplicated'
[[ $(awk '/^Directory: / { print substr($0,12); count++ } END { if (count != 1) exit 1 }' "$temporary/stanza") == "$(jq -r '.package.directory' "$lock")" ]] || fail 'source directory mismatch'
awk '
  /^Checksums-Sha256:$/ { in_hashes=1; next }
  in_hashes && /^[^ ]/ { in_hashes=0 }
  in_hashes { if (NF != 3) exit 1; print $3 "\t" $2 "\t" $1; count++ }
  END { if (count != 3) exit 1 }
' "$temporary/stanza" | LC_ALL=C sort > "$temporary/authenticated-files"
jq -r '.files[] | [.file, (.bytes|tostring), .sha256] | @tsv' "$lock" | LC_ALL=C sort > "$temporary/selected-files"
cmp -s "$temporary/authenticated-files" "$temporary/selected-files" || fail 'source files differ from signed index'

if [[ $# == 1 ]]; then
  archives=$1
  [[ -d "$archives" && ! -L "$archives" ]] || fail 'source archive directory rejected'
  shopt -s nullglob dotglob
  entries=("$archives"/*)
  [[ ${#entries[@]} == 3 ]] || fail 'source archive directory must contain exactly three files'
  while IFS=$'\t' read -r name bytes digest; do
    check_file "$archives/$name" "$bytes" "$digest"
  done < "$temporary/selected-files"
  echo 'Verified authenticated source metadata and all three downloaded source files; no extraction or build performed.'
else
  echo 'Verified authenticated source selection only; downloaded source bytes and kernel build remain unverified.'
fi
