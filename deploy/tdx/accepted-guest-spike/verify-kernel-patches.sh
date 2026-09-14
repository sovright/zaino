#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "kernel patch set refused: $*" >&2; exit 1; }
[[ $# == 0 ]] || fail 'usage: verify-kernel-patches.sh'
lock="$root/kernel-patches.json"; patches="$root/kernel-source"
[[ -f "$lock" && ! -L "$lock" ]] || fail 'invalid patch lock'
lock_sha=$(sha256sum -- "$lock"); [[ ${lock_sha%% *} == fa4aa401443c303077fc1a434bb82c5fe558f44b5a62f4ca3d6534f649c2289a ]] || fail 'patch lock digest changed'
jq -e '
  .schema == "zaino-custom-kernel-patches-v1" and
  .source_driver_sha256 == "06d50d736be3f708dd78654884b296b379736529f0a1cb73f7753e3f9e4fa078" and
  .patched_driver_sha256 == "ac7a2fed535b553fbd112bca77d42f7d734fa23e72341ce7437b853d311f582a" and
  .scope == "reviewed-status-and-host-controlled-length-fixes-only;boot-qualification-required" and
  (.upstream | length) == 2 and
  .upstream[0].commit == "0f409eaea53e49932cf92a761de66345c9a4b4be" and
  .upstream[1].commit == "c3fd16c3b98ed726294feab2f94f876290bf7b61" and
  .applied_backport.file == "0003-tdx-getquote-linux-6.17-backport.patch"
' "$lock" >/dev/null || fail 'patch lock schema or identities changed'
expected=$'0001-tdx-getquote-status.patch\t2597\tb9b94ea121334581b71f95bd723ea060222420ab09ee4773cf9ef35a57355035\n0002-tdx-getquote-length.patch\t2960\t7bf1c49441cf2d168adedbf4a57df65b0e758e37ff713aa48f4e9b2d58e22ed1\n0003-tdx-getquote-linux-6.17-backport.patch\t1340\tab420f4663f504a61f33d054a350a88dd9dae8e35431c5fcdd800f025ee88bf8'
actual=$(jq -r '(.upstream[]), .applied_backport | [.file,(.bytes|tostring),.sha256] | @tsv' "$lock")
[[ "$actual" == "$expected" ]] || fail 'reviewed patch triples changed'
while IFS=$'\t' read -r file bytes digest; do
  [[ "$file" =~ ^[0-9]{4}-tdx-getquote-[a-z0-9.-]+\.patch$ ]] || fail 'unsafe patch filename'
  path="$patches/$file"; [[ -f "$path" && ! -L "$path" ]] || fail "missing patch: $file"
  actual_bytes=$(wc -c < "$path"); actual_bytes=${actual_bytes//[[:space:]]/}
  [[ "$actual_bytes" == "$bytes" ]] || fail "patch size mismatch: $file"
  actual=$(sha256sum -- "$path"); [[ ${actual%% *} == "$digest" ]] || fail "patch digest mismatch: $file"
done < <(jq -r '(.upstream[]), .applied_backport | [.file,(.bytes|tostring),.sha256] | @tsv' "$lock")
actual_names=$(find -L "$patches" -mindepth 1 -maxdepth 1 -name '*.patch' -exec basename -- {} \; | LC_ALL=C sort)
expected_names=$'0001-tdx-getquote-status.patch\n0002-tdx-getquote-length.patch\n0003-tdx-getquote-linux-6.17-backport.patch'
[[ "$actual_names" == "$expected_names" ]] || fail 'unknown, missing, or non-regular patch input'
echo 'kernel patch set verified'
