#!/usr/bin/env bash
# Download the three source archives selected by the retained signed Sources index.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock="$root/custom-kernel-source.json"
fail() { echo "custom kernel source download refused: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: download-custom-kernel-source.sh NEW_OUTPUT_DIRECTORY'
for tool in curl jq openssl stat timeout; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_KERNEL_SOURCE_DEADLINE_GUARD:-} != 1 ]]; then
  export ZAINO_KERNEL_SOURCE_DEADLINE_GUARD=1
  exec timeout --signal=TERM --kill-after=10s 1200s bash "$0" "$@"
fi
bash "$root/verify-custom-kernel-source.sh" >/dev/null
requested=$1
[[ ! -e "$requested" ]] || fail 'output already exists'
parent=$(cd -- "$(dirname -- "$requested")" && pwd -P)
name=$(basename -- "$requested")
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'unsafe output name'
final="$parent/$name"
partial="$final.partial.$$"
mkdir -m 700 -- "$partial"
published=false
cleanup() { if [[ $published != true ]]; then rm -rf -- "$partial"; fi; }
trap cleanup EXIT
snapshot=$(jq -r '.snapshot' "$lock")
directory=$(jq -r '.package.directory' "$lock")
total=0
while IFS=$'\t' read -r file bytes digest; do
  [[ "$file" =~ ^[A-Za-z0-9][A-Za-z0-9.+_~-]*$ ]] || fail 'unsafe archive filename'
  total=$((total + bytes)); (( total <= 268435456 )) || fail 'source byte budget exceeded'
  destination="$partial/$file"
  curl --fail --silent --show-error --location --proto '=https' --max-time 900 \
    --max-filesize 536870912 --output "$destination" "$snapshot$directory/$file"
  [[ $(stat -c %s "$destination") == "$bytes" ]] || fail 'downloaded source size mismatch'
  actual=$(openssl dgst -sha256 -r "$destination"); actual=${actual%% *}
  [[ "$actual" == "$digest" ]] || fail 'downloaded source digest mismatch'
done < <(jq -r '.files[] | [.file, (.bytes|tostring), .sha256] | @tsv' "$lock")
bash "$root/verify-custom-kernel-source.sh" "$partial" >/dev/null
chmod -R go-rwx -- "$partial"
mv --no-clobber --no-target-directory -- "$partial" "$final"
[[ -d "$final" && ! -e "$partial" ]] || fail 'atomic publication collision'
published=true
echo 'Downloaded and authenticated the selected custom-kernel source archives.'
