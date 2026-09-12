#!/usr/bin/env bash
# Offline metadata/authenticity regressions; optional real archive-byte checks.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -le 1 ]] || { echo 'usage: test-custom-kernel-source.sh [downloaded-source-directory]' >&2; exit 1; }
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
chmod 700 "$temporary"
cases=0
fresh_case() {
  cases=$((cases + 1))
  fixture="$temporary/case-$cases"
  mkdir "$fixture"
  cp "$root/custom-kernel-source.json" "$root/upstream-selection.json" \
     "$root/verify-upstream-selection.sh" "$root/verify-custom-kernel-source.sh" "$fixture/"
  cp -R "$root/upstream" "$root/kernel-source" "$fixture/"
}
mutate_lock() {
  jq "$1" "$fixture/custom-kernel-source.json" > "$fixture/changed.json"
  mv "$fixture/changed.json" "$fixture/custom-kernel-source.json"
}
refuses() {
  local expected=$1
  shift
  if bash "$fixture/verify-custom-kernel-source.sh" "$@" > "$temporary/refusal.log" 2>&1; then
    echo "custom kernel negative case $cases unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq "$expected" "$temporary/refusal.log" || {
    cat "$temporary/refusal.log" >&2
    echo "custom kernel negative case $cases failed for the wrong reason" >&2
    exit 1
  }
}
bash "$root/verify-custom-kernel-source.sh" >/dev/null
fresh_case
mutate_lock '.kernel_build_complete = true'
refuses 'source lock schema rejected'
fresh_case
mutate_lock '.snapshot = "https://snapshot.ubuntu.com/ubuntu/latest/"'
refuses 'source lock schema rejected'
fresh_case
mutate_lock '.package.version = "6.17.0-1012.12~24.04.1"'
refuses 'selected source package missing or duplicated'
fresh_case
mutate_lock '.files[0].file = "../escape.diff.gz"'
refuses 'source lock schema rejected'
fresh_case
mutate_lock '.files[1] = .files[0]'
refuses 'source lock schema rejected'
fresh_case
mutate_lock '.files[0].sha256 = ("0" * 64)'
refuses 'source files differ from signed index'
fresh_case
printf 'tampered source index\n' > "$fixture/kernel-source/noble-updates-main-Sources.xz"
digest=$(openssl dgst -sha256 -r "$fixture/kernel-source/noble-updates-main-Sources.xz")
digest=${digest%% *}
bytes=$(wc -c < "$fixture/kernel-source/noble-updates-main-Sources.xz" | tr -d '[:space:]')
jq --arg digest "$digest" --argjson bytes "$bytes" \
  '.index.sha256=$digest | .index.bytes=$bytes' "$fixture/custom-kernel-source.json" > "$fixture/changed.json"
mv "$fixture/changed.json" "$fixture/custom-kernel-source.json"
refuses 'source index does not match signed release'
fresh_case
mv "$fixture/kernel-source/noble-updates-main-Sources.xz" "$fixture/index.xz"
ln -s ../index.xz "$fixture/kernel-source/noble-updates-main-Sources.xz"
refuses 'missing regular input'

if [[ $# == 1 ]]; then
  # One known-good control verifies all real archive bytes. Hard links keep
  # negative layout checks cheap; these checks never write linked contents.
  bash "$root/verify-custom-kernel-source.sh" "$1" >/dev/null
  fresh_case
  mkdir "$fixture/archives"
  while IFS= read -r name; do ln "$1/$name" "$fixture/archives/$name"; done < <(jq -r '.files[].file' "$root/custom-kernel-source.json")
  touch "$fixture/archives/.extra"
  refuses 'source archive directory must contain exactly three files' "$fixture/archives"
  fresh_case
  mkdir "$fixture/archives"
  while IFS= read -r name; do ln "$1/$name" "$fixture/archives/$name"; done < <(jq -r '.files[].file' "$root/custom-kernel-source.json")
  dsc=$(jq -r '.files[].file | select(endswith(".dsc"))' "$root/custom-kernel-source.json")
  rm "$fixture/archives/$dsc"
  ln -s "$1/$dsc" "$fixture/archives/$dsc"
  refuses 'missing regular input' "$fixture/archives"
  fresh_case
  mkdir "$fixture/archives"
  while IFS= read -r name; do ln "$1/$name" "$fixture/archives/$name"; done < <(jq -r '.files[].file' "$root/custom-kernel-source.json")
  # Unlink the owned hard link before creating a same-length changed copy.
  rm "$fixture/archives/$dsc"
  { printf 'X'; tail -c +2 "$1/$dsc"; } > "$fixture/archives/$dsc"
  refuses 'input digest mismatch' "$fixture/archives"
fi
echo "Custom kernel source positive controls and $cases refusal cases passed."
