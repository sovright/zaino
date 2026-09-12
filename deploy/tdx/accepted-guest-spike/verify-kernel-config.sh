#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
policy="$root/kernel-config-policy.json"
fail() { echo "kernel config refused: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: verify-kernel-config.sh CONFIG_FILE'
config=$1
[[ -f "$config" && ! -L "$config" ]] || fail 'config is not a regular file'
bytes=$(wc -c < "$config" | tr -d ' ')
[[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -le 2097152 ]] || fail 'config byte budget'
jq -e '
  .schema == "zaino-boot-spike-kernel-config-policy-v1" and
  (.required | type == "object" and length > 0 and all(keys[]; test("^CONFIG_[A-Z0-9_]+$"))) and
  (.required | all(.[]; length > 0 and all(.[]; . == "y" or . == "m"))) and
  (.prohibited | length > 0 and length == (unique | length) and all(.[]; test("^CONFIG_[A-Z0-9_]+$"))) and
  ([.required | keys[]] - .prohibited | length) == (.required | length) and
  .scope == "static-config-policy-only;halt-fixes-runtime-device-and-image-admission-unverified"
' "$policy" >/dev/null || fail 'invalid policy'
while IFS=$'\t' read -r name accepted; do
  count=$(awk -v name="$name" '$0 ~ ("^" name "=") || $0 == ("# " name " is not set") { n++ } END { print n+0 }' "$config")
  [[ "$count" == 1 ]] || fail "missing or duplicate setting: $name"
  value=$(awk -F= -v name="$name" '$1 == name { print $2 }' "$config")
  [[ -n "$value" && ",$accepted," == *",$value,"* ]] || fail "required setting: $name"
done < <(jq -r '.required | to_entries[] | [.key, (.value | join(","))] | @tsv' "$policy")
while IFS= read -r name; do
  count=$(awk -v name="$name" '$0 ~ ("^" name "=") || $0 == ("# " name " is not set") { n++ } END { print n+0 }' "$config")
  [[ "$count" == 1 ]] || fail "missing or duplicate prohibition: $name"
  grep -Fqx "# $name is not set" "$config" || fail "prohibited setting enabled: $name"
done < <(jq -r '.prohibited[]' "$policy")
echo 'Verified static kernel config policy. Halt fixes, runtime devices, and image admission remain unverified.'
