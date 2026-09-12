#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
jq -r '.required | to_entries[] | "\(.key)=\(.value[0])"' "$root/kernel-config-policy.json" > "$scratch/good"
jq -r '.prohibited[] | "# \(.) is not set"' "$root/kernel-config-policy.json" >> "$scratch/good"
bash "$root/verify-kernel-config.sh" "$scratch/good" > "$scratch/positive.log"
refuse() {
  local name=$1
  shift
  cp "$scratch/good" "$scratch/$name"
  "$@" "$scratch/$name"
  if bash "$root/verify-kernel-config.sh" "$scratch/$name" > "$scratch/$name.log" 2>&1; then
    echo "unexpected kernel config acceptance: $name" >&2
    exit 1
  fi
}
enable_kexec() { awk '{ if ($0 == "# CONFIG_KEXEC is not set") print "CONFIG_KEXEC=y"; else print }' "$1" > "$1.new"; mv "$1.new" "$1"; }
remove_tdx() { grep -v '^CONFIG_INTEL_TDX_GUEST=' "$1" > "$1.new"; mv "$1.new" "$1"; }
duplicate_gve() { printf 'CONFIG_GVE=y\n' >> "$1"; }
refuse enabled-kexec enable_kexec
refuse missing-tdx remove_tdx
refuse duplicate-gve duplicate_gve
echo 'Kernel config policy: positive control and 3 negative cases passed.'
