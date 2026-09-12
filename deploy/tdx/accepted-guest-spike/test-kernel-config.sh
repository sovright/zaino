#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
jq -r '.required | to_entries[] | "\(.key)=\(.value[0])"' "$root/kernel-config-policy.json" > "$scratch/good"
jq -r '.prohibited[] | "# \(.) is not set"' "$root/kernel-config-policy.json" >> "$scratch/good"
bash "$root/verify-kernel-config.sh" "$scratch/good" > "$scratch/positive.log"
grep -v '^# CONFIG_HIBERNATION is not set$' "$scratch/good" > "$scratch/hidden-absent"
bash "$root/verify-kernel-config.sh" "$scratch/hidden-absent" > "$scratch/hidden-absent.log"
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
enable_setting() {
  local file=$1 symbol=$2
  awk -v symbol="$symbol" '{ if ($0 == "# " symbol " is not set") print symbol "=y"; else print }' "$file" > "$file.new"
  mv "$file.new" "$file"
}
enable_kexec() { enable_setting "$1" CONFIG_KEXEC; }
enable_debug_fs() { enable_setting "$1" CONFIG_DEBUG_FS; }
enable_ftrace() { enable_setting "$1" CONFIG_FTRACE; }
enable_kgdb() { enable_setting "$1" CONFIG_KGDB; }
enable_kprobes() { enable_setting "$1" CONFIG_KPROBES; }
remove_tdx() { grep -v '^CONFIG_INTEL_TDX_GUEST=' "$1" > "$1.new"; mv "$1.new" "$1"; }
duplicate_gve() { printf 'CONFIG_GVE=y\n' >> "$1"; }
conflict_gve() { printf '# CONFIG_GVE is not set\n' >> "$1"; }
remove_visible_prohibition() { grep -v '^# CONFIG_KEXEC is not set$' "$1" > "$1.new"; mv "$1.new" "$1"; }
refuse enabled-kexec enable_kexec
refuse enabled-debug-fs enable_debug_fs
refuse enabled-ftrace enable_ftrace
refuse enabled-kgdb enable_kgdb
refuse enabled-kprobes enable_kprobes
refuse missing-tdx remove_tdx
refuse duplicate-gve duplicate_gve
refuse conflicting-gve conflict_gve
refuse missing-visible-prohibition remove_visible_prohibition
echo 'Kernel config policy: 2 positive controls and 9 negative cases passed.'
