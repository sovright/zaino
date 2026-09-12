#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
cp -- "$root/custom-kernel.config" "$temporary/effective.config"
printf '%s\n' 'CONFIG_TSM_REPORTS=y' >> "$temporary/effective.config"
printf '%s\n' 'CONFIG_SYSCTL=y' >> "$temporary/effective.config"
bash "$root/verify-custom-kernel-effective-config.sh" "$temporary/effective.config" >/dev/null
cp -- "$temporary/effective.config" "$temporary/mutated.config"
awk '{ if ($0 == "CONFIG_NR_CPUS=4") print "CONFIG_NR_CPUS=8"; else print }' "$temporary/mutated.config" > "$temporary/changed"
mv -- "$temporary/changed" "$temporary/mutated.config"
if bash "$root/verify-custom-kernel-effective-config.sh" "$temporary/mutated.config" >/dev/null 2>&1; then
  echo 'mutated requested value was accepted' >&2; exit 1
fi
awk '{ if ($0 == "# CONFIG_MODULES is not set") print "CONFIG_MODULES=y"; else print }' "$temporary/effective.config" > "$temporary/enabled-disabled.config"
if bash "$root/verify-custom-kernel-effective-config.sh" "$temporary/enabled-disabled.config" >/dev/null 2>&1; then
  echo 'enabled requested-disabled value was accepted' >&2; exit 1
fi
cp -- "$temporary/effective.config" "$temporary/duplicate-effective.config"
printf '%s\n' 'CONFIG_GVE=y' >> "$temporary/duplicate-effective.config"
if bash "$root/verify-custom-kernel-effective-config.sh" --requested-only "$temporary/duplicate-effective.config" >/dev/null 2>&1; then
  echo 'duplicate effective value was accepted in requested-only mode' >&2; exit 1
fi
cp -- "$root/custom-kernel.config" "$temporary/conflicting-fragment.config"
printf '%s\n' '# CONFIG_GVE is not set' >> "$temporary/conflicting-fragment.config"
if bash "$root/verify-custom-kernel-effective-config.sh" --requested-only "$temporary/effective.config" "$temporary/conflicting-fragment.config" >/dev/null 2>&1; then
  echo 'conflicting requested value was accepted in requested-only mode' >&2; exit 1
fi
diagnostic=$(bash "$root/build-custom-kernel-once.sh" /missing /missing "$root/custom-kernel.config" invalid "$temporary/output" 2>&1) && {
  echo 'invalid run label or missing inputs were accepted' >&2; exit 1
}
[[ "$diagnostic" == 'custom kernel build refused: invalid run label' ]] || { echo 'invalid-label refusal was not reached' >&2; exit 1; }
echo 'custom kernel build front-door tests passed (no full kernel allocation performed)'
