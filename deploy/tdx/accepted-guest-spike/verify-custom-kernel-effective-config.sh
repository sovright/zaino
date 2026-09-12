#!/usr/bin/env bash
# Verify that Kconfig retained every requested value and the accepted policy.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=kernel-config-common.sh
source "$root/kernel-config-common.sh"
fail() { echo "custom kernel effective config refused: $*" >&2; exit 1; }
allows_hidden_absence() {
  case "$1" in
    CONFIG_KEXEC_CORE|CONFIG_HIBERNATION|CONFIG_PM_SLEEP|CONFIG_PROC_VMCORE|CONFIG_NETCONSOLE|CONFIG_DEBUG_INFO|CONFIG_KGDB|CONFIG_RUST) return 0 ;;
    *) return 1 ;;
  esac
}
requested_only=false
if [[ ${1:-} == --requested-only ]]; then requested_only=true; shift; fi
[[ $# -ge 1 && $# -le 2 ]] || fail 'usage: verify-custom-kernel-effective-config.sh [--requested-only] EFFECTIVE_CONFIG [REQUESTED_FRAGMENT]'
effective=$1
fragment=${2:-$root/custom-kernel.config}
for file in "$effective" "$fragment"; do
  [[ -f "$file" && ! -L "$file" ]] || fail 'missing regular config input'
  [[ $(wc -c < "$file") -le 4194304 ]] || fail 'config input exceeds cap'
done
refuse_duplicate_kernel_config_symbols "$effective" || fail 'duplicate or conflicting config assignments'
refuse_duplicate_kernel_config_symbols "$fragment" || fail 'duplicate or conflicting config assignments'
mismatches=0
while IFS= read -r requested; do
  if [[ "$requested" =~ ^CONFIG_[A-Z0-9_]+= || "$requested" =~ ^#[[:space:]]CONFIG_[A-Z0-9_]+[[:space:]]is[[:space:]]not[[:space:]]set$ ]]; then
    symbol=${requested#\# }; symbol=${symbol%%[= ]*}
    if grep -Fqx -- "$requested" "$effective"; then
      :
    elif [[ "$requested" == '# '* ]] && ! grep -Eq "^${symbol}=" "$effective" && allows_hidden_absence "$symbol"; then
      :
    else
      echo "custom kernel effective config mismatch: $requested" >&2
      mismatches=$((mismatches + 1))
    fi
  fi
done < "$fragment"
[[ $mismatches == 0 ]] || fail "$mismatches requested settings did not survive"
if [[ $requested_only == true ]]; then
  echo 'Verified requested values in the effective custom-kernel config; static policy not evaluated in this mode.'
else
  bash "$root/verify-kernel-config.sh" "$effective" >/dev/null
  echo 'Verified requested values in the effective custom-kernel config and applied the static policy.'
fi
