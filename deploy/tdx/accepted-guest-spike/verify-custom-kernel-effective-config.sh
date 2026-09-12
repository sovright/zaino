#!/usr/bin/env bash
# Verify that Kconfig retained every requested value and the accepted policy.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "custom kernel effective config refused: $*" >&2; exit 1; }
requested_only=false
if [[ ${1:-} == --requested-only ]]; then requested_only=true; shift; fi
[[ $# -ge 1 && $# -le 2 ]] || fail 'usage: verify-custom-kernel-effective-config.sh [--requested-only] EFFECTIVE_CONFIG [REQUESTED_FRAGMENT]'
effective=$1
fragment=${2:-$root/custom-kernel.config}
for file in "$effective" "$fragment"; do
  [[ -f "$file" && ! -L "$file" ]] || fail 'missing regular config input'
  [[ $(wc -c < "$file") -le 4194304 ]] || fail 'config input exceeds cap'
done
mismatches=0
while IFS= read -r requested; do
  if [[ "$requested" =~ ^CONFIG_[A-Z0-9_]+= || "$requested" =~ ^#[[:space:]]CONFIG_[A-Z0-9_]+[[:space:]]is[[:space:]]not[[:space:]]set$ ]]; then
    if ! grep -Fqx -- "$requested" "$effective"; then
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
