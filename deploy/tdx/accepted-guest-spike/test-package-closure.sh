#!/usr/bin/env bash
# Linux-only mutation tests over one successfully resolved closure.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "package closure tests failed: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: test-package-closure.sh CLOSURE_DIRECTORY'
closure=$(cd -- "$1" && pwd -P) || fail 'missing closure'
lock="$closure/package-lock.json"
scratch=$(mktemp -d)
backup="$scratch/package-lock.json"
cp -- "$lock" "$backup"
package=''
package_backup=''
proof=''
proof_backup=''
cleanup() {
  cp -- "$backup" "$lock"
  if [[ -n "$package_backup" && -f "$package_backup" ]]; then cp -- "$package_backup" "$package"; fi
  if [[ -n "$proof_backup" && -f "$proof_backup" ]]; then cp -- "$proof_backup" "$proof"; fi
  rm -rf -- "$closure/packages/extra-link" "$closure/packages/extra-dir"
  rm -rf -- "$scratch"
}
trap cleanup EXIT
bash "$root/verify-package-closure.sh" "$closure" >/dev/null
refuse_lock() {
  local name=$1 filter=$2
  jq "$filter" "$backup" > "$lock"
  if bash "$root/verify-package-closure.sh" "$closure" > "$scratch/$name.log" 2>&1; then fail "unexpected acceptance: $name"; fi
  cp -- "$backup" "$lock"
}
refuse_lock changed-control '.packages[0].name = "altered-package"'
refuse_lock missing-root 'del(.packages[] | select(.name == "linux-image-6.17.0-1012-gcp"))'

first_file=$(jq -r '.packages[0].filename | split("/")[-1]' "$lock")
package="$closure/packages/$first_file"
package_backup="$scratch/package.deb"
cp -- "$package" "$package_backup"
printf 'tamper\n' >> "$package"
bytes=$(stat -c %s "$package")
digest=$(sha256sum -- "$package" | awk '{print $1}')
jq --arg file "$first_file" --arg digest "$digest" --argjson bytes "$bytes" '
  (.packages[] | select((.filename | split("/")[-1]) == $file)) |= (.sha256 = $digest | .bytes = $bytes)
' "$backup" > "$lock"
if bash "$root/verify-package-closure.sh" "$closure" > "$scratch/repaired-digest.log" 2>&1; then fail 'unexpected repaired-digest acceptance'; fi
cp -- "$package_backup" "$package"
cp -- "$backup" "$lock"
rm -f -- "$package_backup"
package_backup=''

ln -s "$first_file" "$closure/packages/extra-link"
if bash "$root/verify-package-closure.sh" "$closure" > "$scratch/extra-link.log" 2>&1; then fail 'unexpected extra-symlink acceptance'; fi
rm -f -- "$closure/packages/extra-link"
mkdir "$closure/packages/extra-dir"
if bash "$root/verify-package-closure.sh" "$closure" > "$scratch/extra-dir.log" 2>&1; then fail 'unexpected extra-directory acceptance'; fi
rmdir "$closure/packages/extra-dir"

proof="$closure/indexes/noble-main-Packages.xz"
proof_backup="$scratch/proof.xz"
cp -- "$proof" "$proof_backup"
printf 'tamper\n' >> "$proof"
if bash "$root/verify-package-closure.sh" "$closure" > "$scratch/mutated-proof.log" 2>&1; then fail 'unexpected mutated-proof acceptance'; fi
cp -- "$proof_backup" "$proof"
rm -f -- "$proof_backup"
proof_backup=''
bash "$root/verify-package-closure.sh" "$closure" >/dev/null
echo 'Package closure: positive controls and 6 tamper cases passed.'
