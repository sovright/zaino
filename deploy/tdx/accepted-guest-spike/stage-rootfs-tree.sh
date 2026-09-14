#!/usr/bin/env bash
# Reconstruct the reviewed guest file tree without executing guest content.
set -euo pipefail
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1789084800
fail() { echo "rootfs staging refused: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'internal usage: WORKLOAD EMPTY_STAGE'
workload=$1 stage=$2
[[ -d "$workload" && -d "$stage" && -z $(find "$stage" -mindepth 1 -print -quit) ]] || fail 'invalid staging roots'
mkdir -m 755 -- "$stage/dev" "$stage/proc" "$stage/sys" "$stage/sys/kernel" "$stage/sys/kernel/config" "$stage/run" "$stage/tmp" "$stage/usr" "$stage/usr/lib" "$stage/usr/lib/zaino"
install -m 755 -- "$workload/artifacts/tdx-evidence-agent" "$stage/usr/lib/zaino/tdx-evidence-agent"
while IFS= read -r source; do
  relative=${source#"$workload/runtime-libs"}
  [[ "$relative" == /* && "$relative" != *..* ]] || fail 'unsafe runtime path'
  install -d -m 755 -- "$stage$(dirname -- "$relative")"
  mode=$(stat -c %a "$source"); [[ "$mode" == 644 || "$mode" == 755 ]] || fail 'unsafe runtime mode'
  install -m "$mode" -- "$source" "$stage$relative"
done < <(find "$workload/runtime-libs" -type f -print | sort)
chmod 1777 "$stage/tmp"
find "$stage" -xdev -exec chown -h 0:0 {} +
find "$stage" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
if find "$stage" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then fail 'special staged path'; fi
if find "$stage" -xdev -type f -perm /6000 -print -quit | grep -q .; then fail 'set-id staged file'; fi
