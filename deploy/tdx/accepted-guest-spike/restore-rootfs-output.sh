#!/usr/bin/env bash
# Restore the fixed, closed rootfs output mode policy into a new owned directory.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "rootfs output restore refused: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: ZIP_OUTPUT NEW_RESTORED_OUTPUT'
source=$(cd -- "$1" && pwd -P); destination=$2
[[ ! -e "$destination" ]] || fail 'destination exists'
expected=$(printf '%s\n' build-run.json cmdline.txt init-bindings.env OUTPUT-SHA256SUMS rootfs-files.txt rootfs.img rootfs.verity rootfs-tool-versions.txt root-hash.txt | sort)
[[ $(find "$source" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == "$expected" ]] || fail 'unexpected source path'
[[ $(find "$source" -mindepth 1 -maxdepth 1 -type f | wc -l) == 9 ]] || fail 'nonregular source path'
for file in build-run.json cmdline.txt init-bindings.env OUTPUT-SHA256SUMS rootfs-files.txt rootfs-tool-versions.txt root-hash.txt; do [[ $(stat -c %s "$source/$file") -le 65536 ]] || fail "oversized source metadata: $file"; done
manifest=$(awk 'NF==2 && $1 ~ /^[0-9a-f]{64}$/ && $2 ~ /^\.\/[A-Za-z0-9+._-]+$/ {print $2; next} {bad=1} END {if(bad) exit 1}' "$source/OUTPUT-SHA256SUMS" | sort) || fail 'unsafe source manifest'
[[ "$manifest" == $(printf '%s\n' ./build-run.json ./cmdline.txt ./init-bindings.env ./rootfs-files.txt ./rootfs.img ./rootfs.verity ./rootfs-tool-versions.txt ./root-hash.txt | sort) ]] || fail 'source manifest file set mismatch'
layout="$root/rootfs-layout.json"; bytes=$(jq -r .filesystem.bytes "$layout"); data_bs=$(jq -r .verity.data_block_size "$layout"); hash_bs=$(jq -r .verity.hash_block_size "$layout"); level_blocks=$((bytes / data_bs)); hashes_per_block=$((hash_bs / 32)); hash_blocks=0
while (( level_blocks > 1 )); do level_blocks=$(((level_blocks + hashes_per_block - 1) / hashes_per_block)); hash_blocks=$((hash_blocks + level_blocks)); done
[[ $(stat -c %s "$source/rootfs.img") == "$bytes" && $(stat -c %s "$source/rootfs.verity") == $((hash_blocks * hash_bs)) ]] || fail 'source image geometry'
(cd "$source" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'source checksum mismatch'
mkdir -m 700 "$destination"
while IFS= read -r name; do install -m 644 "$source/$name" "$destination/$name"; done < <(printf '%s\n' build-run.json cmdline.txt init-bindings.env OUTPUT-SHA256SUMS rootfs-files.txt rootfs-tool-versions.txt root-hash.txt)
install -m 600 "$source/rootfs.img" "$source/rootfs.verity" "$destination/"
(cd "$destination" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'restored checksum mismatch'
