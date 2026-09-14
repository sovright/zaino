#!/usr/bin/env bash
# Exercise independent output verification against repaired candidate metadata.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "rootfs output test failed: $*" >&2; exit 1; }
[[ $# == 4 ]] || fail 'usage: test-rootfs-output.sh GOOD_OUTPUT WORKLOAD EXPECTATIONS TOOL_CLOSURE'
good=$1 workload=$2 expectations=$3 closure=$4
bash "$root/verify-rootfs-output.sh" "$good" "$workload" "$expectations" "$closure" >/dev/null
scratch=$(mktemp -d); trap 'rm -rf -- "$scratch"' EXIT
layout="$root/rootfs-layout.json"

checksums() {
  (cd "$1" && find . -type f ! -name OUTPUT-SHA256SUMS -print | sort | while read -r file; do
    digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"
  done) > "$1/OUTPUT-SHA256SUMS"
}
reseal() {
  local candidate=$1 refresh_inventory=${2:-true} bytes data_bs hash_bs data_blocks hashes_per_block level_blocks hash_blocks root_hash algorithm
  bytes=$(jq -r .filesystem.bytes "$layout"); data_bs=$(jq -r .verity.data_block_size "$layout"); hash_bs=$(jq -r .verity.hash_block_size "$layout")
  data_blocks=$((bytes / data_bs)); hashes_per_block=$((hash_bs / 32)); level_blocks=$data_blocks; hash_blocks=0
  while (( level_blocks > 1 )); do level_blocks=$(((level_blocks + hashes_per_block - 1) / hashes_per_block)); hash_blocks=$((hash_blocks + level_blocks)); done
  truncate -s $((hash_blocks * hash_bs)) "$candidate/rootfs.verity"
  algorithm=$(jq -r .verity.hash "$layout")
  root_hash=$(veritysetup format --no-superblock --hash "$algorithm" --data-block-size "$data_bs" --hash-block-size "$hash_bs" --salt "$(jq -r .verity.salt "$layout")" "$candidate/rootfs.img" "$candidate/rootfs.verity" | awk '/^Root hash:/ {print $3}')
  printf '%s\n' "$root_hash" > "$candidate/root-hash.txt"
  local sectors dm_uuid mapping data_device hash_device table tail cmdline_sha
  sectors=$((bytes / 512)); dm_uuid=$(jq -r .verity.dm_uuid "$layout"); mapping=$(jq -r .verity.mapping_name "$layout")
  data_device=$(jq -r .verity.data_device "$layout"); hash_device=$(jq -r .verity.hash_device "$layout")
  table="0 $sectors verity 1 $data_device $hash_device $data_bs $hash_bs $data_blocks 0 $algorithm $root_hash $(jq -r .verity.salt "$layout") 1 panic_on_corruption"
  tail=$(jq -r '.kernel_cmdline_tail | join(" ")' "$layout")
  printf 'dm-mod.create="%s,%s,0,ro,%s" %s\n' "$mapping" "$dm_uuid" "$table" "$tail" > "$candidate/cmdline.txt"
  cmdline_sha=$(sha256sum "$candidate/cmdline.txt" | awk '{print $1}')
  printf 'ZAINO_EXPECTED_ROOT_BYTES=%s\nZAINO_EXPECTED_DM_UUID=%s\nZAINO_EXPECTED_CMDLINE_SHA256=%s\n' "$bytes" "$dm_uuid" "$cmdline_sha" > "$candidate/init-bindings.env"
  if [[ "$refresh_inventory" == true ]]; then rm -f "$candidate/rootfs-files.txt"; bash "$root/inspect-ext4-tree.sh" "$candidate/rootfs.img" "$candidate/rootfs-files.txt"; fi
  checksums "$candidate"
}
refused() {
  local name=$1 candidate="$scratch/$1"; shift
  cp -a "$good" "$candidate"; "$@" "$candidate"; reseal "$candidate"
  if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >/dev/null 2>&1; then fail "$name mutation accepted"; fi
}
refused_metadata() {
  local name=$1 candidate="$scratch/$1"; shift
  cp -a "$good" "$candidate"; "$@" "$candidate"; reseal "$candidate" false
  if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >"$scratch/$name.log" 2>&1; then fail "$name mutation accepted"; fi
  grep -Eq 'ext4 inspection refused: (unsupported inode type|set-id inode|world-writable file|extended inode metadata)' "$scratch/$name.log" || fail "$name refused for an unexpected reason"
}
debugfs_mutation() { local candidate=$1 command=$2; debugfs -w -R "$command" "$candidate/rootfs.img" >/dev/null 2>&1; }
extra_file() { printf bad > "$scratch/payload"; debugfs_mutation "$1" "write $scratch/payload /extra"; }
forbidden_executable() { extra_file "$1"; debugfs_mutation "$1" "set_inode_field /extra mode 0100755"; }
set_id() { debugfs_mutation "$1" "set_inode_field /usr/lib/zaino/tdx-evidence-agent mode 0104755"; }
writable() { debugfs_mutation "$1" "set_inode_field /usr/lib/zaino/tdx-evidence-agent mode 0100777"; }
symlink_path() { debugfs_mutation "$1" "symlink /bad-link /usr/lib/zaino/tdx-evidence-agent"; }
device_path() { debugfs_mutation "$1" "mknod /bad-device c 1 3"; }
xattr_path() { debugfs_mutation "$1" "ea_set /usr/lib/zaino/tdx-evidence-agent user.test bad"; }
refused extra-file extra_file
refused forbidden-executable forbidden_executable
refused_metadata set-id set_id
refused_metadata writable-path writable
refused_metadata symlink symlink_path
refused_metadata device device_path
refused_metadata xattr xattr_path

candidate="$scratch/content"; cp -a "$good" "$candidate"
block=$(debugfs -R 'blocks /usr/lib/zaino/tdx-evidence-agent' "$candidate/rootfs.img" 2>/dev/null | awk '{print $1; exit}')
[[ "$block" =~ ^[0-9]+$ ]] || fail 'could not locate agent data block'
printf X | dd of="$candidate/rootfs.img" bs=1 seek=$((block * 4096)) conv=notrunc status=none
reseal "$candidate"
if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >"$scratch/content.log" 2>&1; then fail 'same-length repaired content mutation accepted'; fi
grep -F 'filesystem content mismatch: usr/lib/zaino/tdx-evidence-agent' "$scratch/content.log" >/dev/null || fail 'content mutation refused for an unexpected reason'

candidate="$scratch/cmdline"; cp -a "$good" "$candidate"; printf ' changed\n' >> "$candidate/cmdline.txt"
cmdline_sha=$(sha256sum "$candidate/cmdline.txt" | awk '{print $1}'); sed -i "s/^ZAINO_EXPECTED_CMDLINE_SHA256=.*/ZAINO_EXPECTED_CMDLINE_SHA256=$cmdline_sha/" "$candidate/init-bindings.env"; checksums "$candidate"
if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >/dev/null 2>&1; then fail 'repaired cmdline manifest accepted'; fi
candidate="$scratch/receipt"; cp -a "$good" "$candidate"; jq '.network_during_build="enabled"' "$candidate/build-run.json" >"$candidate/build-run.new"; mv "$candidate/build-run.new" "$candidate/build-run.json"; checksums "$candidate"
if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >/dev/null 2>&1; then fail 'repaired build receipt accepted'; fi
for kind in data hash; do candidate="$scratch/corrupt-$kind"; cp -a "$good" "$candidate"; target=rootfs.img; [[ $kind == hash ]] && target=rootfs.verity; printf X | dd of="$candidate/$target" bs=1 seek=4096 conv=notrunc status=none; checksums "$candidate"; if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >/dev/null 2>&1; then fail "$kind corruption accepted"; fi; done
candidate="$scratch/appended-hash"; cp -a "$good" "$candidate"; printf X >> "$candidate/rootfs.verity"; checksums "$candidate"
if bash "$root/verify-rootfs-output.sh" "$candidate" "$workload" "$expectations" "$closure" >/dev/null 2>&1; then fail 'appended verity bytes accepted'; fi
echo 'Rootfs verifier refused repaired-manifest content/mode/type mutations and verity corruption.'
