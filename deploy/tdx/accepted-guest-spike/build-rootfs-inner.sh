#!/usr/bin/env bash
# Assemble the only guest root and its dm-verity tree inside the pinned builder.
set -euo pipefail
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1789084800 E2FSPROGS_FAKE_TIME=1789084800
fail() { echo "rootfs build refused: $*" >&2; exit 1; }
[[ $# == 7 ]] || fail 'internal usage: WORKLOAD EXPECTATIONS REPO EXPECTED_PACKAGES LAYOUT OUTPUT OWNER'
workload=$1 expectations=$2 repository=$3 expected_packages=$4 layout=$5 output=$6 owner=$7
[[ "$owner" =~ ^[0-9]+:[0-9]+$ && ! -e "$output" ]] || fail 'invalid output contract'
mkdir -m 700 -- "$output"
handoff() { local status=$?; trap - EXIT; chown -R -h -- "$owner" "$output" || { [[ $status != 0 ]] || status=1; }; exit "$status"; }
trap handoff EXIT
bash /builder/install-packages.sh "$repository" "$expected_packages" /tmp/zaino-rootfs-apt
bash /builder/verify-workload.sh "$workload" "$expectations" >/dev/null
bash /builder/verify-layout.sh "$layout" >/dev/null
for tool in dd debugfs e2fsck find jq mke2fs sha256sum stat tune2fs veritysetup; do command -v "$tool" >/dev/null || fail "missing pinned tool: $tool"; done

stage=/tmp/rootfs-stage
mkdir -m 755 -- "$stage"
bash /builder/stage-rootfs.sh "$workload" "$stage"

bytes=$(jq -r .filesystem.bytes "$layout"); block_size=$(jq -r .filesystem.block_size "$layout")
inode_size=$(jq -r .filesystem.inode_size "$layout"); inode_count=$(jq -r .filesystem.inode_count "$layout")
fs_uuid=$(jq -r .filesystem.uuid "$layout"); hash_seed=$(jq -r .filesystem.directory_hash_seed "$layout")
label=$(jq -r .filesystem.label "$layout"); features=$(jq -r .filesystem.features "$layout")
[[ $((bytes % block_size)) == 0 ]] || fail 'unaligned filesystem geometry'
dd if=/dev/zero of="$output/rootfs.img" bs="$block_size" count=$((bytes / block_size)) status=none
mke2fs -q -t ext4 -F -b "$block_size" -I "$inode_size" -N "$inode_count" -m 0 -U "$fs_uuid" -L "$label" \
  -O "$features" -E "root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0,hash_seed=$hash_seed" -d "$stage" "$output/rootfs.img"
debugfs -w -R 'rmdir /lost+found' "$output/rootfs.img" >/dev/null 2>&1 || fail 'could not remove default lost+found'
e2fsck -fn "$output/rootfs.img" >/dev/null
[[ $(tune2fs -l "$output/rootfs.img" | awk -F': *' '/Filesystem UUID:/ {print $2}') == "$fs_uuid" ]] || fail 'filesystem UUID mismatch'
[[ $(tune2fs -l "$output/rootfs.img" | awk -F': *' '/Directory Hash Seed:/ {print $2}') == "$hash_seed" ]] || fail 'directory hash seed mismatch'
[[ $(stat -c %s "$output/rootfs.img") == "$bytes" ]] || fail 'filesystem byte geometry mismatch'
expected_features=$(jq -r .filesystem.expected_features "$layout")
actual_features=$(tune2fs -l "$output/rootfs.img" | awk -F': *' '/Filesystem features:/ {print $2}')
[[ "$actual_features" == "$expected_features" ]] || fail 'filesystem feature mismatch'
bash /builder/inspect-ext4.sh "$output/rootfs.img" "$output/rootfs-files.txt"

algorithm=$(jq -r .verity.hash "$layout"); data_bs=$(jq -r .verity.data_block_size "$layout"); hash_bs=$(jq -r .verity.hash_block_size "$layout")
salt=$(jq -r .verity.salt "$layout"); data_blocks=$((bytes / data_bs)); hashes_per_block=$((hash_bs / 32)); level_blocks=$data_blocks; hash_blocks=0
while (( level_blocks > 1 )); do level_blocks=$(((level_blocks + hashes_per_block - 1) / hashes_per_block)); hash_blocks=$((hash_blocks + level_blocks)); done
(( hash_blocks > 0 )) || fail 'invalid verity geometry'
dd if=/dev/zero of="$output/rootfs.verity" bs="$hash_bs" count="$hash_blocks" status=none
format_output=$(veritysetup format --no-superblock --hash "$algorithm" --data-block-size "$data_bs" --hash-block-size "$hash_bs" --salt "$salt" "$output/rootfs.img" "$output/rootfs.verity")
root_hash=$(printf '%s\n' "$format_output" | awk '/^Root hash:/ {print $3}')
[[ "$root_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'missing verity root hash'
veritysetup verify --no-superblock --hash "$algorithm" --data-block-size "$data_bs" --hash-block-size "$hash_bs" --salt "$salt" "$output/rootfs.img" "$output/rootfs.verity" "$root_hash"
[[ $(stat -c %s "$output/rootfs.verity") == $((hash_blocks * hash_bs)) ]] || fail 'verity byte geometry mismatch'
printf '%s\n' "$root_hash" > "$output/root-hash.txt"

sectors=$((bytes / 512)); dm_uuid=$(jq -r .verity.dm_uuid "$layout"); mapping=$(jq -r .verity.mapping_name "$layout")
data_device=$(jq -r .verity.data_device "$layout"); hash_device=$(jq -r .verity.hash_device "$layout")
table="0 $sectors verity 1 $data_device $hash_device $data_bs $hash_bs $data_blocks 0 $algorithm $root_hash $salt 1 panic_on_corruption"
tail=$(jq -r '.kernel_cmdline_tail | join(" ")' "$layout")
printf 'dm-mod.create="%s,%s,0,ro,%s" %s\n' "$mapping" "$dm_uuid" "$table" "$tail" > "$output/cmdline.txt"
# The final static init must hash the same newline-terminated bytes read from /proc/cmdline.
cmdline_sha=$(sha256sum "$output/cmdline.txt" | awk '{print $1}')
printf 'ZAINO_EXPECTED_ROOT_BYTES=%s\nZAINO_EXPECTED_DM_UUID=%s\nZAINO_EXPECTED_CMDLINE_SHA256=%s\n' "$bytes" "$dm_uuid" "$cmdline_sha" > "$output/init-bindings.env"
printf 'mke2fs=%s\nveritysetup=%s\n' "$(mke2fs -V 2>&1 | awk 'NR==1 {print $2}')" "$(veritysetup --version)" > "$output/rootfs-tool-versions.txt"
chmod 600 "$output/rootfs.img" "$output/rootfs.verity"
chmod 644 "$output/root-hash.txt" "$output/cmdline.txt" "$output/init-bindings.env" "$output/rootfs-files.txt" "$output/rootfs-tool-versions.txt"
rm -rf -- "$stage"
