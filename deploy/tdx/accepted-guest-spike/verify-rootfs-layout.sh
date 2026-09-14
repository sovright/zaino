#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
input=${1:-$root/rootfs-layout.json}
fail() { echo "rootfs layout refused: $*" >&2; exit 1; }
[[ $# -le 1 && -f "$input" && ! -L "$input" ]] || fail 'usage: verify-rootfs-layout.sh [rootfs-layout.json]'
command -v jq >/dev/null || fail 'missing tool: jq'
jq -e '
  .schema == "zaino-minimal-rootfs-layout-v1" and
  .source_date_epoch == 1789084800 and
  .filesystem == {
    bytes:67108864, block_size:4096, inode_size:256, inode_count:256,
    uuid:"7d2d60d6-a70c-4be5-bd35-5bb7d420e8b8",
    directory_hash_seed:"e68f3609-930f-4683-aeb6-2f787198b299", label:"ZAINO_ROOT",
    features:"none,extents,filetype,sparse_super,large_file",
    expected_features:"filetype extent sparse_super large_file"
  } and
  .verity == {
    hash:"sha256", data_block_size:4096, hash_block_size:4096,
    salt:"74113d379d2244acc577a97b59e9b5e2a5335bd7682935300c63a00e75a2888f",
    dm_uuid:"CRYPT-VERITY-ZAINO-BOOT-SPIKE-ROOT-V1", mapping_name:"zaino-root",
    data_device:"/dev/nvme0n1p2", hash_device:"/dev/nvme0n1p3"
  } and
  .kernel_cmdline_tail == ["root=/dev/dm-0","rootfstype=ext4","ro","rdinit=/tdx-guest-init","ip=dhcp"] and
  .scope == "rootfs-and-verity-binding-only;not-init;not-UKI;not-disk;not-boot;not-TEE-admission" and
  (keys == ["filesystem","kernel_cmdline_tail","schema","scope","source_date_epoch","verity"])
' "$input" >/dev/null || fail 'unreviewed layout value'
echo 'Verified frozen minimal-rootfs and verity layout.'
