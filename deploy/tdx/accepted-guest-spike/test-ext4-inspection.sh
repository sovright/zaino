#!/usr/bin/env bash
# Exercise direct inode inspection using the selected e2fsprogs implementation.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "ext4 inspection test failed: $*" >&2; exit 1; }
for tool in debugfs mke2fs truncate; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
scratch=$(mktemp -d); trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/tree/dir"; printf fixture >"$scratch/tree/dir/file"; chmod 755 "$scratch/tree" "$scratch/tree/dir"; chmod 644 "$scratch/tree/dir/file"
truncate -s 16777216 "$scratch/base.img"
mke2fs -q -t ext4 -F -b 4096 -I 256 -N 64 -m 0 -O none,extents,filetype,sparse_super,large_file -d "$scratch/tree" "$scratch/base.img"
debugfs -w -R 'rmdir /lost+found' "$scratch/base.img" >/dev/null 2>&1
bash "$root/inspect-ext4-tree.sh" "$scratch/base.img" "$scratch/inventory"
grep -Fx 'd 0755 0 0 .' "$scratch/inventory" >/dev/null
grep -Fx 'd 0755 0 0 ./dir' "$scratch/inventory" >/dev/null
grep -Fx 'f 0644 0 0 ./dir/file' "$scratch/inventory" >/dev/null
refused() { local name=$1 command=$2 image; image="$scratch/$name.img"; cp "$scratch/base.img" "$image"; debugfs -w -R "$command" "$image" >/dev/null 2>&1; if bash "$root/inspect-ext4-tree.sh" "$image" "$scratch/$name.inventory" >/dev/null 2>&1; then fail "$name mutation accepted"; fi; }
refused set-id 'set_inode_field /dir/file mode 0104644'
refused symlink 'symlink /link /dir/file'
refused device 'mknod /device c 1 3'
refused xattr 'ea_set /dir/file user.test bad'
echo 'Direct ext4 inode inspection accepted the closed tree and refused mode, type, and xattr mutations.'
