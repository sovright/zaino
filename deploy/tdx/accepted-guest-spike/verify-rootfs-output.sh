#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "rootfs output refused: $*" >&2; exit 1; }
[[ $# == 4 ]] || fail 'usage: verify-rootfs-output.sh OUTPUT WORKLOAD TRUSTED_EXPECTATIONS TOOL_CLOSURE'
output=$(cd -- "$1" && pwd -P) || fail 'missing output'
workload=$(cd -- "$2" && pwd -P) || fail 'missing workload'
expectations=$(cd -- "$(dirname -- "$3")" && pwd -P)/$(basename -- "$3")
closure=$(cd -- "$4" && pwd -P) || fail 'missing closure'
for tool in cmp debugfs e2fsck find git jq sha256sum stat tune2fs veritysetup; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
bash "$root/verify-rootfs-layout.sh" >/dev/null
bash "$root/verify-workload-output.sh" "$workload" "$expectations" >/dev/null
bash "$root/verify-package-closure.sh" "$closure" "$root/rootfs-tool-roots.json" >/dev/null
expected=$(printf '%s\n' build-run.json cmdline.txt init-bindings.env OUTPUT-SHA256SUMS rootfs-files.txt rootfs.img rootfs.verity rootfs-tool-versions.txt root-hash.txt | sort)
[[ $(find "$output" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == "$expected" ]] || fail 'unexpected output path'
if find "$output" -xdev ! -type d ! -type f -print -quit | grep -q .; then fail 'special output path'; fi
(cd "$output" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'output checksum mismatch'
[[ $(awk '{print $2}' "$output/OUTPUT-SHA256SUMS" | sort) == $(find "$output" -type f ! -name OUTPUT-SHA256SUMS -printf './%P\n' | sort) ]] || fail 'manifest file set mismatch'

layout="$root/rootfs-layout.json"; bytes=$(jq -r .filesystem.bytes "$layout"); block_size=$(jq -r .filesystem.block_size "$layout")
inode_size=$(jq -r .filesystem.inode_size "$layout"); inode_count=$(jq -r .filesystem.inode_count "$layout")
fs_uuid=$(jq -r .filesystem.uuid "$layout"); hash_seed=$(jq -r .filesystem.directory_hash_seed "$layout"); label=$(jq -r .filesystem.label "$layout")
expected_features=$(jq -r .filesystem.expected_features "$layout")
[[ $(stat -c %s "$output/rootfs.img") == "$bytes" && $(stat -c %a "$output/rootfs.img") == 600 && $(stat -c %a "$output/rootfs.verity") == 600 ]] || fail 'image geometry or mode'
super=$(tune2fs -l "$output/rootfs.img")
field() { awk -F': *' -v key="$1" '$1 == key {print $2}' <<<"$super"; }
[[ $(field 'Filesystem UUID') == "$fs_uuid" && $(field 'Directory Hash Seed') == "$hash_seed" && $(field 'Filesystem volume name') == "$label" ]] || fail 'filesystem identity'
[[ $(field 'Block count') == $((bytes / block_size)) && $(field 'Block size') == "$block_size" ]] || fail 'filesystem block geometry'
[[ $(field 'Inode count') == "$inode_count" && $(field 'Inode size') == "$inode_size" ]] || fail 'filesystem inode geometry'
[[ $(field 'Filesystem features') == "$expected_features" ]] || fail 'filesystem features'
e2fsck -fn "$output/rootfs.img" >/dev/null || fail 'filesystem check'

inspection=$(mktemp -d); trap 'rm -rf -- "$inspection"' EXIT
mkdir -m 755 "$inspection/expected" "$inspection/actual"
bash "$root/stage-rootfs-tree.sh" "$workload" "$inspection/expected"
bash "$root/inspect-ext4-tree.sh" "$output/rootfs.img" "$inspection/image-inventory"
expected_inventory() {
  local tree=$1 entry relative
  while IFS= read -r entry; do relative=${entry#"$tree"}; relative=.${relative:-}; printf '%s %04o %s %s %s\n' "$(stat -c %F "$entry" | awk '{print ($0=="directory" ? "d" : $0=="regular file" ? "f" : "?")}')" "$((8#$(stat -c %a "$entry")))" "$(stat -c %u "$entry")" "$(stat -c %g "$entry")" "$relative"; done < <(find "$tree" -print | sort)
}
expected_inventory "$inspection/expected" | sort >"$inspection/expected-inventory"
cmp -s "$inspection/image-inventory" "$inspection/expected-inventory" || fail 'filesystem path, type, mode, ownership, or extended metadata mismatch'
cmp -s "$output/rootfs-files.txt" "$inspection/expected-inventory" || fail 'rootfs inventory mismatch'
while IFS= read -r source; do
  relative=${source#"$inspection/expected/"}; destination="$inspection/actual/$relative"; mkdir -p "$(dirname "$destination")"
  stderr="$inspection/dump-stderr"; debugfs -R "dump -p /$relative $destination" "$output/rootfs.img" >/dev/null 2>"$stderr" || fail "filesystem extraction: $relative"
  sed '/^debugfs [0-9]/d' "$stderr" >"$inspection/dump-errors"; [[ ! -s "$inspection/dump-errors" ]] || fail "filesystem extraction diagnostics: $relative"
  cmp -s "$source" "$destination" || fail "filesystem content mismatch: $relative"
done < <(find "$inspection/expected" -type f -print | sort)

root_hash=$(cat "$output/root-hash.txt"); [[ "$root_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'root hash framing'
algorithm=$(jq -r .verity.hash "$layout"); data_bs=$(jq -r .verity.data_block_size "$layout"); hash_bs=$(jq -r .verity.hash_block_size "$layout"); salt=$(jq -r .verity.salt "$layout")
data_blocks=$((bytes / data_bs)); hashes_per_block=$((hash_bs / 32)); level_blocks=$data_blocks; hash_blocks=0
while (( level_blocks > 1 )); do level_blocks=$(((level_blocks + hashes_per_block - 1) / hashes_per_block)); hash_blocks=$((hash_blocks + level_blocks)); done
[[ $(stat -c %s "$output/rootfs.verity") == $((hash_blocks * hash_bs)) ]] || fail 'verity byte geometry'
veritysetup verify --no-superblock --hash "$algorithm" --data-block-size "$data_bs" --hash-block-size "$hash_bs" --salt "$salt" "$output/rootfs.img" "$output/rootfs.verity" "$root_hash" || fail 'verity verification'

sectors=$((bytes / 512)); dm_uuid=$(jq -r .verity.dm_uuid "$layout"); mapping=$(jq -r .verity.mapping_name "$layout")
data_device=$(jq -r .verity.data_device "$layout"); hash_device=$(jq -r .verity.hash_device "$layout")
table="0 $sectors verity 1 $data_device $hash_device $data_bs $hash_bs $data_blocks 0 $algorithm $root_hash $salt 1 panic_on_corruption"
tail=$(jq -r '.kernel_cmdline_tail | join(" ")' "$layout")
printf 'dm-mod.create="%s,%s,0,ro,%s" %s\n' "$mapping" "$dm_uuid" "$table" "$tail" >"$inspection/expected-cmdline.txt"
# Keep the build artifact byte-for-byte aligned with the final init's newline-terminated /proc/cmdline read.
cmp -s "$output/cmdline.txt" "$inspection/expected-cmdline.txt" || fail 'kernel command line mismatch'
cmdline_sha=$(sha256sum "$inspection/expected-cmdline.txt" | awk '{print $1}')
expected_bindings=$(printf 'ZAINO_EXPECTED_ROOT_BYTES=%s\nZAINO_EXPECTED_DM_UUID=%s\nZAINO_EXPECTED_CMDLINE_SHA256=%s\n' "$bytes" "$dm_uuid" "$cmdline_sha")
[[ $(cat "$output/init-bindings.env") == "$expected_bindings" ]] || fail 'native init binding mismatch'

layout_sha=$(sha256sum "$layout" | awk '{print $1}'); tools_sha=$(sha256sum "$closure/package-lock.json" | awk '{print $1}'); workload_sha=$(sha256sum "$workload/OUTPUT-SHA256SUMS" | awk '{print $1}')
image=$(jq -r .selected_builder_base_image "$root/rootfs-tool-roots.json"); image_id=$(jq -r .config.digest "$root/upstream/builder-amd64-manifest.json")
build_sha=$(sha256sum "$root/build-rootfs-inner.sh" | awk '{print $1}'); outer_sha=$(sha256sum "$root/build-rootfs-once.sh" | awk '{print $1}'); stage_sha=$(sha256sum "$root/stage-rootfs-tree.sh" | awk '{print $1}'); inspect_sha=$(sha256sum "$root/inspect-ext4-tree.sh" | awk '{print $1}'); install_sha=$(sha256sum "$root/install-authenticated-package-closure.sh" | awk '{print $1}')
builder_revision=$(git -c safe.directory=/repository -C "$root" rev-parse HEAD); builder_tree=$(git -c safe.directory=/repository -C "$root" rev-parse 'HEAD^{tree}')
jq -e --arg image "$image" --arg image_id "$image_id" --arg layout "$layout_sha" --arg tools "$tools_sha" --arg workload "$workload_sha" --arg build "$build_sha" --arg outer "$outer_sha" --arg stage "$stage_sha" --arg inspect "$inspect_sha" --arg install "$install_sha" --arg revision "$builder_revision" --arg tree "$builder_tree" '
 .schema=="zaino-minimal-rootfs-build-v1" and (.run_label=="run-1" or .run_label=="run-2") and
 .selected_builder_base_image==$image and .executed_builder_image_id==$image_id and .network_during_build=="disabled" and
 .layout_sha256==$layout and .tool_closure_lock_sha256==$tools and .trusted_workload_output_sha256s_sha256==$workload and
 .build_rootfs_inner_sha256==$build and .build_rootfs_once_sha256==$outer and .stage_rootfs_tree_sha256==$stage and .inspect_ext4_tree_sha256==$inspect and .install_authenticated_package_closure_sha256==$install and
 .builder_repository_revision==$revision and .builder_source_tree==$tree and
 .scope=="rootfs-and-verity-binding-only;not-init;not-UKI;not-disk;not-boot;not-TEE-admission" and
 (keys==["build_rootfs_inner_sha256","build_rootfs_once_sha256","builder_repository_revision","builder_source_tree","executed_builder_image_id","inspect_ext4_tree_sha256","install_authenticated_package_closure_sha256","layout_sha256","network_during_build","run_label","schema","scope","selected_builder_base_image","stage_rootfs_tree_sha256","tool_closure_lock_sha256","trusted_workload_output_sha256s_sha256"])
' "$output/build-run.json" >/dev/null || fail 'build receipt differs from reviewer-owned inputs'
echo 'Verified reviewer-bound rootfs content, exact ext4/verity geometry, command line, and build identities.'
