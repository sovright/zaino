#!/usr/bin/env bash
# Produce one clean rootfs/verity output in the selected network-disabled builder.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "rootfs build refused: $*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'usage: build-rootfs-once.sh WORKLOAD TRUSTED_EXPECTATIONS TOOL_CLOSURE RUN_LABEL NEW_OUTPUT'
for tool in docker dpkg-query dpkg-scanpackages git jq sha256sum timeout; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_ROOTFS_DEADLINE_GUARD:-} != 1 ]]; then export ZAINO_ROOTFS_DEADLINE_GUARD=1; exec timeout --signal=TERM --kill-after=30s 3600s bash "$0" "$@"; fi
zip_workload=$(cd -- "$1" && pwd -P); expectations=$(cd -- "$(dirname -- "$2")" && pwd -P)/$(basename -- "$2"); closure=$(cd -- "$3" && pwd -P); run_label=$4
[[ "$run_label" =~ ^run-[12]$ ]] || fail 'invalid run label'
bash "$root/verify-package-closure.sh" "$closure" "$root/rootfs-tool-roots.json" >/dev/null
bash "$root/verify-rootfs-layout.sh" >/dev/null
requested=$5; [[ ! -e "$requested" ]] || fail 'output already exists'; parent=$(cd -- "$(dirname -- "$requested")" && pwd -P); name=$(basename -- "$requested")
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'unsafe output name'
partial=$(mktemp -d "$parent/.${name}.partial.XXXXXX"); mkdir -m 700 "$partial/output"; mkdir -m 755 "$partial/repo"
published=false container_id='' cidfile="$partial/container.cid"
cleanup() { local saved=$? id='' inspect='' inspect_status=0 safe=true; trap - EXIT INT TERM; [[ -s "$cidfile" ]] && id=$(cat "$cidfile"); if [[ -n "$id" ]]; then timeout --signal=KILL 10s docker rm -f "$id" >/dev/null 2>&1 || safe=false; if inspect=$(timeout --signal=KILL 5s docker inspect "$id" 2>&1); then safe=false; else inspect_status=$?; [[ $inspect_status == 1 && "$inspect" == *'No such object'* ]] || safe=false; fi; fi; if [[ $safe == true && $published != true ]]; then rm -rf -- "$partial"; else [[ $published == true ]] || echo "rootfs build retained uncertain container and staging: $partial" >&2; fi; [[ $safe == true ]] || saved=1; exit "$saved"; }
trap cleanup EXIT; trap 'exit 130' INT TERM
workload="$partial/workload"
bash "$root/restore-workload-output.sh" "$zip_workload" "$expectations" "$workload"
bash "$root/verify-workload-output.sh" "$workload" "$expectations" >/dev/null
[[ $(dpkg-query -W -f='${Version}' dpkg-dev) == 1.22.6ubuntu6.6 ]] || fail 'unexpected repository generator'
cp "$closure/packages/"*.deb "$partial/repo/"; chmod 644 "$partial/repo/"*.deb
(cd "$partial/repo" && dpkg-scanpackages . /dev/null > Packages); chmod 644 "$partial/repo/Packages"
jq -r '.packages[] | [.name,.version,.architecture] | @tsv' "$closure/package-lock.json" > "$partial/expected.tsv"
image=$(jq -r .selected_builder_base_image "$root/rootfs-tool-roots.json"); docker pull -q "$image" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$image"); [[ "$image_id" == "$(jq -r .config.digest "$root/upstream/builder-amd64-manifest.json")" ]] || fail 'executed OCI identity mismatch'
owner=$(stat -c '%u:%g' "$partial/output")
container_id=$(docker create --cidfile "$cidfile" --network none --pull never --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --mount "type=bind,src=$workload,dst=/inputs/workload,readonly" --mount "type=bind,src=$expectations,dst=/inputs/expectations.json,readonly" \
  --mount "type=bind,src=$partial/repo,dst=/inputs/repo,readonly" --mount "type=bind,src=$partial/expected.tsv,dst=/inputs/expected.tsv,readonly" \
  --mount "type=bind,src=$root/rootfs-layout.json,dst=/inputs/layout.json,readonly" --mount "type=bind,src=$root/build-rootfs-inner.sh,dst=/builder/build.sh,readonly" \
  --mount "type=bind,src=$root/stage-rootfs-tree.sh,dst=/builder/stage-rootfs.sh,readonly" \
  --mount "type=bind,src=$root/inspect-ext4-tree.sh,dst=/builder/inspect-ext4.sh,readonly" \
  --mount "type=bind,src=$root/install-authenticated-package-closure.sh,dst=/builder/install-packages.sh,readonly" \
  --mount "type=bind,src=$root/verify-workload-output.sh,dst=/builder/verify-workload.sh,readonly" --mount "type=bind,src=$root/verify-rootfs-layout.sh,dst=/builder/verify-layout.sh,readonly" \
  --mount "type=bind,src=$partial/output,dst=/output" "$image" bash /builder/build.sh /inputs/workload /inputs/expectations.json /inputs/repo /inputs/expected.tsv /inputs/layout.json /output/result "$owner")
docker start -a "$container_id"; docker rm "$container_id" >/dev/null; container_id=''; rm -f "$cidfile"
layout_sha=$(sha256sum "$root/rootfs-layout.json" | awk '{print $1}'); tools_sha=$(sha256sum "$closure/package-lock.json" | awk '{print $1}'); workload_sha=$(sha256sum "$workload/OUTPUT-SHA256SUMS" | awk '{print $1}')
build_sha=$(sha256sum "$root/build-rootfs-inner.sh" | awk '{print $1}'); outer_sha=$(sha256sum "$root/build-rootfs-once.sh" | awk '{print $1}'); stage_sha=$(sha256sum "$root/stage-rootfs-tree.sh" | awk '{print $1}'); inspect_sha=$(sha256sum "$root/inspect-ext4-tree.sh" | awk '{print $1}'); install_sha=$(sha256sum "$root/install-authenticated-package-closure.sh" | awk '{print $1}')
builder_revision=$(git -C "$root" rev-parse HEAD); builder_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
jq -n --arg run "$run_label" --arg image "$image" --arg image_id "$image_id" --arg layout "$layout_sha" --arg tools "$tools_sha" --arg workload "$workload_sha" --arg build "$build_sha" --arg outer "$outer_sha" --arg stage "$stage_sha" --arg inspect "$inspect_sha" --arg install "$install_sha" --arg revision "$builder_revision" --arg tree "$builder_tree" \
  '{schema:"zaino-minimal-rootfs-build-v1",run_label:$run,selected_builder_base_image:$image,executed_builder_image_id:$image_id,network_during_build:"disabled",layout_sha256:$layout,tool_closure_lock_sha256:$tools,trusted_workload_output_sha256s_sha256:$workload,build_rootfs_inner_sha256:$build,build_rootfs_once_sha256:$outer,stage_rootfs_tree_sha256:$stage,inspect_ext4_tree_sha256:$inspect,install_authenticated_package_closure_sha256:$install,builder_repository_revision:$revision,builder_source_tree:$tree,scope:"rootfs-and-verity-binding-only;not-init;not-UKI;not-disk;not-boot;not-TEE-admission"}' > "$partial/output/result/build-run.json"
(cd "$partial/output/result" && find . -type f ! -name OUTPUT-SHA256SUMS -print | sort | while read -r file; do digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done) > "$partial/output/result/OUTPUT-SHA256SUMS"
mv --no-clobber --no-target-directory "$partial/output/result" "$requested"
[[ -d "$requested" && ! -e "$partial/output/result" ]] || fail 'publication failed'
rm -rf "$partial"; published=true
echo 'Built one authenticated rootfs and verity binding; independent equality, init, UKI, disk, boot, and TEE admission remain unverified.'
