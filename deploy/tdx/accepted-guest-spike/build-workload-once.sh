#!/usr/bin/env bash
# Build one workload output in an owned, network-disabled container.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "offline workload build refused: $*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'usage: build-workload-once.sh SOURCE_INPUT TOOL_CLOSURE RUST_ARCHIVES RUN_LABEL NEW_OUTPUT'
source_input=$(cd "$1" && pwd -P); closure=$(cd "$2" && pwd -P); rust_archives=$(cd "$3" && pwd -P); run_label=$4
[[ "$run_label" =~ ^run-[12]$ ]] || fail 'invalid run label'
for tool in docker dpkg-query dpkg-scanpackages jq openssl timeout; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_WORKLOAD_DEADLINE_GUARD:-} != 1 ]]; then export ZAINO_WORKLOAD_DEADLINE_GUARD=1; exec timeout --signal=TERM --kill-after=30s 7200s bash "$0" "$@"; fi
bash "$root/verify-workload-source.sh" "$source_input" >/dev/null
bash "$root/verify-package-closure.sh" "$closure" "$root/workload-tool-roots.json" >/dev/null
bash "$root/verify-rust-toolchain-inputs.sh" "$rust_archives" >/dev/null
requested=$5; [[ ! -e "$requested" ]] || fail 'output already exists'; parent=$(cd "$(dirname "$requested")" && pwd -P); name=$(basename "$requested")
partial=$(mktemp -d "$parent/.${name}.partial.XXXXXX"); mkdir -m 700 "$partial/output"; mkdir -m 755 "$partial/repo"
published=false container_id='' cidfile="$partial/container.cid"
cleanup() { local s=$? id='' safe=true inspect='' status=0; trap - EXIT INT TERM; if [[ -s "$cidfile" ]]; then id=$(cat "$cidfile"); else id=$container_id; fi; if [[ -n "$id" ]]; then timeout --signal=KILL 10s docker rm -f "$id" >/dev/null 2>&1 || safe=false; if inspect=$(timeout --signal=KILL 5s docker inspect "$id" 2>&1); then safe=false; else status=$?; [[ $status == 1 && "$inspect" == *'No such object'* ]] || safe=false; fi; fi; if [[ $safe == true && $published != true ]]; then rm -rf "$partial"; else [[ $published == true ]] || echo "retained uncertain staging: $partial" >&2; fi; exit "$s"; }
trap cleanup EXIT; trap 'exit 130' INT TERM
version=$(dpkg-query -W -f='${Version}' dpkg-dev); [[ "$version" == 1.22.6ubuntu6.6 ]] || fail 'unexpected repository generator'
cp "$closure/packages/"*.deb "$partial/repo/"; chmod 644 "$partial/repo/"*.deb; (cd "$partial/repo" && dpkg-scanpackages . /dev/null > Packages); chmod 644 "$partial/repo/Packages"
awk '/^Filename: / {value=substr($0,11); if (value !~ /^\.\/[A-Za-z0-9][A-Za-z0-9+._~:-]*\.deb$/ || value ~ /\.\./) bad=1; count++} END {if (bad || count==0) exit 1}' "$partial/repo/Packages" || fail 'unsafe local repository filename'
jq -r '.packages[] | [.name,.version,.architecture] | @tsv' "$closure/package-lock.json" > "$partial/expected.tsv"
image=$(jq -r .selected_builder_base_image "$root/workload-tool-roots.json"); docker pull -q "$image" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$image"); image_os=$(docker image inspect --format '{{.Os}}' "$image"); image_arch=$(docker image inspect --format '{{.Architecture}}' "$image")
[[ "$image_os" == linux && "$image_arch" == amd64 && "$image_id" == "$(jq -r .config.digest "$root/upstream/builder-amd64-manifest.json")" ]] || fail 'executed OCI identity mismatch'
owner=$(stat -c '%u:%g' "$partial/output")
container_id=$(docker create --cidfile "$cidfile" --network none --pull never --tmpfs /tmp:rw,nosuid,nodev,size=12g \
  --mount "type=bind,src=$source_input,dst=/inputs/source,readonly" \
  --mount "type=bind,src=$source_input/vendor,dst=/inputs/vendor,readonly" \
  --mount "type=bind,src=$partial/repo,dst=/inputs/repo,readonly" \
  --mount "type=bind,src=$partial/expected.tsv,dst=/inputs/expected.tsv,readonly" --mount "type=bind,src=$rust_archives,dst=/inputs/rust,readonly" \
  --mount "type=bind,src=$root/build-workload-inner.sh,dst=/builder/build.sh,readonly" \
  --mount "type=bind,src=$root/install-authenticated-package-closure.sh,dst=/builder/install-packages.sh,readonly" \
  --mount "type=bind,src=$partial/output,dst=/output" "$image" bash /builder/build.sh /inputs/source/repository /inputs/source /inputs/repo /inputs/expected.tsv /inputs/rust /output/result "$run_label" "$owner")
docker start -a "$container_id"; docker rm "$container_id" >/dev/null; container_id=''; rm -f "$cidfile"
source_sha=$(openssl dgst -sha256 -r "$source_input/source.json"); source_sha=${source_sha%% *}; tools_sha=$(openssl dgst -sha256 -r "$closure/package-lock.json"); tools_sha=${tools_sha%% *}
rust_lock_sha=$(openssl dgst -sha256 -r "$root/rust-toolchain-inputs.json"); rust_lock_sha=${rust_lock_sha%% *}; rust_inputs_sha=$(for file in "$rust_archives"/*.tar.xz; do openssl dgst -sha256 -r "$file" | awk '{print $1}'; done | LC_ALL=C sort | openssl dgst -sha256 -r); rust_inputs_sha=${rust_inputs_sha%% *}
scripts_sha=$(for file in build-workload-inner.sh build-workload-once.sh install-authenticated-package-closure.sh verify-workload-source.sh workload-cargo-config.toml; do openssl dgst -sha256 -r "$root/$file" | awk '{print $1}'; done | LC_ALL=C sort | openssl dgst -sha256 -r); scripts_sha=${scripts_sha%% *}
builder_revision=$(git -C "$root" rev-parse HEAD); builder_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
jq -n --arg run "$run_label" --arg image "$image" --arg image_id "$image_id" --arg source "$source_sha" --arg tools "$tools_sha" --arg scripts "$scripts_sha" --arg rust_lock "$rust_lock_sha" --arg rust_inputs "$rust_inputs_sha" --arg builder_revision "$builder_revision" --arg builder_tree "$builder_tree" \
 '{schema:"zaino-offline-workload-build-v1",run_label:$run,selected_builder_base_image:$image,executed_builder_image_id:$image_id,network_during_build:"disabled",source_receipt_sha256:$source,tool_closure_lock_sha256:$tools,rust_input_lock_sha256:$rust_lock,rust_archive_set_sha256:$rust_inputs,builder_scripts_sha256:$scripts,builder_repository_revision:$builder_revision,builder_source_tree:$builder_tree,init_status:"deferred-until-authenticated-rootfs-binding",scope:"evidence-agent-and-runtime-closure;not-init;not-image;not-boot;not-TEE-admission"}' > "$partial/output/result/build-run.json"
(cd "$partial/output/result" && find . -type f -print | LC_ALL=C sort | while read -r file; do printf '%s\t%s\n' "$(stat -c %a "$file")" "$file"; done > OUTPUT-MODES.tsv)
manifest_tmp="$partial/output/OUTPUT-SHA256SUMS"
(cd "$partial/output/result" && find . -type f -print | LC_ALL=C sort | while read -r file; do digest=$(sha256sum "$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done) > "$manifest_tmp"
mv "$manifest_tmp" "$partial/output/result/OUTPUT-SHA256SUMS"
mv --no-clobber --no-target-directory "$partial/output/result" "$requested"; [[ -d "$requested" && ! -e "$partial/output/result" ]] || fail 'publication failed'
rm -rf "$partial"; published=true
