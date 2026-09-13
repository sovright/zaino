#!/usr/bin/env bash
# Produce one clean custom-kernel build for cross-runner comparison by CI.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "custom kernel build refused: $*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'usage: build-custom-kernel-once.sh SOURCE_ARCHIVES TOOL_CLOSURE CONFIG RUN_LABEL NEW_OUTPUT_DIRECTORY'
run_label=$4
[[ "$run_label" =~ ^run-[12]$ ]] || fail 'invalid run label'
for tool in docker dpkg-query dpkg-scanpackages jq openssl timeout; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_CUSTOM_KERNEL_DEADLINE_GUARD:-} != 1 ]]; then
  export ZAINO_CUSTOM_KERNEL_DEADLINE_GUARD=1
  exec timeout --signal=TERM --kill-after=30s 9000s bash "$0" "$@"
fi
sources=$(cd -- "$1" && pwd -P) || fail 'missing source archives'
closure=$(cd -- "$2" && pwd -P) || fail 'missing tool closure'
fragment=$(cd -- "$(dirname -- "$3")" && pwd -P)/$(basename -- "$3")
[[ -f "$fragment" && ! -L "$fragment" ]] || fail 'invalid config fragment'
bash "$root/verify-custom-kernel-source.sh" "$sources" >/dev/null
bash "$root/verify-kernel-patches.sh" >/dev/null
bash "$root/verify-package-closure.sh" "$closure" "$root/custom-kernel-tool-roots.json" >/dev/null
requested=$5; [[ ! -e "$requested" ]] || fail 'output already exists'
parent=$(cd -- "$(dirname -- "$requested")" && pwd -P); name=$(basename -- "$requested")
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'unsafe output name'
final="$parent/$name"; failure="$final.failure"
partial=$(mktemp -d "$parent/.${name}.partial.XXXXXX")
mkdir -m 700 -- "$partial/output"; published=false; container_id=''; cidfile="$partial/container.cid"
cleanup() {
  local status=$? owned_id='' safe=true candidate="$partial/output/result/effective-config.candidate"
  trap - EXIT INT TERM
  if [[ -s "$cidfile" ]]; then owned_id=$(cat "$cidfile"); elif [[ -n "$container_id" ]]; then owned_id=$container_id; fi
  if [[ -n "$owned_id" ]]; then
    if [[ ! "$owned_id" =~ ^[0-9a-f]{64}$ ]] || ! timeout --signal=KILL 10s docker rm --force "$owned_id" >/dev/null 2>&1; then safe=false; fi
    if timeout --signal=KILL 5s docker inspect "$owned_id" >/dev/null 2>&1; then
      safe=false
    else
      inspect_status=$?
      [[ $inspect_status == 1 ]] || safe=false
    fi
  fi
  if [[ $safe == true && $published != true ]]; then
    if [[ -f "$candidate" && ! -L "$candidate" && ! -e "$failure" && $(wc -c < "$candidate") -le 4194304 ]]; then
      mkdir -m 700 -- "$failure"
      cp -- "$candidate" "$failure/effective-config.rejected"
      printf '%s\n' 'Effective configuration retained from an incomplete or rejected build.' > "$failure/README"
    fi
    rm -rf -- "$partial"
  elif [[ $safe != true ]]; then
    echo "custom kernel build cleanup refused; retained staging: $partial" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
image=$(jq -r '.selected_builder_base_image' "$root/custom-kernel-tool-roots.json")
jq -r '.packages[] | [.name,.version,.architecture] | @tsv' "$closure/package-lock.json" > "$partial/expected-packages.tsv"
repository_generator_version=$(dpkg-query -W -f='${Version}' dpkg-dev)
[[ "$repository_generator_version" == 1.22.6ubuntu6.6 ]] || fail 'unexpected host dpkg-scanpackages package version'
mkdir -m 755 -- "$partial/local-repo"
cp -- "$closure/packages/"*.deb "$partial/local-repo/"
(cd "$partial/local-repo" && dpkg-scanpackages . /dev/null > Packages)
awk '
  /^Filename: / {
    value=substr($0,11); if (value !~ /^\.\/[A-Za-z0-9][A-Za-z0-9+._~:-]*\.deb$/ || value ~ /\.\./) bad=1; count++
  }
  END { if (bad || count == 0) exit 1 }
' "$partial/local-repo/Packages" || fail 'unsafe generated local repository filename'
chmod 644 "$partial/local-repo/"*
docker pull --quiet "$image" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$image")
image_os=$(docker image inspect --format '{{.Os}}' "$image")
image_arch=$(docker image inspect --format '{{.Architecture}}' "$image")
repo_digests=$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$image")
selected_digest=${image##*@}
expected_image_id=$(jq -r '.config.digest' "$root/upstream/builder-amd64-manifest.json")
[[ "$image_os" == linux && "$image_arch" == amd64 && "$image_id" == "$expected_image_id" ]] || fail 'executed OCI config or platform mismatch'
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ && "$selected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'malformed OCI identity'
grep -Eq "@${selected_digest}$" <<< "$repo_digests" || fail 'selected OCI digest absent after pull'
container_id=$(docker create --cidfile "$cidfile" --network none --pull never --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --mount "type=bind,src=$sources,dst=/inputs/sources,readonly" \
  --mount "type=bind,src=$closure,dst=/inputs/closure,readonly" \
  --mount "type=bind,src=$partial/local-repo,dst=/inputs/repo,readonly" \
  --mount "type=bind,src=$partial/expected-packages.tsv,dst=/inputs/expected-packages.tsv,readonly" \
  --mount "type=bind,src=$fragment,dst=/inputs/custom-kernel.config,readonly" \
  --mount "type=bind,src=$root/kernel-source,dst=/inputs/patches,readonly" \
  --mount "type=bind,src=$root/build-custom-kernel-inner.sh,dst=/builder/build.sh,readonly" \
  --mount "type=bind,src=$root/kernel-patches.json,dst=/builder/kernel-patches.json,readonly" \
  --mount "type=bind,src=$root/verify-tdx-quote-hardening.sh,dst=/builder/verify-tdx-quote-hardening.sh,readonly" \
  --mount "type=bind,src=$root/verify-custom-kernel-effective-config.sh,dst=/builder/verify-effective-config.sh,readonly" \
  --mount "type=bind,src=$root/kernel-config-common.sh,dst=/builder/kernel-config-common.sh,readonly" \
  --mount "type=bind,src=$partial/output,dst=/output" \
  "$image" bash /builder/build.sh /inputs/sources /inputs/closure /inputs/repo /inputs/expected-packages.tsv /inputs/custom-kernel.config /inputs/patches /output/result "$run_label")
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || fail 'builder container creation failed'
docker start --attach "$container_id"
docker rm "$container_id" >/dev/null
container_id=''
rm -f -- "$cidfile"
bash "$root/verify-custom-kernel-effective-config.sh" "$partial/output/result/artifacts/config" "$fragment" >/dev/null
source_lock_sha=$(openssl dgst -sha256 -r "$root/custom-kernel-source.json"); source_lock_sha=${source_lock_sha%% *}
tool_lock_sha=$(openssl dgst -sha256 -r "$closure/package-lock.json"); tool_lock_sha=${tool_lock_sha%% *}
config_sha=$(openssl dgst -sha256 -r "$fragment"); config_sha=${config_sha%% *}
scripts_sha=$(for file in build-custom-kernel-inner.sh build-custom-kernel-once.sh kernel-config-common.sh verify-custom-kernel-effective-config.sh verify-kernel-config.sh kernel-config-policy.json verify-kernel-patches.sh verify-tdx-quote-hardening.sh; do openssl dgst -sha256 -r "$root/$file" | awk '{print $1}'; done | LC_ALL=C sort | openssl dgst -sha256 -r); scripts_sha=${scripts_sha%% *}
patches_sha=$(openssl dgst -sha256 -r "$root/kernel-patches.json"); patches_sha=${patches_sha%% *}
revision=$(git -C "$root" rev-parse HEAD)
artifact_manifest_sha=$(openssl dgst -sha256 -r "$partial/output/result/artifacts/SHA256SUMS"); artifact_manifest_sha=${artifact_manifest_sha%% *}
tool_versions_sha=$(openssl dgst -sha256 -r "$partial/output/result/tool-versions.txt"); tool_versions_sha=${tool_versions_sha%% *}
jq -n --arg run "$run_label" --arg image "$image" --arg image_id "$image_id" --arg source "$source_lock_sha" --arg tools "$tool_lock_sha" --arg config "$config_sha" \
  --arg repository_generator "$repository_generator_version" \
  --arg scripts "$scripts_sha" --arg patches "$patches_sha" --arg revision "$revision" --arg artifacts "$artifact_manifest_sha" --arg tool_versions "$tool_versions_sha" \
  '{schema:"zaino-custom-kernel-build-run-v1",run_label:$run,selected_builder_base_image:$image,executed_builder_image_id:$image_id,
    network_during_build:"disabled",source_lock_sha256:$source,tool_closure_lock_sha256:$tools,requested_config_sha256:$config,
    local_repository_generator_dpkg_dev_version:$repository_generator,
    builder_scripts_sha256:$scripts,kernel_patch_lock_sha256:$patches,repository_revision:$revision,artifact_manifest_sha256:$artifacts,tool_versions_sha256:$tool_versions,
    scope:"single-clean-builder-output;cross-runner-reproducibility-unverified;boot-and-TEE-admission-unverified"}' > "$partial/output/result/build-run.json"
mv --no-clobber --no-target-directory -- "$partial/output/result" "$final"
[[ -d "$final" && ! -e "$partial/output/result" ]] || fail 'atomic publication failure'
rm -rf -- "$partial"
published=true
echo 'Built one custom kernel in the selected network-disabled builder; cross-runner comparison remains required.'
