#!/usr/bin/env bash
# Run rootfs verification with only an authenticated offline tool closure.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd); repo=$(git -C "$root" rev-parse --show-toplevel)
fail() { echo "container rootfs verification refused: $*" >&2; exit 1; }
[[ $# == 5 || $# == 8 ]] || fail 'usage: OUTPUT WORKLOAD EXPECTATIONS TOOL_CLOSURE verify|test [OUTPUT_2 WORKLOAD_2 TOOL_CLOSURE_2]'
zip_output=$(cd -- "$1" && pwd -P); zip_workload=$(cd -- "$2" && pwd -P); expectations=$(cd -- "$(dirname -- "$3")" && pwd -P)/$(basename -- "$3"); closure=$(cd -- "$4" && pwd -P); action=$5
[[ "$action" == verify || "$action" == test || "$action" == compare ]] || fail 'invalid action'
if [[ "$action" == compare ]]; then [[ $# == 8 ]] || fail 'compare inputs missing'; zip_output_two=$(cd -- "$6" && pwd -P); zip_workload_two=$(cd -- "$7" && pwd -P); closure_two=$(cd -- "$8" && pwd -P); else [[ $# == 5 ]] || fail 'unexpected secondary inputs'; fi
for tool in cmp docker dpkg-scanpackages jq stat timeout; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_ROOTFS_VERIFY_DEADLINE_GUARD:-} != 1 ]]; then export ZAINO_ROOTFS_VERIFY_DEADLINE_GUARD=1; exec timeout --signal=TERM --kill-after=30s 900s bash "$0" "$@"; fi
bash "$root/verify-package-closure.sh" "$closure" "$root/rootfs-tool-roots.json" >/dev/null
if [[ "$action" == compare ]]; then bash "$root/verify-package-closure.sh" "$closure_two" "$root/rootfs-tool-roots.json" >/dev/null; cmp -s "$closure/package-lock.json" "$closure_two/package-lock.json" || fail 'comparison tool closures differ'; fi
scratch=$(mktemp -d); cidfile="$scratch/container.cid"; safe=true
cleanup() { local saved=$? id='' inspect='' status=0; trap - EXIT INT TERM; [[ -s "$cidfile" ]] && id=$(cat "$cidfile"); if [[ -n "$id" ]]; then timeout --signal=KILL 10s docker rm -f "$id" >/dev/null 2>&1 || safe=false; if inspect=$(timeout --signal=KILL 5s docker inspect "$id" 2>&1); then safe=false; else status=$?; [[ $status == 1 && "$inspect" == *'No such object'* ]] || safe=false; fi; fi; [[ $safe == true ]] && rm -rf -- "$scratch" || echo "retained uncertain verifier staging: $scratch" >&2; [[ $safe == true ]] || saved=1; exit "$saved"; }
trap cleanup EXIT; trap 'exit 130' INT TERM
output="$scratch/output"; workload="$scratch/workload"
bash "$root/restore-rootfs-output.sh" "$zip_output" "$output"; bash "$root/restore-workload-output.sh" "$zip_workload" "$expectations" "$workload"
if [[ "$action" == compare ]]; then output_two="$scratch/output-two"; workload_two="$scratch/workload-two"; bash "$root/restore-rootfs-output.sh" "$zip_output_two" "$output_two"; bash "$root/restore-workload-output.sh" "$zip_workload_two" "$expectations" "$workload_two"; fi
mkdir -m 755 "$scratch/repo"; cp "$closure/packages/"*.deb "$scratch/repo/"; chmod 644 "$scratch/repo/"*.deb
(cd "$scratch/repo" && dpkg-scanpackages . /dev/null >Packages); chmod 644 "$scratch/repo/Packages"
jq -r '.packages[] | [.name,.version,.architecture] | @tsv' "$closure/package-lock.json" >"$scratch/expected.tsv"
image=$(jq -r .selected_builder_base_image "$root/rootfs-tool-roots.json"); docker pull -q "$image" >/dev/null
[[ $(docker image inspect --format '{{.Id}}' "$image") == "$(jq -r .config.digest "$root/upstream/builder-amd64-manifest.json")" ]] || fail 'executed OCI identity mismatch'
mounts=(--mount "type=bind,src=$repo,dst=/repository,readonly" --mount "type=bind,src=$output,dst=/inputs/output,readonly" --mount "type=bind,src=$workload,dst=/inputs/workload,readonly" --mount "type=bind,src=$expectations,dst=/inputs/expectations.json,readonly" --mount "type=bind,src=$closure,dst=/inputs/closure,readonly" --mount "type=bind,src=$scratch/repo,dst=/inputs/repo,readonly" --mount "type=bind,src=$scratch/expected.tsv,dst=/inputs/expected.tsv,readonly")
command=/repository/deploy/tdx/accepted-guest-spike/verify-rootfs-output.sh; command_args=(/inputs/output /inputs/workload /inputs/expectations.json /inputs/closure)
if [[ "$action" == test ]]; then command=/repository/deploy/tdx/accepted-guest-spike/test-rootfs-output.sh; fi
if [[ "$action" == compare ]]; then mounts+=(--mount "type=bind,src=$output_two,dst=/inputs/output-two,readonly" --mount "type=bind,src=$workload_two,dst=/inputs/workload-two,readonly" --mount "type=bind,src=$closure_two,dst=/inputs/closure-two,readonly"); command=/repository/deploy/tdx/accepted-guest-spike/compare-rootfs-outputs.sh; command_args=(/inputs/output /inputs/output-two /inputs/expectations.json /inputs/closure /inputs/closure-two /inputs/workload /inputs/workload-two); fi
id=$(docker create --cidfile "$cidfile" --network none --pull never --tmpfs /tmp:rw,nosuid,nodev,size=1g "${mounts[@]}" "$image" bash -c 'set -euo pipefail; bash /repository/deploy/tdx/accepted-guest-spike/install-authenticated-package-closure.sh /inputs/repo /inputs/expected.tsv /tmp/apt >/dev/null; [[ "$1" != test ]] || bash /repository/deploy/tdx/accepted-guest-spike/test-ext4-inspection.sh; shift; exec bash "$@"' _ "$action" "$command" "${command_args[@]}")
docker start -a "$id"; docker rm "$id" >/dev/null; : >"$cidfile"
