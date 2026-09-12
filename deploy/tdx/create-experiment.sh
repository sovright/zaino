#!/usr/bin/env bash
# shellcheck disable=SC2155

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${script_dir}/common.sh"

readonly RUN_DIR="${1:?usage: create-experiment.sh NEW_LOCAL_RUN_DIR}"
[[ ! -e "${RUN_DIR}" ]] || {
  echo "refusing to replace run directory: ${RUN_DIR}" >&2
  exit 1
}
mkdir -m 0700 "${RUN_DIR}"
readonly MANIFEST="${RUN_DIR}/manifest.json"
readonly RUN_ID="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
readonly RESOURCE_NAME="${RESOURCE_PREFIX}-${RUN_ID}"
readonly NETWORK="${RESOURCE_NAME}"
readonly SUBNET="${RESOURCE_NAME}"
readonly FIREWALL="${RESOURCE_NAME}-iap-ssh"
readonly INSTANCE="${RESOURCE_NAME}"
readonly INSTANCE_TAG="${RESOURCE_PREFIX}-${RUN_ID##*-}"
readonly OWNER="zaino-tdx-experiment/${RUN_ID}"

write_manifest() {
  local tmp="${MANIFEST}.tmp"
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg owner "${OWNER}" \
    --arg project "${PROJECT_ID}" \
    --arg region "${REGION}" \
    --arg zone "${ZONE}" \
    --arg network "${NETWORK}" \
    --arg network_id "${network_id:-}" \
    --arg subnet "${SUBNET}" \
    --arg subnet_id "${subnet_id:-}" \
    --arg firewall "${FIREWALL}" \
    --arg firewall_id "${firewall_id:-}" \
    --arg instance "${INSTANCE}" \
    --arg instance_tag "${INSTANCE_TAG}" \
    --arg instance_id "${instance_id:-}" \
    --arg boot_disk "${boot_disk:-}" \
    --arg boot_disk_id "${boot_disk_id:-}" \
    --arg boot_source_image_id "${boot_source_image_id:-}" \
    --arg image_name "${IMAGE_NAME}" \
    --arg image_id "${IMAGE_ID}" \
    --arg state "${state:-initializing}" \
    '{run_id:$run_id,owner:$owner,project:$project,region:$region,zone:$zone,
      network:$network,network_id:$network_id,subnet:$subnet,subnet_id:$subnet_id,
      firewall:$firewall,firewall_id:$firewall_id,instance:$instance,instance_tag:$instance_tag,
      instance_id:$instance_id,boot_disk:$boot_disk,boot_disk_id:$boot_disk_id,
      boot_source_image_id:$boot_source_image_id,
      image_name:$image_name,image_id:$image_id,state:$state}' > "${tmp}"
  chmod 0600 "${tmp}"
  mv -- "${tmp}" "${MANIFEST}"
}

write_manifest

reject_dangerous_project_metadata

actual_image_id="$(gcloud compute images describe "${IMAGE_NAME}" \
  --project="${IMAGE_PROJECT}" --format='value(id)')"
[[ "${actual_image_id}" == "${IMAGE_ID}" ]] || {
  echo "pinned image ID mismatch: expected ${IMAGE_ID}, got ${actual_image_id}" >&2
  exit 1
}

create_complete=false
cleanup_partial_create() {
  local status=$?
  if [[ "${create_complete}" != true ]]; then
    "${script_dir}/teardown-experiment.sh" "${MANIFEST}" || \
      echo "automatic cleanup incomplete; use manifest: ${MANIFEST}" >&2
  fi
  exit "${status}"
}
trap cleanup_partial_create EXIT

network_json="$(gcloud compute networks create "${NETWORK}" \
  --project="${PROJECT_ID}" \
  --description="${OWNER}" \
  --subnet-mode=custom \
  --bgp-routing-mode=regional \
  --format=json)"
network_id="$(jq -er 'if type == "array" then if length == 1 then .[0].id else error("expected one network") end else .id end' <<< "${network_json}")"
write_manifest

subnet_json="$(gcloud compute networks subnets create "${SUBNET}" \
  --project="${PROJECT_ID}" \
  --description="${OWNER}" \
  --network="${NETWORK}" \
  --region="${REGION}" \
  --range="${SUBNET_RANGE}" \
  --no-enable-private-ip-google-access \
  --format=json)"
subnet_id="$(jq -er 'if type == "array" then if length == 1 then .[0].id else error("expected one subnet") end else .id end' <<< "${subnet_json}")"
write_manifest

firewall_json="$(gcloud compute firewall-rules create "${FIREWALL}" \
  --project="${PROJECT_ID}" \
  --description="${OWNER}" \
  --network="${NETWORK}" \
  --direction=INGRESS \
  --priority=1000 \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges="${IAP_TCP_RANGE}" \
  --target-tags="${INSTANCE_TAG}" \
  --enable-logging \
  --format=json)"
firewall_id="$(jq -er 'if type == "array" then if length == 1 then .[0].id else error("expected one firewall") end else .id end' <<< "${firewall_json}")"
write_manifest

instance_json="$(gcloud compute instances create "${INSTANCE}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --description="${OWNER}" \
  --machine-type="${MACHINE_TYPE}" \
  --provisioning-model=STANDARD \
  --reservation-affinity=none \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --no-restart-on-failure \
  --max-run-duration="${MAX_RUN_DURATION}" \
  --instance-termination-action=DELETE \
  --network-interface="subnet=${SUBNET},no-address" \
  --tags="${INSTANCE_TAG}" \
  --image="${IMAGE_NAME}" \
  --image-project="${IMAGE_PROJECT}" \
  --boot-disk-type=pd-balanced \
  --boot-disk-interface=NVME \
  --boot-disk-size=30GB \
  --boot-disk-auto-delete \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --no-service-account \
  --no-scopes \
  --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE,serial-port-enable=FALSE \
  --labels=purpose=zaino-tdx-experiment,run-id="${RUN_ID##*-}",lifetime=6h \
  --format=json)"
instance_id="$(jq -er '.[0].id' <<< "${instance_json}")"
boot_disk="$(jq -er '.[0].disks[] | select(.boot == true) | .source | split("/")[-1]' <<< "${instance_json}")"
state="instance-created"
write_manifest
disk_json="$(gcloud compute disks describe "${boot_disk}" \
  --project="${PROJECT_ID}" --zone="${ZONE}" --format=json)"
boot_disk_id="$(jq -er '.id' <<< "${disk_json}")"
boot_source_image_id="$(jq -er '.sourceImageId' <<< "${disk_json}")"
state="disk-identified"
write_manifest
[[ "${boot_source_image_id}" == "${IMAGE_ID}" ]] || {
  echo "created boot disk source image ID mismatch" >&2
  exit 1
}
state="created"
write_manifest

"${script_dir}/verify-cloud-config.sh" "${MANIFEST}"
state="verified"
write_manifest
create_complete=true
trap - EXIT
printf 'experiment_manifest=%s\n' "${MANIFEST}"
