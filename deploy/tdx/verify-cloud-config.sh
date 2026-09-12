#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${script_dir}/common.sh"
readonly MANIFEST="${1:?usage: verify-cloud-config.sh MANIFEST_JSON}"
[[ -f "${MANIFEST}" ]] || { echo "missing manifest" >&2; exit 1; }
[[ "$(manifest_value "${MANIFEST}" project)" == "${PROJECT_ID}" && "$(manifest_value "${MANIFEST}" region)" == "${REGION}" && "$(manifest_value "${MANIFEST}" zone)" == "${ZONE}" ]] || { echo "manifest scope mismatch" >&2; exit 1; }
reject_dangerous_project_metadata
instance="$(manifest_value "${MANIFEST}" instance)"; instance_id="$(manifest_value "${MANIFEST}" instance_id)"; owner="$(manifest_value "${MANIFEST}" owner)"
network="$(manifest_value "${MANIFEST}" network)"; network_id="$(manifest_value "${MANIFEST}" network_id)"; subnet="$(manifest_value "${MANIFEST}" subnet)"; subnet_id="$(manifest_value "${MANIFEST}" subnet_id)"
firewall="$(manifest_value "${MANIFEST}" firewall)"; firewall_id="$(manifest_value "${MANIFEST}" firewall_id)"; instance_tag="$(manifest_value "${MANIFEST}" instance_tag)"; disk="$(manifest_value "${MANIFEST}" boot_disk)"; disk_id="$(manifest_value "${MANIFEST}" boot_disk_id)"; source_image_id="$(manifest_value "${MANIFEST}" boot_source_image_id)"
instance_json="$(gcloud compute instances describe "${instance}" --project="${PROJECT_ID}" --zone="${ZONE}" --format=json)"
snapshot_dir="$(cd -- "$(dirname -- "${MANIFEST}")" && pwd)"
jq '{name,id,status,machineType,description,confidentialInstanceConfig,scheduling,
  networkInterfaces:[.networkInterfaces[]|{network,subnetwork,accessConfigs}],
  disks:[.disks[]|{source,boot,autoDelete,interface}],
  metadata_keys:[.metadata.items[]?.key],tags,labels,shieldedInstanceConfig,
  serviceAccountCount:((.serviceAccounts//[])|length)}' <<< "${instance_json}" > "${snapshot_dir}/instance-config-sanitized.json"
chmod 0600 "${snapshot_dir}/instance-config-sanitized.json"
disk_json="$(gcloud compute disks describe "${disk}" --project="${PROJECT_ID}" --zone="${ZONE}" --format=json)"
network_json="$(gcloud compute networks describe "${network}" --project="${PROJECT_ID}" --format=json)"
subnet_json="$(gcloud compute networks subnets describe "${subnet}" --project="${PROJECT_ID}" --region="${REGION}" --format=json)"
firewall_json="$(gcloud compute firewall-rules describe "${firewall}" --project="${PROJECT_ID}" --format=json)"
jq '{name,id,status,type,sizeGb,sourceImage,sourceImageId,users}' <<< "${disk_json}" > "${snapshot_dir}/disk-config-sanitized.json"
jq -n --argjson network "${network_json}" --argjson subnet "${subnet_json}" --argjson firewall "${firewall_json}" '{network:($network|{name,id,description,autoCreateSubnetworks}),subnet:($subnet|{name,id,description,ipCidrRange,privateIpGoogleAccess,network}),firewall:($firewall|{name,id,description,network,direction,priority,sourceRanges,allowed,targetTags,logConfig})}' > "${snapshot_dir}/network-config-sanitized.json"
chmod 0600 "${snapshot_dir}/disk-config-sanitized.json" "${snapshot_dir}/network-config-sanitized.json"
jq -e --arg id "${instance_id}" --arg owner "${owner}" --arg machine "${MACHINE_TYPE}" --arg network "${network}" --arg subnet "${subnet}" --arg tag "${instance_tag}" '
(.id==$id) and (.description==$owner) and (.machineType|endswith("/"+$machine)) and
(.confidentialInstanceConfig.enableConfidentialCompute==true) and (.confidentialInstanceConfig.confidentialInstanceType=="TDX") and
(.scheduling.automaticRestart==false) and (.scheduling.onHostMaintenance=="TERMINATE") and (.scheduling.provisioningModel=="STANDARD") and (.scheduling.instanceTerminationAction=="DELETE") and ((.scheduling.maxRunDuration.seconds|tonumber)==21600) and
((.networkInterfaces|length)==1) and (((.networkInterfaces[0].accessConfigs//[])|length)==0) and (.networkInterfaces[0].network|endswith("/"+$network)) and (.networkInterfaces[0].subnetwork|endswith("/"+$subnet)) and
((.disks|length)==1) and (.disks[0].boot==true) and (.disks[0].autoDelete==true) and (.disks[0].interface=="NVME") and (.tags.items==[$tag]) and (((.serviceAccounts//[])|length)==0) and
(.shieldedInstanceConfig.enableSecureBoot==true) and (.shieldedInstanceConfig.enableVtpm==true) and (.shieldedInstanceConfig.enableIntegrityMonitoring==true) and
([.metadata.items[]|{key,value}]|sort_by(.key))==([{"key":"block-project-ssh-keys","value":"TRUE"},{"key":"enable-oslogin","value":"TRUE"},{"key":"serial-port-enable","value":"FALSE"}]|sort_by(.key))' <<< "${instance_json}" >/dev/null || { echo "instance policy assertion failed" >&2; exit 1; }
instance_self_link="$(jq -er '.selfLink' <<< "${instance_json}")"
jq -e --arg id "${disk_id}" --arg sid "${source_image_id}" --arg image "${IMAGE_NAME}" --arg instance "${instance_self_link}" '(.id==$id) and (.sourceImageId==$sid) and (.sourceImage|endswith("/"+$image)) and (.type|endswith("/diskTypes/pd-balanced")) and (.sizeGb=="30") and ((.users//[])==[$instance])' <<< "${disk_json}" >/dev/null || { echo "boot disk policy assertion failed" >&2; exit 1; }
[[ "${source_image_id}" == "${IMAGE_ID}" ]] || { echo "source image ID mismatch" >&2; exit 1; }
jq -e --arg id "${network_id}" --arg owner "${owner}" '(.id==$id) and (.description==$owner) and (.autoCreateSubnetworks==false)' <<< "${network_json}" >/dev/null || { echo "network policy assertion failed" >&2; exit 1; }
jq -e --arg id "${subnet_id}" --arg owner "${owner}" --arg range "${SUBNET_RANGE}" '(.id==$id) and (.description==$owner) and (.ipCidrRange==$range) and (.privateIpGoogleAccess==false)' <<< "${subnet_json}" >/dev/null || { echo "subnet policy assertion failed" >&2; exit 1; }
jq -e --arg id "${firewall_id}" --arg owner "${owner}" --arg network "${network}" --arg range "${IAP_TCP_RANGE}" --arg tag "${instance_tag}" '(.id==$id) and (.description==$owner) and (.network|endswith("/"+$network)) and (.direction=="INGRESS") and (.priority==1000) and (.sourceRanges==[$range]) and (.allowed==[{"IPProtocol":"tcp","ports":["22"]}]) and (.targetTags==[$tag]) and (.logConfig.enable==true)' <<< "${firewall_json}" >/dev/null || { echo "firewall policy assertion failed" >&2; exit 1; }
printf 'verified_instance=%s\nverified_instance_id=%s\nverified_boot_source_image_id=%s\n' "${instance}" "${instance_id}" "${source_image_id}"
