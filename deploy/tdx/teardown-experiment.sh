#!/usr/bin/env bash
# shellcheck disable=SC2155

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${script_dir}/common.sh"

readonly MANIFEST="${1:?usage: teardown-experiment.sh MANIFEST_JSON}"
[[ -f "${MANIFEST}" ]] || {
  echo "missing manifest: ${MANIFEST}" >&2
  exit 1
}

readonly RUN_ID="$(manifest_value "${MANIFEST}" run_id)"
readonly OWNER="$(manifest_value "${MANIFEST}" owner)"
readonly MANIFEST_PROJECT="$(manifest_value "${MANIFEST}" project)"
readonly MANIFEST_REGION="$(manifest_value "${MANIFEST}" region)"
readonly MANIFEST_ZONE="$(manifest_value "${MANIFEST}" zone)"
[[ "${MANIFEST_PROJECT}" == "${PROJECT_ID}" && "${MANIFEST_REGION}" == "${REGION}" && "${MANIFEST_ZONE}" == "${ZONE}" ]] || {
  echo "manifest scope does not match the pinned experiment scope" >&2
  exit 1
}

verify_identity() {
  local kind="$1"
  local name="$2"
  local expected_id="$3"
  local json="$4"
  local actual_id actual_description
  actual_id="$(jq -er '.id' <<< "${json}")"
  actual_description="$(jq -er '.description // ""' <<< "${json}")"
  [[ "${actual_id}" == "${expected_id}" && "${actual_description}" == "${OWNER}" ]] || {
    echo "refusing to delete ${kind} ${name}: ownership or immutable ID mismatch" >&2
    exit 1
  }
}

verify_disk_identity() {
  local json="$1"
  [[ "$(jq -er '.id' <<< "${json}")" == "${boot_disk_id}" ]] || {
    echo "refusing to delete disk ${boot_disk}: immutable ID mismatch" >&2; exit 1;
  }
  [[ "$(jq -er '.sourceImageId' <<< "${json}")" == "${boot_source_image_id}" ]] || {
    echo "refusing to delete disk ${boot_disk}: source image ID mismatch" >&2; exit 1;
  }
}

describe_resource() {
  local error_file
  error_file="$(mktemp)"
  if RESOURCE_JSON="$("$@" 2>"${error_file}")"; then
    RESOURCE_STATE="present"
  elif grep -q 'was not found' "${error_file}"; then
    RESOURCE_STATE="absent"
    RESOURCE_JSON=""
  else
    cat "${error_file}" >&2
    rm -f -- "${error_file}"
    echo "resource inspection failed; teardown is incomplete" >&2
    exit 1
  fi
  rm -f -- "${error_file}"
}

instance="$(manifest_value "${MANIFEST}" instance)"
instance_id="$(manifest_value "${MANIFEST}" instance_id)"
boot_disk="$(manifest_value "${MANIFEST}" boot_disk)"
boot_disk_id="$(manifest_value "${MANIFEST}" boot_disk_id)"
boot_source_image_id="$(manifest_value "${MANIFEST}" boot_source_image_id)"
if [[ -n "${instance_id}" ]]; then
  describe_resource gcloud compute instances describe "${instance}" --project="${PROJECT_ID}" --zone="${ZONE}" --format=json
  if [[ "${RESOURCE_STATE}" == present ]]; then
    instance_json="${RESOURCE_JSON}"
    verify_identity instance "${instance}" "${instance_id}" "${instance_json}"
    boot_source="$(jq -er '.disks[] | select(.boot == true) | .source' <<< "${instance_json}")"
    [[ "${boot_source}" == */disks/"${boot_disk}" ]] || {
      echo "refusing teardown: recorded boot disk is not the current boot disk" >&2
      exit 1
    }
    disk_json="$(gcloud compute disks describe "${boot_disk}" \
      --project="${PROJECT_ID}" --zone="${ZONE}" --format=json)"
    verify_disk_identity "${disk_json}"
    instance_self_link="$(jq -er '.selfLink' <<< "${instance_json}")"
    [[ "$(jq -r --arg instance "${instance_self_link}" '(.users // []) == [$instance]' <<< "${disk_json}")" == true ]] || {
      echo "refusing teardown: owned boot disk has unexpected attachments" >&2
      exit 1
    }
    gcloud compute instances delete "${instance}" \
      --project="${PROJECT_ID}" --zone="${ZONE}" \
      --keep-disks=all --quiet
  fi
fi

if [[ -n "${boot_disk_id}" ]]; then
  describe_resource gcloud compute disks describe "${boot_disk}" --project="${PROJECT_ID}" --zone="${ZONE}" --format=json
fi
if [[ -n "${boot_disk_id}" && "${RESOURCE_STATE:-absent}" == present ]]; then
  disk_json="${RESOURCE_JSON}"
  verify_disk_identity "${disk_json}"
  [[ "$(jq '.users | length' <<< "${disk_json}")" -eq 0 ]] || {
    echo "refusing teardown: owned boot disk remains attached" >&2
    exit 1
  }
  gcloud compute disks delete "${boot_disk}" \
    --project="${PROJECT_ID}" --zone="${ZONE}" --quiet
fi

firewall="$(manifest_value "${MANIFEST}" firewall)"
firewall_id="$(manifest_value "${MANIFEST}" firewall_id)"
if [[ -n "${firewall_id}" ]]; then describe_resource gcloud compute firewall-rules describe "${firewall}" --project="${PROJECT_ID}" --format=json; fi
if [[ -n "${firewall_id}" && "${RESOURCE_STATE:-absent}" == present ]]; then
  firewall_json="${RESOURCE_JSON}"
  verify_identity firewall "${firewall}" "${firewall_id}" "${firewall_json}"
  gcloud compute firewall-rules delete "${firewall}" --project="${PROJECT_ID}" --quiet
fi

subnet="$(manifest_value "${MANIFEST}" subnet)"
subnet_id="$(manifest_value "${MANIFEST}" subnet_id)"
if [[ -n "${subnet_id}" ]]; then describe_resource gcloud compute networks subnets describe "${subnet}" --project="${PROJECT_ID}" --region="${REGION}" --format=json; fi
if [[ -n "${subnet_id}" && "${RESOURCE_STATE:-absent}" == present ]]; then
  subnet_json="${RESOURCE_JSON}"
  verify_identity subnet "${subnet}" "${subnet_id}" "${subnet_json}"
  gcloud compute networks subnets delete "${subnet}" \
    --project="${PROJECT_ID}" --region="${REGION}" --quiet
fi

network="$(manifest_value "${MANIFEST}" network)"
network_id="$(manifest_value "${MANIFEST}" network_id)"
if [[ -n "${network_id}" ]]; then describe_resource gcloud compute networks describe "${network}" --project="${PROJECT_ID}" --format=json; fi
if [[ -n "${network_id}" && "${RESOURCE_STATE:-absent}" == present ]]; then
  network_json="${RESOURCE_JSON}"
  verify_identity network "${network}" "${network_id}" "${network_json}"
  gcloud compute networks delete "${network}" --project="${PROJECT_ID}" --quiet
fi

report_dir="$(cd -- "$(dirname -- "${MANIFEST}")" && pwd)"
printf 'teardown_verified_run_id=%s\nteardown_completed_at=%s\n' "${RUN_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "${report_dir}/teardown-verified.txt"
