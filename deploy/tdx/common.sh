#!/usr/bin/env bash
# shellcheck disable=SC2034 # Constants are consumed by scripts that source this file.

set -euo pipefail

readonly PROJECT_ID="sovright-bedrock-mainnet"
readonly REGION="us-central1"
readonly ZONE="us-central1-a"
readonly RESOURCE_PREFIX="zaino-tdx-exp"
readonly SUBNET_RANGE="10.251.0.0/28"
readonly MACHINE_TYPE="c3-standard-4"
readonly IMAGE_PROJECT="ubuntu-os-cloud"
readonly IMAGE_NAME="ubuntu-2404-noble-amd64-v20260906"
readonly IMAGE_ID="6257327608773510097"
readonly MAX_RUN_DURATION="6h"
readonly IAP_TCP_RANGE="35.235.240.0/20"

manifest_value() {
  local manifest="$1"
  local key="$2"
  jq -er --arg key "${key}" '.[$key]' "${manifest}"
}

reject_dangerous_project_metadata() {
  local project_metadata dangerous_keys
  project_metadata="$(gcloud compute project-info describe --project="${PROJECT_ID}" --format=json)"
  dangerous_keys="$(jq -r '[.commonInstanceMetadata.items[]?.key | select(test("(^|[-_])(startup|shutdown)[-_]script($|[-_])|user[-_]data|secret|token|password|credential|private[-_]?key"; "i"))] | join(",")' <<< "${project_metadata}")"
  [[ -z "${dangerous_keys}" ]] || {
    echo "refusing inherited project metadata keys: ${dangerous_keys}" >&2
    return 1
  }
}
