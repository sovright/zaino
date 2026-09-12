#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${script_dir}/common.sh"
readonly MANIFEST="${1:?usage: connect-iap.sh MANIFEST_JSON}"
"${script_dir}/verify-cloud-config.sh" "${MANIFEST}"
instance="$(manifest_value "${MANIFEST}" instance)"
gcloud compute ssh "${instance}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --tunnel-through-iap
