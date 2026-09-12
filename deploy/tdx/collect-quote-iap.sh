#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${script_dir}/common.sh"

readonly MANIFEST="${1:?usage: collect-quote-iap.sh MANIFEST REPORT_DATA_BIN NEW_LOCAL_OUTPUT_DIR}"
readonly REPORT_DATA="${2:?usage: collect-quote-iap.sh MANIFEST REPORT_DATA_BIN NEW_LOCAL_OUTPUT_DIR}"
readonly LOCAL_OUTPUT="${3:?usage: collect-quote-iap.sh MANIFEST REPORT_DATA_BIN NEW_LOCAL_OUTPUT_DIR}"

[[ -f "${REPORT_DATA}" ]] || {
  echo "missing report-data input: ${REPORT_DATA}" >&2
  exit 1
}
[[ "$(wc -c < "${REPORT_DATA}")" -eq 64 ]] || {
  echo "report-data input must be exactly 64 bytes" >&2
  exit 1
}
[[ ! -e "${LOCAL_OUTPUT}" ]] || {
  echo "refusing to replace local output: ${LOCAL_OUTPUT}" >&2
  exit 1
}

"${script_dir}/verify-cloud-config.sh" "${MANIFEST}"
instance="$(manifest_value "${MANIFEST}" instance)"
round_id="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
remote_dir="/tmp/zaino-tdx-evidence-${round_id}"
stage="$(mktemp -d)"
cleanup_stage() { rm -f -- "${stage}/report-data.bin" "${stage}/collect-quote-guest.sh"; rmdir -- "${stage}"; }
trap cleanup_stage EXIT
cp -- "${REPORT_DATA}" "${stage}/report-data.bin"
cp -- "${script_dir}/collect-quote-guest.sh" "${stage}/collect-quote-guest.sh"
gcloud compute ssh "${instance}" --project="${PROJECT_ID}" --zone="${ZONE}" --tunnel-through-iap --command="umask 077; mkdir -- '${remote_dir}'"
gcloud compute scp \
  "${stage}/report-data.bin" "${stage}/collect-quote-guest.sh" \
  "${instance}:${remote_dir}/" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --tunnel-through-iap

gcloud compute ssh "${instance}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --tunnel-through-iap \
  --command="chmod 0700 '${remote_dir}/collect-quote-guest.sh'; '${remote_dir}/collect-quote-guest.sh' '${remote_dir}/report-data.bin' '${remote_dir}/evidence'"

mkdir -m 0700 "${LOCAL_OUTPUT}"
gcloud compute scp --recurse \
  "${instance}:${remote_dir}/evidence/*" \
  "${LOCAL_OUTPUT}/" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --tunnel-through-iap

(cd -- "${LOCAL_OUTPUT}" && shasum -a 256 --check SHA256SUMS)
cmp -- "${REPORT_DATA}" "${LOCAL_OUTPUT}/report-data.bin"
printf 'evidence_round=%s\n' "${round_id}" > "${LOCAL_OUTPUT}/collection.txt"
