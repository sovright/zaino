#!/usr/bin/env bash

set -euo pipefail

readonly INPUT="${1:-report-data.bin}"
readonly OUTPUT_DIR="${2:-evidence}"

[[ -f "${INPUT}" ]] || {
  echo "missing report-data input: ${INPUT}" >&2
  exit 1
}
[[ "$(wc -c < "${INPUT}")" -eq 64 ]] || {
  echo "report-data input must be exactly 64 bytes" >&2
  exit 1
}
[[ ! -e "${OUTPUT_DIR}" ]] || {
  echo "refusing to replace output: ${OUTPUT_DIR}" >&2
  exit 1
}

mkdir -m 0700 "${OUTPUT_DIR}"
sudo modprobe tdx_guest
sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
sudo mkdir /sys/kernel/config/tsm/report/zaino0
cleanup_report() {
  sudo rmdir /sys/kernel/config/tsm/report/zaino0
}
trap cleanup_report EXIT

sudo cp -- "${INPUT}" /sys/kernel/config/tsm/report/zaino0/inblob
sudo cp -- /sys/kernel/config/tsm/report/zaino0/outblob "${OUTPUT_DIR}/quote.bin"
sudo chown "$(id -u):$(id -g)" "${OUTPUT_DIR}/quote.bin"
cp -- "${INPUT}" "${OUTPUT_DIR}/report-data.bin"
sudo cp -- /sys/firmware/acpi/tables/data/CCEL "${OUTPUT_DIR}/ccel.bin"
sudo chown "$(id -u):$(id -g)" "${OUTPUT_DIR}/ccel.bin"

{
  uname -a
  grep -E 'MemTotal|SwapTotal' /proc/meminfo
  printf 'tdx_guest='
  if [[ -d /sys/module/tdx_guest ]]; then
    printf 'loaded\n'
  else
    printf 'absent\n'
  fi
} > "${OUTPUT_DIR}/guest-environment.txt"

(cd -- "${OUTPUT_DIR}" && \
  sha256sum quote.bin report-data.bin ccel.bin guest-environment.txt > SHA256SUMS)
