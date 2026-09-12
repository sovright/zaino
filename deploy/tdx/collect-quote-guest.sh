#!/usr/bin/env bash

set -euo pipefail
umask 077

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

collect_bounded() {
  local source="$1" destination="$2" limit="$3" bytes
  # Sysfs/ConfigFS nodes may advertise a size unrelated to their stream length.
  # Read one byte beyond the verifier's cap, then refuse incomplete evidence.
  # The caller owns destination; only the privileged stream read needs sudo.
  # shellcheck disable=SC2024
  sudo head -c "$((limit + 1))" -- "${source}" > "${destination}"
  bytes="$(wc -c < "${destination}")"
  if (( bytes == 0 || bytes > limit )); then
    echo "evidence stream is empty or exceeds its bound: ${source}" >&2
    return 1
  fi
}

sudo cp -- "${INPUT}" /sys/kernel/config/tsm/report/zaino0/inblob
# Read the virtual ConfigFS attribute as a stream. The caller owns OUTPUT_DIR;
# sudo is needed only to read the node, not to create the local artifact.
collect_bounded /sys/kernel/config/tsm/report/zaino0/outblob "${OUTPUT_DIR}/quote.bin" 16384
cp -- "${INPUT}" "${OUTPUT_DIR}/report-data.bin"
# These are distinct artifacts: the ACPI table declares the event-log area.
collect_bounded /sys/firmware/acpi/tables/CCEL "${OUTPUT_DIR}/ccel-table.bin" 4096
collect_bounded /sys/firmware/acpi/tables/data/CCEL "${OUTPUT_DIR}/ccel.bin" 1048576

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
  sha256sum quote.bin report-data.bin ccel-table.bin ccel.bin guest-environment.txt > SHA256SUMS)
