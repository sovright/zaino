#!/usr/bin/env bash

# Exercise stream collection without sudo, ConfigFS, or a TDX machine.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf -- "${stage}"' EXIT
mkdir "${stage}/bin"
head -c 64 /dev/zero > "${stage}/report-data.bin"

cat > "${stage}/bin/sudo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  modprobe|mountpoint|mkdir|rmdir|cp) exit 0 ;;
  head)
    case "$5" in
      /sys/kernel/config/tsm/report/zaino0/outblob) stream=quote; size=8000 ;;
      /sys/firmware/acpi/tables/CCEL) stream=table; size=56 ;;
      /sys/firmware/acpi/tables/data/CCEL) stream=log; size=262144 ;;
      *) exit 90 ;;
    esac
    if [[ "${MOCK_STREAM:-}" == "${stream}" ]]; then
      case "${MOCK_FAILURE}" in
        empty) exit 0 ;;
        oversized) size="$3" ;;
        missing) exit 1 ;;
        *) exit 91 ;;
      esac
    fi
    head -c "${size}" /dev/zero
    ;;
  *) exit 92 ;;
esac
MOCK
cat > "${stage}/bin/grep" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" == 3 && "$1" == -E && "$2" == 'MemTotal|SwapTotal' && "$3" == /proc/meminfo ]]; then
  printf 'MemTotal: 16384 kB\nSwapTotal: 0 kB\n'
else
  exit 93
fi
MOCK
chmod 0700 "${stage}/bin/sudo" "${stage}/bin/grep"
export PATH="${stage}/bin:${PATH}"

bash "${script_dir}/../collect-quote-guest.sh" "${stage}/report-data.bin" "${stage}/ok"
(cd "${stage}/ok" && shasum -a 256 --check SHA256SUMS)
cmp "${stage}/report-data.bin" "${stage}/ok/report-data.bin"
[[ "$(wc -l < "${stage}/ok/SHA256SUMS")" -eq 5 ]]
[[ "$(wc -c < "${stage}/ok/quote.bin")" -eq 8000 ]]
[[ "$(wc -c < "${stage}/ok/ccel-table.bin")" -eq 56 ]]
[[ "$(wc -c < "${stage}/ok/ccel.bin")" -eq 262144 ]]

for stream in quote table log; do
  for failure in empty oversized missing; do
    output="${stage}/${stream}-${failure}"
    if MOCK_STREAM="${stream}" MOCK_FAILURE="${failure}" \
      bash "${script_dir}/../collect-quote-guest.sh" "${stage}/report-data.bin" "${output}" \
      > "${stage}/stdout" 2> "${stage}/stderr"; then
      echo "unexpected success: ${stream}/${failure}" >&2
      exit 1
    fi
    [[ ! -e "${output}/SHA256SUMS" ]]
  done
done
printf 'collector smoke: complete bundle and nine stream failures passed\n'
