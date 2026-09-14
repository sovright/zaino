#!/usr/bin/env bash
# Authenticate one offline workload output against independently reviewed facts.
set -euo pipefail
export LC_ALL=C
fail() { echo "rootfs workload input refused: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: verify-workload-output.sh WORKLOAD_OUTPUT TRUSTED_EXPECTATIONS.json'
workload=$(cd -- "$1" && pwd -P) || fail 'missing workload output'
expectations=$(cd -- "$(dirname -- "$2")" && pwd -P)/$(basename -- "$2")
[[ -f "$expectations" && ! -L "$expectations" ]] || fail 'missing trusted expectations'
for tool in cmp find jq readelf sha256sum sort stat; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done

jq -e '
  .schema == "zaino-rootfs-trusted-workload-v1" and
  (.producer | type == "object" and .schema == "zaino-offline-workload-build-v1" and
    .network_during_build == "disabled" and .init_status == "deferred-until-authenticated-rootfs-binding" and
    .scope == "evidence-agent-and-runtime-closure;not-init;not-image;not-boot;not-TEE-admission") and
  (.accepted_runs | type == "array" and length == 2 and
    ([.[].run_label] == ["run-1","run-2"]) and
    all(.[]; (.output_sha256s_sha256 | test("^[0-9a-f]{64}$")))) and
  (keys == ["accepted_runs","producer","schema"])
' "$expectations" >/dev/null || fail 'invalid trusted expectations'

expected_roots=$(printf '%s\n' artifacts build-run.json canonical-runtime-closure.tsv evidence-agent.link-map init-status.txt native-tool-versions.txt OUTPUT-MODES.tsv OUTPUT-SHA256SUMS runtime-closure.txt runtime-libs rust-tool-versions.txt SHA256SUMS | sort)
actual_roots=$(find "$workload" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
[[ "$actual_roots" == "$expected_roots" ]] || fail 'unexpected top-level path'
[[ -d "$workload/artifacts" && ! -L "$workload/artifacts" && -d "$workload/runtime-libs" && ! -L "$workload/runtime-libs" ]] || fail 'invalid output directories'
for file in build-run.json canonical-runtime-closure.tsv evidence-agent.link-map init-status.txt native-tool-versions.txt OUTPUT-MODES.tsv OUTPUT-SHA256SUMS runtime-closure.txt rust-tool-versions.txt SHA256SUMS artifacts/tdx-evidence-agent; do
  [[ -f "$workload/$file" && ! -L "$workload/$file" ]] || fail "nonregular required file: $file"
done
[[ $(find "$workload/artifacts" -mindepth 1 -maxdepth 1 -printf '%f\n') == tdx-evidence-agent ]] || fail 'unexpected artifact'
if find "$workload" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then fail 'special file or symlink'; fi
if find "$workload" -xdev -type f -perm /6000 -print -quit | grep -q .; then fail 'set-id input file'; fi
while IFS= read -r file; do
  case "$file" in
    "$workload/artifacts/tdx-evidence-agent") expected_mode=755 ;;
    "$workload/runtime-libs/"*) expected_mode=$(awk -F '\t' -v path="/${file#"$workload/runtime-libs/"}" '$3==path {print $1}' "$workload/canonical-runtime-closure.tsv") ;;
    *) expected_mode=644 ;;
  esac
  [[ $(stat -c %a "$file") == "$expected_mode" ]] || fail "unexpected file mode: ${file#"$workload/"}"
done < <(find "$workload" -xdev -type f -print | sort)
while IFS= read -r directory; do
  if [[ "$directory" == "$workload" || "$directory" == "$workload/artifacts" || "$directory" == "$workload/runtime-libs" ]]; then expected_mode=700; else expected_mode=755; fi
  [[ $(stat -c %a "$directory") == "$expected_mode" ]] || fail "unexpected directory mode: ${directory#"$workload/"}"
done < <(find "$workload" -xdev -type d -print | sort)

run_label=$(jq -r '.run_label // empty' "$workload/build-run.json")
[[ "$run_label" == run-1 || "$run_label" == run-2 ]] || fail 'invalid run label'
actual_producer=$(mktemp); expected_producer=$(mktemp)
trap 'rm -f -- "$actual_producer" "$expected_producer"' EXIT
jq -S 'del(.run_label)' "$workload/build-run.json" > "$actual_producer"
jq -S '.producer' "$expectations" > "$expected_producer"
cmp -s "$actual_producer" "$expected_producer" || fail 'producer provenance differs from reviewed expectation'

outer_sha=$(sha256sum "$workload/OUTPUT-SHA256SUMS" | awk '{print $1}')
[[ "$outer_sha" == "$(jq -r --arg run "$run_label" '.accepted_runs[] | select(.run_label == $run) | .output_sha256s_sha256' "$expectations")" ]] || fail 'output manifest is not reviewer accepted'
(cd "$workload" && sha256sum --strict -c OUTPUT-SHA256SUMS >/dev/null) || fail 'outer checksum mismatch'
(cd "$workload" && sha256sum --strict -c SHA256SUMS >/dev/null) || fail 'inner checksum mismatch'
expected_outer=$(find "$workload" -xdev -type f ! -name OUTPUT-SHA256SUMS -printf './%P\n' | sort)
manifest_outer=$(awk '{print $2}' "$workload/OUTPUT-SHA256SUMS" | sort)
[[ "$expected_outer" == "$manifest_outer" ]] || fail 'outer manifest file set mismatch'
expected_inner=$(printf '%s\n' artifacts/tdx-evidence-agent; find "$workload/runtime-libs" -type f -printf 'runtime-libs/%P\n'; printf '%s\n' canonical-runtime-closure.tsv init-status.txt native-tool-versions.txt rust-tool-versions.txt)
expected_inner=$(printf '%s\n' "$expected_inner" | sort)
manifest_inner=$(awk '{print $2}' "$workload/SHA256SUMS" | sort)
[[ "$expected_inner" == "$manifest_inner" ]] || fail 'inner manifest file set mismatch'

agent="$workload/artifacts/tdx-evidence-agent"
[[ $(stat -c %a "$agent") == 755 ]] || fail 'agent mode'
readelf -hW "$agent" | grep -Eq 'Class:[[:space:]]+ELF64' || fail 'agent is not ELF64'
readelf -hW "$agent" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || fail 'agent architecture'
readelf -hW "$agent" | grep -Eq 'Type:[[:space:]]+DYN' || fail 'agent is not PIE'
interpreter=$(readelf -lW "$agent" | awk -F': ' '/Requesting program interpreter/ {gsub(/]/,"",$2); print $2}')
[[ "$interpreter" =~ ^/(lib|lib64)/[A-Za-z0-9+._/-]+$ && "$interpreter" != *..* ]] || fail 'unsafe ELF interpreter'
[[ -f "$workload/runtime-libs$interpreter" && ! -L "$workload/runtime-libs$interpreter" ]] || fail 'missing actual ELF interpreter'

declare -A provided=()
while IFS= read -r library; do
  relative=${library#"$workload/runtime-libs"}
  mode=$(stat -c %a "$library")
  [[ "$relative" == /* && ( "$mode" == 644 || "$mode" == 755 ) ]] || fail 'runtime library path or mode'
  digest=$(sha256sum "$library" | awk '{print $1}')
  [[ $(awk -F '\t' -v mode="$mode" -v digest="$digest" -v path="$relative" '$1==mode && $2==digest && $3==path {count++} END {print count+0}' "$workload/canonical-runtime-closure.tsv") == 1 ]] || fail 'runtime library differs from canonical closure'
  readelf -hW "$library" | grep -Eq 'Class:[[:space:]]+ELF64' || fail 'runtime library is not ELF64'
  base=${relative##*/}; [[ -z ${provided[$base]+x} ]] || fail "duplicate runtime basename: $base"
  provided[$base]=$relative
done < <(find "$workload/runtime-libs" -type f -print | sort)
[[ $(wc -l <"$workload/canonical-runtime-closure.tsv") == "${#provided[@]}" ]] || fail 'canonical runtime closure file set mismatch'
[[ ${#provided[@]} -gt 0 ]] || fail 'empty runtime closure'

declare -A needed=()
while IFS= read -r elf; do
  while IFS= read -r name; do [[ -z "$name" ]] || needed[$name]=1; done < <(readelf -dW "$elf" 2>/dev/null | awk -F'[][]' '/\(NEEDED\)/ {print $2}')
done < <(printf '%s\n' "$agent"; find "$workload/runtime-libs" -type f -print | sort)
for name in "${!needed[@]}"; do [[ -n ${provided[$name]+x} ]] || fail "missing parsed ELF dependency: $name"; done
for name in "${!provided[@]}"; do
  [[ "${provided[$name]}" == "$interpreter" || -n ${needed[$name]+x} ]] || fail "unreferenced runtime library: ${provided[$name]}"
done
grep -Fx "init_artifact=deferred_until_rootfs_verity_cmdline_binding" "$workload/init-status.txt" >/dev/null || fail 'unexpected init status'
echo 'Authenticated reviewed workload provenance and parsed ELF runtime closure.'
