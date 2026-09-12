#!/usr/bin/env bash

# Bundle the already-tested native research runner, without rebuilding it.
set -euo pipefail
umask 077

output="${1:?usage: package-oram-build.sh NEW_OUTPUT_DIRECTORY}"
[[ ! -e "${output}" ]] || { echo 'output already exists' >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'native Linux x86_64 build evidence required' >&2
  exit 1
}
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || {
  echo 'refusing build evidence for a dirty source checkout' >&2
  exit 1
}

# Keep the workflow's documented build invocation free of ambient overrides.
# Inspect names/emptiness only; never print arbitrary environment values.
for variable in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET \
  CARGO_BUILD_RUSTFLAGS RUSTC RUSTC_BOOTSTRAP RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
  CC CXX AR CFLAGS CXXFLAGS CPPFLAGS LDFLAGS \
  ${!CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_@} ${!CARGO_PROFILE_RELEASE_@}; do
  [[ -z "${!variable:-}" ]] || {
    echo "refusing ambient build override: ${variable}" >&2
    exit 1
  }
done

binary=target/release/zainod-oram
[[ -f "${binary}" && ! -L "${binary}" && -x "${binary}" ]] || {
  echo 'missing regular executable research runner' >&2
  exit 1
}
# Verify the ELF header independently of the runner's version string.
header="$(od -An -tx1 -N20 "${binary}" | tr -d ' \n')"
[[ "${header:0:12}" == 7f454c460201 && "${header:36:4}" == 3e00 ]] || {
  echo 'runner is not little-endian ELF64 for x86_64' >&2
  exit 1
}

source_commit="$(git rev-parse --verify HEAD)"
source_tree="$(git rev-parse --verify 'HEAD^{tree}')"
binary_sha="$(sha256sum "${binary}" | cut -d ' ' -f 1)"
lock_sha="$(sha256sum Cargo.lock | cut -d ' ' -f 1)"
mkdir -m 0700 -- "${output}"
install -m 0755 -- "${binary}" "${output}/zainod-oram"
cp -- Cargo.lock "${output}/Cargo.lock"
rustc --version --verbose > "${output}/rustc-version.txt"
cargo --version --verbose > "${output}/cargo-version.txt"
cc --version > "${output}/cc-version.txt"
ld --version > "${output}/ld-version.txt"
readelf --file-header --program-headers --dynamic "${binary}" > "${output}/elf-linkage.txt"

jq -n \
  --arg source_commit "${source_commit}" \
  --arg source_tree "${source_tree}" \
  --arg binary_sha256 "${binary_sha}" \
  --arg cargo_lock_sha256 "${lock_sha}" \
  --arg repository "${GITHUB_REPOSITORY:?CI repository identity required}" \
  --arg workflow_commit "${GITHUB_SHA:?CI workflow commit required}" \
  --arg run_id "${GITHUB_RUN_ID:?CI run identity required}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:?CI run attempt required}" \
  '{schema:"zaino-oram-native-build-v1", source_commit:$source_commit,
    source_tree:$source_tree, source_dirty:false,
    binary_sha256:$binary_sha256, cargo_lock_sha256:$cargo_lock_sha256,
    repository:$repository, workflow_commit:$workflow_commit,
    run_id:$run_id, run_attempt:$run_attempt,
    build_command:"cargo build -p zainod-oram --all-features --locked --release",
    environment_policy:"listed_compiler_target_and_release_overrides_absent",
    target_os:"linux", target_arch:"x86_64", profile:"release",
    scope:"unsigned_ci_build_identity_only"}' > "${output}/build.json"

(
  cd -- "${output}"
  sha256sum zainod-oram Cargo.lock build.json \
    rustc-version.txt cargo-version.txt cc-version.txt ld-version.txt \
    elf-linkage.txt > SHA256SUMS
  sha256sum --check SHA256SUMS
  [[ "$(sha256sum zainod-oram | cut -d ' ' -f 1)" == "${binary_sha}" ]]
  [[ "$(sha256sum Cargo.lock | cut -d ' ' -f 1)" == "${lock_sha}" ]]
)
