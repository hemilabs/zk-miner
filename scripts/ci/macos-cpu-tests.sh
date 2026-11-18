#!/usr/bin/env bash
# The macOS CI tests that need no GPU (B9-CI; build-macos.yml's cpu-tests job):
#
#   macos-cpu-tests.sh
#
# They build with the kit's settings (minimum macOS, the Metal compiler wrapper: assemble-macos.sh
# ASSEMBLE_ENV_ONLY=1 writes them), in their own job: the tests' dev-dependencies change the features
# of most dependencies, so their build shares little with the release build and both together do
# not fit the runner's 14 GB of disk (docs/ci-macos.md).
# 1. The Metal worker's unit tests (release, as Makefile.mac mac-test-miner runs them), except the
#    ones that read this Mac's Metal device or power state (MACOS_GPU_TESTS below): a CI runner may have no Apple GPU
#    (a VM's paravirtual device), and 14 GB of RAM where the worker wants 16. The metal-probe job
#    reports the device instead.
#    Then the guests' build intermediates are deleted (macos-prune-target.sh --guests; disk).
# 2. zkminer-prover's discovery and dispatcher tests (as mac-test-miner), except the ones that
#    assert this Mac's GPU, input devices and power source (MACOS_HOST_TESTS below).
# 3. scripts/ci/test-metal-tc.sh with risc0-build-kernel from the pinned risc0 checkout: the Metal
#    compiler wrapper the kit uses, through risc0-build-kernel and cargo (compiles kernels, runs none).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$ci/../.." && pwd)
envf=$(mktemp "${TMPDIR:-/tmp}/zkminer-kit-env.XXXXXX")
trap 'rm -f "$envf"' EXIT
ASSEMBLE_ENV_ONLY=1 ASSEMBLE_ENV_OUT=$envf "$ci/assemble-macos.sh" "${TMPDIR:-/tmp}/zkminer-env-only"
# shellcheck disable=SC1090
. "$envf"
export NVCC=off HIPCC=off
cd "$repo"

# Tests that need an Apple Silicon GPU (or a 16 GB Mac): run by Makefile.mac mac-test-miner on a Mac.
# Also the ones that assert the host's own state (an input device's idle time, a power source, the
# thermal state): a headless or VM runner may have none of these, which says nothing about the kit.
MACOS_GPU_TESTS=(
  metal_host::tests::enforcement_on_this_mac
  metal_host::tests::this_mac_is_supported
  metal_start::tests::this_macs_gpu_architecture_is_readable
  metal_start::tests::this_macs_power_state_is_readable
)
MACOS_HOST_TESTS=(
  discovery::tests::this_mac_reports_one_apple_gpu
  discovery::tests::this_macs_owner_probes_answer
  discovery::tests::this_macs_power_state_answers_and_is_full
)
skips=()
for t in "${MACOS_GPU_TESTS[@]}"; do skips+=(--skip "$t"); done
host_skips=()
for t in "${MACOS_HOST_TESTS[@]}"; do host_skips+=(--skip "$t"); done

echo "== the Metal worker's unit tests (without ${MACOS_GPU_TESTS[*]})"
cargo test --locked --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal -- "${skips[@]}"
"$ci/macos-disk.sh" "after the worker's tests"
# The rest builds no guest: their builds' intermediates (~3.5 GB) can go (disk).
"$ci/macos-prune-target.sh" --guests "$repo"

echo "== zkminer-prover discovery and dispatcher (without ${MACOS_HOST_TESTS[*]})"
cargo test --locked --release -p zkminer-prover --lib -- discovery:: dispatcher:: "${host_skips[@]}"

echo "== test-metal-tc.sh (the Metal compiler wrapper through risc0-build-kernel)"
bk=$(cargo metadata --locked --format-version 1 | python3 -I -c 'import json, os, sys
m = json.load(sys.stdin)
print(next(os.path.dirname(p["manifest_path"]) for p in m["packages"] if p["name"] == "risc0-build-kernel"))')
# Its one-kernel crate lives outside this repository, so rust-toolchain.toml does not reach it, and
# the runner's rustup may have no default toolchain.
RUSTUP_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml) "$ci/test-metal-tc.sh" "$bk"
