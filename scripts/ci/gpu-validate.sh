#!/usr/bin/env bash
# The release's GPU validation, on the self-hosted runner (label zkminer-gpu, set up by
# setup-gpu-runner.sh): mines with the release's binaries on every GPU of the host, inside stock
# distribution images that hold no GPU software, so that what it proves is that a host needs nothing
# but its GPU driver.
#
#   gpu-validate.sh <release dir> <validation kit dir>
#
# Each image gets, from the host:
# - the GPU device nodes: /dev/kfd and /dev/dri (AMD, Intel), /dev/nvidia* (NVIDIA);
# - the NVIDIA driver's user-space libraries and nvidia-smi, which are part of that driver (a host
#   with an NVIDIA card has them; the NVIDIA Container Toolkit passes the same set);
# - the release, unpacked as a host installs it, and the validation kit (the localnet test, anvil);
# - a cache that outlives the run: SP1's Groth16 circuit (8 GB), compiled-kernel caches, anvil's RPC
#   cache.
# It runs crates/zkminer-cli/tests/localnet.rs's `mines_on_every_gpu`: a localnet fork of 743111 with
# risc0 and SP1 jobs, which the miner must claim, prove on every card and fulfil, each proof
# verified on chain.
#
# Settings (environment, or ~/.config/zkminer-ci/validate.env on the runner, for what is particular to
# the host's cards):
# - GPU_VALIDATE_IMAGES: the images, space-separated (default Ubuntu 22.04);
# - ZKMINER_LOCALNET_*: passed to the test (e.g. ZKMINER_LOCALNET_RISC0_PO2 for cards without a
#   benchmark, ZKMINER_LOCALNET_FIB_N), and ZKMINER_MIN_AVAILABLE_VRAM_MB;
# - ZKMINER_CI_CACHE: the cache directory (default ~/.cache/zkminer-ci).
set -euo pipefail

release=$(readlink -f "${1:?usage: $0 <release dir> <validation kit dir>}")
kit=$(readlink -f "${2:?usage: $0 <release dir> <validation kit dir>}")
ci=$(dirname "$(readlink -f "$0")")
settings=${XDG_CONFIG_HOME:-$HOME/.config}/zkminer-ci/validate.env
if [ -f "$settings" ]; then
  echo "settings from $settings"
  set -a
  # shellcheck disable=SC1090
  . "$settings"
  set +a
fi
images=${GPU_VALIDATE_IMAGES:-docker.io/library/ubuntu:22.04}
cache=${ZKMINER_CI_CACHE:-$HOME/.cache/zkminer-ci}
mkdir -p "$cache/home" "$cache/sp1-circuits"

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/zkminer-gpu-validate.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$ci/unpack-provers.sh" "$release" "$work/zkminer/provers" >/dev/null
chmod 0755 "$kit/localnet" "$kit/anvil"

args=(--rm --pull=newer --group-add keep-groups --shm-size=46g
  --security-opt label=disable
  -v "$work/zkminer:/opt/zkminer:ro" -v "$kit:/opt/kit:ro" -v "$ci:/ci:ro" -v "$cache:/cache")

# GPUs.
for d in /dev/kfd /dev/dri /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools /dev/nvidia-modeset \
         /dev/nvidia[0-9]*; do
  [ -e "$d" ] && args+=(--device "$d")
done

# The NVIDIA driver's user-space part: its libraries, under the names programs load them by, and
# nvidia-smi. Nothing from a CUDA toolkit.
if [ -e /dev/nvidiactl ]; then
  while read -r name path; do
    args+=(-v "$(readlink -f "$path"):/opt/nvidia-driver/lib/$name:ro")
  done < <(ldconfig -p | awk '$1 ~ /^lib(cuda|nvidia-(ml|ptxjitcompiler|nvvm|gpucomp|cfg))\.so\.[0-9]+$/ && $NF ~ /^\// {print $1, $NF}' | sort -u -k1,1)
  smi=$(command -v nvidia-smi) && args+=(-v "$(readlink -f "$smi"):/usr/bin/nvidia-smi:ro")
fi

# What the test is told, from the environment or the settings file.
for var in $(compgen -e | grep -E '^(ZKMINER_LOCALNET_|ZKMINER_MIN_AVAILABLE_VRAM_MB$|CUDA_DEVICE_ORDER$)'); do
  args+=(-e "$var")
done

status=0
for image in $images; do
  echo "::group::$image"
  if podman run "${args[@]}" "$image" bash /ci/gpu-validate-inside.sh; then
    echo "ok: $image"
  else
    echo "::error::GPU validation failed in $image"
    status=1
  fi
  echo "::endgroup::"
done
exit $status
