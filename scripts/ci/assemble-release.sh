#!/usr/bin/env bash
# Assembles the release from the build artifacts (.github/workflows/release.yml):
#
#   assemble-release.sh <artifacts dir> <release dir> <validation kit dir>
#
# <artifacts dir> holds one directory per build-docker.yml target (dist-cli/, dist-rocm/, ...), as
# actions/download-artifact leaves them. The release gets:
# - the CLI and the NVIDIA and OpenVM provers as single files, as before;
# - zkminer-provers-amd-linux-x86_64.tar.zst: the risc0 ROCm worker with ROCm 7.1's HIP runtime
#   (zkminer-rocm/), and the SP1 HIP server with ROCm 10.1's (sp1-gpu-server-hip-lib/);
# - zkminer-provers-intel-linux-x86_64.tar.zst: the risc0 Intel worker, the SP1 SYCL server, and
#   zkminer-intel/ (the risc0 kernels, libsp1_gpu_sycl.so, oneAPI's SYCL runtime, Intel's compute
#   stack), with sp1-gpu-server-sycl-lib linked to it;
# - SHA256SUMS over all of it.
# Each tarball unpacks into the provers directory (~/.zkminer/provers/) beside the single files.
# The localnet test and anvil, which the GPU validation runs, go to <validation kit dir>, not the
# release.
set -euo pipefail

in=$(readlink -f "${1:?usage: $0 <artifacts dir> <release dir> <validation kit dir>}")
out=${2:?}
kit=${3:?}
mkdir -p "$out" "$kit"
out=$(readlink -f "$out")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

need() { [ -s "$1" ] || { echo "::error::missing from the build artifacts: ${1#"$in"/}" >&2; exit 1; }; }

# Artifacts lose their file modes on upload; give them back.
modes() { # <dir>
  find "$1" -type f -exec chmod 0644 {} +
  find "$1" -type f \( -name '*.so' -o -name '*.so.*' \) -exec chmod 0755 {} +
  for f in "$1"/zkminer* "$1"/sp1-gpu-server* "$1"/localnet "$1"/anvil; do
    [ -f "$f" ] && case "$f" in *.txt|*.sha256) ;; *) chmod 0755 "$f" ;; esac
  done
  return 0
}

echo "== single files"
for f in dist-cli/zkminer dist-cli-windows/zkminer.exe dist-openvm/zkminer-prove-openvm \
         dist-cuda/zkminer-prove-risc0-cuda dist-sp1/zkminer-prove-sp1 dist-sp1-server/sp1-gpu-server \
         dist-sp1-server/libcudart.so.12 dist-sp1-server/libcudart.so.12.LICENSE.txt; do
  need "$in/$f"
  cp "$in/$f" "$out/"
done
modes "$out"

echo "== AMD"
amd=$work/amd
mkdir -p "$amd"
need "$in/dist-rocm/zkminer-prove-risc0-rocm"
need "$in/dist-rocm/zkminer-rocm/lib/libamdhip64.so.7"
need "$in/dist-sp1-server-hip/sp1-gpu-server-hip"
need "$in/dist-sp1-server-hip/sp1-gpu-server-hip-lib/libamdhip64.so.7"
cp -r "$in/dist-rocm/." "$in/dist-sp1-server-hip/." "$amd/"
rm -f "$amd"/*.sha256
modes "$amd"

echo "== Intel"
intel=$work/intel
mkdir -p "$intel"
need "$in/dist-intel/zkminer-prove-risc0-intel"
need "$in/dist-sp1-server-sycl/sp1-gpu-server-sycl"
need "$in/dist-intel/zkminer-intel/lib/libze_intel_gpu.so.1"
need "$in/dist-sp1-server-sycl/zkminer-intel/lib/libsp1_gpu_sycl.so"
cp "$in/dist-intel/zkminer-prove-risc0-intel" "$in/dist-sp1-server-sycl/sp1-gpu-server-sycl" "$intel/"
cp -r "$in/dist-intel/zkminer-intel" "$intel/"
# The SP1 server's libraries join the worker's. Both images stage oneAPI and the compute stack from
# the same toolchain stage, so a library both have must be the same file.
(cd "$in/dist-sp1-server-sycl/zkminer-intel" && find . -type f) | while read -r rel; do
  from=$in/dist-sp1-server-sycl/zkminer-intel/$rel
  to=$intel/zkminer-intel/$rel
  if [ -e "$to" ]; then
    cmp -s "$from" "$to" || { echo "::error::zkminer-intel/$rel differs between the risc0 and SP1 builds" >&2; exit 1; }
  else
    mkdir -p "$(dirname "$to")"
    cp "$from" "$to"
  fi
done
ln -s zkminer-intel/lib "$intel/sp1-gpu-server-sycl-lib"
modes "$intel"

pack() { # <dir> <tarball>
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' -C "$1" -cf - . |
    zstd -q -19 -T0 -o "$out/$2"
  echo "$2: $(du -sh "$1" | cut -f1) unpacked, $(du -h "$out/$2" | cut -f1) packed"
}
pack "$amd" zkminer-provers-amd-linux-x86_64.tar.zst
pack "$intel" zkminer-provers-intel-linux-x86_64.tar.zst

echo "== validation kit"
need "$in/dist-localnet-test/localnet"
need "$in/dist-localnet-test/anvil"
cp "$in/dist-localnet-test/localnet" "$in/dist-localnet-test/anvil" "$kit/"
modes "$kit"

echo "== SHA256SUMS"
(cd "$out" && rm -f SHA256SUMS && sha256sum -- * > SHA256SUMS && cat SHA256SUMS)
