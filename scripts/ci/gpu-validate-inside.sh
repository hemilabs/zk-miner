#!/usr/bin/env bash
# Inside a stock image (see gpu-validate.sh): mine on every GPU with the release's binaries.
#
# The image adds nothing a host would not have: CA certificates, which every installed system carries
# and Ubuntu's container images leave out, and the NVIDIA driver's own libraries, registered with the
# loader as the driver's package does. It must hold no other GPU software, which is checked first.
set -euo pipefail

echo "== the image: $(. /etc/os-release && echo "$PRETTY_NAME"), $(ldd --version | head -n 1)"
if command -v apt-get >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    ca-certificates >/dev/null
elif command -v dnf >/dev/null; then
  [ -e /etc/pki/tls/certs/ca-bundle.crt ] || dnf install -y -q ca-certificates
fi
if [ -d /opt/nvidia-driver/lib ]; then
  echo /opt/nvidia-driver/lib > /etc/ld.so.conf.d/zz-nvidia-driver.conf
  ldconfig
fi
if ldconfig -p | grep -E 'lib(amdhip64|hsa-runtime64|ze_loader|ze_intel_gpu|igc|sycl|cudart)\.so'; then
  echo "this image has GPU runtime libraries of its own: it would not show what the release needs" >&2
  exit 1
fi
ls /dev/dri /dev/kfd 2>/dev/null | tr '\n' ' '; echo
command -v nvidia-smi >/dev/null && nvidia-smi -L

echo "== mining on every GPU"
z=/opt/zkminer
p=$z/provers
export HOME=/cache/home
export ZKMINER_LOCALNET_MINE_ALL=1
export ZKMINER_LOCALNET_ZKMINER=$z/zkminer
export ZKMINER_LOCALNET_WORKERS=$p/zkminer-prove-risc0-cuda:$p/zkminer-prove-risc0-rocm:$p/zkminer-prove-risc0-intel
export ZKMINER_LOCALNET_SP1_WORKER=$p/zkminer-prove-sp1
export ZKMINER_LOCALNET_TMPDIR=/tmp/localnet
export ANVIL=/opt/kit/anvil
export SP1_GROTH16_CIRCUIT_PATH=/cache/sp1-circuits/groth16
export CUDA_DEVICE_ORDER=${CUDA_DEVICE_ORDER:-PCI_BUS_ID}
mkdir -p "$ZKMINER_LOCALNET_TMPDIR"
env | grep -E '^(ZKMINER_|SP1_|CUDA_)' | sort
/opt/kit/localnet mines_on_every_gpu --exact --ignored --nocapture --test-threads=1
