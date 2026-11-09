#!/usr/bin/env bash
# Inside a stock image (see check-release-libs.sh): ldd every binary and library of an unpacked
# release, each with the library path it gets at run time.
#
#   check-release-libs-inside.sh <provers dir>
set -uo pipefail
p=${1:?usage: $0 <provers dir>}
echo "$(ldd --version 2>&1 | head -n 1)"
fail=0

check() { # <file> [library path]
  local file=$1 path=${2:-} out bad
  out=$(env LD_LIBRARY_PATH="$path" ldd "$file" 2>&1)
  # The NVIDIA driver's own library is the host's to provide.
  bad=$(grep -E 'not found|version .* not found|not a dynamic' <<<"$out" |
    grep -vE '^\s*libcuda\.so\.1 => not found' || true)
  if [ -n "$bad" ]; then
    echo "FAIL ${file#"$p"/}${path:+ (library path ${path#"$p"/})}:"
    sed 's/^/    /' <<<"$bad"
    fail=1
  fi
}

check "$p/../zkminer"
check "$p/zkminer-prove-openvm"
check "$p/zkminer-prove-risc0-cuda"
check "$p/zkminer-prove-sp1"
check "$p/sp1-gpu-server" "$p"
check "$p/zkminer-prove-risc0-rocm"
check "$p/sp1-gpu-server-hip" "$p/sp1-gpu-server-hip-lib"
check "$p/zkminer-prove-risc0-intel"
check "$p/sp1-gpu-server-sycl" "$p/sp1-gpu-server-sycl-lib"
n=0
while IFS= read -r -d '' lib; do
  # A library loaded by a worker gets the worker's RPATH, which names its own directory.
  check "$lib" "$(dirname "$lib")"
  n=$((n + 1))
done < <(find "$p/zkminer-rocm/lib" "$p/sp1-gpu-server-hip-lib" "$p/zkminer-intel/lib" -type f -name '*.so*' -print0)
echo "checked 9 binaries and $n libraries"
[ $fail -eq 0 ] && echo "ok: everything loads with only the GPU driver to come from the host"
exit $fail
