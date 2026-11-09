#!/usr/bin/env bash
# Intel's graphics compiler IGC (libigc.so.2, libigdfcl.so.2, libopencl-clang2.so.16: it compiles
# SPIR-V kernels for a card nothing was compiled for in advance) with the LLVM it is built on, and
# the memory manager gmmlib (libigdgmm.so.12), from source into PREFIX. See intel-gpu-build-lib.sh.
#
#   build-intel-igc.sh <prefix>
set -euo pipefail
# shellcheck source=intel-gpu-build-lib.sh
. "$(dirname "$(readlink -f "$0")")/intel-gpu-build-lib.sh"

echo "== gmmlib 22.9.0"
fetch gmmlib intel/gmmlib 5f1c01f46ecbfceec59faef9bf3ba4625fc88fed intel-gmmlib-22.9.0
cmake_build gmmlib build-gmmlib
license gmmlib gmmlib/LICENSE.md

echo "== IGC 2.28.4, with LLVM 16.0.6"
fetch igc intel/intel-graphics-compiler 6b2da2b8a2661adeaebaacbbbf7f35b5ee9e8124 v2.28.4
# A quadratic loop in MergeAllocas, which took the ahead-of-time compile of risc0's eval_check about
# 48 minutes per Intel GPU target instead of about 5. The same code comes out; see the patch.
patch -d igc -p1 --forward < "$(dirname "$(readlink -f "$0")")/patches/igc-2.28.4-mergeallocas-start-index.patch"
fetch vc-intrinsics intel/vc-intrinsics a833c8e165ebcd6c44dbb8f771ab7197fc752472 v0.24.3
fetch SPIRV-Tools KhronosGroup/SPIRV-Tools 28a883ba4c67f58a9540fb0651c647bb02883622
fetch SPIRV-Headers KhronosGroup/SPIRV-Headers 9268f3057354a2cb65991ba5f38b16d81e803692
fetch llvm-project llvm/llvm-project 7cbf1a2591520c2491aa35339f227775f4d3adf6 llvmorg-16.0.6
fetch llvm-project/llvm/projects/opencl-clang intel/opencl-clang 7161d7c6d97da80f12739cebad9bf508555bbfd9
fetch llvm-project/llvm/projects/llvm-spirv KhronosGroup/SPIRV-LLVM-Translator c13fcf6c5072483d50993e9175087bead3b7bf8a
# LLVM from the sources above (Source mode), never a prebuilt LLVM the image might have; opaque
# pointers, as Intel's v2.28.4 packages are built (its release notes: a local build defaults to typed
# pointers). The layout above is the one IGC's Ubuntu build guide gives.
cmake -S igc -B build-igc -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DIGC_OPTION__LLVM_MODE=Source \
  -DIGC_OPTION__LLVM_PREFERRED_VERSION=16.0.6 \
  -DIGC_OPTION__API_ENABLE_OPAQUE_POINTERS=ON 2>&1 | tee igc-configure.log
# Every patch opencl-clang tried must have applied ("Not present - Applying: ..."); an empty log
# after "Not present - " is a `git am` that failed, which it does not stop for.
applied=$(grep -c '\[OPENCL-CLANG\] Not present - Applying' igc-configure.log || true)
skipped=$(grep -cE '\[OPENCL-CLANG\] Not present - *$' igc-configure.log || true)
echo "opencl-clang patches applied: $applied, failed: $skipped"
if [ "$skipped" != 0 ] || [ "$applied" = 0 ]; then
  echo "opencl-clang's patches did not all apply" >&2
  exit 1
fi
cmake --build build-igc -j "$jobs"
cmake --install build-igc
license igc igc/LICENSE.md
license llvm llvm-project/llvm/LICENSE.TXT
license opencl-clang llvm-project/llvm/projects/opencl-clang/LICENSE
license spirv-llvm-translator llvm-project/llvm/projects/llvm-spirv/LICENSE.TXT
license vc-intrinsics vc-intrinsics/LICENSE.md
license spirv-tools SPIRV-Tools/LICENSE
