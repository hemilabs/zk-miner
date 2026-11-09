#!/usr/bin/env bash
# ROCm 7.1.0's clang, AMD's LLVM at the commit `clang --version` names in rocm/dev-ubuntu-22.04:7.1
# (ROCm/llvm-project 1b0eada6), with one compile-time fix, into PREFIX/bin/clang-20. The rocm71-toolchain
# stage puts it in place of the image's.
#
# The fix (patches/llvm-rocm-7.1-codegenprepare-comesbefore.patch, from upstream LLVM e80f32fd20bf):
# CodeGenPrepare numbered the whole basic block for every instruction whose operands it considered
# sinking. That is quadratic in the block's length. risc0's rv32im eval_check for RDNA4 (gfx1200,
# gfx1201) is one kernel with every chain function inlined, and AMDGPU counts its many vector-element
# extracts as free to sink. With ROCm 7.1's own compiler each RDNA4 target takes hours: about 5 h for
# gfx1200 on a 32-core host, both targets about 4.5 h on CI's large runner. With the fix it takes about
# 8 minutes (gfx11, which never hit it: about 17).
# The fix orders the instructions the same way, so the code does not change: on gfx11-generic, the
# eval_check code object's .text, .rodata and notes are byte-identical to stock ROCm 7.1's, and so is
# the driver's whole job list.
#
#   build-rocm71-clang.sh <prefix>
set -euo pipefail
prefix=${1:?usage: $0 <prefix>}
commit=1b0eada6b0ee93e2e694c8c146d23fca90bc11c5
sha256=2c1d84869f8c952d1fa8912fdecc7af47bddd0889ebb351a0d8bdd0303186815
src=${SRC_DIR:-/tmp/rocm-llvm-src}
build=${BUILD_DIR:-/tmp/rocm-llvm-build}
patches=$(dirname "$(readlink -f "$0")")/patches
mkdir -p "$src" "$prefix/bin"

curl -fsSL --retry 3 -o /tmp/rocm-llvm.tar.gz "https://github.com/ROCm/llvm-project/archive/$commit.tar.gz"
echo "$sha256  /tmp/rocm-llvm.tar.gz" | sha256sum -c -
tar xzf /tmp/rocm-llvm.tar.gz -C "$src" --strip-components=1 \
  "llvm-project-$commit/llvm" "llvm-project-$commit/clang" "llvm-project-$commit/cmake" \
  "llvm-project-$commit/third-party"
rm /tmp/rocm-llvm.tar.gz
patch -d "$src" -p1 --forward < "$patches/llvm-rocm-7.1-codegenprepare-comesbefore.patch"

# AMD's targets, a release build without assertions, and the compression libraries AMD's clang links.
# The version string names AMD's source and says it is patched.
cmake -G Ninja -S "$src/llvm" -B "$build" -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD="AMDGPU;X86" -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_ENABLE_ZLIB=FORCE_ON -DLLVM_ENABLE_ZSTD=FORCE_ON \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DCLANG_INCLUDE_TESTS=OFF -DLLVM_PARALLEL_LINK_JOBS=2 \
  -DCLANG_VENDOR=AMD \
  -DCLANG_REPOSITORY_STRING="https://github.com/RadeonOpenCompute/llvm-project roc-7.1.0 25425 $commit +zkminer-codegenprepare-e80f32fd20bf"
ninja -C "$build" -j "${JOBS:-$(nproc)}" clang
install -m 0755 "$build/bin/clang-20" "$prefix/bin/clang-20"
"$prefix/bin/clang-20" --version | head -n 1
rm -rf "$src" "$build"
