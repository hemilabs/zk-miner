#!/usr/bin/env bash
# The rest of Intel's GPU compute stack, on top of build-intel-igc.sh's install in PREFIX:
#
#   build-intel-gpu-runtime.sh <prefix>
#
# - the compute runtime "NEO" (libze_intel_gpu.so.1, the Level Zero driver; and ocloc, the
#   offline compiler: the build compiles kernels ahead of time with it, and the SYCL runtime loads
#   libocloc.so to check those kernels fit the card);
# - the Level Zero loader (libze_loader.so.1), which the SYCL runtime opens.
#
# Then every library gets RUNPATH $ORIGIN, so the set finds itself wherever it is copied: the loader
# opens the driver, and the driver opens IGC, from the same directory, ahead of any system copy. See
# intel-gpu-build-lib.sh.
set -euo pipefail
# shellcheck source=intel-gpu-build-lib.sh
. "$(dirname "$(readlink -f "$0")")/intel-gpu-build-lib.sh"
[ -e "$prefix/lib/libigc.so.2" ] || { echo "no IGC in $prefix: run build-intel-igc.sh first" >&2; exit 1; }

echo "== compute runtime 26.05.37020.3"
fetch neo intel/compute-runtime a5e0dd79db5ff7b3ed6c5cd3d11064ab7cbb9aa5 26.05.37020.3
# Built against the Level Zero headers it was released with (v1.27.0, its release notes), which it
# takes from ../level_zero. Before the loader is installed: CMake looks in the install prefix first,
# and the loader's newer headers there clash with the driver's own (zeCommandListAppendHostFunction).
fetch level_zero oneapi-src/level-zero d562046e7266120e8be3533597b65f34a00524c1 v1.27.0
# IGC_DIR and GMM_DIR name the installs above; left unset, the build would take ../igc and
# ../gmmlib, the source trees here, and build them again in-tree.
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" cmake_build neo build-neo \
  -DNEO_SKIP_UNIT_TESTS=1 -DSKIP_UNIT_TESTS=1 \
  -DIGC_DIR="$prefix" -DGMM_DIR="$prefix"
license compute-runtime neo/LICENSE.md

# The loader the release ships: 1.32.0, the version the Intel workers were validated with (beside
# compute runtime 26.05). It talks to any driver through the Level Zero interface's own versioning.
echo "== Level Zero loader 1.32.0"
fetch level-zero oneapi-src/level-zero d3b3efbdaa27a0aef9a9812cc8fa4260557c1e7c v1.32.0
cmake_build level-zero build-level-zero
license level-zero level-zero/LICENSE

echo "== RUNPATH \$ORIGIN"
find "$prefix/lib" -maxdepth 1 -type f -name '*.so*' -print0 |
  while IFS= read -r -d '' lib; do patchelf --set-rpath '$ORIGIN' "$lib"; done
find "$prefix/bin" -maxdepth 1 -type f -perm -u+x -print0 |
  while IFS= read -r -d '' exe; do
    if file -b "$exe" | grep -q ELF; then patchelf --set-rpath '$ORIGIN/../lib' "$exe"; fi
  done

echo "== check"
for lib in libze_loader.so.1 libze_intel_gpu.so.1 libigc.so.2 libigdfcl.so.2 libigdgmm.so.12 libocloc.so; do
  [ -e "$prefix/lib/$lib" ] || { echo "missing: $prefix/lib/$lib" >&2; exit 1; }
done
if LD_LIBRARY_PATH= ldd "$prefix"/lib/*.so* 2>/dev/null | grep 'not found'; then
  echo "a library above does not resolve from $prefix/lib" >&2
  exit 1
fi
max_glibc=$(objdump -T "$prefix"/lib/*.so* 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)
echo "highest glibc symbol version needed: $max_glibc"
ocloc=$(find "$prefix/bin" -name 'ocloc*' -type f | head -n 1)
[ -n "$ocloc" ] && ln -sf "$(basename "$ocloc")" "$prefix/bin/ocloc"
"$prefix/bin/ocloc" -version 2>/dev/null | head -n 3 || true
du -sh "$prefix/lib"
