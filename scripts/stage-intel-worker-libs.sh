#!/usr/bin/env bash
# Stage the shared libraries the Intel risc0 worker needs and the system does not provide, so it runs
# without LD_LIBRARY_PATH.
#
#   scripts/stage-intel-worker-libs.sh <path/to/zkminer-prove-risc0-intel> [cargo target dir]
#
# The risc0 -sys crates build their SYCL kernels as shared libraries inside the cargo target dir, and
# the worker needs oneAPI's SYCL runtime (libsycl, the Unified Runtime loader and its Level Zero
# adapters, which the loader dlopen()s). This copies all of them into `zkminer-intel/lib/` next to the
# binary, which the binary's RPATH names (see crates/zkminer-prove-risc0/build.rs). The directory is
# called `lib` because oneAPI's own libraries look for each other in `$ORIGIN/../lib`, which is then
# the same directory. Copy the binary together with `zkminer-intel/` when installing it (e.g. into
# ~/.zkminer/provers/).
#
# Needs ONEAPI_ROOT (source oneAPI's setvars.sh first). The GPU driver stack itself (Level Zero loader
# libze_loader, the compute runtime and IGC) comes from the system and is not copied, unless
# INTEL_GPU_RUNTIME names a build of it (scripts/ci/build-intel-gpu-runtime.sh's prefix): then its
# libraries are staged too, so the worker needs only the kernel driver. The release does this.
#
# The same works for hemilabs/sp1's SYCL `sp1-gpu-server` (pass it and its cargo target dir); it has no
# RPATH of its own, and the SP1 worker puts the staged directory on its library path instead.
# STAGE_DIR overrides where `lib/` (and `LICENSES/`, with INTEL_GPU_RUNTIME) go: by default
# `zkminer-intel/` beside the binary.
set -euo pipefail

bin=$(readlink -f "${1:?usage: $0 <zkminer-prove-risc0-intel> [target dir]}")
[ -x "$bin" ] || { echo "not an executable: $bin" >&2; exit 1; }
target=$(readlink -f "${2:-$(dirname "$(dirname "$bin")")}")
: "${ONEAPI_ROOT:?set ONEAPI_ROOT (source oneAPI setvars.sh) first}"
oneapi=$(readlink -f "$ONEAPI_ROOT")
stage_dir=${STAGE_DIR:-$(dirname "$bin")/zkminer-intel}
out=$stage_dir/lib
rm -rf "$out" && mkdir -p "$out"   # afresh: a staged copy would otherwise resolve to itself
gpu=${INTEL_GPU_RUNTIME:+$(readlink -f "$INTEL_GPU_RUNTIME")}

# Where the kernel libraries are: every directory under the target dir holding a .so, the newest .so
# first, so an older build's library of the same name never wins.
mapfile -t kdirs < <(find "$target" -name '*.so' -printf '%T@ %h\n' 2>/dev/null | sort -rn |
  awk '!seen[$2]++ {print $2}')
odirs=("$oneapi/compiler/latest/lib" "$oneapi/umf/latest/lib" "$oneapi/tcm/latest/lib"
  "$oneapi/tbb/latest/lib/intel64/gcc4.8")
[ -n "$gpu" ] && odirs+=("$gpu/lib")
search=$(IFS=:; echo "${kdirs[*]}:${odirs[*]}")

# Everything ldd resolves from the target dir or oneAPI (not the system), transitively.
missing=$(LD_LIBRARY_PATH="$search" ldd "$bin" | awk '/not found/ {print $1}')
if [ -n "$missing" ]; then
  echo "unresolved even with the target dir and oneAPI on the search path: $missing" >&2
  exit 1
fi
# Each library is staged under the name it is asked for (its soname, e.g. libsycl.so.9), not the
# versioned file a symlink chain ends at (libsycl.so.9.0.0), which the loader would not look for.
n=0
stage() { # <ldd output of one object>
  while read -r name path; do
    case "$(readlink -f "$path")" in
      "$target"/*|"$oneapi"/*) cp -L "$path" "$out/$name"; n=$((n + 1)) ;;
      "${gpu:-/nonexistent}"/*) cp -L "$path" "$out/$name"; n=$((n + 1)) ;;
    esac
  done < <(awk '$2 == "=>" && $3 ~ /^\// {print $1, $3}' <<<"$1")
}
stage "$(LD_LIBRARY_PATH="$search" ldd "$bin")"

# dlopen()ed, so ldd does not list them: the Unified Runtime's Level Zero adapters, and their own deps.
for lib in "$oneapi"/compiler/latest/lib/libur_adapter_level_zero*.so.[0-9]; do
  [ -f "$lib" ] || continue
  cp -L "$lib" "$out/$(basename "$lib")"; n=$((n + 1))
  stage "$(LD_LIBRARY_PATH="$search" ldd "$lib")"
done

# The driver stack built for the release: every library under the name it is loaded by (its soname),
# which takes in what is dlopen()ed by name and so missing from ldd's view: the loader opens the
# driver (libze_intel_gpu.so.1), the driver opens IGC (libigdfcl.so.2), SYCL opens libocloc.so. Each
# has RUNPATH $ORIGIN, so they find each other here. Their licenses, and oneAPI's, go to LICENSES/.
if [ -n "$gpu" ]; then
  for lib in "$gpu"/lib/*.so*; do
    [ -f "$lib" ] && [ ! -L "$lib" ] || continue
    soname=$(readelf -d "$lib" | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p')
    [ -n "$soname" ] || soname=$(basename "$lib")
    [ -e "$out/$soname" ] || { cp -L "$lib" "$out/$soname"; n=$((n + 1)); }
  done
  mkdir -p "$stage_dir/LICENSES/oneapi"
  cp -r "$gpu"/share/licenses/. "$stage_dir/LICENSES/"
  cp -r "$oneapi"/compiler/latest/share/doc/compiler/credist.txt \
    "$oneapi"/compiler/latest/share/doc/compiler/licensing "$stage_dir/LICENSES/oneapi/"
  cp "$oneapi"/licensing/latest/licensing/latest/license.htm "$stage_dir/LICENSES/oneapi/" 2>/dev/null ||
    find "$oneapi"/licensing -name license.htm -exec cp {} "$stage_dir/LICENSES/oneapi/" \; -quit
  for doc in "$oneapi"/umf/latest/share/doc/umf "$oneapi"/tcm/latest/share/doc/tcm; do
    [ -d "$doc" ] && cp -r "$doc" "$stage_dir/LICENSES/oneapi/"
  done
fi

# Loaded by name at run time too: the compute runtime's offline compiler library, which SYCL uses for
# its ahead-of-time device images. It belongs to the GPU driver stack (Ubuntu/Intel package
# `intel-ocloc`, the same version as the installed compute runtime); stage one only for a host that
# lacks it, from LIBOCLOC or the `ocloc` on PATH.
if [ ! -e "$out/libocloc.so" ] && ! ldconfig -p 2>/dev/null | grep -q 'libocloc\.so '; then
  ocloc_lib=${LIBOCLOC:-}
  if [ -z "$ocloc_lib" ] && command -v ocloc >/dev/null; then
    ocloc_lib=$(dirname "$(dirname "$(readlink -f "$(command -v ocloc)")")")/lib/x86_64-linux-gnu/libocloc.so
  fi
  if [ -n "$ocloc_lib" ] && [ -f "$ocloc_lib" ]; then
    cp -L "$ocloc_lib" "$out/libocloc.so"; n=$((n + 1))
    echo "warning: no system libocloc.so; staged $ocloc_lib (install the intel-ocloc package matching the compute runtime instead)" >&2
  else
    echo "warning: no libocloc.so on this host: install the intel-ocloc package matching the compute runtime" >&2
  fi
fi

echo "staged $n libraries in $out ($(du -sh "$out" | cut -f1))"
# The check: the binary must resolve everything through its RPATH (the worker), or through the staged
# directory on its library path (the SP1 server, as the SP1 worker runs it).
if readelf -d "$bin" | grep -q 'R.*PATH.*zkminer-intel/lib'; then ld_path=; else ld_path=$out; fi
if env LD_LIBRARY_PATH="$ld_path" ldd "$bin" | grep -q 'not found'; then
  env LD_LIBRARY_PATH="$ld_path" ldd "$bin" | grep 'not found' >&2
  echo "the binary still misses libraries: was it built with the intel feature's RPATH?" >&2
  exit 1
fi
echo "ok: $(basename "$bin") resolves all its libraries${ld_path:+ with $out on its library path}"
