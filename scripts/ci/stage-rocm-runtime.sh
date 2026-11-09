#!/usr/bin/env bash
# Stages the HIP runtime an AMD prover loads, so a host needs only the amdgpu kernel driver:
#
#   stage-rocm-runtime.sh <ROCm root, e.g. /opt/rocm-7.1.0 or /opt/rocm/core-10.1> <out dir>
#
# <out dir>/lib gets libamdhip64.so.7, the code object manager libamd_comgr.so.3 (which HIP opens
# with dlopen in some releases, so it is staged by name), and everything they load, transitively:
# - from the ROCm install, at the same path relative to <ROCm root>/lib, because the libraries find
#   each other through RUNPATHs like $ORIGIN (ROCm 7) or $ORIGIN/llvm/lib and
#   $ORIGIN/rocm_sysdeps/lib (ROCm 10);
# - from the build image's system, in lib/ itself, where ROCm's $ORIGIN finds them: the libraries
#   ROCm 7 takes from the distribution (libnuma, libelf, libdrm, libdrm_amdgpu, libzstd), which a
#   host may lack;
# - except glibc, libstdc++, libgcc_s and zlib, which every Linux host has.
# <out dir>/LICENSES gets the licenses of what was staged and a README listing where each file came
# from. The build image is Ubuntu 22.04, so what is staged needs no more than its glibc 2.35.
#
# The release ships two: ROCm 7.1's beside the risc0 prover (zkminer-rocm/, found through its RPATH
# $ORIGIN/zkminer-rocm/lib), whose kernels are compiled with 7.1, and ROCm 10.1's as
# sp1-gpu-server-hip-lib/, which the SP1 worker puts on the HIP server's library path.
set -euo pipefail

root=$(readlink -f "${1:?usage: $0 <ROCm root> <out dir>}")
out=${2:?usage: $0 <ROCm root> <out dir>}
lib=$root/lib
rm -rf "$out" && mkdir -p "$out/lib" "$out/LICENSES"
out=$(readlink -f "$out")
base='^(libc|libm|libdl|librt|libpthread|libgcc_s|libstdc\+\+|ld-linux-x86-64|libz|linux-vdso)\.so'

staged=() system=()
copy() { # <name the loader asks for> <path it resolved to>
  local name=$1 path=$2 real rel
  real=$(readlink -f "$path")
  case "$real" in
    "$lib"/*)
      # Where the name was found, relative to lib/: its directory, and the name itself (a soname
      # link becomes a file of that name).
      rel=$(realpath --relative-to="$lib" "$(dirname "$path")")
      [ -e "$out/lib/$rel/$name" ] && return 0
      mkdir -p "$out/lib/$rel"
      cp -L "$path" "$out/lib/$rel/$name"
      staged+=("$rel/$name")
      ;;
    *)
      [[ $name =~ $base ]] && return 0
      [ -e "$out/lib/$name" ] && return 0
      cp -L "$path" "$out/lib/$name"
      staged+=("./$name")
      system+=("$name $real")
      ;;
  esac
}
closure() { # <library>
  local l=$1
  if env -u LD_LIBRARY_PATH ldd "$l" | grep 'not found'; then
    echo "$l does not resolve" >&2
    exit 1
  fi
  copy "$(basename "$l")" "$l"
  while read -r name path; do copy "$name" "$path"; done < <(env -u LD_LIBRARY_PATH ldd "$l" |
    awk '$2 == "=>" && $3 ~ /^\// {print $1, $3}')
}
closure "$lib/libamdhip64.so.7"
[ -e "$lib/libamd_comgr.so.3" ] && closure "$lib/libamd_comgr.so.3"

# The staged copy must resolve within itself, with only the base libraries from the host. With lib/
# on the search path, as the prover's RPATH or the SP1 worker's library path puts it: a system
# library staged here has no RUNPATH of its own to find its dependencies beside it with.
for l in "$out/lib/libamdhip64.so.7" "$out/lib/libamd_comgr.so.3"; do
  [ -e "$l" ] || continue
  if LD_LIBRARY_PATH="$out/lib" ldd "$l" | grep -E "not found|=> $root/|=> /opt/rocm"; then
    echo "the staged runtime does not resolve within $out/lib" >&2
    exit 1
  fi
  if LD_LIBRARY_PATH="$out/lib" ldd "$l" | awk '$2 == "=>" && $3 ~ /^\// {print $1, $3}' |
     grep -v " $out/lib/" | grep -vE "$base"; then
    echo "the staged runtime loads the above from the host" >&2
    exit 1
  fi
done

# Licenses: ROCm's own, from its share/doc; for each system library, its package's copyright file
# (Debian's, which carries the license); the standard texts for the GPL family.
for component in hip hsa-runtime64 rocr amd_comgr rocprofiler-register; do
  [ -d "$root/share/doc/$component" ] && cp -r "$root/share/doc/$component" "$out/LICENSES/"
done
for text in Apache-2.0 LGPL-2.1 LGPL-3 GPL-2 GPL-3; do
  [ -f "/usr/share/common-licenses/$text" ] && cp "/usr/share/common-licenses/$text" "$out/LICENSES/"
done
{
  echo "This directory is AMD's ROCm HIP runtime ($(basename "$root")) and what it loads, copied"
  echo "unmodified, for zkminer's AMD prover. None of it is covered by zkminer's MIT license; each"
  echo "file is under its own license, in this directory."
  echo
  echo "From AMD's ROCm packages (https://repo.radeon.com/rocm/, https://stable.repo.amd.com/rocm/;"
  echo "sources at https://github.com/ROCm, the ROCm 10 packages' build at"
  echo "https://github.com/ROCm/TheRock): HIP (MIT, hip/), ROCr (NCSA, hsa-runtime64/ or rocr/),"
  echo "the code object manager (Apache-2.0 WITH LLVM-exception, amd_comgr/), rocprofiler-register"
  echo "(MIT); in ROCm 10, LLVM (Apache-2.0 WITH LLVM-exception) and the system libraries AMD builds"
  echo "into rocm_sysdeps/ (elfutils libelf: LGPL-3.0-or-later OR GPL-2.0-or-later; numactl"
  echo "libnuma: LGPL-2.1; libdrm: MIT; zlib; zstd: BSD-3-Clause; bzip2; xz: 0BSD), whose"
  echo "sources TheRock names."
  echo
  echo "Files:"
  printf '  %s\n' "${staged[@]}"
} > "$out/LICENSES/README"
if [ ${#system[@]} -gt 0 ]; then
  {
    echo
    echo "From the build image's distribution, with each package's copyright file in"
    echo "LICENSES/<package>/ (Ubuntu's sources: https://launchpad.net/ubuntu/+source/<package>):"
  } >> "$out/LICENSES/README"
  for s in "${system[@]}"; do
    read -r name real <<<"$s"
    pkg=$(dpkg -S "$real" 2>/dev/null | head -n 1 | cut -d: -f1 || true)
    if [ -n "$pkg" ] && [ -f "/usr/share/doc/$pkg/copyright" ]; then
      mkdir -p "$out/LICENSES/$pkg"
      cp "/usr/share/doc/$pkg/copyright" "$out/LICENSES/$pkg/"
      echo "  $name: $pkg $(dpkg-query -W -f='${Version}' "$pkg")" >> "$out/LICENSES/README"
    else
      echo "  $name: (no package found for $real)" >> "$out/LICENSES/README"
    fi
  done
  echo "The LGPL libraries among them are loaded dynamically and may be replaced by a compatible build." \
    >> "$out/LICENSES/README"
fi

echo "staged ${#staged[@]} libraries in $out/lib ($(du -sh "$out/lib" | cut -f1)):"
printf '  %s\n' "${staged[@]}"
