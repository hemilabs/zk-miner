#!/usr/bin/env bash
# Makes a Metal toolchain directory whose compiler targets one macOS release (B9-PKG, B9-M26):
#
#   metal-tc.sh <macOS min, e.g. 26.0> <toolchain dir> [<real metal compiler>]
#   metal-tc.sh <macOS min> --in <parent dir> [<real metal compiler>]
#
# risc0-build-kernel takes no target flag but finds its compiler through METAL_TC; point METAL_TC at
# the printed toolchain directory. With --in it is <parent dir>/metal-tc-<min>-<fingerprint>, the
# fingerprint a SHA-256 (16 hex digits) over the real compiler's path, its `--version` first line,
# the contents of every file in the compiler's directory (the driver and air-* tools beside it), and,
# when that directory is <X>.xctoolchain/usr/bin, the path, size and mtime of every file under <X>.xctoolchain
# (the backends in usr/lib and usr/metal; a content hash of those 2.9 GB would take seconds). Use --in for builds (assemble-macos.sh does): risc0-build-kernel reruns
# the kernel build scripts only when the value of METAL_TC (or a source) changes, never when the
# compiler behind the same METAL_TC path changes, so a fixed directory would keep the metallibs an
# earlier compiler built (B9-M26 review; scripts/ci/test-metal-tc.sh reproduces it). With the
# compiler in the path, another compiler is another METAL_TC and the kernels are rebuilt. Its usr/bin holds symlinks to the real toolchain's tools, except `metal`, a
# wrapper that adds -mmacosx-version-min=<min> to every compile and whose `--version` first line ends
# in " [-mmacosx-version-min=<min>]".
#
# Why the version line matters: risc0's Metal kernel cache (~/Library/Caches/com.risczero.RISC-Zero.risc0,
# shared by every build of the user) is keyed by a SHA-256 over the flags, the SDK, the sources and
# that first line, but not by any deployment target. With the target in the line, the libraries of
# a 26.0 build and of a 27.0 build (and of a plain build, which targets the SDK) never share a cache
# entry, so none can be reused for another target. The real compiler also honours
# MACOSX_DEPLOYMENT_TARGET, which the cache key does not see either; the wrapper refuses to run with
# it set (as does assemble-macos.sh) rather than build for a target its version line does not name.
#
# <real metal compiler>: default $METAL_TC/usr/bin/metal, else `xcrun --sdk macosx --find metal`, else
# `metal` on PATH. metallib comes from beside it (else xcrun). Prints the toolchain directory.
set -euo pipefail
min=${1:?usage: metal-tc.sh <macOS min> <toolchain dir> [<real metal compiler>]}
tc=${2:?usage: metal-tc.sh <macOS min> <toolchain dir> [<real metal compiler>]}
in=
if [ "$tc" = --in ]; then
  in=${3:?usage: metal-tc.sh <macOS min> --in <parent dir> [<real metal compiler>]}
  real=${4:-}
else
  real=${3:-}
fi
[[ "$min" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "metal-tc.sh: the minimum must be <major>.<minor> (got '$min')" >&2; exit 2; }
if [ -z "$real" ]; then
  real=${METAL_TC:+$METAL_TC/usr/bin/metal}
  [ -n "$real" ] && [ -x "$real" ] || real=$(xcrun --sdk macosx --find metal 2>/dev/null || command -v metal || true)
fi
[ -x "$real" ] || { echo "metal-tc.sh: no Metal compiler (xcrun --sdk macosx --find metal): RELEASE-DEPS.md" >&2; exit 1; }
given=$real
# A wrapper of a wrapper would add the flag twice and name it twice: take the compiler it wraps
# (this script's wrappers, and B9-PKG's assemble-macos.sh ones: "# assemble-macos.sh: the Metal
# compiler at <real>, targeting macOS <min>.").
if head -c 2 "$real" | grep -q '#!'; then
  if grep -q '^# metal-tc.sh: real=' "$real"; then
    real=$(sed -n 's/^# metal-tc.sh: real=//p' "$real" | head -1)
  elif grep -q '^# assemble-macos.sh: the Metal compiler at ' "$real"; then
    real=$(sed -n 's/^# assemble-macos.sh: the Metal compiler at \(.*\), targeting macOS [0-9.]*\.$/\1/p' "$real" | head -1)
  fi
  [ -x "$real" ] || { echo "metal-tc.sh: cannot find the compiler behind the wrapper $given" >&2; exit 1; }
fi
case "$real" in /*) ;; *) real=$(cd "$(dirname "$real")" && pwd)/$(basename "$real") ;; esac
if [ -n "$in" ]; then
  bin=$(dirname "$real") root=$(dirname "$(dirname "$real")")   # root: <X>.xctoolchain/usr for a toolchain
  fp=$( { echo "$real"; "$real" --version 2>/dev/null | head -1
          find "$bin" -maxdepth 1 -type f | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done
          if [[ "$root" == *.xctoolchain/usr ]]; then (cd "$root/.." && find . -type f -exec stat -f '%N %z %m' {} + | LC_ALL=C sort); fi
        } | shasum -a 256 | cut -c1-16)
  mkdir -p "$in"
  tc=$(cd "$in" && pwd)/metal-tc-$min-$fp
fi
# The directory is replaced: refuse one that is not empty and not a wrapper directory of this
# script (e.g. METAL_TC itself, a real Metal.xctoolchain, passed by mistake).
if [ -e "$tc" ] && [ -n "$(ls -A "$tc" 2>/dev/null)" ] && ! grep -qs '^# metal-tc.sh: real=' "$tc/usr/bin/metal"; then
  echo "metal-tc.sh: $tc exists and is not a metal-tc.sh toolchain directory; refusing to replace it" >&2
  exit 1
fi
rm -rf "$tc"; mkdir -p "$tc/usr/bin"
tc=$(cd "$tc" && pwd)
for t in "$(dirname "$real")"/*; do ln -s "$t" "$tc/usr/bin/$(basename "$t")"; done
[ -e "$tc/usr/bin/metallib" ] || ln -s "$(xcrun --sdk macosx --find metallib)" "$tc/usr/bin/metallib"
rm -f "$tc/usr/bin/metal"
cat > "$tc/usr/bin/metal" <<EOF
#!/bin/bash
# The Metal compiler at $real, targeting macOS $min (scripts/ci/metal-tc.sh).
# metal-tc.sh: real=$real
# metal-tc.sh: min=$min
if [ -n "\${MACOSX_DEPLOYMENT_TARGET:-}" ]; then
  echo "metal (scripts/ci/metal-tc.sh, macOS $min): MACOSX_DEPLOYMENT_TARGET=\$MACOSX_DEPLOYMENT_TARGET is set; it would change the target without changing risc0's kernel cache key: unset it" >&2
  exit 1
fi
for a in "\$@"; do
  if [ "\$a" = --version ]; then
    "$real" --version | sed '1s/\$/ [-mmacosx-version-min=$min]/'
    exit "\${PIPESTATUS[0]}"
  fi
done
exec "$real" -mmacosx-version-min=$min "\$@"
EOF
chmod 0755 "$tc/usr/bin/metal"
echo "$tc"
