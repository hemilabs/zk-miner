#!/usr/bin/env bash
# Makes a Metal toolchain directory whose compiler targets one macOS release (B9-PKG, B9-M26):
#
#   metal-tc.sh <macOS min, e.g. 26.0> <toolchain dir> [<real metal compiler>]
#
# risc0-build-kernel takes no target flag but finds its compiler through METAL_TC; point METAL_TC at
# <toolchain dir>. Its usr/bin holds symlinks to the real toolchain's tools, except `metal`, a
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
real=${3:-}
[[ "$min" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "metal-tc.sh: the minimum must be <major>.<minor> (got '$min')" >&2; exit 2; }
if [ -z "$real" ]; then
  real=${METAL_TC:+$METAL_TC/usr/bin/metal}
  [ -n "$real" ] && [ -x "$real" ] || real=$(xcrun --sdk macosx --find metal 2>/dev/null || command -v metal || true)
fi
[ -x "$real" ] || { echo "metal-tc.sh: no Metal compiler (xcrun --sdk macosx --find metal): RELEASE-DEPS.md" >&2; exit 1; }
# A wrapper of a wrapper would add the flag twice and name it twice: take the compiler it wraps.
if head -c 2 "$real" | grep -q '#!' && grep -q '^# metal-tc.sh: real=' "$real"; then
  real=$(sed -n 's/^# metal-tc.sh: real=//p' "$real")
fi
case "$real" in /*) ;; *) real=$(cd "$(dirname "$real")" && pwd)/$(basename "$real") ;; esac
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
