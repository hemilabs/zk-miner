#!/usr/bin/env bash
# Picks the Metal compiler for a macOS CI build (B9-CI), prints the versions, and exports METAL_TC:
#
#   macos-metal-toolchain.sh <dir> [pinned|xcode]
#   macos-metal-toolchain.sh --cleanup <dir> [<other dir>...]   end of job: unmount <dir>/mnt, delete
#                                                               the directories, print the free disk
#
# pinned (default; the only mode for a release, B9-M26 decision (b)): Metal Toolchain 27B47, the
#   compiler every validation of the beta used, fetched and checked by fetch-metal-toolchain.sh into
#   <dir> (the .aar and the disk image are SHA-256 pinned there) and checked here against
#   macos-validated.sh's VALIDATED_METAL_COMPILER. The runner's own Xcode compiler is only reported.
# xcode: the runner's Xcode Metal toolchain. Since Xcode 26 it is a separate component: when
#   `xcrun --sdk macosx --find metal` finds nothing it is downloaded with
#   `xcodebuild -downloadComponent MetalToolchain`. Its kernels are unvalidated GPU code (another
#   compiler build), so this mode also exports METAL_COMPILER_UNVALIDATED=1 and the kit's BUILDINFO
#   says metal_compiler_validated=no: for trying a new Xcode, never for a release.
# Also prints the runner (macOS, Xcode, SDK, Command Line Tools). In a GitHub Actions step the
# variables go to GITHUB_ENV; elsewhere they are printed as export lines.
set -euo pipefail
if [ "${1:-}" = --cleanup ]; then
  shift
  d=${1:?usage: $0 --cleanup <dir> [<other dir>...]}
  real=$(cd "$d" 2>/dev/null && pwd -P || echo "$d")
  if mount | grep -qF -e " on $d/mnt " -e " on $real/mnt "; then
    hdiutil detach "$d/mnt" > /dev/null || hdiutil detach -force "$d/mnt" > /dev/null || echo "::warning::cannot unmount $d/mnt"
  fi
  rm -rf "$@"
  df -h "${GITHUB_WORKSPACE:-$PWD}"
  exit 0
fi
dir=${1:?usage: $0 <dir> [pinned|xcode]}
mode=${2:-pinned}
ci=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=macos-validated.sh
. "$ci/macos-validated.sh"
die() { echo "::error::macos-metal-toolchain: $*" >&2; exit 1; }

echo "== runner"
echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m), $(sysctl -n hw.ncpu) CPUs, $(( $(sysctl -n hw.memsize) >> 20 )) MiB RAM"
echo "developer dir: $(xcode-select -p 2>/dev/null || echo none)"
xcodebuild -version 2>/dev/null || echo "xcodebuild: not available (Command Line Tools only?)"
echo "SDK: $(xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo none) at $(xcrun --sdk macosx --show-sdk-path 2>/dev/null || echo none)"
pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null | sed -n 's/^version: /Command Line Tools: /p' || true

xcode_metal() { # the runner's own compiler, if any: "<path>\t<version line>"
  local m
  m=$(xcrun --sdk macosx --find metal 2>/dev/null) || return 1
  [ -x "$m" ] || return 1
  printf '%s\t%s\n' "$m" "$("$m" --version 2>/dev/null | head -1)"
}
if x=$(xcode_metal); then
  echo "the runner's Metal compiler: ${x#*$'\t'} (${x%%$'\t'*})"
else
  echo "the runner's Metal compiler: none (Xcode 26+ ships it as a separate component)"
fi

case $mode in
  pinned)
    tc=$("$ci/fetch-metal-toolchain.sh" "$dir")
    unvalidated=0
    ;;
  xcode)
    if ! x=$(xcode_metal) || [ -z "${x#*$'\t'}" ]; then
      command -v xcodebuild >/dev/null || die "no xcodebuild: the xcode mode needs Xcode"
      echo "== xcodebuild -downloadComponent MetalToolchain"
      xcodebuild -downloadComponent MetalToolchain
      x=$(xcode_metal) || die "still no Metal compiler after xcodebuild -downloadComponent MetalToolchain"
    fi
    m=${x%%$'\t'*}
    # .../Metal.xctoolchain/usr/bin/metal -> .../Metal.xctoolchain (risc0-build-kernel wants usr/bin/metal in it)
    tc=$(cd "$(dirname "$m")/../.." && pwd)
    [ -x "$tc/usr/bin/metal" ] || die "$m is not inside a toolchain directory (<tc>/usr/bin/metal)"
    unvalidated=1
    ;;
  *) die "mode must be pinned or xcode (got '$mode')" ;;
esac

v=$("$tc/usr/bin/metal" --version | head -1)
echo "== Metal compiler for this build: $v ($tc)"
"$tc/usr/bin/metal" --version
[ -x "$tc/usr/bin/metallib" ] && echo "metallib: $tc/usr/bin/metallib" || echo "metallib: not beside metal (risc0-build-kernel uses xcrun's)"
[ -x "$tc/usr/bin/metal-tt" ] && echo "metal-tt: $tc/usr/bin/metal-tt" || echo "metal-tt: not beside metal (only the AOT archive build needs it)"
if [ "$v" = "$VALIDATED_METAL_COMPILER" ]; then
  echo "validated compiler: yes"
elif [ $unvalidated = 1 ]; then
  echo "::warning::the kit's kernels will be built by '$v', not the validated '$VALIDATED_METAL_COMPILER' (metal_compiler_validated=no; not for a release)"
else
  die "the pinned toolchain is '$v', not the validated '$VALIDATED_METAL_COMPILER'"
fi

out=("METAL_TC=$tc")
[ $unvalidated = 1 ] && out+=("METAL_COMPILER_UNVALIDATED=1")
if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "${out[@]}" >> "$GITHUB_ENV"
else
  printf 'export %s\n' "${out[@]}"
fi
