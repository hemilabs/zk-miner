#!/usr/bin/env bash
# Checks the macOS beta kit without a GPU (the macOS counterpart of check-release-libs.sh):
#
#   check-macos-release.sh <zkminer-<version>-macos-arm64.tar.gz>
#   check-macos-release.sh --binaries <min macOS> <Mach-O file>...   (just the binary checks)
#
# On the tarball:
# - it unpacks as one directory, zkminer-<version>-macos-arm64/, and its SHA256SUMS hold;
# - every Mach-O file (the CLI, the worker) is arm64 only, links only /usr/lib and /System
#   libraries (otool -L: a Mac needs nothing installed), has LC_BUILD_VERSION minos = BUILDINFO's
#   min_macos, and carries a valid (ad hoc, linker) signature, without which arm64 macOS kills it;
# - every metallib the worker embeds targets that same macOS (the Metal compiler's target, which
#   decides on which macOS Metal loads the library);
# - the offline archive set: its SHA256SUMS hold, every archive is of a metallib the worker embeds
#   (digest field), of a family BUILDINFO lists, and has the macos<major> key of min_macos;
# - no risc0-groth16 component file is in the kit, and the worker pins the Groth16 blob BUILDINFO
#   names (install.sh --with-groth16 downloads that one);
# - install.sh and the tools parse (bash -n).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
fail=0
bad() { echo "FAIL $*"; fail=1; }

# MTLB headers in a file: "<offset> <os major>.<os minor> <platform>" per embedded metallib.
metallib_targets() {
  python3 -I - "$1" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
p = d.find(b'MTLB')
while p >= 0:
    step = 4
    if p + 0x58 <= len(d):
        (size,) = struct.unpack_from('<Q', d, p + 0x10)
        if 0x58 < size <= len(d) - p:
            offs = struct.unpack_from('<8Q', d, p + 0x18)
            if all(o + s <= size for o, s in zip(offs[0::2], offs[1::2])) and offs[0] >= 0x58:
                # 'MTLB', u16 platform, u16 u16 file version, u8 type, u8 os, u16 os major, u16 os minor
                platform, = struct.unpack_from('<H', d, p + 4)
                os_kind = d[p + 11]
                major, minor = struct.unpack_from('<HH', d, p + 12)
                print(f"{p:#x} {major}.{minor} {platform:#06x}/{os_kind:#04x}")
                step = size
    p = d.find(b'MTLB', p + step)
PY
}

check_binary() { # <min macOS> <file>
  local want=$1 f=$2 archs minos libs bad_libs
  archs=$(lipo -archs "$f" 2>/dev/null || echo "?")
  [ "$archs" = arm64 ] || bad "$f: architectures '$archs', want arm64 only"
  minos=$(otool -l "$f" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}')
  [ "$minos" = "$want" ] || bad "$f: LC_BUILD_VERSION minos ${minos:-none}, want $want"
  libs=$(otool -L "$f" | tail -n +2 | awk '{print $1}')
  bad_libs=$(grep -vE '^(/usr/lib/|/System/Library/)' <<<"$libs" || true)
  [ -z "$bad_libs" ] || bad "$f links libraries a stock Mac does not have: $(echo $bad_libs)"
  codesign --verify "$f" 2>/dev/null || bad "$f: no valid code signature (arm64 macOS refuses to run it)"
  local targets wrong
  targets=$(metallib_targets "$f")
  if [ -n "$targets" ]; then
    wrong=$(awk -v w="$want" '$2 != w || $3 != "0x8001/0x81"' <<<"$targets")
    [ -z "$wrong" ] || bad "$f embeds metallibs for another macOS than $want: $(echo $wrong)"
  fi
  echo "  $(basename "$f"): arm64, minos $minos, $(wc -l <<<"$libs" | tr -d ' ') system libraries, $(grep -c . <<<"$targets" || true) metallibs for macOS $want"
}

if [ "${1:-}" = --binaries ]; then
  want=${2:?usage: $0 --binaries <min macOS> <file>...}
  shift 2
  for f in "$@"; do check_binary "$want" "$f"; done
  exit $fail
fi

tarball=${1:?usage: $0 <tarball>}
root=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-macos-check.XXXXXX")
trap 'rm -rf "$root"' EXIT
tops=$(tar -tzf "$tarball" | cut -d/ -f1 | sort -u)
[ "$(wc -l <<<"$tops" | tr -d ' ')" = 1 ] || { echo "FAIL $tarball does not unpack into one directory: $(echo $tops)"; exit 1; }
name=$tops
case "$name" in zkminer-*-macos-arm64) ;; *) bad "top directory '$name' is not zkminer-<version>-macos-arm64";; esac
tar -xzf "$tarball" -C "$root"
k=$root/$name
echo "== $name"

(cd "$k" && shasum -a 256 -c --quiet SHA256SUMS) || bad "SHA256SUMS does not hold"
listed=$(cd "$k" && awk '{print $2}' SHA256SUMS | sort)
present=$(cd "$k" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort)
[ "$listed" = "$present" ] || bad "SHA256SUMS does not list exactly the kit's files: $(diff <(echo "$listed") <(echo "$present") | grep '^[<>]' | head -5 | tr '\n' ' ')"
for f in zkminer provers/zkminer-prove-risc0-metal install.sh README.md LICENSE BUILDINFO \
         tools/install-metal-aot.sh tools/build-metal-aot.sh metal-aot; do
  [ -e "$k/$f" ] || bad "missing $f"
done
for f in zkminer provers/zkminer-prove-risc0-metal install.sh tools/install-metal-aot.sh tools/build-metal-aot.sh; do
  [ -x "$k/$f" ] || bad "$f is not executable"
done
info() { sed -n "s/^$1=//p" "$k/BUILDINFO"; }
min=$(info min_macos)
[ -n "$min" ] || bad "BUILDINFO has no min_macos"

echo "binaries:"
while IFS= read -r f; do
  if file -b "$f" | grep -q '^Mach-O'; then check_binary "$min" "$f"; fi
done < <(find "$k" -type f ! -name '*.binarchive')

echo "offline Metal archives:"
w=$k/provers/zkminer-prove-risc0-metal
n=$(find "$k/metal-aot" -name '*.binarchive' | wc -l | tr -d ' ')
if [ "$n" -gt 0 ]; then
  (cd "$k/metal-aot" && shasum -a 256 -c --quiet SHA256SUMS) || bad "metal-aot/SHA256SUMS does not hold"
  digests=$("$k/tools/build-metal-aot.sh" --worker-digests "$w")
  arches=" $(info aot_arches) "
  for f in "$k"/metal-aot/*.binarchive; do
    b=$(basename "$f")
    IFS=- read -r unit d arch oskey _ <<<"$b"
    grep -qx "$d" <<<"$digests" || bad "metal-aot/$b: digest $d is no metallib the worker embeds"
    [[ "$arches" == *" $arch "* ]] || bad "metal-aot/$b: family $arch is not in BUILDINFO aot_arches"
    [ "$oskey" = "macos${min%%.*}" ] || bad "metal-aot/$b: OS key $oskey, want macos${min%%.*}"
  done
  echo "  $n archives ($(du -sh "$k/metal-aot" | cut -f1)) for $(info aot_arches), all of this worker's metallibs, key macos${min%%.*}"
else
  echo "  none (the first start compiles the GPU pipelines)"
fi
for a in $(info aot_validated); do
  [[ " $(info aot_arches) " == *" $a "* ]] || echo "  note: validated family $a has no archives in this kit"
done

echo "Groth16:"
g=$(find "$k" -type f \( -name '*.zkey' -o -name 'stark_verify_graph.bin' -o -name 'fuzzed_msm_results.bin' \
      -o -name 'preprocessed_coeffs.bin' -o -name '*risc0-groth16*' \) | sed "s|^$k/||")
[ -z "$g" ] || bad "the kit holds risc0-groth16 component files (it must download them): $g"
sha=$(info groth16_sha256); url=$(info groth16_url)
[[ "$url" == *"/$sha" ]] || bad "BUILDINFO groth16_url does not name groth16_sha256"
LC_ALL=C grep -aqF "$url" "$w" || bad "the worker does not pin $url (BUILDINFO and the worker disagree)"
echo "  not bundled; the worker and install.sh --with-groth16 fetch v$(info groth16_version), sha256 ${sha:0:16}..."

echo "scripts:"
for s in install.sh tools/install-metal-aot.sh tools/build-metal-aot.sh; do
  bash -n "$k/$s" || bad "$s does not parse"
done
echo "  parse"
size=$(stat -f %z "$tarball")
[ "$size" -lt $((1 << 30)) ] || bad "the tarball is $size bytes (over 1 GiB: something large got in)"

[ $fail = 0 ] && echo "ok: $name ($(du -h "$tarball" | cut -f1)) is a self-contained arm64 kit for macOS $min and later"
exit $fail
