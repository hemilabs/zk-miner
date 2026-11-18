#!/usr/bin/env bash
# Checks the macOS beta kit without a GPU (the macOS counterpart of check-release-libs.sh):
#
#   check-macos-release.sh <zkminer-<version>-macos-arm64.tar.gz>
#   check-macos-release.sh --binaries <min macOS> <Mach-O file>...   (just the binary checks: minos
#                          and every embedded metallib's target equal to <min macOS>)
#   check-macos-release.sh --requirements <Mach-O file>...  prints "<minos> <metallib target>" of the
#                          files (`none` without metallibs); fails if they disagree among themselves
#   check-macos-release.sh --compilers <Mach-O file>...  prints the distinct compiler lines ("Apple metal
#                          version ...", the first line of `metal --version`) the embedded metallibs'
#                          AIR names, one per line; fails if a metallib names none
#
# On the tarball:
# - it unpacks as one directory, zkminer-<version>-macos-arm64/, and its SHA256SUMS hold;
# - every Mach-O file (the CLI, the worker) is arm64 only, links only /usr/lib and /System
#   libraries (otool -L: a Mac needs nothing installed), has LC_BUILD_VERSION minos = BUILDINFO's
#   binaries_minos, and carries a valid (ad hoc, linker) signature, without which arm64 macOS kills it;
# - every metallib the worker embeds targets BUILDINFO's metal_target (the Metal compiler's target,
#   which decides on which macOS Metal loads the library);
# - BUILDINFO's min_macos (what install.sh enforces) is the newer of the two: the kit's binaries
#   start and its kernels load on every macOS install.sh accepts, and on no older one it rejects
#   needlessly. (A default kit has all three equal; a ZKMINER_MACOS_MIN=sdk kit has minos 11.0 and
#   metallibs for the build SDK, so its min_macos is the SDK's version.)
# - the offline archive set: its SHA256SUMS hold, every archive is of a metallib the worker embeds
#   (digest field), of a family BUILDINFO lists, and has a macos<N> key BUILDINFO aot_os_keys lists,
#   with N no older than min_macos's major (the runtime opens only macos<its major>, so a set keyed
#   for an older macOS than the kit's minimum is never used) and, by manifest.jsonl, built with
#   metal-tt -macos-version-min N.0; every key holds the same units and families (B9-M26), and every
#   key is one validated on hardware (macos-validated.sh VALIDATED_AOT_OS_MAJORS; opt-in for another:
#   AOT_ALLOW_UNVALIDATED_OS=1);
# - every embedded metallib names one compiler in its AIR, the same for all, BUILDINFO's
#   metal_compiler, and the validated one (macos-validated.sh VALIDATED_METAL_COMPILER; opt-in for
#   another: METAL_COMPILER_UNVALIDATED=1): kernels another compiler built never pass as built by the
#   pinned one (B9-M26 review);
# - no risc0-groth16 component file is in the kit, and the worker pins the Groth16 blob BUILDINFO
#   names (install.sh --with-groth16 downloads that one);
# - install.sh and the tools parse (bash -n).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=macos-validated.sh
. "$ci/macos-validated.sh"
fail=0
bad() { echo "FAIL $*"; fail=1; }

# The compiler lines in every embedded metallib: "<offset> <line>" per (metallib, line); a metallib
# without one prints "<offset> none".
metallib_compilers() {
  python3 -I - "$1" <<'PY'
import re, struct, sys
d = open(sys.argv[1], 'rb').read()
p = d.find(b'MTLB')
while p >= 0:
    step = 4
    if p + 0x58 <= len(d):
        (size,) = struct.unpack_from('<Q', d, p + 0x10)
        if 0x58 < size <= len(d) - p:
            offs = struct.unpack_from('<8Q', d, p + 0x18)
            if all(o + s <= size for o, s in zip(offs[0::2], offs[1::2])) and offs[0] >= 0x58:
                found = sorted(set(re.findall(rb'Apple metal version [0-9.]+ \([^)\n]*\)', d[p:p + size])))
                for c in found or [b'none']:
                    print(f"{p:#x} {c.decode('ascii', 'replace')}")
                step = size
    p = d.find(b'MTLB', p + step)
PY
}

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

# The newest of dotted versions (27.2 > 27.0 > 11.0).
vmax() { printf '%s\n' "$@" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1; }
minos_of() { otool -l "$1" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}'; }

check_binary() { # <minos> <metallib target> <file>
  local want=$1 want_metal=$2 f=$3 archs minos libs bad_libs
  archs=$(lipo -archs "$f" 2>/dev/null || echo "?")
  [ "$archs" = arm64 ] || bad "$f: architectures '$archs', want arm64 only"
  minos=$(minos_of "$f")
  [ "$minos" = "$want" ] || bad "$f: LC_BUILD_VERSION minos ${minos:-none}, want $want"
  libs=$(otool -L "$f" | tail -n +2 | awk '{print $1}')
  bad_libs=$(grep -vE '^(/usr/lib/|/System/Library/)' <<<"$libs" || true)
  [ -z "$bad_libs" ] || bad "$f links libraries a stock Mac does not have: $(echo $bad_libs)"
  codesign --verify "$f" 2>/dev/null || bad "$f: no valid code signature (arm64 macOS refuses to run it)"
  local targets wrong
  targets=$(metallib_targets "$f")
  if [ -n "$targets" ]; then
    wrong=$(awk -v w="$want_metal" '$2 != w || $3 != "0x8001/0x81"' <<<"$targets")
    [ -z "$wrong" ] || bad "$f embeds metallibs for another macOS than $want_metal: $(echo $wrong)"
  fi
  echo "  $(basename "$f"): arm64, minos $minos, $(wc -l <<<"$libs" | tr -d ' ') system libraries, $(grep -c . <<<"$targets" || true) metallibs for macOS $want_metal"
}

if [ "${1:-}" = --binaries ]; then
  want=${2:?usage: $0 --binaries <min macOS> <file>...}
  shift 2
  for f in "$@"; do check_binary "$want" "$want" "$f"; done
  exit $fail
fi

if [ "${1:-}" = --compilers ]; then
  shift
  [ $# -gt 0 ] || { echo "usage: $0 --compilers <file>..." >&2; exit 2; }
  all=$(for f in "$@"; do metallib_compilers "$f"; done)
  [ -n "$all" ] || { echo "FAIL no embedded metallib in $*" >&2; exit 1; }
  if grep -q ' none$' <<<"$all"; then
    echo "FAIL a metallib names no compiler: $(grep ' none$' <<<"$all" | head -3 | tr '\n' ' ')" >&2; exit 1
  fi
  cut -d' ' -f2- <<<"$all" | sort -u
  exit 0
fi

if [ "${1:-}" = --requirements ]; then
  shift
  [ $# -gt 0 ] || { echo "usage: $0 --requirements <file>..." >&2; exit 2; }
  minos=$(for f in "$@"; do minos_of "$f"; done | sort -u)
  metal=$(for f in "$@"; do metallib_targets "$f"; done | awk '{print $2}' | sort -u)
  [ "$(grep -c . <<<"$minos")" = 1 ] || { echo "FAIL the binaries have different (or no) minos: $(echo $minos)" >&2; exit 1; }
  [ "$(grep -c . <<<"$metal" || true)" -le 1 ] || { echo "FAIL the metallibs target different macOS versions: $(echo $metal)" >&2; exit 1; }
  echo "$minos ${metal:-none}"
  exit 0
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
         tools/install-metal-aot.sh tools/build-metal-aot.sh tools/macos-smoke.sh metal-aot; do
  [ -e "$k/$f" ] || bad "missing $f"
done
for f in zkminer provers/zkminer-prove-risc0-metal install.sh tools/install-metal-aot.sh tools/build-metal-aot.sh tools/macos-smoke.sh; do
  [ -x "$k/$f" ] || bad "$f is not executable"
done
info() { sed -n "s/^$1=//p" "$k/BUILDINFO"; }
min=$(info min_macos)
[ -n "$min" ] || bad "BUILDINFO has no min_macos"
bin_minos=$(info binaries_minos); metal_target=$(info metal_target)
[ -n "$bin_minos" ] && [ -n "$metal_target" ] || bad "BUILDINFO has no binaries_minos or metal_target"
newest=$(vmax "$bin_minos" "$metal_target")
[ "$min" = "$newest" ] || bad "BUILDINFO min_macos $min is not the newer of binaries_minos $bin_minos and metal_target $metal_target ($newest): install.sh would accept a macOS the kit does not run on, or refuse one it runs on"

echo "binaries:"
while IFS= read -r f; do
  if file -b "$f" | grep -q '^Mach-O'; then check_binary "$bin_minos" "$metal_target" "$f"; fi
done < <(find "$k" -type f ! -name '*.binarchive')

echo "Metal compiler:"
w=$k/provers/zkminer-prove-risc0-metal
built_by=$("$ci/check-macos-release.sh" --compilers "$w" 2>&1) || bad "$built_by"
claimed=$(info metal_compiler)
if [ "$(grep -c . <<<"$built_by")" != 1 ]; then
  bad "the worker's metallibs were built by more than one compiler: $(echo $built_by)"
elif [ "$built_by" != "$claimed" ]; then
  bad "the worker's metallibs were built by '$built_by', BUILDINFO metal_compiler says '$claimed'"
fi
if [ "$built_by" != "$VALIDATED_METAL_COMPILER" ]; then
  if [ "${METAL_COMPILER_UNVALIDATED:-0}" = 1 ]; then
    echo "  note: built by '$built_by', not the validated '$VALIDATED_METAL_COMPILER' (METAL_COMPILER_UNVALIDATED=1)"
  else
    bad "the worker's metallibs were built by '$built_by', not by the validated compiler '$VALIDATED_METAL_COMPILER' (scripts/ci/fetch-metal-toolchain.sh; METAL_COMPILER_UNVALIDATED=1 accepts it)"
  fi
fi
[ "$built_by" = "$VALIDATED_METAL_COMPILER" ] && want_v=yes || want_v=no
[ "$(info metal_compiler_validated)" = "$want_v" ] \
  || bad "BUILDINFO metal_compiler_validated=$(info metal_compiler_validated), but '$built_by' is$([ $want_v = yes ] || echo ' not') the validated compiler: it must say $want_v"
echo "  every metallib: $built_by"

echo "offline Metal archives:"
n=$(find "$k/metal-aot" -name '*.binarchive' | wc -l | tr -d ' ')
if [ "$n" -gt 0 ]; then
  (cd "$k/metal-aot" && shasum -a 256 -c --quiet SHA256SUMS) || bad "metal-aot/SHA256SUMS does not hold"
  digests=$("$k/tools/build-metal-aot.sh" --worker-digests "$w")
  arches=" $(info aot_arches) "
  keys=" $(info aot_os_keys) "
  [ "$keys" != "  " ] || bad "BUILDINFO has no aot_os_keys"
  for key in $keys; do
    [[ "$key" =~ ^macos[0-9]+$ ]] && [ "${key#macos}" -ge "${min%%.*}" ] \
      || bad "BUILDINFO aot_os_keys: $key is not macos<N> with N >= ${min%%.*} (min_macos $min): the runtime of no supported macOS opens it"
    if [[ " $VALIDATED_AOT_OS_MAJORS " != *" ${key#macos} "* ]]; then
      if [ "${AOT_ALLOW_UNVALIDATED_OS:-0}" = 1 ]; then
        echo "  note: the $key archives are not validated on hardware (AOT_ALLOW_UNVALIDATED_OS=1)"
      else
        bad "metal-aot holds $key archives, a key not validated on hardware (validated: $VALIDATED_AOT_OS_MAJORS; AOT_ALLOW_UNVALIDATED_OS=1 accepts it)"
      fi
    fi
  done
  unval=
  for key in $keys; do [[ " $VALIDATED_AOT_OS_MAJORS " == *" ${key#macos} "* ]] || unval="$unval $key"; done
  [ "$(info aot_os_unvalidated)" = "${unval# }" ] \
    || bad "BUILDINFO aot_os_unvalidated='$(info aot_os_unvalidated)', but the unvalidated keys are '${unval# }'"
  : > "$root/sets"
  for f in "$k"/metal-aot/*.binarchive; do
    b=$(basename "$f")
    IFS=- read -r unit d arch oskey _ <<<"$b"
    grep -qx "$d" <<<"$digests" || bad "metal-aot/$b: digest $d is no metallib the worker embeds"
    [[ "$arches" == *" $arch "* ]] || bad "metal-aot/$b: family $arch is not in BUILDINFO aot_arches"
    [[ "$keys" == *" $oskey "* ]] || bad "metal-aot/$b: OS key $oskey is not in BUILDINFO aot_os_keys ($(info aot_os_keys))"
    mm=$(python3 -I -c 'import json,sys
for l in open(sys.argv[1]):
    if l.strip() and json.loads(l)["file"] == sys.argv[2]: print(json.loads(l).get("macos_min", ""))' "$k/metal-aot/manifest.jsonl" "$b" 2>/dev/null | head -1)
    [ "${mm%%.*}" = "${oskey#macos}" ] || bad "metal-aot/$b: manifest.jsonl says it was built for macOS '${mm:-?}', not for its key $oskey"
    echo "$oskey $unit-$d-$arch" >> "$root/sets"
  done
  first=
  for key in $keys; do
    this=$(awk -v k="$key" '$1 == k {print $2}' "$root/sets" | sort)
    [ -n "$this" ] || bad "BUILDINFO aot_os_keys lists $key, but metal-aot has no $key archives"
    if [ -z "$first" ]; then first=$this; firstkey=$key
    elif [ "$this" != "$first" ]; then bad "metal-aot: the $key archives are not the same units and families as the $firstkey ones"; fi
  done
  echo "  $n archives ($(du -sh "$k/metal-aot" | cut -f1)) for $(info aot_arches), all of this worker's metallibs, keys$keys"
else
  [ -z "$(info aot_os_unvalidated)" ] || bad "BUILDINFO aot_os_unvalidated='$(info aot_os_unvalidated)', but the kit has no archives"
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
for s in install.sh tools/install-metal-aot.sh tools/build-metal-aot.sh tools/macos-smoke.sh; do
  bash -n "$k/$s" || bad "$s does not parse"
done
echo "  parse"
size=$(stat -f %z "$tarball")
[ "$size" -lt $((1 << 30)) ] || bad "the tarball is $size bytes (over 1 GiB: something large got in)"

[ $fail = 0 ] && echo "ok: $name ($(du -h "$tarball" | cut -f1)) is a self-contained arm64 kit for macOS $min and later (minos $bin_minos, Metal libraries for $metal_target)"
exit $fail
