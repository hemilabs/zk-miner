#!/usr/bin/env bash
# Fetches and mounts the pinned, validated Metal toolchain (B9-M26), so a CI runner compiles the kit's
# kernels with the compiler they were validated with instead of whatever its Xcode has:
#
#   fetch-metal-toolchain.sh <dir>        prints the toolchain directory to use as METAL_TC
#
# The pin is Metal Toolchain 27B47 (Xcode 27.2; `Apple metal version 32023.922 (metalfe-32023.922.4)`),
# the compiler of every R17 audit, unit suite and benchmark of the beta (docs/macos-beta.md "Metal
# compiler"). Its binaries need macOS 14.0, so it runs on a macOS 26 runner. No Xcode, Apple ID or
# sudo: the toolchain is Apple's MobileAsset for `xcodebuild -downloadComponent MetalToolchain`,
# fetched from Apple's CDN directly:
#   1. download the encrypted Apple Archive (.aar) and check its SHA-256 (pinned below; Apple's asset
#      catalogue publishes the same value as `_Measurement-SHA256`);
#   2. `aea decrypt` it with the asset's published key, take the payload out of its container, and
#      `aa extract` the disk image;
#   3. check the disk image's SHA-256 (pinned) and mount it read-only (hdiutil, user mount) at
#      <dir>/mnt; reuse an existing mount of the same image.
# How the pin was found (Apple's Xcode downloadables index maps Xcode build 27B52 to toolchain 27B47;
# gdmf.apple.com/v2/assets answers with the URL and key): ~/zkminer/deps/metal-toolchain/README.md
# on the build Mac, and the B9-M26 note.
#
# Needs: curl, aea, aa, hdiutil, python3 (all on a macOS runner with Xcode or the Command Line Tools),
# ~1.8 GB free in <dir> while unpacking, 0.9 GB after.
set -euo pipefail
BUILD=27B47
AAR_URL=https://updates.cdn-apple.com/MobileAssets2026/mobileassets/022-22478/8A094E5D-0597-4526-BA3F-A3C56614D1E5/com_apple_MobileAsset_MetalToolchain/0FA81854-B432-47C5-9913-0A496FDCAC4B.aar
AAR_SHA256=fcea0f3c0b038950bfe1c838ec05af56589b62591c9f9892457bfc1e2b6513d9
AAR_KEY=zIZ89LUdcdQ66mceeKpURt8POdwcLIu57HoZzQrxsPI=
DMG_SHA256=9a7f61869f1ec662b69634db473f81d7b18f947e9cd81601d4b2825f903b6265
COMPILER="Apple metal version 32023.922 (metalfe-32023.922.4)"

dir=${1:?usage: fetch-metal-toolchain.sh <dir>}
mkdir -p "$dir"; dir=$(cd "$dir" && pwd)
dmg=$dir/MetalToolchain-$BUILD.dmg
mnt=$dir/mnt
die() { echo "fetch-metal-toolchain: $*" >&2; exit 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

if [ -x "$mnt/Metal.xctoolchain/usr/bin/metal" ]; then
  v=$("$mnt/Metal.xctoolchain/usr/bin/metal" --version | head -1)
  [ "$v" = "$COMPILER" ] || die "$mnt holds another compiler ($v); unmount it (hdiutil detach $mnt)"
  # The version line alone could be anyone's: reuse the mount only when it is the pinned image.
  img=$(hdiutil info -plist | python3 -I -c 'import plistlib, sys
for i in plistlib.loads(sys.stdin.buffer.read()).get("images", []):
    if any(e.get("mount-point") == sys.argv[1] for e in i.get("system-entities", [])): print(i.get("image-path", ""))' "$mnt")
  [ -n "$img" ] && [ -f "$img" ] && [ "$(sha "$img")" = "$DMG_SHA256" ] \
    || die "$mnt is mounted from '${img:-?}', not the pinned disk image (SHA-256 $DMG_SHA256); unmount it (hdiutil detach $mnt)"
  echo "$mnt/Metal.xctoolchain"; exit 0
fi
if [ ! -f "$dmg" ] || [ "$(sha "$dmg")" != "$DMG_SHA256" ]; then
  work=$(mktemp -d "$dir/.fetch.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  echo "fetch-metal-toolchain: downloading Metal Toolchain $BUILD ($AAR_URL)" >&2
  curl -fL --retry 5 --retry-delay 5 -C - -o "$work/tc.aar" "$AAR_URL" || die "download failed"
  [ "$(sha "$work/tc.aar")" = "$AAR_SHA256" ] || die "the archive's SHA-256 is $(sha "$work/tc.aar"), not $AAR_SHA256"
  aea decrypt -i "$work/tc.aar" -o "$work/plain.aar" -key-value "base64:$AAR_KEY" || die "aea decrypt failed"
  rm -f "$work/tc.aar"
  # The decrypted file is a container of Apple Archive headers (AA01) whose `main` entry's DAT blob
  # is the payload (a pbzx-compressed Apple Archive holding AssetData/Restore/<n>.dmg).
  python3 -I - "$work/plain.aar" "$work/payload.aa" <<'PY' || die "unexpected archive layout"
import struct, sys
src, dst = sys.argv[1:3]
f = open(src, 'rb'); data_end = f.seek(0, 2); f.seek(0); best = None; p = 0
while p < data_end:
    f.seek(p); head = f.read(6)
    if head[:4] not in (b'AA01', b'YAA1'): sys.exit(f'no Apple Archive header at {p}')
    hs, = struct.unpack('<H', head[4:6]); f.seek(p); h = f.read(hs); q = 6; blob = 0
    while q < hs:
        t = chr(h[q + 3]); q += 4
        if t in '1248': q += int(t)
        elif t == 'P': l, = struct.unpack_from('<H', h, q); q += 2 + l
        elif t in 'ABC': w = {'A': 2, 'B': 4, 'C': 8}[t]; blob += int.from_bytes(h[q:q + w], 'little'); q += w
        elif t == '*': pass
        elif t == 'T': q += 12
        elif t == 'S': q += 8
        else: sys.exit(f'field type {t!r}')
    if best is None or blob > best[1]: best = (p + hs, blob)
    p += hs + blob
off, size = best
f.seek(off)
if f.read(4) != b'pbzx': sys.exit('the largest blob is not pbzx')
f.seek(off)
with open(dst, 'wb') as o:
    while size:
        b = f.read(min(size, 1 << 24)); o.write(b); size -= len(b)
PY
  rm -f "$work/plain.aar"
  mkdir -p "$work/x"
  aa extract -i "$work/payload.aa" -d "$work/x" || die "aa extract failed"
  found=$(find "$work/x" -name '*.dmg' | head -1)
  [ -n "$found" ] || die "no disk image in the archive"
  [ "$(sha "$found")" = "$DMG_SHA256" ] || die "the disk image's SHA-256 is $(sha "$found"), not $DMG_SHA256"
  mv -f "$found" "$dmg"
  rm -rf "$work"; trap - EXIT
fi
mkdir -p "$mnt"
hdiutil attach -nobrowse -readonly -mountpoint "$mnt" "$dmg" >/dev/null || die "hdiutil attach failed"
v=$("$mnt/Metal.xctoolchain/usr/bin/metal" --version | head -1)
[ "$v" = "$COMPILER" ] || die "the mounted compiler is '$v', not '$COMPILER'"
echo "fetch-metal-toolchain: $v at $mnt/Metal.xctoolchain (detach: hdiutil detach $mnt)" >&2
echo "$mnt/Metal.xctoolchain"
