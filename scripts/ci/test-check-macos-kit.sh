#!/usr/bin/env bash
# Tests check-macos-kit.py (the release assemble job's Mach-O check, B9-CI) on a real kit and on
# broken copies of it, without a GPU and in about a minute:
#
#   test-check-macos-kit.sh <zkminer-<version>-macos-arm64.tar.gz> [<commit>]
#
# 1. the kit passes (with its version, and with <commit> when given);
# 2. it fails for: another --version, another --commit, a worker that links a library outside
#    /usr/lib and /System/Library (its libSystem load path rewritten), a universal (x86_64 + arm64)
#    CLI, an unsigned CLI (LC_CODE_SIGNATURE removed by codesign), a BUILDINFO binaries_minos other
#    than the binaries' minos, a file not in SHA256SUMS, a file that does not match it, a symbolic
#    link, a non-Mach-O worker, (with --require-validated, as the release runs it) a kit whose
#    kernels were not compiled by the validated Metal compiler, and a README.md that does not
#    describe the kit: one that claims offline archives the kit lacks (or, for a kit with archives,
#    denies them), one that says there are none while metal-aot/ holds one, and a wrong kit size.
# Each broken kit gets a correct SHA256SUMS (except the cases about it), so only the case's own
# defect can fail it. Needs python3, tar and, for the signature and universal cases, codesign and lipo.
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
tarball=$(cd "$(dirname "${1:?usage: $0 <kit tarball> [<commit>]}")" && pwd)/$(basename "$1")
commit=${2:-}
name=$(basename "$tarball" .tar.gz)
version=${name#zkminer-}; version=${version%-macos-arm64}
T=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-test-check-macos-kit.XXXXXX")
trap 'rm -rf "$T"' EXIT
pass=0 fails=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fails=$((fails + 1)); }
check() { python3 -I "$ci/check-macos-kit.py" "$@" > "$T/out" 2>&1; }
expect_fail() { # <case> <grep pattern> <args...>
  local c=$1 pat=$2; shift 2
  if check "$@"; then no "$c: accepted"; sed 's/^/    /' "$T/out"
  elif grep -qE "$pat" "$T/out"; then ok "$c: rejected ($(grep -m1 -E "$pat" "$T/out" | cut -c1-150))"
  else no "$c: rejected, but not for '$pat':"; sed 's/^/    /' "$T/out"; fi
}
resum() { # <kit dir>: SHA256SUMS as assemble-macos.sh writes it
  (cd "$1" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS)
}
pack() { # <case>: packs $T/<case>/$name into $T/<case>/$name.tar.gz
  (cd "$T/$1" && COPYFILE_DISABLE=1 tar --no-xattrs -czf "$name.tar.gz" "$name")
}
variant() { # <case>: a fresh copy of the kit in $T/<case>/$name
  rm -rf "${T:?}/$1"; mkdir -p "$T/$1"; tar -xzf "$tarball" -C "$T/$1"
}
patch_bytes() { # <file> <old> <new> (same length)
  python3 -I - "$@" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
assert len(old) == len(new)
d = open(p, 'rb').read()
assert d.count(old) >= 1, 'pattern not found'
open(p, 'wb').write(d.replace(old, new, 1))
PY
}

# 1.
if check --version "$version" ${commit:+--commit "$commit"} "$tarball"; then ok "1: the kit passes"; else no "1: the kit fails:"; sed 's/^/    /' "$T/out"; fi
if [ "$(tar -xzOf "$tarball" "$name/BUILDINFO" | sed -n 's/^metal_compiler_validated=//p')" = yes ]; then
  if check --require-validated "$tarball"; then ok "1b: the kit passes --require-validated"; else no "1b: the kit fails --require-validated:"; sed 's/^/    /' "$T/out"; fi
else
  echo "SKIP 1b: this kit's kernels were not built by the validated Metal compiler"
fi

# 2.
expect_fail "2a: another version" 'version .* want' --version 9.9.9 "$tarball"
expect_fail "2b: another commit" 'commit=.*want' --commit 0000000000000000000000000000000000000000 "$tarball"

variant lib; w=$T/lib/$name/provers/zkminer-prove-risc0-metal
patch_bytes "$w" /usr/lib/libSystem.B.dylib /opt/lib/libSystem.B.dylib
resum "$T/lib/$name"; pack lib
expect_fail "2c: a non-system library" 'links libraries a stock Mac does not have' "$T/lib/$name.tar.gz"

variant fat; c=$T/fat/$name/zkminer
if command -v lipo > /dev/null; then
  lipo -create "$c" /usr/bin/true -output "$T/fat.bin" 2>/dev/null || lipo -create -arch arm64 "$c" -arch x86_64 /usr/bin/true -output "$T/fat.bin" 2>/dev/null || true
fi
if [ -s "$T/fat.bin" ]; then
  cp "$T/fat.bin" "$c"; resum "$T/fat/$name"; pack fat
  expect_fail "2d: a universal CLI" 'universal \(fat\)' "$T/fat/$name.tar.gz"
else
  # Without lipo: a fat header around the CLI's bytes, enough for the parser.
  python3 -I - "$c" <<'PY'
import struct, sys
p = sys.argv[1]; d = open(p, 'rb').read()
hdr = struct.pack('>II', 0xCAFEBABE, 2) + struct.pack('>iiIII', 0x01000007, 3, 4096, len(d), 12) + struct.pack('>iiIII', 0x0100000C, 0, 4096, len(d), 14)
open(p, 'wb').write(hdr + b'\0' * (4096 - len(hdr)) + d)
PY
  resum "$T/fat/$name"; pack fat
  expect_fail "2d: a universal CLI" 'universal \(fat\)' "$T/fat/$name.tar.gz"
fi

if command -v codesign > /dev/null; then
  variant unsigned; c=$T/unsigned/$name/zkminer
  codesign --remove-signature "$c"
  resum "$T/unsigned/$name"; pack unsigned
  expect_fail "2e: an unsigned CLI" 'no code signature' "$T/unsigned/$name.tar.gz"
else
  echo "SKIP 2e: no codesign on this host"
fi

variant minos; b=$T/minos/$name/BUILDINFO
sed -i.bak 's/^binaries_minos=.*/binaries_minos=99.0/' "$b"; rm -f "$b.bak"
resum "$T/minos/$name"; pack minos
expect_fail "2f: BUILDINFO binaries_minos != the binaries' minos" 'binaries_minos=99.0' "$T/minos/$name.tar.gz"

variant extra; echo extra > "$T/extra/$name/tools/extra.sh"; pack extra
expect_fail "2g: a file not in SHA256SUMS" 'not in SHA256SUMS' "$T/extra/$name.tar.gz"

variant edited; echo '# edited' >> "$T/edited/$name/install.sh"; pack edited
expect_fail "2h: a file that does not match SHA256SUMS" 'install.sh does not match SHA256SUMS' "$T/edited/$name.tar.gz"

variant link; ln -s /usr/bin/true "$T/link/$name/tools/link"; pack link
expect_fail "2i: a symbolic link" 'not a regular file' "$T/link/$name.tar.gz"

variant notmacho; printf '#!/bin/sh\nexit 0\n' > "$T/notmacho/$name/provers/zkminer-prove-risc0-metal"
resum "$T/notmacho/$name"; pack notmacho
expect_fail "2j: a worker that is not a Mach-O program" 'is not a Mach-O file' "$T/notmacho/$name.tar.gz"

variant unvalidated; b=$T/unvalidated/$name/BUILDINFO
sed -i.bak 's/^metal_compiler_validated=.*/metal_compiler_validated=no/' "$b"; rm -f "$b.bak"
resum "$T/unvalidated/$name"; pack unvalidated
expect_fail "2k: an unvalidated Metal compiler (--require-validated)" 'metal_compiler_validated=no' --require-validated "$T/unvalidated/$name.tar.gz"

readme_edit() { # <kit README> <python expression on the whitespace-normalised text t>
  python3 -I - "$@" <<'PY'
import sys
p, expr = sys.argv[1], sys.argv[2]
t = ' '.join(open(p, encoding='utf-8').read().split())
new = eval(expr, {'t': t})
assert new != t, 'README edit changed nothing'
open(p, 'w', encoding='utf-8').write(new + '\n')
PY
}
none_text='This kit has no offline GPU pipeline archives'
if tar -tzf "$tarball" | grep -q '^[^/]*/metal-aot/.*\.binarchive$'; then
  variant readme_aot; readme_edit "$T/readme_aot/$name/README.md" "t + ' $none_text.'"
  resum "$T/readme_aot/$name"; pack readme_aot
  expect_fail "2l: a README denying the kit's offline archives" 'README.md says .* GPU binary archives' "$T/readme_aot/$name.tar.gz"
  echo "SKIP 2n: this kit has offline archives"
else
  variant readme_aot; readme_edit "$T/readme_aot/$name/README.md" "t.replace('$none_text', 'This kit ships offline GPU pipeline archives')"
  resum "$T/readme_aot/$name"; pack readme_aot
  expect_fail "2l: a README claiming offline archives the kit lacks" 'README.md does not say' "$T/readme_aot/$name.tar.gz"
  variant aot_added; mkdir -p "$T/aot_added/$name/metal-aot"
  # A Mach-O header for the Apple GPU's CPU type: the checker counts it as a GPU binary archive.
  python3 -I -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack("<IiiIIIII",0xFEEDFACF,0x01000013,0,1,0,0,0,0))' \
    "$T/aot_added/$name/metal-aot/zkp-applegpu_g17s-macos27-0.binarchive"
  resum "$T/aot_added/$name"; pack aot_added
  expect_fail "2n: a README saying 'no archives' over a kit with one" 'README.md says .* 1 GPU binary archives' "$T/aot_added/$name.tar.gz"
fi
variant readme_size; readme_edit "$T/readme_size/$name/README.md" "__import__('re').sub(r'About [0-9.]+ GB for the kit', 'About 9.5 GB for the kit', t)"
resum "$T/readme_size/$name"; pack readme_size
expect_fail "2m: a README with a wrong kit size" 'About 9.5 GB for the kit' "$T/readme_size/$name.tar.gz"

echo "test-check-macos-kit: $pass passed, $fails failed"
[ $fails = 0 ]
