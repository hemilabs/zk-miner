#!/usr/bin/env bash
# Tests metal-tc.sh, the Metal compiler wrapper assemble-macos.sh points METAL_TC at (B9-M26), and
# the finding of the B9-M26 review it fixes: with the wrapper at a fixed path per minimum, a
# different real compiler behind it left the old compiler's metallibs in the build (cargo reruns
# risc0-build-kernel's build scripts only when METAL_TC's value changes) while BUILDINFO named the
# new compiler.
#
#   test-metal-tc.sh [<risc0 build_kernel crate dir>]
#
# No GPU (it compiles, never runs, Metal code). Needs a real Metal compiler (METAL_TC, xcrun or PATH).
# Without, or with, the crate dir:
# 1. --in names the directory after the compiler: the same compiler gives the same directory (no
#    needless rebuilds), another compiler or another minimum another one.
# 2. it refuses to replace a directory that is not one of its own (e.g. a real Metal.xctoolchain).
# 3. it unwraps its own wrappers and B9-PKG's assemble-macos.sh ones: one -mmacosx-version-min,
#    named once in the version line.
# 4. the wrapper refuses MACOSX_DEPLOYMENT_TARGET.
# With the crate dir (e.g. ~/.cargo/git/checkouts/risc0-*/<rev>/risc0/build_kernel; one cargo build
# of a one-kernel crate per step, isolated HOME so the user's kernel cache is not touched):
# 5. control, the finding: the old fixed-path scheme (metal-tc.sh <min> <fixed dir>) with compiler A
#    (the real one, 26.0) then compiler B (the real one with a different target, 15.0, and another
#    version line) keeps A's metallib (target 26.0), and its AIR names a compiler that is not B's
#    version line: what check-macos-release.sh --compilers / assemble-macos.sh now detect.
# 6. the fix: with --in, compiler B rebuilds the kernels (target 15.0), and A again gives 26.0.
# 7. a compiler whose version line differs (C: the real compiler, output relabelled
#    "32023.999") rebuilt through --in: check-macos-release.sh --compilers reads C's line from the
#    metallib (test-assemble-macos.sh case 11: assemble-macos.sh and the check then refuse it).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
bk=${1:-}
T=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-test-metal-tc.XXXXXX")
trap 'rm -rf "$T"' EXIT
pass=0 fails=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fails=$((fails + 1)); }

real=${METAL_TC:+$METAL_TC/usr/bin/metal}
[ -n "$real" ] && [ -x "$real" ] || real=$(xcrun --sdk macosx --find metal 2>/dev/null || command -v metal || true)
if [ -x "$real" ] && grep -qs '^# metal-tc.sh: real=' "$real"; then real=$(sed -n 's/^# metal-tc.sh: real=//p' "$real"); fi
[ -x "$real" ] || { echo "no Metal compiler" >&2; exit 2; }
echo "real compiler: $real ($("$real" --version | head -1))"
unset MACOSX_DEPLOYMENT_TARGET

# Compiler B: the real one, targeting 15.0 (its flag comes last, so it wins over the wrapper's).
mkdir -p "$T/B"
for t in "$(dirname "$real")"/*; do ln -s "$t" "$T/B/$(basename "$t")"; done
rm -f "$T/B/metal"
cat > "$T/B/metal" <<EOF
#!/bin/bash
for a in "\$@"; do [ "\$a" = --version ] && { echo "Fake metal B 99.0"; exit 0; }; done
exec "$real" "\$@" -mmacosx-version-min=15.0
EOF
chmod 0755 "$T/B/metal"
# Compiler C: the real one, its version line and the AIR's compiler line relabelled 32023.999.
mkdir -p "$T/C"
for t in "$(dirname "$real")"/*; do ln -s "$t" "$T/C/$(basename "$t")"; done
rm -f "$T/C/metal"
cat > "$T/C/metal" <<EOF
#!/bin/bash
for a in "\$@"; do
  [ "\$a" = --version ] && { "$real" --version | sed -E '1s/version [0-9]+\.[0-9]+ \(metalfe-[0-9]+\.[0-9]+/version 32023.999 (metalfe-32023.999/'; exit 0; }
done
"$real" "\$@" || exit \$?
out=; prev=
for a in "\$@"; do [ "\$prev" = -o ] && out=\$a; prev=\$a; done
[ -n "\$out" ] && [ -f "\$out" ] && perl -0pi -e 's/Apple metal version \d+\.\d+ \(metalfe-\d+\.\d+/Apple metal version 32023.999 (metalfe-32023.999/g' "\$out"
exit 0
EOF
chmod 0755 "$T/C/metal"

# --- 1. --in names -------------------------------------------------------------------------------
a1=$("$ci/metal-tc.sh" 26.0 --in "$T/kit" "$real")
a2=$("$ci/metal-tc.sh" 26.0 --in "$T/kit" "$real")
b1=$("$ci/metal-tc.sh" 26.0 --in "$T/kit" "$T/B/metal")
a27=$("$ci/metal-tc.sh" 27.0 --in "$T/kit" "$real")
[ "$a1" = "$a2" ] && ok "1: the same compiler gives the same directory ($(basename "$a1"))" || no "1: $a1 != $a2"
[ "$a1" != "$b1" ] && ok "1: another compiler, another directory ($(basename "$b1"))" || no "1: B got A's directory $a1"
[ "$a1" != "$a27" ] && [[ "$(basename "$a27")" == metal-tc-27.0-* ]] && ok "1: another minimum, another directory" || no "1: 27.0 got $a27"
[ "$("$a1/usr/bin/metal" --version | head -1)" = "$("$real" --version | head -1) [-mmacosx-version-min=26.0]" ] \
  && ok "1: the version line names the target" || no "1: version line $("$a1/usr/bin/metal" --version | head -1)"

# --- 2. refuses a foreign directory ----------------------------------------------------------------
mkdir -p "$T/xc/usr/bin"; cp "$T/B/metal" "$T/xc/usr/bin/metal"; echo keep > "$T/xc/marker"
if "$ci/metal-tc.sh" 26.0 "$T/xc" "$real" > "$T/2.log" 2>&1; then no "2: replaced a foreign directory"
elif [ -f "$T/xc/marker" ] && grep -q "refusing to replace" "$T/2.log"; then ok "2: refuses to replace a directory that is not its own"
else no "2: $(cat "$T/2.log")"; fi
"$ci/metal-tc.sh" 26.0 "$a1" "$real" > /dev/null && ok "2: replaces its own directory" || no "2: refused its own directory"

# --- 3. unwrapping ---------------------------------------------------------------------------------
w=$("$ci/metal-tc.sh" 27.0 --in "$T/kit2" "$a1/usr/bin/metal")
[ "$(sed -n 's/^# metal-tc.sh: real=//p' "$w/usr/bin/metal")" = "$real" ] && [ "$("$w/usr/bin/metal" --version | head -1 | grep -o mmacosx | wc -l | tr -d ' ')" = 1 ] \
  && ok "3: a metal-tc.sh wrapper is unwrapped" || no "3: wrapper of a wrapper: $(sed -n 's/^# metal-tc.sh: real=//p' "$w/usr/bin/metal")"
mkdir -p "$T/pkg/usr/bin"
cat > "$T/pkg/usr/bin/metal" <<EOF
#!/bin/bash
# assemble-macos.sh: the Metal compiler at $real, targeting macOS 27.0.
exec "$real" -mmacosx-version-min=27.0 "\$@"
EOF
chmod 0755 "$T/pkg/usr/bin/metal"
w=$("$ci/metal-tc.sh" 26.0 --in "$T/kit2" "$T/pkg/usr/bin/metal")
[ "$(sed -n 's/^# metal-tc.sh: real=//p' "$w/usr/bin/metal")" = "$real" ] && [ "$w" = "$("$ci/metal-tc.sh" 26.0 --in "$T/kit2" "$real")" ] \
  && ok "3: a B9-PKG assemble-macos.sh wrapper is unwrapped (same directory as the real compiler)" || no "3: B9-PKG wrapper: $w"

# --- 4. MACOSX_DEPLOYMENT_TARGET -------------------------------------------------------------------
if MACOSX_DEPLOYMENT_TARGET=15.0 "$a1/usr/bin/metal" -c /dev/null -o "$T/x.air" > "$T/4.log" 2>&1; then no "4: ran with MACOSX_DEPLOYMENT_TARGET"
else grep -q MACOSX_DEPLOYMENT_TARGET "$T/4.log" && ok "4: the wrapper refuses MACOSX_DEPLOYMENT_TARGET" || no "4: $(cat "$T/4.log")"; fi

# --- 5.-7. through risc0-build-kernel and cargo ---------------------------------------------------------
if [ -z "$bk" ]; then
  echo "SKIP 5-7: no risc0 build_kernel crate dir given"
else
  bk=$(cd "$bk" && pwd)
  p=$T/proj
  mkdir -p "$p/src"
  cat > "$p/Cargo.toml" <<EOF
[package]
name = "metaltcprobe"
version = "0.1.0"
edition = "2021"
[build-dependencies]
risc0-build-kernel = { path = "$bk" }
[workspace]
EOF
  echo 'fn main() {}' > "$p/src/main.rs"
  cat > "$p/build.rs" <<'EOF'
fn main() {
    risc0_build_kernel::KernelBuild::new(risc0_build_kernel::KernelType::Metal).file("k.metal").compile("k");
}
EOF
  cat > "$p/k.metal" <<'EOF'
#include <metal_stdlib>
using namespace metal;
kernel void add1(device uint* a [[buffer(0)]], uint gid [[thread_position_in_grid]]) { threadgroup_barrier(mem_flags::mem_device); a[gid] += 1; }
EOF
  # The tools stay the user's; only the kernel cache (HOME/Library/Caches) is isolated.
  export CARGO_HOME=${CARGO_HOME:-$HOME/.cargo} RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
  mkdir -p "$T/home"
  build() { # <METAL_TC> <log>: cargo build; prints "<target> <compiler line>" of k.metallib
    (cd "$p" && HOME=$T/home METAL_TC=$1 cargo build -v --offline > "$2" 2>&1) \
      || { (cd "$p" && HOME=$T/home METAL_TC=$1 cargo build -v > "$2" 2>&1) || { tail -5 "$2" >&2; echo "build-failed"; return; }; }
    local m; m=$(ls "$p"/target/debug/build/metaltcprobe-*/out/k.metallib | head -1)
    echo "$(python3 -I -c 'import struct,sys; d=open(sys.argv[1],"rb").read(); p=d.find(b"MTLB"); print("%d.%d" % struct.unpack_from("<HH", d, p + 12))' "$m") $("$ci/check-macos-release.sh" --compilers "$m" | tr '\n' ' ' | sed 's/ $//')"
  }
  rl=$("$real" --version | head -1)
  # 5. the old scheme: one fixed path
  fixed=$T/fixed/metal-tc-26.0
  "$ci/metal-tc.sh" 26.0 "$fixed" "$real" > /dev/null
  r=$(build "$fixed" "$T/5a.log")
  [ "$r" = "26.0 $rl" ] && ok "5: control: compiler A at the fixed path: metallib for 26.0" || no "5: compiler A at the fixed path: '$r'"
  "$ci/metal-tc.sh" 26.0 "$fixed" "$T/B/metal" > /dev/null
  r=$(build "$fixed" "$T/5b.log")
  if [ "$r" = "26.0 $rl" ] && grep -q 'Fresh metaltcprobe' "$T/5b.log"; then
    ok "5: control reproduces the finding: compiler B behind the same path leaves A's metallib (cargo: Fresh), which still names '$rl', not B's 'Fake metal B 99.0'"
  else
    no "5: control: B behind the fixed path gave '$r' (the finding no longer reproduces: cargo or risc0-build-kernel changed)"
  fi
  # 6. the fix
  tA=$("$ci/metal-tc.sh" 26.0 --in "$T/kit3" "$real")
  tB=$("$ci/metal-tc.sh" 26.0 --in "$T/kit3" "$T/B/metal")
  r=$(build "$tA" "$T/6a.log")
  [ "$r" = "26.0 $rl" ] && ok "6: --in, compiler A: 26.0" || no "6: --in A: '$r'"
  r=$(build "$tB" "$T/6b.log")
  [ "${r%% *}" = 15.0 ] && grep -q 'METAL_TC changed' "$T/6b.log" && ok "6: --in, compiler B: rebuilt (METAL_TC changed), metallib for 15.0" || no "6: --in B: '$r'"
  r=$(build "$tA" "$T/6c.log")
  [ "$r" = "26.0 $rl" ] && ok "6: --in, compiler A again: 26.0" || no "6: --in A again: '$r'"
  # 7. another compiler line
  tC=$("$ci/metal-tc.sh" 26.0 --in "$T/kit3" "$T/C/metal")
  r=$(build "$tC" "$T/7.log")
  cl=$("$T/C/metal" --version | head -1)
  [ "$r" = "26.0 $cl" ] && [ "$cl" != "$rl" ] && ok "7: compiler C's metallib names '$cl' (what check-macos-release.sh compares with BUILDINFO and the pin)" || no "7: C: '$r' (C says '$cl')"
fi

echo "test-metal-tc: $pass passed, $fails failed"
[ $fails = 0 ]
