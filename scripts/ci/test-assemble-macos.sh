#!/usr/bin/env bash
# Tests assemble-macos.sh's minimum-macOS handling and check-macos-release.sh's BUILDINFO checks on
# prebuilt binaries, without a build and without a GPU (the B9-PKG review finding: the revert knob
# ZKMINER_MACOS_MIN=sdk produced no kit, and its BUILDINFO would have let install.sh accept a macOS
# on which Metal does not load the kernels):
#
#   test-assemble-macos.sh <sdk worker> <sdk CLI> [<kit worker> <kit CLI>]
#
# <sdk ...>: a worker and CLI built with no deployment target (ZKMINER_MACOS_MIN=sdk, or a plain
# `make -f Makefile.mac mac-build-worker`): minos 11.0, metallibs for the build SDK.
# <kit ...>: optional, a kit build for a minimum T (the default 26.0, or 27.0: minos T, metallibs for
# T), e.g. from a kit tarball. T is read from the worker.
#
# It copies the files assemble-macos.sh reads into a scratch repo, puts the binaries in its
# target/release, and runs assemble-macos.sh with ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none:
# 1. sdk mode on the sdk build: a kit; BUILDINFO binaries_minos = the binaries' minos, metal_target =
#    the metallibs' target, min_macos = the newer of the two (the SDK's version, not 11.0); the
#    outer SHA256SUMS is written.
# 2. default mode (26.0) on the sdk build: refused (the build is not for 26.0).
# 3. with a kit build for T: ZKMINER_MACOS_MIN=T gives min_macos = binaries_minos = metal_target = T,
#    and sdk mode on it reads the same T; the default mode refuses a build for another T.
# 8. (with a kit build; runs the worker's --metal-arch, so a Metal device is needed) install.sh
#    installs only the offline archives keyed for the running macOS's major (fake archives keyed
#    macos26 and macos27 in the kit, a sw_vers shim): on 27.x only the macos27 files, on 26.x none
#    (with a message) when the kit has no macos26 files, and the macos26 ones when it has them.
# 9. (with a 26.0 kit build) install.sh refuses macOS 25.9 naming macOS 26.0 (Tahoe), and installs
#    on 26.0; the refused install creates no prefix directory.
# 10. (with a kit build; B9-M26 review) the archive keys do not follow the build host: with a sw_vers
#    shim reporting macOS 26.4.1 and a fake mac-build-aot (archives named after the worker's
#    metallib digests, keyed macos<AOT_MACOS_MIN's major>), the default builds only the validated
#    macos27 set; AOT_OS_MAJORS="26 27" is refused without AOT_ALLOW_UNVALIDATED_OS=1, and with it
#    BUILDINFO aot_os_unvalidated=macos26 and check-macos-release.sh rejects that kit without the
#    opt-in.
# 11. (with a kit build; B9-M26 review) the compiler: check-macos-release.sh rejects a BUILDINFO
#    metal_compiler that is not what the metallibs' AIR names; assemble-macos.sh refuses a worker
#    whose metallibs another compiler built (the worker with its compiler line relabelled
#    32023.999, re-signed) as a stale build (wrapper mode, even with METAL_COMPILER_UNVALIDATED=1)
#    and as unvalidated (sdk mode); with the opt-in it labels the kit with the AIR's compiler, which
#    check-macos-release.sh then rejects without the opt-in.
# 4. check-macos-release.sh rejects the sdk kit with BUILDINFO edited (SHA256SUMS redone) to the
#    old min_macos (the binaries' 11.0), to an older macOS than the metallibs', to a newer one than
#    needed, and with a metal_target the worker does not embed.
# 5. install.sh (--no-aot, scratch HOME and prefix, a sw_vers shim) refuses the sdk kit on a macOS
#    older than the metallibs' target and accepts it on that version; with the old BUILDINFO
#    (min_macos = 11.0) it would have accepted the older macOS.
# 6. install.sh --with-groth16 takes the worker's lock file (RISC0_HOME/tmp/.risc0-groth16-<v>.lock):
#    while another process holds it and completes the component, install.sh waits and then
#    downloads nothing (the kit's groth16_url points at a closed port, so a download would fail).
# 7. install.sh leaves no partial .<name>.tmp.<pid> file when a copy fails (a cp shim fails on the
#    worker's copy, as on a full disk).
# Needs about 1 GB in TMPDIR and a few minutes (each kit is gzip -9 packed).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$ci/../.." && pwd)
sdk_worker=${1:?usage: $0 <sdk worker> <sdk CLI> [<kit worker> <kit CLI>]}
sdk_cli=${2:?usage: $0 <sdk worker> <sdk CLI> [<kit worker> <kit CLI>]}
m27_worker=${3:-} m27_cli=${4:-}
default_min=$(sed -n 's/^macos_min=\${ZKMINER_MACOS_MIN:-\([0-9.]*\)}$/\1/p' "$ci/assemble-macos.sh")
[ -n "$default_min" ] || { echo "cannot read assemble-macos.sh's default minimum" >&2; exit 2; }

T=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-test-assemble-macos.XXXXXX")
trap 'rm -rf "$T"' EXIT
pass=0 fails=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fails=$((fails + 1)); }
info() { sed -n "s/^$2=//p" "$1"; }

# A scratch repo with what assemble-macos.sh reads (no git: its commit fields say "unknown").
fake_repo() { # <dir> <worker> <cli>
  local r=$1 f
  mkdir -p "$r"
  for f in Cargo.toml LICENSE scripts/ci scripts/mac packaging/macos crates/zkminer-prove-risc0/src/groth16_component.rs; do
    mkdir -p "$r/$(dirname "$f")"
    cp -R "$repo/$f" "$r/$f"
  done
  mkdir -p "$r/target/release"
  cp "$2" "$r/target/release/zkminer-prove-risc0-metal"
  cp "$3" "$r/target/release/zkminer"
}
assemble() { # <repo> <out> <ZKMINER_MACOS_MIN>
  env -u MACOSX_DEPLOYMENT_TARGET -u RUSTFLAGS ENV_SH=/nonexistent ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none \
    ZKMINER_MACOS_MIN="$3" "$1/scripts/ci/assemble-macos.sh" "$2"
}
kit_buildinfo() { # <tarball> <dest dir>: unpack, print the BUILDINFO path
  mkdir -p "$2"; tar -xzf "$1" -C "$2"; echo "$2"/zkminer-*-macos-arm64/BUILDINFO
}

# Read independently of the scripts under test: minos by otool, the metallib target from the first
# MTLB header (u16 os major, u16 os minor at +12).
sdk_minos=$(otool -l "$sdk_worker" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}')
sdk_metal=$(python3 -I -c '
import struct, sys
d = open(sys.argv[1], "rb").read(); p = d.find(b"MTLB\x01\x80")
print("%d.%d" % struct.unpack_from("<HH", d, p + 12) if p >= 0 else "none")' "$sdk_worker")
echo "sdk build: minos $sdk_minos, metallibs for $sdk_metal"
[ "$sdk_metal" != none ] || { echo "the sdk worker embeds no metallib" >&2; exit 2; }
[ "$sdk_minos" != "$sdk_metal" ] || echo "note: the sdk build's minos equals its metallib target; case 1 then cannot tell the fix apart"

# --- 1. sdk mode on the sdk build ---------------------------------------------------------------
fake_repo "$T/r-sdk" "$sdk_worker" "$sdk_cli"
if assemble "$T/r-sdk" "$T/out-sdk" sdk > "$T/sdk.log" 2>&1; then
  ok "1: ZKMINER_MACOS_MIN=sdk assembles a kit"
  tarball=$(ls "$T"/out-sdk/zkminer-*-macos-arm64.tar.gz)
  bi=$(kit_buildinfo "$tarball" "$T/u-sdk")
  [ "$(info "$bi" binaries_minos)" = "$sdk_minos" ] && ok "1: binaries_minos $sdk_minos" || no "1: binaries_minos $(info "$bi" binaries_minos), want $sdk_minos"
  [ "$(info "$bi" metal_target)" = "$sdk_metal" ] && ok "1: metal_target $sdk_metal" || no "1: metal_target $(info "$bi" metal_target), want $sdk_metal"
  want=$(printf '%s\n' "$sdk_minos" "$sdk_metal" | sort -t. -k1,1n -k2,2n | tail -1)
  [ "$(info "$bi" min_macos)" = "$want" ] && ok "1: min_macos $want (the newer of the two)" || no "1: min_macos $(info "$bi" min_macos), want $want"
  [ -s "$T/out-sdk/SHA256SUMS" ] && (cd "$T/out-sdk" && shasum -a 256 -c --quiet SHA256SUMS) \
    && ok "1: outer SHA256SUMS written and holds" || no "1: no valid outer SHA256SUMS"
else
  no "1: ZKMINER_MACOS_MIN=sdk failed (log below)"; tail -20 "$T/sdk.log"
  tarball=
fi

# --- 2. default mode on the sdk build -----------------------------------------------------------
if env -u ZKMINER_MACOS_MIN ENV_SH=/nonexistent ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none \
    "$T/r-sdk/scripts/ci/assemble-macos.sh" "$T/out-sdk-def" > "$T/sdk-def.log" 2>&1; then
  no "2: the default mode ($default_min) packaged a build that is not for $default_min"
else
  grep -q "the build is not for macOS $default_min" "$T/sdk-def.log" && ok "2: the default mode ($default_min) refuses the sdk build" \
    || { no "2: the default mode failed for another reason"; tail -5 "$T/sdk-def.log"; }
fi

# --- 3. a kit build for T -----------------------------------------------------------------------
kit_tarball=
if [ -n "$m27_worker" ]; then
  tm=$(otool -l "$m27_worker" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}')
  echo "kit build: minos $tm"
  fake_repo "$T/r-27" "$m27_worker" "$m27_cli"
  for mode in "$tm" sdk; do
    if assemble "$T/r-27" "$T/out-27-$mode" "$mode" > "$T/27-$mode.log" 2>&1; then
      bi=$(kit_buildinfo "$(ls "$T"/out-27-$mode/zkminer-*-macos-arm64.tar.gz)" "$T/u-27-$mode")
      got="$(info "$bi" min_macos) $(info "$bi" binaries_minos) $(info "$bi" metal_target)"
      [ "$got" = "$tm $tm $tm" ] && ok "3: ZKMINER_MACOS_MIN=$mode on the $tm build: min_macos, binaries_minos, metal_target $tm" \
        || no "3: ZKMINER_MACOS_MIN=$mode on the $tm build: got '$got'"
      if [ "$mode" = "$tm" ]; then kit_tarball=$T/kit-$tm.tar.gz; cp "$T"/out-27-$mode/zkminer-*-macos-arm64.tar.gz "$kit_tarball"; fi
      rm -rf "$T/u-27-$mode" "$T/out-27-$mode"
    else
      no "3: ZKMINER_MACOS_MIN=$mode on the $tm build failed"; tail -10 "$T/27-$mode.log"
    fi
  done
  other=27.0; [ "$tm" = 27.0 ] && other=26.0
  if assemble "$T/r-27" "$T/out-27-other" "$other" > "$T/27-other.log" 2>&1; then
    no "3: ZKMINER_MACOS_MIN=$other packaged the $tm build"
  else
    grep -q "the build is not for macOS $other" "$T/27-other.log" && ok "3: ZKMINER_MACOS_MIN=$other refuses the $tm build" \
      || { no "3: ZKMINER_MACOS_MIN=$other on the $tm build failed for another reason"; tail -5 "$T/27-other.log"; }
  fi
else
  echo "SKIP 3, 8, 9: no kit build given"
fi

# --- 4. check-macos-release.sh on edited BUILDINFOs ---------------------------------------------
rekit() { # <field=value>...: the sdk kit with BUILDINFO fields replaced, repacked; prints the tarball
  local d=$T/edit k e
  rm -rf "$d"; mkdir -p "$d"; tar -xzf "$tarball" -C "$d"
  k=$(echo "$d"/zkminer-*-macos-arm64)
  for e in "$@"; do
    sed -i '' "s|^${e%%=*}=.*|$e|" "$k/BUILDINFO"
    grep -qxF "$e" "$k/BUILDINFO" || { echo "rekit: cannot set $e" >&2; exit 2; }
  done
  (cd "$k" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS)
  (cd "$d" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - "$(basename "$k")" | gzip -1 > "$d.tar.gz")
  rm -rf "$d"; echo "$d.tar.gz"
}
neg() { # <label> <expected FAIL text> <field=value>...
  local label=$1 text=$2 t; shift 2
  t=$(rekit "$@")
  if "$ci/check-macos-release.sh" "$t" > "$T/neg.log" 2>&1; then
    no "4: check-macos-release.sh accepted $label"
  elif grep -q "$text" "$T/neg.log"; then
    ok "4: check-macos-release.sh rejects $label"
  else
    no "4: $label rejected for another reason: $(grep FAIL "$T/neg.log" | head -2)"
  fi
  rm -f "$t"
}
if [ -n "$tarball" ]; then
  older=$(awk -F. '{printf "%d.%d", $1, ($2 > 0 ? $2 - 1 : 0)}' <<<"$sdk_metal")
  [ "$older" != "$sdk_metal" ] || older=$(( ${sdk_metal%%.*} - 1 )).0
  neg "min_macos = the binaries' minos $sdk_minos (the old sdk BUILDINFO)" "is not the newer of" "min_macos=$sdk_minos"
  neg "min_macos $older, older than the metallibs' $sdk_metal" "is not the newer of" "min_macos=$older"
  neg "min_macos 99.0, newer than needed" "is not the newer of" "min_macos=99.0"
  neg "metal_target $sdk_minos (min_macos $sdk_minos), which the worker does not embed" "embeds metallibs for another macOS" "metal_target=$sdk_minos" "min_macos=$sdk_minos"
fi

# --- 5. install.sh on the sdk kit, on a faked macOS version ---------------------------------------
inst() { # <tarball> <macOS version>: install.sh --no-aot into scratch; prints its exit code
  local d=$T/inst rc=0
  rm -rf "$d"; mkdir -p "$d/bin" "$d/home" "$d/kit"
  printf '#!/bin/sh\n[ "$1" = -productVersion ] && echo %s || /usr/bin/sw_vers "$@"\n' "$2" > "$d/bin/sw_vers"
  chmod 0755 "$d/bin/sw_vers"
  tar -xzf "$1" -C "$d/kit"
  HOME=$d/home PATH="$d/bin:$PATH" "$(echo "$d"/kit/zkminer-*-macos-arm64)/install.sh" --no-aot --prefix "$d/home/.zkminer" > "$T/inst.log" 2>&1 || rc=$?
  [ -e "$d/home/.zkminer" ] && echo yes > "$T/inst.prefix" || echo no > "$T/inst.prefix"
  rm -rf "$d"; echo $rc
}
if [ -n "$tarball" ]; then
  rc=$(inst "$tarball" "$older")
  [ "$rc" != 0 ] && grep -q "needs macOS $sdk_metal or later" "$T/inst.log" \
    && ok "5: install.sh refuses the sdk kit on macOS $older (its metallibs need $sdk_metal)" \
    || no "5: install.sh on macOS $older: rc $rc: $(tail -1 "$T/inst.log")"
  rc=$(inst "$tarball" "$sdk_metal")
  [ "$rc" = 0 ] && ok "5: install.sh installs the sdk kit on macOS $sdk_metal" || no "5: install.sh on macOS $sdk_metal: rc $rc: $(tail -2 "$T/inst.log")"
  t=$(rekit "min_macos=$sdk_minos")
  rc=$(inst "$t" "$older")
  [ "$rc" = 0 ] && echo "info 5: with the old BUILDINFO (min_macos $sdk_minos) install.sh would accept macOS $older, where Metal refuses the $sdk_metal kernels (the finding)" \
    || echo "info 5: the old BUILDINFO on macOS $older: rc $rc"
  rm -f "$t"
fi

# --- 6. install.sh and the worker's risc0-groth16 lock ------------------------------------------
inst_env() { # <tarball> <dir> <install args>...: install.sh in <dir> (HOME, RISC0_HOME, bin shims); rc
  local t=$1 d=$2 rc=0; shift 2
  mkdir -p "$d/bin" "$d/home" "$d/kit"
  printf '#!/bin/sh\n[ "$1" = -productVersion ] && echo %s || /usr/bin/sw_vers "$@"\n' "$sdk_metal" > "$d/bin/sw_vers"
  chmod 0755 "$d/bin/sw_vers"
  tar -xzf "$t" -C "$d/kit"
  HOME=$d/home RISC0_HOME=$d/r0 PATH="$d/bin:$PATH" "$(echo "$d"/kit/zkminer-*-macos-arm64)/install.sh" \
    --no-aot --prefix "$d/home/.zkminer" "$@" > "$d/log" 2>&1 || rc=$?
  echo $rc
}
if [ -n "$tarball" ]; then
  t=$(rekit "groth16_url=http://127.0.0.1:9/no-download")
  # control: no lock holder, no component: install.sh tries the (closed) URL and fails
  d=$T/g16-control; rc=$(inst_env "$t" "$d" --with-groth16)
  [ "$rc" != 0 ] && grep -q "the download failed" "$d/log" && ok "6: control: without a component install.sh downloads (and the closed URL fails)" \
    || no "6: control: rc $rc: $(tail -2 "$d/log")"
  rm -rf "$d"
  d=$T/g16-lock; mkdir -p "$d/r0/tmp"
  lock=$d/r0/tmp/.risc0-groth16-$(sed -n 's/^groth16_version=//p' "$T/u-sdk"/*/BUILDINFO).lock
  comp=$d/r0/extensions/v$(sed -n 's/^groth16_version=//p' "$T/u-sdk"/*/BUILDINFO)-risc0-groth16
  perl -e 'use Fcntl qw(:flock); open(my $f, ">", $ARGV[0]) or die; flock($f, LOCK_EX) or die;
    open(my $r, ">", "$ARGV[0].held"); close $r; sleep 4;
    system("mkdir", "-p", $ARGV[1]);
    for my $n (qw(stark_verify_graph.bin stark_verify_final.zkey fuzzed_msm_results.bin preprocessed_coeffs.bin)) {
      open(my $o, ">", "$ARGV[1]/$n") or die; print $o "x"; close $o }
    flock($f, LOCK_UN)' "$lock" "$comp" &
  holder=$!
  while [ ! -e "$lock.held" ]; do sleep 0.1; done
  t0=$(perl -MTime::HiRes=time -e 'printf "%.1f", time')
  rc=$(inst_env "$t" "$d" --with-groth16)
  waited=$(perl -MTime::HiRes=time -e "printf '%.1f', time - $t0")
  wait "$holder" || true
  if [ "$rc" = 0 ] && grep -q "installed meanwhile" "$d/log" && ! grep -q downloading "$d/log"; then
    ok "6: install.sh waited ${waited} s for the lock holder and downloaded nothing"
  else
    no "6: lock: rc $rc after ${waited} s: $(tail -3 "$d/log")"
  fi
  rm -rf "$d" "$t"
fi

# --- 7. install.sh cleans up a failed copy ------------------------------------------------------
if [ -n "$tarball" ]; then
  d=$T/cpfail; mkdir -p "$d/bin"
  cat > "$d/bin/cp" <<'EOF'
#!/bin/sh
case "$2" in
  */.zkminer-prove-risc0-metal.tmp.*) head -c 4096 "$1" > "$2"; echo "cp: $2: No space left on device" >&2; exit 1 ;;
esac
exec /bin/cp "$@"
EOF
  chmod 0755 "$d/bin/cp"
  rc=$(inst_env "$tarball" "$d")
  left=$(find "$d/home/.zkminer" -name '.*.tmp.*' 2>/dev/null)
  [ "$rc" != 0 ] && [ -z "$left" ] && ok "7: a failed copy (rc $rc) leaves no partial file" || no "7: rc $rc, left: $left"
  rm -rf "$d"
fi

# --- 8. install.sh installs the archives of this macOS's major only -------------------------------
aotkit() { # <keys...>: the kit build's kit with fake g17s archives for those macOS keys; prints the tarball
  local d=$T/aotkit k key u
  rm -rf "$d"; mkdir -p "$d"; tar -xzf "$kit_tarball" -C "$d"
  k=$(echo "$d"/zkminer-*-macos-arm64)
  : > "$k/metal-aot/manifest.jsonl"
  for key in "$@"; do
    for u in zkp rv32im; do
      f=$u-000000000000000000000000-applegpu_g17s-$key-0000000000000000.binarchive
      echo "fake $u $key" > "$k/metal-aot/$f"
      echo "{\"file\": \"$f\", \"unit\": \"$u\", \"arch\": \"applegpu_g17s\", \"os_key\": \"$key\", \"macos_min\": \"${key#macos}.0\"}" >> "$k/metal-aot/manifest.jsonl"
    done
  done
  (cd "$k/metal-aot" && shasum -a 256 *.binarchive > SHA256SUMS)
  sed -i '' "s|^aot_arches=.*|aot_arches=applegpu_g17s|; s|^aot_os_keys=.*|aot_os_keys=$*|" "$k/BUILDINFO"
  (cd "$k" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS)
  (cd "$d" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - "$(basename "$k")" | gzip -1 > "$d.tar.gz")
  rm -rf "$d"; echo "$d.tar.gz"
}
inst_aot() { # <tarball> <macOS version> <dir>: install.sh (with archives) on a faked macOS; rc
  local d=$3 rc=0
  rm -rf "$d"; mkdir -p "$d/bin" "$d/home" "$d/kit"
  printf '#!/bin/sh\n[ "$1" = -productVersion ] && echo %s || /usr/bin/sw_vers "$@"\n' "$2" > "$d/bin/sw_vers"
  chmod 0755 "$d/bin/sw_vers"
  tar -xzf "$1" -C "$d/kit"
  HOME=$d/home PATH="$d/bin:$PATH" ZKMINER_AOT_VALIDATED=applegpu_g17s \
    "$(echo "$d"/kit/zkminer-*-macos-arm64)/install.sh" --prefix "$d/home/.zkminer" > "$d/log" 2>&1 || rc=$?
  echo $rc
}
if [ -n "$kit_tarball" ] && [ "${TEST_ASSEMBLE_GPU:-1}" = 1 ]; then
  arch=$(/usr/bin/env "$m27_worker" --metal-arch 2>/dev/null || true)
  if [ "$arch" != applegpu_g17s ]; then
    echo "SKIP 8: this Mac's GPU is '${arch:-none}', the fake archives are applegpu_g17s"
  else
    t=$(aotkit macos27)
    d=$T/a27; rc=$(inst_aot "$t" 27.2 "$d")
    n=$(ls "$d/home/.zkminer/provers/metal-aot" 2>/dev/null | grep -c macos27 || true)
    [ "$rc" = 0 ] && [ "$n" = 2 ] && ok "8: macOS 27.2: the 2 macos27 archives installed" || no "8: macOS 27.2: rc $rc, $n macos27 archives: $(tail -2 "$d/log")"
    d=$T/a26; rc=$(inst_aot "$t" 26.4 "$d")
    if [ "${tm%%.*}" -gt 26 ]; then
      [ "$rc" != 0 ] && grep -q "needs macOS $tm or later" "$d/log" && ok "8: the $tm kit refuses macOS 26.4" \
        || no "8: the $tm kit on macOS 26.4: rc $rc: $(tail -2 "$d/log")"
    else
    [ "$rc" = 0 ] && [ ! -e "$d/home/.zkminer/provers/metal-aot" ] && grep -q "not for macOS 26: none installed" "$d/log" \
      && ok "8: macOS 26.4 with a macos27-only kit: no archives installed, and it says why" || no "8: macOS 26.4: rc $rc: $(tail -3 "$d/log")"
    rm -f "$t"; t=$(aotkit macos26 macos27)
    d=$T/a26b; rc=$(inst_aot "$t" 26.4 "$d")
    got=$(ls "$d/home/.zkminer/provers/metal-aot" 2>/dev/null | grep binarchive | sed 's/.*-applegpu_g17s-\(macos[0-9]*\)-.*/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
    [ "$rc" = 0 ] && [ "$got" = " 2 macos26 " ] && ok "8: macOS 26.4 with macos26 + macos27 archives: only the 2 macos26 ones installed" \
      || no "8: macOS 26.4 with both keys: rc $rc, installed '$got': $(tail -2 "$d/log")"
    fi
    rm -rf "$T"/a27 "$T"/a26 "$T"/a26b "$t"
  fi
fi

# --- 9. install.sh on a 26.0 kit and macOS 25.9 ---------------------------------------------------
if [ -n "$kit_tarball" ] && [ "$tm" = 26.0 ]; then
  rc=$(inst "$kit_tarball" 25.9)
  [ "$rc" != 0 ] && grep -q "needs macOS 26.0 (Tahoe) or later; this Mac runs macOS 25.9" "$T/inst.log" \
    && ok "9: install.sh refuses macOS 25.9: $(tail -1 "$T/inst.log" | cut -c1-110)" || no "9: macOS 25.9: rc $rc: $(tail -1 "$T/inst.log")"
  [ "$(cat "$T/inst.prefix")" = no ] && ok "9: the refused install created no prefix directory" || no "9: the refused install left an (empty) prefix directory"
  rc=$(inst "$kit_tarball" 26.0)
  [ "$rc" = 0 ] && ok "9: install.sh installs the 26.0 kit on macOS 26.0" || no "9: macOS 26.0: rc $rc: $(tail -2 "$T/inst.log")"
fi

# --- 10. archive keys do not follow the build host ------------------------------------------------
if [ -n "$kit_tarball" ]; then
  r=$T/r-aot
  fake_repo "$r" "$m27_worker" "$m27_cli"
  printf '%s\n' \
    'mac-build-aot:' \
    '	@set -e; m=$${AOT_MACOS_MIN%%.*}; mkdir -p "$(AOT_OUT)"; rm -f "$(AOT_OUT)"/*.binarchive; : > "$(AOT_OUT)/manifest.jsonl"; \' \
    '	i=0; for d in $$(scripts/mac/build-metal-aot.sh --worker-digests target/release/zkminer-prove-risc0-metal); do i=$$((i+1)); \' \
    '	  f=u$$i-$$d-applegpu_g17s-macos$$m-0000000000000000.binarchive; echo "fake $$m $$d" > "$(AOT_OUT)/$$f"; \' \
    '	  echo "{\"file\": \"$$f\", \"macos_min\": \"$$m.0\"}" >> "$(AOT_OUT)/manifest.jsonl"; done; \' \
    '	echo "fake worker macos$$m" > "$(AOT_OUT)/WORKER"' > "$r/Makefile.mac"
  mkdir -p "$T/sv26"
  printf '#!/bin/sh\n[ "$1" = -productVersion ] && echo 26.4.1 || /usr/bin/sw_vers "$@"\n' > "$T/sv26/sw_vers"; chmod 0755 "$T/sv26/sw_vers"
  asm_aot() { # <out> <env...>: assemble with archives on a "macOS 26.4.1" build host
    local o=$1; shift
    env -u MACOSX_DEPLOYMENT_TARGET -u RUSTFLAGS -u AOT_OS_MAJORS -u AOT_ALLOW_UNVALIDATED_OS PATH="$T/sv26:$PATH" \
      ENV_SH=/nonexistent ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=applegpu_g17s ZKMINER_MACOS_MIN="$tm" "$@" \
      "$r/scripts/ci/assemble-macos.sh" "$o"
  }
  if asm_aot "$T/out-aot" > "$T/aot.log" 2>&1; then
    bi=$(kit_buildinfo "$(ls "$T"/out-aot/zkminer-*-macos-arm64.tar.gz)" "$T/u-aot")
    [ "$(info "$bi" aot_os_keys)" = macos27 ] && [ -z "$(info "$bi" aot_os_unvalidated)" ] && grep -q '^build_macos=26.4.1' "$bi" \
      && ok "10: on a macOS 26.4.1 build host the default ships only the validated macos27 set (check passes)" \
      || no "10: default keys '$(info "$bi" aot_os_keys)', unvalidated '$(info "$bi" aot_os_unvalidated)', $(grep '^build_macos' "$bi")"
  else
    no "10: the default assemble failed"; tail -8 "$T/aot.log"
  fi
  if [ "${tm%%.*}" -gt 26 ]; then
    if asm_aot "$T/out-aot2" AOT_OS_MAJORS="26 27" AOT_ALLOW_UNVALIDATED_OS=1 > "$T/aot2.log" 2>&1; then no "10: the $tm kit took macos26 archives"
    else grep -q "macOS 26 is older than the kit.s minimum" "$T/aot2.log" && ok "10: the $tm kit refuses macos26 archives (older than its minimum)" || no "10: $(tail -2 "$T/aot2.log")"; fi
  elif asm_aot "$T/out-aot2" AOT_OS_MAJORS="26 27" > "$T/aot2.log" 2>&1; then
    no "10: AOT_OS_MAJORS=\"26 27\" built an unvalidated macos26 set without the opt-in"
  else
    grep -q "macos26 archives are not validated on hardware" "$T/aot2.log" && ok "10: AOT_OS_MAJORS=\"26 27\" refused without AOT_ALLOW_UNVALIDATED_OS=1" \
      || { no "10: AOT_OS_MAJORS=\"26 27\" failed for another reason"; tail -5 "$T/aot2.log"; }
  fi
  if [ "${tm%%.*}" -le 26 ]; then
    if asm_aot "$T/out-aot3" AOT_OS_MAJORS="26 27" AOT_ALLOW_UNVALIDATED_OS=1 > "$T/aot3.log" 2>&1; then
      t3=$(ls "$T"/out-aot3/zkminer-*-macos-arm64.tar.gz)
      bi=$(kit_buildinfo "$t3" "$T/u-aot3")
      [ "$(info "$bi" aot_os_keys)" = "macos26 macos27" ] && [ "$(info "$bi" aot_os_unvalidated)" = macos26 ] \
        && ok "10: with the opt-in: keys macos26 macos27, BUILDINFO aot_os_unvalidated=macos26" \
        || no "10: opt-in: keys '$(info "$bi" aot_os_keys)', unvalidated '$(info "$bi" aot_os_unvalidated)'"
      if env -u AOT_ALLOW_UNVALIDATED_OS "$ci/check-macos-release.sh" "$t3" > "$T/aot3c.log" 2>&1; then
        no "10: check-macos-release.sh accepted a macos26 set without the opt-in"
      else
        grep -q "macos26 archives, a key not validated on hardware" "$T/aot3c.log" && ok "10: check-macos-release.sh rejects the macos26 set without the opt-in" \
          || no "10: check failed for another reason: $(grep FAIL "$T/aot3c.log" | head -2)"
      fi
    else
      no "10: AOT_OS_MAJORS=\"26 27\" AOT_ALLOW_UNVALIDATED_OS=1 failed"; tail -8 "$T/aot3.log"
    fi
  fi
  rm -rf "$r" "$T"/out-aot* "$T"/u-aot*
fi

# --- 11. the compiler that built the metallibs ------------------------------------------------------
if [ -n "$kit_tarball" ]; then
  tarball_saved=$tarball; tarball=$kit_tarball
  t=$(rekit "metal_compiler=Apple metal version 32023.999 (metalfe-32023.999.4)")
  if "$ci/check-macos-release.sh" "$t" > "$T/c1.log" 2>&1; then no "11: check accepted a BUILDINFO metal_compiler the metallibs do not name"
  else grep -q "BUILDINFO metal_compiler says" "$T/c1.log" && ok "11: check rejects a BUILDINFO metal_compiler the metallibs do not name" \
    || no "11: rejected for another reason: $(grep FAIL "$T/c1.log" | head -2)"; fi
  rm -f "$t"; tarball=$tarball_saved
  rw=$T/relabelled-worker
  perl -0pe 's/Apple metal version (\d+)\.(\d+) \(metalfe-\1\.\2/"Apple metal version " . ("9" x length($1)) . "." . ("9" x length($2)) . " (metalfe-" . ("9" x length($1)) . "." . ("9" x length($2))/ge' "$m27_worker" > "$rw"
  chmod 0755 "$rw"; codesign -f -s - "$rw" 2>/dev/null
  relabel=$("$ci/check-macos-release.sh" --compilers "$rw")
  [ "$relabel" != "$("$ci/check-macos-release.sh" --compilers "$m27_worker")" ] || no "11: relabelling the worker changed nothing"
  r=$T/r-cc; fake_repo "$r" "$rw" "$m27_cli"
  for optin in 0 1; do
    if METAL_COMPILER_UNVALIDATED=$optin assemble "$r" "$T/out-cc" "$tm" > "$T/cc.log" 2>&1; then
      no "11: the $tm mode packaged metallibs of '$relabel' (METAL_COMPILER_UNVALIDATED=$optin)"
    else
      grep -q "a stale build" "$T/cc.log" && ok "11: the $tm mode refuses metallibs another compiler built as a stale build (METAL_COMPILER_UNVALIDATED=$optin)" \
        || { no "11: the $tm mode failed for another reason"; tail -4 "$T/cc.log"; }
    fi
  done
  if (unset METAL_COMPILER_UNVALIDATED; assemble "$r" "$T/out-cc" sdk) > "$T/cc2.log" 2>&1; then
    no "11: sdk mode packaged metallibs of an unvalidated compiler"
  else
    grep -q "not by the validated" "$T/cc2.log" && ok "11: sdk mode refuses metallibs of an unvalidated compiler" || { no "11: sdk mode failed for another reason"; tail -4 "$T/cc2.log"; }
  fi
  if METAL_COMPILER_UNVALIDATED=1 assemble "$r" "$T/out-cc3" sdk > "$T/cc3.log" 2>&1; then
    t3=$(ls "$T"/out-cc3/zkminer-*-macos-arm64.tar.gz)
    bi=$(kit_buildinfo "$t3" "$T/u-cc3")
    [ "$(info "$bi" metal_compiler)" = "$relabel" ] && [ "$(info "$bi" metal_compiler_validated)" = no ] \
      && ok "11: with the opt-in the kit is labelled with the AIR's compiler ('$relabel', metal_compiler_validated=no)" \
      || no "11: opt-in BUILDINFO: '$(info "$bi" metal_compiler)' validated=$(info "$bi" metal_compiler_validated)"
    if env -u METAL_COMPILER_UNVALIDATED "$ci/check-macos-release.sh" "$t3" > "$T/cc3c.log" 2>&1; then no "11: check accepted it without the opt-in"
    else grep -q "not by the validated compiler" "$T/cc3c.log" && ok "11: check rejects it without the opt-in" || no "11: check: $(grep FAIL "$T/cc3c.log" | head -2)"; fi
  else
    no "11: sdk mode with METAL_COMPILER_UNVALIDATED=1 failed"; tail -5 "$T/cc3.log"
  fi
  rm -rf "$r" "$rw" "$T"/out-cc* "$T"/u-cc3
fi

echo "test-assemble-macos: $pass passed, $fails failed"
[ $fails = 0 ]
