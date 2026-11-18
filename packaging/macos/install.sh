#!/bin/bash
# zk-miner macOS beta (Apple Silicon, Metal): installs this kit into ~/.zkminer.
#
#   ./install.sh [--prefix DIR] [--no-aot] [--with-groth16] [--warm] [--force]
#   ./install.sh --uninstall [--prefix DIR]
#
#   --prefix DIR     install into DIR instead of ~/.zkminer (the miner looks for its workers in
#                    ~/.zkminer/provers; another prefix needs a [workers] search_dirs entry)
#   --no-aot         do not install the offline Metal archives (the first start compiles the GPU
#                    pipelines, about a minute on an M5 Max, longer on smaller Macs)
#   --with-groth16   download RISC Zero's risc0-groth16 component now (2.4 GB download, 5.4 GB on
#                    disk, checked against its pinned SHA-256) instead of at the worker's first warm-up
#   --warm           afterwards prove one small program with the worker (builds its GPU pipelines;
#                    needs the risc0-groth16 component, so it implies --with-groth16)
#   --force          install on a Mac the worker will refuse (less than 12 GiB of RAM)
#   --uninstall      remove what this script installs (not ~/.zkminer/config.toml, keys, caches or
#                    the risc0-groth16 component)
#
# What it installs:
#   <prefix>/zkminer                              the CLI
#   <prefix>/provers/zkminer-prove-risc0-metal    the Metal worker
#   <prefix>/provers/metal-aot/                   this Mac's offline Metal archives, only when its GPU
#                                                 family is one validated on hardware (BUILDINFO) and
#                                                 the kit has a set for its macOS major version
# Every file is checked against the kit's SHA256SUMS first. The kit is not signed or notarized
# (beta), so macOS marks a downloaded copy as quarantined; this script removes the
# com.apple.quarantine attribute from the files it installs, and only from those.
set -euo pipefail

kit=$(cd "$(dirname "$0")" && pwd)
prefix=$HOME/.zkminer
aot=1 groth16=0 warm=0 force=0 uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:?--prefix needs a directory}; shift ;;
    --prefix=*) prefix=${1#--prefix=} ;;
    --no-aot) aot=0 ;;
    --with-groth16) groth16=1 ;;
    --warm) warm=1; groth16=1 ;;
    --force) force=1 ;;
    --uninstall) uninstall=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $1 (--help lists them)" >&2; exit 2 ;;
  esac
  shift
done
# Not created before the checks below: a refused install leaves nothing behind.
set_prefix() { [ -d "$prefix" ] && prefix=$(cd "$prefix" && pwd); provers=$prefix/provers; worker=$provers/zkminer-prove-risc0-metal; }
set_prefix

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
info() { sed -n "s/^$1=//p" "$kit/BUILDINFO"; }

if [ $uninstall = 1 ]; then
  for f in "$prefix/zkminer" "$worker" "$provers/metal-aot"; do
    [ -e "$f" ] && rm -rf "$f" && say "removed $f"
  done
  say "Left in place: $prefix/config.toml and keys, ~/.risc0 (the risc0-groth16 component, 5.4 GB),"
  say "~/Library/Caches/com.risczero.RISC-Zero.risc0 (compiled GPU pipelines). Remove them by hand if wanted."
  exit 0
fi

# --- this Mac -------------------------------------------------------------------------------
[ "$(uname -s)" = Darwin ] || die "this kit is for macOS"
[ "$(uname -m)" = arm64 ] || die "this kit is for Apple Silicon Macs (arm64); this is $(uname -m) (an Intel Mac, or a shell under Rosetta)"
[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 0 ] || die "this shell runs under Rosetta: use a native (arm64) Terminal"
min=$(info min_macos)
have=$(sw_vers -productVersion)
older() { # is $1 < $2 (dotted versions)?
  local IFS=.; local -a a=($1) b=($2); local i
  for i in 0 1 2; do
    [ "${a[i]:-0}" -lt "${b[i]:-0}" ] && return 0
    [ "${a[i]:-0}" -gt "${b[i]:-0}" ] && return 1
  done
  return 1
}
if [ -n "$min" ] && older "$have" "$min"; then
  case "$min" in
    26.*) name=" (Tahoe)" ;;
    *) name= ;;
  esac
  die "this build needs macOS $min$name or later; this Mac runs macOS $have: update macOS (System Settings > General > Software Update), then run install.sh again"
fi
mem=$(sysctl -n hw.memsize)
# 12 GiB: the worker's MIN_HOST_MEMORY_BYTES (crates/zkminer-prove-risc0/src/metal_host.rs), below
# which it refuses to prove; keep the two equal.
if [ "$mem" -lt $((12 << 30)) ]; then
  msg="this Mac has $((mem >> 30)) GiB of RAM; the Metal worker needs a Mac with at least 16 GB and refuses to prove on this one"
  [ $force = 1 ] && say "warning: $msg (--force: installing anyway)" || die "$msg (--force installs anyway)"
fi

# --- the kit --------------------------------------------------------------------------------
say "checking the kit ($(info version), commit $(info commit | cut -c1-12))"
(cd "$kit" && shasum -a 256 -c --quiet SHA256SUMS) || die "the kit's files do not match its SHA256SUMS: download it again"

# Partial files to remove if the script stops (a failed cp on a full disk, ^C, a failed unpack).
cleanup=()
trap 'for c in ${cleanup[@]+"${cleanup[@]}"}; do rm -rf "$c"; done' EXIT

# Copy, then rename into place: a running worker keeps its old (unlinked) file, and macOS never
# sees a signed binary modified in place (it kills such a process).
place() { # <src> <dest>
  local tmp
  tmp="$(dirname "$2")/.$(basename "$2").tmp.$$"
  cleanup+=("$tmp")
  cp "$1" "$tmp"
  chmod 0755 "$tmp"
  xattr -d com.apple.quarantine "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$2"
}
mkdir -p "$prefix"; set_prefix
mkdir -p "$provers"
place "$kit/zkminer" "$prefix/zkminer"
place "$kit/provers/zkminer-prove-risc0-metal" "$worker"
for f in "$prefix/zkminer" "$worker"; do
  if xattr -p com.apple.quarantine "$f" >/dev/null 2>&1; then die "could not clear com.apple.quarantine on $f"; fi
done
say "installed $prefix/zkminer"
say "installed $worker"

# --- offline Metal archives -----------------------------------------------------------------
# tools/install-metal-aot.sh copies only this Mac's family, only a validated one, each file checked
# against metal-aot/SHA256SUMS. The digest check against the worker needs python3 (which on a Mac
# without the Command Line Tools opens an installer dialog); it was made when the kit was built
# (check-macos-release.sh), and the kit's SHA256SUMS just tied the archives to this worker.
if [ $aot = 1 ]; then
  arch=$("$worker" --metal-arch 2>/dev/null) || die "$worker --metal-arch failed: does this Mac have a Metal GPU?"
  # The runtime opens only the archives keyed for this Mac's macOS major version (macos<N>, B9-M26):
  # hand install-metal-aot.sh just those (symlinks, with their SHA256SUMS and manifest lines).
  key=macos${have%%.*}
  set_dir=
  if [ -n "$(ls "$kit/metal-aot" 2>/dev/null | grep -- "-$key-.*\.binarchive\$" || true)" ]; then
    set_dir=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-metal-aot.XXXXXX")
    cleanup+=("$set_dir")
    for f in "$kit"/metal-aot/*-"$key"-*.binarchive; do ln -s "$f" "$set_dir/$(basename "$f")"; done
    grep -- "-$key-" "$kit/metal-aot/SHA256SUMS" > "$set_dir/SHA256SUMS" || true
    grep -F -- "\"os_key\": \"$key\"" "$kit/metal-aot/manifest.jsonl" > "$set_dir/manifest.jsonl" 2>/dev/null || true
  elif [ -n "$(ls "$kit/metal-aot" 2>/dev/null | grep '\.binarchive$' || true)" ]; then
    say "this kit's offline Metal archives are for $(info aot_os_keys), not for macOS ${have%%.*}: none installed"
    rm -rf "$provers/metal-aot"
  fi
  if [ -n "$set_dir" ]; then
    # shellcheck disable=SC2046
    AOT_SKIP_DIGEST_CHECK=1 "$kit/tools/install-metal-aot.sh" "$set_dir" "$worker" \
      ${ZKMINER_AOT_VALIDATED:-$(info aot_validated)}
    if [ -d "$provers/metal-aot" ]; then
      xattr -dr com.apple.quarantine "$provers/metal-aot" 2>/dev/null || true
    fi
  elif [ -z "$(ls "$kit/metal-aot" 2>/dev/null | grep '\.binarchive$' || true)" ]; then
    say "this kit has no offline Metal archives; the first start compiles the GPU pipelines"
  fi
  [ -d "$provers/metal-aot" ] || say "GPU $arch: the worker's first start compiles its GPU pipelines (about a minute once on an M5 Max, longer on smaller Macs; cached afterwards)"
else
  rm -rf "$provers/metal-aot"
  say "--no-aot: no offline Metal archives installed"
fi

# --- risc0-groth16 component ----------------------------------------------------------------
# The same blob the worker downloads at its first warm-up (crates/zkminer-prove-risc0/src/
# groth16_component.rs), into the same place, checked against the same SHA-256; curl resumes a cut
# download. Under the worker's lock file ($RISC0_HOME/tmp/.risc0-groth16-<version>.lock, flock(2),
# taken through perl, which every Mac has), so a worker installing at the same time and this script
# never both replace the directory; whoever comes second finds it complete.
g16_home=${RISC0_HOME:-$HOME/.risc0}
g16_dir=${RISC0_GROTH16_DIR:-$g16_home/extensions/v$(info groth16_version)-risc0-groth16}
g16_files="stark_verify_graph.bin stark_verify_final.zkey fuzzed_msm_results.bin preprocessed_coeffs.bin"
g16_complete() { local f; for f in $g16_files; do [ -s "$1/$f" ] || return 1; done; }
g16_install() { # under the lock
  if g16_complete "$g16_dir"; then
    say "risc0-groth16 component in $g16_dir (installed meanwhile)"
    return
  fi
  sha=$(info groth16_sha256); url=$(info groth16_url)
  part=$tmp/risc0-groth16-$(info groth16_version).tar.xz.part
  say "downloading the risc0-groth16 component v$(info groth16_version) (2.4 GB) to $tmp"
  curl -fL -# --retry 5 --retry-delay 5 -C - -o "$part" "$url" || die "the download failed (run install.sh --with-groth16 again to resume)"
  got=$(shasum -a 256 "$part" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    rm -f "$part"
    die "the risc0-groth16 archive has SHA-256 $got, not $sha: removed it"
  fi
  staging=$tmp/risc0-groth16-$(info groth16_version).$$
  cleanup+=("$staging")
  rm -rf "$staging"; mkdir -p "$staging"
  tar -xJf "$part" -C "$staging" || { rm -rf "$staging"; die "cannot unpack $part"; }
  g16_complete "$staging" || { rm -rf "$staging"; die "the archive does not hold $g16_files"; }
  mkdir -p "$(dirname "$g16_dir")"
  rm -rf "$g16_dir"
  mv "$staging" "$g16_dir"
  rm -f "$part"
  say "installed the risc0-groth16 component in $g16_dir"
}
if [ $groth16 = 1 ]; then
  if g16_complete "$g16_dir"; then
    say "risc0-groth16 component already in $g16_dir"
  elif [ -n "${RISC0_GROTH16_DIR:-}" ]; then
    die "RISC0_GROTH16_DIR=$RISC0_GROTH16_DIR does not hold the risc0-groth16 component"
  else
    tmp=$g16_home/tmp
    mkdir -p "$tmp"
    exec 9>"$tmp/.risc0-groth16-$(info groth16_version).lock"
    say "taking the risc0-groth16 install lock (waits while a worker installs it)"
    perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", 9) or die "$!\n"; flock($f, LOCK_EX) or die "$!\n"' \
      || die "cannot lock $tmp/.risc0-groth16-$(info groth16_version).lock"
    g16_install
    exec 9>&-
  fi
fi

# --- warm-up --------------------------------------------------------------------------------
if [ $warm = 1 ]; then
  say "warming the GPU pipelines (BENCH_ONLY=fibonacci $worker --benchmark)"
  t0=$(date +%s)
  BENCH_ONLY=fibonacci "$worker" --benchmark
  say "warm-up done in $(( $(date +%s) - t0 )) s"
fi

say ""
say "Done. Next:"
case ":$PATH:" in *":$prefix:"*) ;; *) say "  add the CLI to your PATH:  echo 'export PATH=\"$prefix:\$PATH\"' >> ~/.zshrc" ;; esac
say "  $prefix/zkminer init           # writes ~/.zkminer/config.toml (needed once, whatever the options)"
if [ $groth16 = 1 ]; then
  say "  $prefix/zkminer benchmark      # the risc0-groth16 component is already installed"
else
  say "  $prefix/zkminer benchmark      # its first run downloads the risc0-groth16 component (2.4 GB)"
fi
say "  $prefix/zkminer run"
say "Neither binary has --version: this kit's version and commit are in $kit/BUILDINFO."
say "See README.md in this kit (memory tiers, first start, Gatekeeper, uninstall)."
