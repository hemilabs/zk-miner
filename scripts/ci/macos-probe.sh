#!/usr/bin/env bash
# What a macOS CI runner's GPU can do with the beta kit (B9-CI; build-macos.yml's metal-probe job,
# never a required check):
#
#   macos-probe.sh <zkminer-<version>-macos-arm64.tar.gz> <work dir>
#
# 1. unpacks the kit and installs it into <work dir>/prefix (install.sh --prefix: the runner user's
#    ~/.zkminer is not touched);
# 2. the kit's tools/macos-smoke.sh --no-proof: launch checks and the device probe
#    (MTLCreateSystemDefaultDevice: name, architecture/family, unified memory,
#    recommendedMaxWorkingSetSize);
# 3. with PROBE_PROOF=1 (default) and a Metal device that can be tried: the risc0-groth16 component
#    (the runner's own when ~/.risc0 has it complete, else downloaded into <work dir>/g16, streamed
#    and checked against the kit's pinned SHA-256: 2.4 GB download, 5.4 GB on disk, deleted at the
#    end; skipped with a notice when the disk has less than PROBE_MIN_FREE_GIB free, default 7) and
#    one tiny proof (macos-smoke.sh --try-paravirtual:
#    fibonacci, lift, join, Groth16 wrap, verified by the worker). On a paravirtual (VM) device the
#    proof is informational: it says nothing about a real Mac's GPU.
# Exit: 0 when nothing points at a kit defect (smoke exit 0, 3 no Metal device, 4 paravirtual,
# 5 the worker refuses this runner, or the proof skipped for disk); the smoke script's code for a
# real failure (1 proof failed, 6 a binary did not launch, 7 no Groth16 component, 8 quarantined,
# 2 usage). Writes a summary to GITHUB_STEP_SUMMARY when set.
set -uo pipefail
tarball=${1:?usage: $0 <kit tarball> <work dir>}
work=${2:?usage: $0 <kit tarball> <work dir>}
proof=${PROBE_PROOF:-1}
min_free=${PROBE_MIN_FREE_GIB:-7}
mkdir -p "$work"; work=$(cd "$work" && pwd)
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
note() { echo "$*"; echo "$*" >> "$summary"; }
meaning() {
  case $1 in
    0) echo "ok: launched, an Apple Silicon GPU, proof verified (or not asked for)" ;;
    1) echo "the proof failed or did not verify" ;;
    2) echo "usage error, or no worker / CLI found" ;;
    3) echo "no Metal device" ;;
    4) echo "a paravirtual (VM) or non-Apple-Silicon Metal device: GPU results say nothing about a real Mac" ;;
    5) echo "the worker refuses this machine (e.g. under 12 GiB of RAM)" ;;
    6) echo "a binary did not launch on this macOS" ;;
    7) echo "the risc0-groth16 component is missing" ;;
    8) echo "a quarantined binary was chosen (nothing launched)" ;;
    *) echo "unexpected exit $1" ;;
  esac
}

rm -rf "$work/kit" "$work/prefix"
mkdir -p "$work/kit"
tar -xzf "$tarball" -C "$work/kit" || { echo "::error::cannot unpack $tarball"; exit 2; }
kit=$(echo "$work"/kit/zkminer-*-macos-arm64)
[ -x "$kit/install.sh" ] || { echo "::error::no install.sh in $tarball"; exit 2; }
note "### macOS metal-probe"
note ""
note "- runner: macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(sysctl -n hw.ncpu) CPUs, $(( $(sysctl -n hw.memsize) >> 30 )) GiB RAM, $(df -h "$work" | awk 'NR==2{print $4}') free"
note "- kit: $(basename "$tarball"), $(grep -E '^(commit|min_macos|metal_compiler|aot_os_keys)=' "$kit/BUILDINFO" | tr '\n' ' ')"

"$kit/install.sh" --prefix "$work/prefix" || { echo "::error::install.sh failed"; exit 2; }

echo "== launch checks and device probe"
"$kit/tools/macos-smoke.sh" --prefix "$work/prefix" --no-proof 2>&1 | tee "$work/probe.log"
rc=${PIPESTATUS[0]}
note "- device: $(grep -E 'Metal device|architecture|recommendedMaxWorkingSetSize|RESULT' "$work/probe.log" | sed 's/^ *//' | tr '\n' ';' | cut -c1-400)"
note "- launch and probe: exit $rc ($(meaning "$rc"))"

if [ "$proof" = 1 ] && { [ "$rc" = 0 ] || [ "$rc" = 4 ]; }; then
  info() { sed -n "s/^$1=//p" "$kit/BUILDINFO"; }
  g16_name=v$(info groth16_version)-risc0-groth16
  user_g16=${RISC0_HOME:-$HOME/.risc0}/extensions/$g16_name
  g16_ok() { local f; for f in stark_verify_graph.bin stark_verify_final.zkey fuzzed_msm_results.bin preprocessed_coeffs.bin; do [ -s "$1/$f" ] || return 1; done; }
  free_gib=$(( $(df -k "$work" | awk 'NR==2{print $4}') >> 20 ))
  skip=
  if g16_ok "$user_g16"; then
    export RISC0_GROTH16_DIR=$user_g16
    note "- risc0-groth16 component: the runner's ($user_g16)"
  elif [ "$free_gib" -lt "$min_free" ]; then
    skip="$free_gib GiB free; the risc0-groth16 component takes 5.4 GB (PROBE_MIN_FREE_GIB=$min_free)"
  else
    # Into this job's temp directory, never the runner user's ~/.risc0: on a persistent runner 5.4 GB
    # left there would not leave the build job its room. Streamed (curl | SHA-256 | tar), so the
    # 2.4 GB archive is never on disk; checked against the kit's pinned SHA-256 before it is used.
    echo "== the risc0-groth16 component ($(info groth16_url)), streamed into $work/g16"
    rm -rf "$work/g16" && mkdir -p "$work/g16"
    t0=$(date +%s)
    if curl -fsSL --connect-timeout 30 --speed-limit 102400 --speed-time 60 "$(info groth16_url)" |
        python3 -I -c 'import hashlib, sys
h = hashlib.sha256()
while True:
    b = sys.stdin.buffer.read(1 << 20)
    if not b: break
    h.update(b); sys.stdout.buffer.write(b)
open(sys.argv[1], "w").write(h.hexdigest())' "$work/g16.sha256" | tar -xJf - -C "$work/g16" &&
        [ "$(cat "$work/g16.sha256")" = "$(info groth16_sha256)" ] && g16_ok "$work/g16"; then
      export RISC0_GROTH16_DIR=$work/g16
      note "- risc0-groth16 component: downloaded and checked in $(( $(date +%s) - t0 )) s"
    else
      rm -rf "$work/g16"
      skip="the risc0-groth16 component download failed or did not match its SHA-256 $(info groth16_sha256)"
      rc=7
    fi
  fi
  if [ -n "$skip" ]; then
    note "- proof: skipped: $skip"
  else
    echo "== one tiny proof (fibonacci, Groth16 wrap, verified)"
    t0=$(date +%s)
    "$kit/tools/macos-smoke.sh" --prefix "$work/prefix" --try-paravirtual --receipt-dir "$work/receipts" 2>&1 | tee "$work/proof.log"
    rc=${PIPESTATUS[0]}
    note "- proof: exit $rc ($(meaning "$rc")) in $(( $(date +%s) - t0 )) s; $(grep -E '^RESULT' "$work/proof.log" | tail -1)"
  fi
  rm -rf "$work/g16"
fi
"$kit/install.sh" --uninstall --prefix "$work/prefix" > /dev/null || true

case $rc in
  0|3|4|5) exit 0 ;;
  *) echo "::error::macos-smoke.sh exit $rc: $(meaning "$rc")"; exit "$rc" ;;
esac
