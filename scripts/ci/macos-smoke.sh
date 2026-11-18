#!/bin/bash
# GPU smoke test of the macOS beta kit on a real Mac (B9-M26): run it on every macOS release the kit
# supports before tagging, and in CI's metal-probe job.
#
#   macos-smoke.sh [--worker PATH] [--cli PATH] [--receipt-dir DIR] [--try-paravirtual] [--no-proof]
#
#   --worker PATH       the Metal worker (default: provers/zkminer-prove-risc0-metal beside this script's
#                       kit, else ~/.zkminer/provers/zkminer-prove-risc0-metal, else target/release)
#   --cli PATH          the zkminer CLI (default: the same places)
#   --receipt-dir DIR   keep the proof's Groth16 receipt there (for an independent verifier, e.g.
#                       risc0's tools/stock_verify31; STOCK_VERIFY=<its binary> runs it here)
#   --try-paravirtual   also prove on a paravirtual (virtual machine) Metal device
#   --no-proof          launch checks and device probe only
#
# Steps:
#   1. launch: `zkminer --help` and `worker --metal-arch` start (dyld: missing libraries or symbols, a
#      minimum macOS above this one, a refused signature). macOS crash reports written meanwhile
#      (~/Library/Logs/DiagnosticReports) are listed.
#   2. device probe (osascript JavaScript, no developer tools needed): MTLCreateSystemDefaultDevice's
#      name, unified memory, GPU architecture, families, recommendedMaxWorkingSetSize.
#   3. one tiny proof and its verification: BENCH_ONLY=fibonacci worker --benchmark (execute, prove,
#      lift and join, Groth16 wrap, then the worker verifies the Groth16 receipt). The first run on a
#      Mac compiles the GPU pipelines unless the kit's offline archives cover this Mac (up to a few
#      minutes); the risc0-groth16 component must be installed (install.sh --with-groth16).
#
# Exit status:
#   0  launched, an Apple Silicon GPU, the proof verified
#   1  the proof failed or did not verify (a real failure: report it with the log)
#   2  usage error, or no worker / CLI found
#   3  no Metal device at all
#   4  a paravirtual (virtual machine) or otherwise non-Apple-Silicon Metal device: launch and probe
#      passed; the proof was skipped (or, with --try-paravirtual, its result is informational). GPU
#      results from such a device say nothing about a real Mac.
#   5  the worker refuses this Mac (e.g. less than 12 GiB of RAM): launch and probe passed, no proof
#   6  a binary did not launch (dyld, signature, minimum macOS): a blocker for this macOS release
#   7  the risc0-groth16 component is missing (install.sh --with-groth16)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
worker= cli= receipts= try_pv=0 proof=1
while [ $# -gt 0 ]; do
  case "$1" in
    --worker) worker=${2:?}; shift ;;
    --cli) cli=${2:?}; shift ;;
    --receipt-dir) receipts=${2:?}; shift ;;
    --try-paravirtual) try_pv=1 ;;
    --no-proof) proof=0 ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "macos-smoke.sh: unknown option $1 (--help)" >&2; exit 2 ;;
  esac
  shift
done
pick() { local f; for f in "$@"; do [ -x "$f" ] && { echo "$f"; return; }; done; }
[ -n "$worker" ] || worker=$(pick "$here/../provers/zkminer-prove-risc0-metal" "$here/provers/zkminer-prove-risc0-metal" \
  "$HOME/.zkminer/provers/zkminer-prove-risc0-metal" "$here/../../target/release/zkminer-prove-risc0-metal")
[ -n "$cli" ] || cli=$(pick "$here/../zkminer" "$here/zkminer" "$HOME/.zkminer/zkminer" "$here/../../target/release/zkminer")
[ -n "$worker" ] && [ -x "$worker" ] || { echo "macos-smoke.sh: no worker found (--worker)" >&2; exit 2; }
[ -n "$cli" ] && [ -x "$cli" ] || { echo "macos-smoke.sh: no zkminer CLI found (--cli)" >&2; exit 2; }
log=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-smoke.XXXXXX")
stamp=$log/.start; : > "$stamp"
say() { printf '%s\n' "$*"; }
crashes() {
  local d
  for d in "$HOME/Library/Logs/DiagnosticReports" /Library/Logs/DiagnosticReports; do
    [ -d "$d" ] && find "$d" -newer "$stamp" -type f \( -name 'zkminer*' -o -name '*prove-risc0*' -o -name 'osascript*' \) 2>/dev/null
  done
}
say "== macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m), $(( $(sysctl -n hw.memsize) >> 30 )) GiB RAM, $(sysctl -n hw.ncpu) CPUs"
say "   model $(sysctl -n hw.model 2>/dev/null), chip $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
say "   worker $worker"
say "   cli    $cli"

# --- 1. launch ----------------------------------------------------------------------------------
launch_fail=0
"$cli" --help > "$log/cli-help.log" 2>&1; rc=$?
if [ $rc = 0 ]; then say "== launch: zkminer --help ok"; else
  say "== launch: zkminer --help FAILED (exit $rc):"; sed 's/^/   /' "$log/cli-help.log" | head -20; launch_fail=1; fi
arch=$("$worker" --metal-arch 2> "$log/metal-arch.log"); rc=$?
case $rc in
  0) say "== launch: worker --metal-arch ok: $arch" ;;
  2) say "== launch: worker started; it found no Metal device architecture ($(head -1 "$log/metal-arch.log"))" ;;
  *) say "== launch: worker --metal-arch FAILED (exit $rc):"; sed 's/^/   /' "$log/metal-arch.log" | head -20; launch_fail=1 ;;
esac
if grep -qE 'dyld|Library not loaded|Symbol not found|built for macOS|code signature' "$log/cli-help.log" "$log/metal-arch.log"; then launch_fail=1; fi
if [ $launch_fail = 1 ]; then
  say "crash reports: $(crashes | tr '\n' ' ')"
  say "RESULT: a binary did not launch on this macOS (exit 6); logs in $log"
  exit 6
fi

# --- 2. device probe ----------------------------------------------------------------------------
cat > "$log/probe.js" <<'EOF'
ObjC.import('Metal');
function run() {
  var d = $.MTLCreateSystemDefaultDevice();
  if (!d || d.isNil()) return "device=none";
  var out = ["device=yes"];
  out.push("name=" + ObjC.unwrap(d.name));
  out.push("unified=" + d.hasUnifiedMemory);
  out.push("recommendedMaxWorkingSetSize=" + d.recommendedMaxWorkingSetSize);
  out.push("maxBufferLength=" + d.maxBufferLength);
  out.push("architecture=" + (d.respondsToSelector('architecture') ? ObjC.unwrap(d.architecture.name) : "?"));
  var names = {1001:"apple1",1002:"apple2",1003:"apple3",1004:"apple4",1005:"apple5",1006:"apple6",1007:"apple7",
               1008:"apple8",1009:"apple9",1010:"apple10",1011:"apple11",5001:"metal3",5002:"metal4"};
  var fams = [];
  for (var k in names) { if (d.supportsFamily(parseInt(k))) fams.push(names[k]); }
  out.push("families=" + fams.join(","));
  return out.join("\n");
}
EOF
osascript -l JavaScript "$log/probe.js" > "$log/probe.txt" 2> "$log/probe.err"; rc=$?
p() { sed -n "s/^$1=//p" "$log/probe.txt"; }
if [ $rc != 0 ]; then
  say "== device probe: osascript failed (exit $rc): $(head -3 "$log/probe.err")"
fi
if [ "$(p device)" != yes ]; then
  say "RESULT: no Metal device (exit 3)"; exit 3
fi
ws=$(p recommendedMaxWorkingSetSize)
say "== Metal device: $(p name)"
say "   architecture $(p architecture), unified memory $(p unified), families $(p families)"
say "   recommendedMaxWorkingSetSize $ws ($(awk -v b="$ws" 'BEGIN{printf "%.2f GiB", b/1073741824}')), maxBufferLength $(p maxBufferLength)"
paravirtual=0
case "$(p name)" in *aravirtual*|*irtual*) paravirtual=1 ;; esac
case "$(p architecture)" in applegpu_*) ;; *) paravirtual=1 ;; esac
[ "$(p unified)" = true ] || paravirtual=1
if [ $paravirtual = 1 ]; then
  say "   NOTE: this is not an Apple Silicon GPU (a virtual machine's paravirtual device, or a discrete GPU)."
  say "         The kit's GPU results here say nothing about a real Mac; run this script on Apple Silicon."
fi

# --- 3. one tiny proof --------------------------------------------------------------------------
if [ $proof = 0 ] || { [ $paravirtual = 1 ] && [ $try_pv = 0 ]; }; then
  [ $paravirtual = 1 ] && { say "RESULT: paravirtual device, proof skipped (exit 4; --try-paravirtual proves anyway)"; exit 4; }
  rm -rf "$log"
  say "RESULT: launch and device probe ok (--no-proof)"; exit 0
fi
g16=${RISC0_GROTH16_DIR:-${RISC0_HOME:-$HOME/.risc0}/extensions/v0.2.0-risc0-groth16}
if [ ! -s "$g16/stark_verify_final.zkey" ]; then
  say "RESULT: the risc0-groth16 component is not in $g16: run the kit's install.sh --with-groth16 first (exit 7)"
  exit 7
fi
rdir=${receipts:-$log/receipts}
mkdir -p "$rdir"
say "== proof: BENCH_ONLY=fibonacci $worker --benchmark (log $log/proof.log)"
t0=$(date +%s)
BENCH_ONLY=fibonacci ZKMINER_BENCH_RECEIPT_DIR=$rdir "$worker" --benchmark > "$log/proof.log" 2>&1 < /dev/null; rc=$?
secs=$(( $(date +%s) - t0 ))
clean() { sed 's/\x1b\[[0-9;]*m//g' "$log/proof.log"; }
clean | grep -E 'Metal device|Metal budget|PSOs in|offline Metal archives' | sed 's/^.*Z  *//; s/^/   /' | cut -c1-200
ok=0
if [ $rc = 0 ] && clean | grep -q 'fibonacci: .* cycles .* verified' && [ -s "$rdir/fibonacci.groth16.receipt" ]; then ok=1; fi
if [ $ok = 1 ] && [ -n "${STOCK_VERIFY:-}" ]; then
  if "$STOCK_VERIFY" verify "$rdir/fibonacci.groth16.receipt" "$(cat "$rdir/fibonacci.image_id")" > "$log/stock.log" 2>&1; then
    say "   independent verifier: $(grep '^STOCK' "$log/stock.log")"
  else
    say "   independent verifier REJECTED the receipt: $(grep '^STOCK' "$log/stock.log")"; ok=0
  fi
fi
cr=$(crashes | tr '\n' ' ')
[ -z "$cr" ] || say "   crash reports: $cr"
if [ $ok = 1 ]; then
  say "   $(clean | grep -o 'fibonacci: .* verified' | head -1)"
  say "   wall ${secs} s (first run on a Mac without matching offline archives compiles the GPU pipelines)"
  [ $paravirtual = 1 ] && { say "RESULT: proof verified on a paravirtual device (exit 4: informational)"; exit 4; }
  rm -rf "$log"
  say "RESULT: ok (exit 0)"; exit 0
fi
if clean | grep -qE 'needs at least 16 GB|not an Apple Silicon GPU|Rosetta|no Metal device'; then
  say "   the worker refuses this Mac: $(clean | grep -oE '(this Mac has|Metal device|the Metal risc0 worker)[^"]*' | head -1)"
  [ $paravirtual = 1 ] && { say "RESULT: paravirtual device, the worker refuses it (exit 4)"; exit 4; }
  say "RESULT: the worker refuses this Mac (exit 5)"; exit 5
fi
say "   last lines of the log:"; clean | tail -15 | sed 's/^/   /'
[ $paravirtual = 1 ] && { say "RESULT: the proof failed on a paravirtual device (exit 4: informational; logs in $log)"; exit 4; }
say "RESULT: the proof FAILED (worker exit $rc; exit 1; logs in $log)"
exit 1
