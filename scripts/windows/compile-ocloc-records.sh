#!/usr/bin/env bash
# Compile the ocloc calls a Windows build recorded (scripts/windows/ocloc-shim, ZKMINER_OCLOC_MODE=
# record) with this machine's ocloc: on Linux, the one zk-miner builds with IGC's MergeAllocas
# quadratic fixed (Dockerfile.build's intel-gpu-runtime stage), which compiles risc0's Intel
# kernels in minutes where oneAPI's Windows ocloc takes hours. Each record's image is written to
# `output.bin` beside it, for the Windows build to replay.
#
# Usage: compile-ocloc-records.sh <records dir> [jobs]
set -euo pipefail
records=$1
jobs=${2:-$(nproc)}
ocloc=${OCLOC:-ocloc}
"$ocloc" -version 2>/dev/null | head -n 2 || true

compile_one() {
  local dir=$1 ocloc=$2
  [ -f "$dir/output.bin" ] && return 0
  local tmp
  tmp=$(mktemp -d)
  mapfile -t args < "$dir/args"
  local start=$SECONDS
  if ! "$ocloc" "${args[@]}" -file "$dir/input.spv" -output "$tmp/image" > "$tmp/log" 2>&1; then
    echo "FAILED $(basename "$dir") (${args[*]})" >&2
    cat "$tmp/log" >&2
    rm -rf "$tmp"
    return 1
  fi
  # ocloc names the file itself (with -output_no_suffix it still adds an extension): take the one
  # image it wrote.
  local made=("$tmp"/image*)
  [ ${#made[@]} -eq 1 ] && [ -f "${made[0]}" ] || { echo "no single image for $dir" >&2; ls -l "$tmp" >&2; return 1; }
  mv "${made[0]}" "$dir/output.bin.part" && mv "$dir/output.bin.part" "$dir/output.bin"
  rm -rf "$tmp"
  printf '%5ds %10d bytes  %s  %s\n' $((SECONDS - start)) "$(stat -c %s "$dir/output.bin")" \
    "$(basename "$dir" | cut -c1-12)" "${args[*]}"
}
export -f compile_one

count=$(find "$records" -mindepth 1 -maxdepth 1 -type d | wc -l)
echo "compiling $count recorded ocloc calls, $jobs at a time"
find "$records" -mindepth 1 -maxdepth 1 -type d -print0 \
  | xargs -0 -n 1 -P "$jobs" bash -c 'compile_one "$2" "$1"' _ "$ocloc" 2>&1 \
  | sed 's/^/  /' || true
missing=$(find "$records" -mindepth 1 -maxdepth 1 -type d ! -exec test -f '{}/output.bin' \; -print | wc -l)
[ "$missing" -eq 0 ] || { echo "$missing of $count calls have no image" >&2; exit 1; }
echo "all $count compiled"
