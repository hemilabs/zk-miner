#!/usr/bin/env bash
# Deletes build intermediates in the macOS CI job (B9-CI; the runner has about 14 GB of disk):
#
#   macos-prune-target.sh --guests <repo>   after the build, before the tests
#   macos-prune-target.sh <repo>            after the tests, before the kit is packaged
#
# --guests: the benchmark guests' builds (target/riscv-guest, ~3.5 GB) down to the guest programs
#   the worker embeds (riscv32im-risc0-zkvm-elf/release/<guest>[.bin], named in the worker's
#   dep-info, so cargo keeps seeing them): the guests' own dependencies and build scripts go. The
#   tests then reuse the build (the worker's build script, which builds the guests, does not rerun:
#   its inputs, the guest sources, are unchanged).
# default: keeps only what assemble-macos.sh ASSEMBLE_SKIP_BUILD=1 reads: target/release/zkminer,
#   target/release/zkminer-prove-risc0-metal and target/macos-kit (the Metal compiler wrapper
#   directory). Everything else under target/ (deps, build script outputs, the guests, test
#   binaries) goes.
set -euo pipefail
guests=0
[ "${1:-}" = --guests ] && { guests=1; shift; }
repo=$(cd "${1:?usage: $0 [--guests] <repo>}" && pwd)
t=$repo/target
mib() { echo $(( $(du -sk "$1" | cut -f1) >> 10 )); }
before=$(mib "$t")

if [ $guests = 1 ]; then
  [ -d "$t/riscv-guest" ] || { echo "macos-prune-target: no $t/riscv-guest"; exit 0; }
  n=0
  # target/riscv-guest/<host crate>/<guest>/{release, riscv32im-risc0-zkvm-elf/release/...}
  for g in "$t"/riscv-guest/*/*/; do
    g=${g%/}
    out=$g/riscv32im-risc0-zkvm-elf/release
    name=$(basename "$g")
    [ -f "$out/$name.bin" ] || { echo "::error::macos-prune-target: no $out/$name.bin" >&2; exit 1; }
    for e in "$g"/* "$g"/.[!.]*; do
      [ -e "$e" ] || continue
      [ "$e" = "$g/riscv32im-risc0-zkvm-elf" ] || rm -rf "$e"
    done
    for e in "$g"/riscv32im-risc0-zkvm-elf/* "$g"/riscv32im-risc0-zkvm-elf/.[!.]*; do
      [ -e "$e" ] || continue
      [ "$e" = "$out" ] || rm -rf "$e"
    done
    for e in "$out"/* "$out"/.[!.]*; do
      [ -e "$e" ] || continue
      [ -d "$e" ] && rm -rf "$e"
    done
    n=$((n + 1))
  done
  echo "macos-prune-target: $n guest builds pruned to their programs; target/ $before MiB -> $(mib "$t") MiB"
  exit 0
fi

keep=(release/zkminer release/zkminer-prove-risc0-metal)
for k in "${keep[@]}"; do [ -x "$t/$k" ] || { echo "::error::macos-prune-target: no $t/$k" >&2; exit 1; }; done
for e in "$t"/* "$t"/.[!.]*; do
  [ -e "$e" ] || continue
  case ${e#"$t"/} in
    release|macos-kit) ;;
    *) rm -rf "$e" ;;
  esac
done
for e in "$t"/release/* "$t"/release/.[!.]*; do
  [ -e "$e" ] || continue
  case ${e#"$t"/} in
    release/zkminer|release/zkminer-prove-risc0-metal) ;;
    *) rm -rf "$e" ;;
  esac
done
echo "macos-prune-target: target/ $before MiB -> $(mib "$t") MiB"
