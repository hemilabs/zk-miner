#!/usr/bin/env bash
# Lays a release out as a host installs it: every prover in one directory, as in ~/.zkminer/provers/.
#
#   unpack-provers.sh <release dir> <provers dir>
#
# The single-file provers are copied (and made executable, which a download does not keep), and the
# AMD and Intel tarballs unpacked beside them. The CLI goes beside the provers directory, with what
# witness jobs run beside it (the witness runtime looks in the CLI's own directory).
set -euo pipefail
release=$(readlink -f "${1:?usage: $0 <release dir> <provers dir>}")
dir=${2:?usage: $0 <release dir> <provers dir>}
mkdir -p "$dir"
for f in zkminer-prove-risc0-cuda zkminer-prove-sp1 sp1-gpu-server zkminer-prove-openvm \
         libcudart.so.12 libcudart.so.12.LICENSE.txt; do
  cp "$release/$f" "$dir/"
done
cli_dir=$(dirname "$(readlink -f "$dir")")
witness=(zkminer-witness-sandbox-probe zkminer-witness-builder zkminer-witness-broker zkminer-prove-risc0-cpu)
for f in zkminer "${witness[@]}"; do
  cp "$release/$f" "$cli_dir/"
  chmod 0755 "$cli_dir/$f"
done
chmod 0755 "$dir"/zkminer-prove-* "$dir/sp1-gpu-server"
for t in "$release"/zkminer-provers-*-linux-x86_64.tar.zst; do
  zstd -q -dc "$t" | tar -C "$dir" -xf -
done
ls -la "$dir"
