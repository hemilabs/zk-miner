#!/usr/bin/env bash
# Prints the disk use of a macOS CI job (B9-CI): the runner has about 14 GB of disk, so every heavy
# step of build-macos.yml ends with this.
#
#   macos-disk.sh <label>
#
# Free space of the workspace's volume, then the sizes of target/ (and its biggest entries), the
# toolchains in HOME (cargo registry and git, rustup, RISC Zero), the risc0 kernel cache and
# RUNNER_TEMP. Never fails the job.
label=${1:-}
ws=${GITHUB_WORKSPACE:-$PWD}
echo "== disk: $label"
df -h "$ws" | sed 's/^/  /'
sizes() { for p in "$@"; do [ -e "$p" ] && du -sh "$p" 2>/dev/null | sed 's/^/  /'; done; return 0; }
sizes "$ws/target" "$ws/dist"
if [ -d "$ws/target" ]; then
  du -sh "$ws"/target/* "$ws"/target/release/* 2>/dev/null | sort -rh | head -8 | sed 's/^/    /'
fi
sizes "${CARGO_HOME:-$HOME/.cargo}/registry" "${CARGO_HOME:-$HOME/.cargo}/git" "${RUSTUP_HOME:-$HOME/.rustup}" \
  "${RISC0_HOME:-$HOME/.risc0}" "$HOME/Library/Caches/com.risczero.RISC-Zero.risc0" "${RUNNER_TEMP:-}"
exit 0
