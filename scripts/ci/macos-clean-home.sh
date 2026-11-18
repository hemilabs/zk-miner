#!/usr/bin/env bash
# Keeps a persistent macOS runner's disk use per job bounded (B9-CI; every build-macos.yml job runs
# it after the checkout and again, with if: always(), at its end):
#
#   macos-clean-home.sh <label>
#
# A self-hosted runner keeps the runner user's HOME from one job to the next (actions/checkout
# cleans only the workspace, the runner only RUNNER_TEMP). What the jobs write there and nothing
# reads back as a cache is deleted:
# - ~/.cargo/registry/src and ~/.cargo/git/checkouts: the unpacked crate sources and git checkouts,
#   which cargo recreates from ~/.cargo/registry/cache and ~/.cargo/git/db (what actions/cache keeps).
#   The tests' dev-dependencies unpack more sources than the release build, so without this a build
#   after a test job started 0.7 GB fuller (B9-CI round 1: 0.90 GB left instead of 2.0 GB);
# - the Groth16 coefficient cache (RISC0_G16_CACHE_DIR, else $XDG_CACHE_HOME/risc0-groth16, else
#   ~/.cache/risc0-groth16; 343 MB after a proof): macos-probe.sh keeps its own in its work dir, this
#   removes one an older probe or a manual run left;
# - risc0-build-kernel's kernel cache (~/Library/Caches/com.risczero.RISC-Zero.risc0): the kernels are
#   compiled again by every build, so a release never reuses an earlier job's kernel objects.
# Kept: ~/.cargo/registry/{index,cache}, ~/.cargo/git/db (the cached downloads), ~/.rustup and
# ~/.risc0 (the pinned toolchains, checked and reused by macos-toolchains.sh).
# One runner per user account: two runners sharing a HOME would delete each other's sources mid-build.
# Prints the sizes deleted and the free space; never fails the job.
label=${1:-}
cargo_home=${CARGO_HOME:-$HOME/.cargo}
g16=${RISC0_G16_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/risc0-groth16}
echo "== clean the runner user's caches: $label"
for p in "$cargo_home/registry/src" "$cargo_home/git/checkouts" "$g16" \
         "$HOME/Library/Caches/com.risczero.RISC-Zero.risc0"; do
  [ -e "$p" ] || continue
  echo "  delete $(du -sh "$p" 2>/dev/null | cut -f1) $p"
  if ! rm -rf "$p" 2>/dev/null; then
    chmod -R u+w "$p" 2>/dev/null; rm -rf "$p" 2>/dev/null || echo "::warning::could not delete $p"
  fi
done
df -h "${GITHUB_WORKSPACE:-$PWD}" | awk 'NR==2{print "  free: " $4 " of " $2}'
exit 0
