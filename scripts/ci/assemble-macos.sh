#!/usr/bin/env bash
# Builds and assembles the macOS (Apple Silicon, Metal) beta release kit (B9-PKG):
#
#   assemble-macos.sh <release dir>
#
# The macOS counterpart of assemble-release.sh. It builds on this Mac (Makefile.mac), so run it from
# a clean checkout. <release dir> gets:
# - zkminer-<version>-macos-arm64.tar.gz, which unpacks into zkminer-<version>-macos-arm64/:
#     zkminer                            the CLI
#     provers/zkminer-prove-risc0-metal  the Metal worker
#     metal-aot/                         the offline (AOT) Metal archive set of that worker, for the GPU
#                                        families in AOT_ARCHES (manifest.jsonl, SHA256SUMS, WORKER)
#     install.sh                         installs into ~/.zkminer (packaging/macos/install.sh)
#     tools/                             install-metal-aot.sh and build-metal-aot.sh (scripts/mac)
#     README.md                          packaging/macos/README.md
#     LICENSE, BUILDINFO                 what was built from what, and what install.sh checks
#     SHA256SUMS                         over every file above
# - SHA256SUMS over the tarball.
# The risc0-groth16 component (2.4 GB) is never in the kit: the worker downloads it, pinned by its
# SHA-256, at its first warm-up (install.sh --with-groth16 fetches it ahead). The kit is unsigned
# (no Developer ID, not notarized): install.sh clears com.apple.quarantine from what it installs.
# check-macos-release.sh checks the tarball at the end (Mach-O libraries, minimum macOS, metallib
# target, archives against the worker, no Groth16 files).
#
# Settings (environment):
# - ZKMINER_MACOS_MIN    the minimum macOS: the binaries' LC_BUILD_VERSION minos and the Metal
#                        libraries' target (default 27.0; docs/macos-beta.md says why). `sdk` changes
#                        nothing: minos 11.0 and Metal libraries for the build SDK (revert knob).
# - AOT_ARCHES           GPU families of the archive set (default applegpu_g17s; `none`: no set)
# - AOT_VALIDATED        families install.sh installs archives for (default applegpu_g17s: the only one
#                        validated on hardware); other Macs compile their pipelines at first start
# - AOT_SRC              a prebuilt set for exactly this worker instead of building one (e.g. made on a
#                        Mac with a GPU when the build host has none; the digests are checked)
# - RISC0_SRC            passed to Makefile.mac (default git: the hemilabs/risc0 rev Cargo.toml pins)
# - ZKMINER_VERSION      default [workspace.package].version of Cargo.toml
# - ASSEMBLE_SKIP_BUILD=1  package target/release as it is (it must have been built by this script's
#                        settings, which the checks verify)
# Needs what Makefile.mac needs (RELEASE-DEPS.md): the Metal toolchain (metal, metallib, metal-tt),
# the rzup Rust guest toolchain, protoc, python3, and a Metal device for the AOT dump tests.
set -euo pipefail

out=${1:?usage: $0 <release dir>}
ci=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$ci/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

die() { echo "::error::$*" >&2; exit 1; }
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "build the macOS kit on an Apple Silicon Mac (this is $(uname -s) $(uname -m))"
[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 0 ] || die "this shell runs under Rosetta"

version=${ZKMINER_VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)}
[ -n "$version" ] || die "no [workspace.package].version in Cargo.toml"
macos_min=${ZKMINER_MACOS_MIN:-27.0}
aot_arches=${AOT_ARCHES:-applegpu_g17s}
aot_validated=${AOT_VALIDATED:-applegpu_g17s}
risc0_src=${RISC0_SRC:-git}
name=zkminer-$version-macos-arm64
worker=$repo/target/release/zkminer-prove-risc0-metal
cli=$repo/target/release/zkminer

# Makefile.mac sources env.sh (the Metal toolchain on PATH) in every recipe, and env.sh sets METAL_TC,
# which would replace the compiler chosen below: source it here, once, and tell make there is none.
env_sh=${ENV_SH:-$(dirname "$repo")/env.sh}
if [ -f "$env_sh" ]; then
  echo "== sourcing $env_sh"
  set +eu
  # shellcheck disable=SC1090
  source "$env_sh"
  set -eu
fi
mk() { make -C "$repo" -f Makefile.mac ENV_SH=/nonexistent RISC0_SRC="$risc0_src" "$@"; }

if [ "$macos_min" = sdk ]; then
  echo "== minimum macOS: what the toolchains default to (ZKMINER_MACOS_MIN=sdk)"
else
  [[ "$macos_min" =~ ^[0-9]+\.[0-9]+$ ]] || die "ZKMINER_MACOS_MIN must be <major>.<minor> or sdk (got '$macos_min')"
  [ -z "${MACOSX_DEPLOYMENT_TARGET:-}" ] || die "unset MACOSX_DEPLOYMENT_TARGET (ZKMINER_MACOS_MIN sets the minimum macOS)"
  [ -z "${RUSTFLAGS:-}" ] || die "RUSTFLAGS is set; it would replace the target rustflags this build needs"
  # Not MACOSX_DEPLOYMENT_TARGET: risc0-build passes the environment (all but CARGO*) to the guest
  # builds, whose proc-macros it would break like ours below. The minimum goes to the two places that
  # decide where the kit runs:
  # 1. The Mach-O binaries' LC_BUILD_VERSION minos (dyld refuses to start them on an older macOS),
  #    through the linker. The release profile's `strip = "debuginfo"` runs the Command Line Tools'
  #    strip on every linked image; for a minimum of 12.0 or later its output has a string table that
  #    is not 8-byte aligned, which dyld refuses to load ("mis-aligned LINKEDIT string pool"; the build's
  #    own proc-macros fail first, E0463). So no strip step (`-C strip=none`, after cargo's own
  #    `-C strip=debuginfo`: the last wins), and the linker's -S drops the same debug symbols (STABS).
  #    Only this cargo sees these flags (risc0-build drops CARGO* for the guests).
  export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="${CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS:+$CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS }-C strip=none -C link-arg=-Wl,-S -C link-arg=-mmacosx-version-min=$macos_min"
  # 2. The Metal libraries' target OS (Metal does not load a library built for a newer macOS; by
  #    default the compiler targets the build SDK's version). risc0-build-kernel takes no target flag,
  #    but finds its compiler through METAL_TC: a toolchain directory whose `metal` adds
  #    -mmacosx-version-min and whose `--version` names it, which also keys risc0's kernel cache
  #    (~/Library/Caches/com.risczero.RISC-Zero.risc0, keyed by that version line) apart from builds
  #    for another target. The AOT dump tests build with the same compiler, so their metallibs match.
  real_metal=${METAL_TC:+$METAL_TC/usr/bin/metal}
  real_metal=${real_metal:-$(xcrun --sdk macosx --find metal 2>/dev/null || command -v metal || true)}
  [ -x "$real_metal" ] || die "no Metal compiler (xcrun --sdk macosx --find metal): RELEASE-DEPS.md"
  tc=$repo/target/macos-kit/metal-tc-$macos_min
  rm -rf "$tc"; mkdir -p "$tc/usr/bin"
  for t in "$(dirname "$real_metal")"/*; do ln -s "$t" "$tc/usr/bin/$(basename "$t")"; done
  [ -e "$tc/usr/bin/metallib" ] || ln -s "$(xcrun --sdk macosx --find metallib)" "$tc/usr/bin/metallib"
  rm -f "$tc/usr/bin/metal"
  cat > "$tc/usr/bin/metal" <<EOF
#!/bin/bash
# assemble-macos.sh: the Metal compiler at $real_metal, targeting macOS $macos_min.
for a in "\$@"; do
  if [ "\$a" = --version ]; then
    "$real_metal" --version | sed '1s/\$/ [-mmacosx-version-min=$macos_min]/'
    exit "\${PIPESTATUS[0]}"
  fi
done
exec "$real_metal" -mmacosx-version-min=$macos_min "\$@"
EOF
  chmod 0755 "$tc/usr/bin/metal"
  export METAL_TC=$tc
  echo "== minimum macOS $macos_min (linker minos; Metal compiler $real_metal with -mmacosx-version-min=$macos_min)"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/zkminer-macos-kit.XXXXXX")
trap 'rm -rf "$work"' EXIT

echo "== build (Makefile.mac, RISC0_SRC=$risc0_src)"
if [ "${ASSEMBLE_SKIP_BUILD:-0}" != 1 ]; then
  mk mac-build-worker
fi
[ -x "$worker" ] && [ -x "$cli" ] || die "missing $worker or $cli"

# The build's minimum macOS: LC_BUILD_VERSION of both binaries and the target OS of every metallib
# the worker embeds. check-macos-release.sh repeats this on the tarball.
if [ "$macos_min" != sdk ]; then
  expect_os=$macos_min
  "$ci/check-macos-release.sh" --binaries "$expect_os" "$worker" "$cli" \
    || die "the build is not for macOS $expect_os (ASSEMBLE_SKIP_BUILD=1 with a build of other settings?)"
else
  expect_os=$(otool -l "$worker" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}')
fi

echo "== offline Metal archives ($aot_arches)"
aot=$work/metal-aot
if [ "$aot_arches" = none ]; then
  mkdir -p "$aot"
elif [ -n "${AOT_SRC:-}" ]; then
  [ -f "$AOT_SRC/SHA256SUMS" ] || die "AOT_SRC=$AOT_SRC has no SHA256SUMS"
  cp -R "$AOT_SRC/." "$aot/"
else
  # mac-build-aot's macOS key is the major version of the minimum: the runtime opens
  # macos<major> archives on every release of that major version (risc0 tools/metal_aot README).
  AOT_MACOS_MIN=${expect_os%%.*}.0 mk AOT_ARCHES="$aot_arches" AOT_OUT="$work/aot-build" mac-build-aot
  cp -R "$work/aot-build/." "$aot/"
fi

echo "== stage $name"
kit=$work/$name
mkdir -p "$kit/provers" "$kit/tools"
cp "$cli" "$kit/zkminer"
cp "$worker" "$kit/provers/"
cp -R "$aot" "$kit/metal-aot"
cp "$repo/packaging/macos/install.sh" "$kit/install.sh"
cp "$repo/packaging/macos/README.md" "$kit/README.md"
cp "$repo/scripts/mac/install-metal-aot.sh" "$repo/scripts/mac/build-metal-aot.sh" "$kit/tools/"
cp "$repo/LICENSE" "$kit/LICENSE"

# The Groth16 component the worker downloads (crates/zkminer-prove-risc0/src/groth16_component.rs),
# for install.sh --with-groth16; check-macos-release.sh checks that the worker pins the same blob.
g16=$repo/crates/zkminer-prove-risc0/src/groth16_component.rs
g16_version=$(sed -n 's/^pub(crate) const VERSION: &str = "\(.*\)";/\1/p' "$g16")
g16_sha=$(sed -n 's/^const ARCHIVE_SHA256: &str = "\([0-9a-f]\{64\}\)";/\1/p' "$g16")
[ -n "$g16_version" ] && [ -n "$g16_sha" ] || die "cannot read the risc0-groth16 pin from $g16"
g16_url=https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/components/risc0-groth16/sha256/$g16_sha

metal_version=$( (xcrun --sdk macosx metal --version 2>/dev/null || true) | head -1)
commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
dirty=$( [ -z "$(git -C "$repo" status --porcelain --untracked-files=no 2>/dev/null)" ] && echo no || echo yes)
risc0_rev=$(sed -n 's/^risc0-zkvm = { git = "https:\/\/github.com\/hemilabs\/risc0", rev = "\([0-9a-f]*\)" }.*/\1/p' "$repo/Cargo.toml")
built_arches=$(cd "$kit/metal-aot" && ls | sed -n 's/^[a-z0-9_]*-[0-9a-f]\{24\}-\(applegpu_[a-z0-9]*\)-.*\.binarchive$/\1/p' | sort -u | tr '\n' ' ' | sed 's/ $//')
cat > "$kit/BUILDINFO" <<EOF
version=$version
commit=$commit
commit_dirty=$dirty
risc0_rev=$risc0_rev
risc0_src=$risc0_src
min_macos=$expect_os
metal_compiler=$metal_version
build_macos=$(sw_vers -productVersion) ($(sw_vers -buildVersion))
aot_arches=$built_arches
aot_validated=$aot_validated
groth16_version=$g16_version
groth16_sha256=$g16_sha
groth16_url=$g16_url
EOF
cat "$kit/BUILDINFO"

# Modes as a release ships them, a fixed mtime (the commit's), and no macOS metadata in the tarball
# (COPYFILE_DISABLE: no ._ AppleDouble entries; --no-xattrs: a quarantine flag on the build host
# never ends up in the kit).
find "$kit" -type d -exec chmod 0755 {} +
find "$kit" -type f -exec chmod 0644 {} +
chmod 0755 "$kit/zkminer" "$kit/provers/zkminer-prove-risc0-metal" "$kit/install.sh" "$kit/tools/"*.sh
xattr -cr "$kit" 2>/dev/null || true
(cd "$kit" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS)
chmod 0644 "$kit/SHA256SUMS"
stamp=$(git -C "$repo" log -1 --format=%cd --date=format-local:%Y%m%d%H%M.%S 2>/dev/null || date +%Y%m%d%H%M.%S)
find "$kit" -exec touch -h -t "$stamp" {} +

tarball=$out/$name.tar.gz
(cd "$work" && find "$name" | LC_ALL=C sort > "$work/list" &&
  COPYFILE_DISABLE=1 tar --no-xattrs --no-acls --uid 0 --gid 0 --uname root --gname wheel \
    -n -cf - -T "$work/list" | gzip -n -9 > "$tarball.tmp")
mv -f "$tarball.tmp" "$tarball"
echo "$name.tar.gz: $(du -sh "$kit" | cut -f1) unpacked, $(du -h "$tarball" | cut -f1) packed"

echo "== check"
"$ci/check-macos-release.sh" "$tarball"

echo "== SHA256SUMS"
(cd "$out" && shasum -a 256 "$name.tar.gz" > SHA256SUMS && cat SHA256SUMS)
