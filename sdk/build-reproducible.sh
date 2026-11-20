#!/bin/sh
# Builds the SDK workspace's modules reproducibly: locked dependencies, the pinned toolchain
# (rust-toolchain.toml, checked), the pinned target features, every host path remapped, and nothing
# from the environment that could swap the compiler, wrap it, or change the flags or the profile; so
# the bytes (and the builderId = sha256 of them) do not depend on the host. Then it puts every module
# through the runner's own pre-pass. Extra arguments go to cargo, e.g. `-p latest-block` or
# `--target-dir DIR`. The modules land in target/wasm32-unknown-unknown/release/ (or under DIR).
#
# The pre-pass runs `zkminer-builder-check`: $ZKMINER_BUILDER_CHECK if set, else built from the
# zkminer repository this directory sits in.
set -eu
cd "$(dirname "$0")"

# The commit of the toolchain rust-toolchain.toml names (rustc 1.97.1, 2026-07-14).
pinned_commit=8bab26f4f68e0e26f0bb7960be334d5b520ea452
pinned_release=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' rust-toolchain.toml)

# Nothing in the environment chooses the toolchain, the compiler, a wrapper, the flags or the
# profile. (An empty RUSTC_WRAPPER also overrides a wrapper set in a cargo config file.)
unset RUSTUP_TOOLCHAIN RUSTC RUSTDOC RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS \
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER \
    CARGO_BUILD_TARGET CARGO_INCREMENTAL CARGO_BUILD_INCREMENTAL
for v in $(env | sed -n 's/^\(CARGO_PROFILE_[A-Za-z0-9_]*\)=.*/\1/p; s/^\(CARGO_BUILD_RUSTC[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$v"
done
export RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=

# The pinned toolchain, and cargo uses exactly the rustc checked here.
rustc_bin=$(rustup which rustc 2>/dev/null || command -v rustc)
info=$("$rustc_bin" -vV)
release=$(printf '%s\n' "$info" | sed -n 's/^release: //p')
commit=$(printf '%s\n' "$info" | sed -n 's/^commit-hash: //p')
if [ "$release" != "$pinned_release" ] || [ "$commit" != "$pinned_commit" ]; then
    echo "build-reproducible.sh: $rustc_bin is rustc $release ($commit); the pinned toolchain is" \
        "$pinned_release ($pinned_commit)" >&2
    exit 1
fi
cargo_release=$(cargo -V | cut -d' ' -f2)
if [ "$cargo_release" != "$pinned_release" ]; then
    echo "build-reproducible.sh: cargo is $cargo_release; the pinned toolchain is $pinned_release" >&2
    exit 1
fi
export RUSTC="$rustc_bin"

# The complete flag list. CARGO_ENCODED_RUSTFLAGS replaces every other source of rustflags (config
# files included), so the target features of .cargo/config.toml are repeated here, followed by
# --remap-path-prefix for every host path that can reach a module through panic locations: the
# toolchain's rust-src, the cargo home (registry dependencies) and this directory.
sysroot=$("$rustc_bin" --print sysroot)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sep=$(printf '\037')
CARGO_ENCODED_RUSTFLAGS="-C${sep}target-cpu=mvp${sep}-C${sep}target-feature=+bulk-memory,+multivalue,+mutable-globals,+nontrapping-fptoint,+reference-types,+sign-ext,-simd128,-relaxed-simd,-tail-call,-extended-const"
CARGO_ENCODED_RUSTFLAGS="$CARGO_ENCODED_RUSTFLAGS${sep}--remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit"
CARGO_ENCODED_RUSTFLAGS="$CARGO_ENCODED_RUSTFLAGS${sep}--remap-path-prefix=$cargo_home=/cargo"
CARGO_ENCODED_RUSTFLAGS="$CARGO_ENCODED_RUSTFLAGS${sep}--remap-path-prefix=$PWD=/sdk"
export CARGO_ENCODED_RUSTFLAGS

messages=$(mktemp)
trap 'rm -f "$messages"' EXIT
cargo build --locked --release --target wasm32-unknown-unknown --message-format=json-render-diagnostics "$@" >"$messages"
modules=$(sed -n 's/.*"filenames":\["\([^"]*\.wasm\)".*/\1/p' "$messages")
if [ -z "$modules" ]; then
    echo "build-reproducible.sh: cargo built no .wasm module" >&2
    exit 1
fi

# The runner's pre-pass, on every module (with the host's own flags: none of the above applies).
check() {
    if [ -n "${ZKMINER_BUILDER_CHECK:-}" ]; then
        "$ZKMINER_BUILDER_CHECK" "$@"
    elif [ -f ../crates/zkminer-witness-builder/Cargo.toml ]; then
        (cd .. && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
            cargo run --locked --release --quiet -p zkminer-witness-builder --bin zkminer-builder-check -- "$@")
    else
        echo "build-reproducible.sh: set ZKMINER_BUILDER_CHECK to a zkminer-builder-check binary" >&2
        return 2
    fi
}
# One argument per line of cargo's output (paths may hold spaces, not newlines).
old_ifs=$IFS
IFS='
'
# shellcheck disable=SC2086
set -- $modules
IFS=$old_ifs
check "$@"
