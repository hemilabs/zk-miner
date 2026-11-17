#!/bin/sh
# The guest lints of plan §21.1 item 4, as clippy: the guest must pass with every host input a guest
# may not use denied (guest/clippy.toml), and the lint control guest, which uses each of them, must
# fail with each one reported. Clippy runs for the zkVM target with the risc0 toolchain (rzup),
# which ships clippy. methods/tests/guest_lints.rs adds the source scan of the libraries the guest
# links and the call-graph check of the built ELF.
#
# Usage: check-guest-lints.sh   (CARGO_TARGET_DIR is honoured; the default is guest-clippy/ here)
set -eu
cd "$(dirname "$0")"
here=$PWD
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/guest-clippy}"
# risc0's guest build passes this cfg to every guest crate; getrandom needs it to compile.
export RUSTFLAGS='--cfg getrandom_backend="custom"'
lint() { # DIR
    (cd "$1" && CLIPPY_CONF_DIR="$here/guest" cargo +risc0 clippy --locked --target riscv32im-risc0-zkvm-elf -- \
        -D clippy::disallowed_methods -D clippy::disallowed_types 2>&1)
}

lint guest >/dev/null || { lint guest; echo "check-guest-lints.sh: the guest uses a disallowed host input" >&2; exit 1; }

out=$(lint lint-control || true)
for expected in std::collections::HashMap risc0_zkvm::guest::env::cycle_count std::env::var std::env::args \
    risc0_zkvm::guest::env::exit risc0_zkvm_platform::syscall::syscall_0_nr risc0_zkvm_platform::syscall::syscall_2_nr \
    risc0_zkvm_platform::syscall::sys_keccak risc0_zkvm::guest::env::FdReader::new core::cell::Cell; do
    if ! printf '%s\n' "$out" | grep -q "disallowed .* \`$expected\`"; then
        printf '%s\n' "$out" >&2
        echo "check-guest-lints.sh: the lint control's use of $expected was not reported" >&2
        exit 1
    fi
done
echo "check-guest-lints.sh: guest clean; the control's ten violations reported"
