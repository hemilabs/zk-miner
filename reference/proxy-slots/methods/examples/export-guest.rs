//! Writes one of this crate's guests (risc0's program binary, as a ProgramRegistry URI serves it) to a
//! file and prints its image id, as `zkminer-prove-risc0 --export-guest` does for the miner's own
//! guests. `crates/zkminer-cli/tests/localnet.rs` serves the reference guest this way.
//!
//! ```text
//! cargo run -p hemiprove-proxy-slots-methods --example export-guest -- proxy-slots out.bin
//! ```

use hemiprove_proxy_slots_methods::{
    HOSTDEP_ELF, HOSTDEP_ID, KECCAK_3_0_ELF, KECCAK_3_0_ID, LINT_CONTROL_ELF, LINT_CONTROL_ID, PROXY_SLOTS_ELF, PROXY_SLOTS_ID,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [name, out] = args.as_slice() else {
        eprintln!("usage: export-guest <proxy-slots|hostdep|lint-control|keccak-3-0> <file>");
        std::process::exit(2);
    };
    let (elf, id) = match name.as_str() {
        "proxy-slots" => (PROXY_SLOTS_ELF, PROXY_SLOTS_ID),
        "hostdep" => (HOSTDEP_ELF, HOSTDEP_ID),
        "lint-control" => (LINT_CONTROL_ELF, LINT_CONTROL_ID),
        "keccak-3-0" => (KECCAK_3_0_ELF, KECCAK_3_0_ID),
        other => {
            eprintln!("export-guest: no guest {other}");
            std::process::exit(2);
        }
    };
    std::fs::write(out, elf).unwrap_or_else(|e| panic!("writing {out}: {e}"));
    // The image id's bytes are its words, little-endian (risc0's `Digest`).
    let bytes: Vec<u8> = id.iter().flat_map(|w| w.to_le_bytes()).collect();
    println!("0x{}", hex::encode(bytes));
}
