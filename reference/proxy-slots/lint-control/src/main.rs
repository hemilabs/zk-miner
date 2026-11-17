//! Everything the guest lints forbid, each on its own input bit so that none is optimised away:
//! a default-seeded `HashMap` (`sys_rand`), the cycle count, an environment variable, the
//! arguments, and an early exit. The lint tests check that the built ELF carries the syscalls
//! these reach and that the source scan flags them. Never deployed.

#![no_main]

use std::collections::HashMap;

use risc0_zkvm::guest::env;

risc0_zkvm::entry!(main);

fn main() {
    let n: u32 = env::read();
    let mut out = 0u64;
    if n & 1 != 0 {
        let mut m = HashMap::new();
        m.insert(n, n);
        out += m.len() as u64;
    }
    if n & 2 != 0 {
        out += env::cycle_count();
    }
    if n & 4 != 0 {
        out += std::env::var("ZKMINER_LINT_CONTROL").map(|v| v.len() as u64).unwrap_or(0);
    }
    if n & 8 != 0 {
        out += std::env::args().count() as u64;
    }
    if n & 16 != 0 {
        env::exit(1);
    }
    env::commit(&out);
}
