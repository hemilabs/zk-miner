//! A guest built with risc0-zkvm 3.0.5 (see Cargo.toml) that runs `n` keccak permutations through
//! risc0's batcher and commits `n` (4 bytes, little-endian). `n` is `W`'s first four bytes,
//! little-endian (1000 when `W` is shorter). A batch holds about `2^keccak_po2 / 200` permutations,
//! so 1000 make two batches at the miner's default keccak po2 (17), and 120 at keccak po2 14.
//!
//! Never deployed.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use risc0_zkvm::guest::env;
use risc0_zkvm_platform::{fileno, syscall::sys_read};

risc0_zkvm::entry!(main);

fn read_input() -> Vec<u8> {
    let mut input = Vec::new();
    let mut words = alloc::vec![0u32; 1024];
    loop {
        // SAFETY: `words` is a live, writable, aligned buffer of `4 * words.len()` bytes.
        let n = unsafe { sys_read(fileno::STDIN, words.as_mut_ptr().cast::<u8>(), 4 * words.len()) };
        if n == 0 {
            return input;
        }
        input.extend(words.iter().flat_map(|w| w.to_le_bytes()).take(n));
    }
}

fn main() {
    let w = read_input();
    let n = match w.get(..4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 1000,
    };
    let mut st = [0u64; 25];
    for i in 0..n {
        st[0] ^= u64::from(i);
        env::risc0_keccak_update(&mut st);
    }
    env::commit_slice(&n.to_le_bytes());
}
