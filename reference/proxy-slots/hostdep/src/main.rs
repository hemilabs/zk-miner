//! A test guest whose journal depends on host inputs a prover controls, so that `zkminer simulate
//! --adversarial`'s host-input reruns are shown to catch them (methods/tests/simulate_adversarial.rs).
//! `W`'s first byte picks the mode; the journal is a 32-byte header word (scheme id 0x77), then:
//!
//! - `0xA1`: 8 bytes of `sys_rand` (depends on the `sys_rand` seed, which no proof binds);
//! - `0xA2`: `n` keccak permutations through risc0's batcher (`n` = `W[1..3]` little-endian, 1000 by
//!   default), then the user cycle count; at a small keccak po2 this makes two or more batches;
//! - `0xA4`: permutations through the raw `sys_keccak` until its status says the host's batch is
//!   full, and their count (depends on the keccak po2);
//! - `0xA5`: a randomized spot check. `W = 0xA5 ‖ v (8 bytes) ‖ k (1 byte) ‖ k items of 8 bytes`,
//!   the statement "every item is `v`", checked at one index drawn from `sys_rand`; the journal is
//!   a header word of its own (0x78) and `v`. An honest `W` gives the same journal under any seed,
//!   so only the guest's `sys_rand` call shows that a prover who picks the seed passes a forged `W`;
//! - anything else: `W` itself (a statement as good as its source: two providers that disagree give
//!   two journals).
//!
//! Never deployed.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use risc0_zkvm::guest::env;
use risc0_zkvm_platform::{
    fileno,
    syscall::{sys_rand, sys_read},
};

risc0_zkvm::entry!(main);

fn read_input() -> Vec<u8> {
    let mut input = Vec::new();
    let mut words = alloc::vec![0u32; 4096];
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
    let mut out = Vec::new();
    let mut header = [0u8; 32];
    header[31] = 0x77;
    out.extend_from_slice(&header);
    match w.first().copied().unwrap_or(0) {
        0xA1 => {
            let mut r = [0u32; 2];
            // SAFETY: a writable buffer of two words.
            unsafe { sys_rand(r.as_mut_ptr(), 2) };
            out.extend_from_slice(&r[0].to_le_bytes());
            out.extend_from_slice(&r[1].to_le_bytes());
        }
        0xA2 => {
            let mut st = [0u64; 25];
            let n = if w.len() >= 3 { u16::from_le_bytes([w[1], w[2]]) as u64 } else { 1000 };
            for i in 0..n {
                st[0] ^= i;
                env::risc0_keccak_update(&mut st);
            }
            out.extend_from_slice(&env::cycle_count().to_le_bytes());
        }
        0xA4 => {
            // The raw permutation reports when the host's keccak batch is full (its size is
            // 2^keccak_po2 / 200): count the permutations until then (capped).
            let mut st = [0u64; 25];
            let mut count = 0u32;
            while count < 2000 {
                // SAFETY: both point at a live 25-word state.
                let full = unsafe { risc0_zkvm_platform::syscall::sys_keccak(&st, &mut st) };
                count += 1;
                if full != 0 {
                    break;
                }
            }
            out.extend_from_slice(&count.to_le_bytes());
        }
        0xA5 => {
            assert!(w.len() >= 10, "malformed");
            let v = &w[1..9];
            let k = w[9] as usize;
            assert!(k > 0 && w.len() == 10 + 8 * k, "malformed");
            let mut r = [0u32; 1];
            // SAFETY: a writable buffer of one word.
            unsafe { sys_rand(r.as_mut_ptr(), 1) };
            let i = r[0] as usize % k;
            assert!(&w[10 + 8 * i..18 + 8 * i] == v, "spot check failed");
            out[31] = 0x78;
            out.extend_from_slice(v);
        }
        _ => out.extend_from_slice(&w),
    }
    env::commit_slice(&out);
}
