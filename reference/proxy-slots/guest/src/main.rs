//! The reference guest of plan §12: proves "at block B, proxy C's EIP-1967 implementation is I
//! (code hash H), and the k slots rule R names hold V1..Vk" from a scheme-1 witness.
//!
//! Everything it checks is in `hemiprove-proxy-slots` (the statement) and `hemiprove-eth-prelude`
//! (RLP, headers, tries, the guards); this file only moves bytes: it reads the whole input
//! (`abi.encode(jobId, prover) ‖ W`, as the miner supplies it to a journal-prefix job), runs the
//! statement, and commits the journal it returns with one `commit_slice`. A failed check panics
//! before anything is committed, so a bad witness yields no proof (plan §8.2: failures abort).
//!
//! `no_std`: the standard library's `HashMap`/`HashSet` (seeded from `sys_rand`), `std::env` and
//! `std::process::exit` are not available to it at all. See README.md for the lints that keep the
//! rest of the host-controlled inputs out.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use risc0_zkvm::guest::env;
use risc0_zkvm_platform::{fileno, syscall::sys_read};

risc0_zkvm::entry!(main);

/// Reads the guest input to its end.
fn read_input() -> Vec<u8> {
    let mut input = Vec::new();
    // Word-aligned, as the read syscall wants its buffer.
    let mut words = alloc::vec![0u32; 4096];
    loop {
        // SAFETY: `words` is a live, writable, aligned buffer of `4 * words.len()` bytes, and the
        // host writes at most that many into it.
        let n = unsafe { sys_read(fileno::STDIN, words.as_mut_ptr().cast::<u8>(), 4 * words.len()) };
        if n == 0 {
            return input;
        }
        input.extend(words.iter().flat_map(|w| w.to_le_bytes()).take(n));
    }
}

fn main() {
    let input = read_input();
    match hemiprove_proxy_slots::run(&input) {
        Ok(journal) => env::commit_slice(&journal),
        Err(e) => panic!("proxy-slots: {e}"),
    }
}
