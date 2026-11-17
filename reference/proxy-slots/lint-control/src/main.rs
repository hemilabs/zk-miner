//! Everything the guest lints forbid, each on its own input bit so that none is optimised away:
//! a default-seeded `HashMap` (`sys_rand`), the cycle count, an environment variable, the
//! arguments, an early exit; and the same host inputs reached around the names the lints used to
//! ban: the raw syscall entry points (`syscall_*_nr` with `nr::SYS_RANDOM`, `SYS_CYCLE_COUNT`,
//! `SYS_GETENV`), another file descriptor (`sys_read` of fd 3, `FdReader`), the raw keccak
//! permutation's status (which shows the host's keccak po2), and a `static` that a non-capturing
//! function reads into an output. The lint tests check that the built ELF carries the syscalls
//! these reach and that the source scan flags them. Never deployed.

#![no_main]

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use risc0_zkvm::guest::env;
use risc0_zkvm_platform::syscall::{nr, sys_keccak, sys_read, syscall_0_nr, syscall_2_nr};

risc0_zkvm::entry!(main);

/// risc0's syscall numbers (`risc0_zkvm_platform::syscall::Syscall`).
const RANDOM: usize = 11;
const CYCLES: usize = 3;
const GETENV: usize = 6;

static SMUGGLED: AtomicU32 = AtomicU32::new(0);

fn read_smuggled(_: &u64) -> u64 {
    u64::from(SMUGGLED.load(Ordering::Relaxed))
}

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
    let mut words = [0u32; 8];
    if n & 32 != 0 {
        // Host entropy without `sys_rand`.
        unsafe { syscall_0_nr(RANDOM, nr::SYS_RANDOM, words.as_mut_ptr(), 2) };
        out += u64::from(words[0]);
    }
    if n & 64 != 0 {
        // The cycle count without `sys_cycle_count`.
        out += u64::from(unsafe { syscall_0_nr(CYCLES, nr::SYS_CYCLE_COUNT, core::ptr::null_mut(), 0) }.0);
    }
    if n & 128 != 0 {
        // An environment variable without `sys_getenv` (and past its allowlist).
        let name = b"HINT";
        let r = unsafe {
            syscall_2_nr(GETENV, nr::SYS_GETENV, words.as_mut_ptr(), 8, name.as_ptr() as u32, name.len() as u32)
        };
        out += u64::from(r.0);
    }
    if n & 256 != 0 {
        // A hint channel: file descriptor 3.
        out += unsafe { sys_read(3, words.as_mut_ptr().cast(), 16) } as u64;
    }
    if n & 512 != 0 {
        // The raw permutation's status: whether the host's keccak batch is full.
        let mut st = [0u64; 25];
        out += unsafe { sys_keccak(&st, &mut st) } as u64;
    }
    if n & 1024 != 0 {
        // The same channel through the standard reader of another fd.
        let mut b = [0u8; 4];
        risc0_zkvm::guest::env::Read::read_slice(&mut env::FdReader::new(3), &mut b);
        out += u64::from(b[0]);
    }
    if n & 2048 != 0 {
        // A static filled from the input, read back by a function that captures nothing.
        SMUGGLED.store(n, Ordering::Relaxed);
        let c = Cell::new(read_smuggled(&0));
        out += c.get();
    }
    env::commit(&out);
}
