//! Segment-size steering guest, for tests of `zkminer simulate`'s size check.
//!
//! A guest can learn the segment size it runs at: the machine records where it paused at every split, at
//! a fixed address, and the sha ecall with no blocks copies from there into guest memory. This one polls
//! for the first split, and spins only if it came at the 2^20 size. It commits the same journal either way.

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

fn peek(addr: u32, out: &mut [u32; 8]) {
    let scratch = [0u32; 16];
    unsafe {
        core::arch::asm!("ecall",
            in("t0") 3u32,
            in("a0") out.as_mut_ptr() as u32, in("a1") addr,
            in("a2") scratch.as_ptr() as u32, in("a3") scratch.as_ptr().add(8) as u32,
            in("a4") 0u32, options(nostack));
    }
}

fn main() {
    let mut w = [0u32; 8];
    peek(0xffff_0210, &mut w);
    let start = w[0];
    let mut first_split = 0u64;
    let mut z = 1u32;
    while risc0_zkvm::guest::env::cycle_count() < (1 << 23) {
        for i in 0..2000u32 {
            z = z.wrapping_mul(i | 1) ^ 0x55;
            core::hint::black_box(z);
        }
        peek(0xffff_0210, &mut w);
        if w[0] != start {
            first_split = risc0_zkvm::guest::env::cycle_count();
            break;
        }
    }
    if (655_360..1_179_648).contains(&first_split) {
        for i in 0..4_000_000u32 {
            z = z.wrapping_mul(i | 1) ^ 0x55;
            core::hint::black_box(z);
        }
    }
    risc0_zkvm::guest::env::commit_slice(&[0xABu8, 0xCD, 0, 0]);
}
