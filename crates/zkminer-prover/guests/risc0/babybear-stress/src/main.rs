//! BabyBear field stress test.
//!
//! RISC0's STARK operates over BabyBear (p = 2^31 - 2^27 + 1 = 2013265921 = 0x78000001).
//! Values near this prime could trigger field reduction bugs in the constraint
//! evaluator or NTT kernel. This guest manipulates u32 values near p, p-1,
//! p+1, 2p, and other field-significant boundaries.
//!
//! Input: iterations (u32).

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use core::hint::black_box;

const BABYBEAR_P: u32 = 2013265921; // 0x78000001

fn main() {
    let iterations: u32 = risc0_zkvm::guest::env::read();
    let mut acc: u64 = 0;

    // Field-significant constants
    let field_vals: [u32; 12] = [
        0,
        1,
        BABYBEAR_P - 1,          // p-1 = 2013265920
        BABYBEAR_P,              // p   = 2013265921
        BABYBEAR_P + 1,          // p+1 = 2013265922
        BABYBEAR_P.wrapping_mul(2), // 2p
        BABYBEAR_P.wrapping_mul(2).wrapping_sub(1), // 2p-1
        BABYBEAR_P >> 1,         // p/2
        (BABYBEAR_P >> 1) + 1,   // p/2 + 1 (midpoint)
        0x7FFFFFFF,              // i32::MAX
        0x80000000,              // i32::MIN as u32
        0xFFFFFFFF,              // u32::MAX
    ];

    for iter in 0..iterations {
        let iter = black_box(iter);

        for &a in &field_vals {
            for &b in &field_vals {
                let a = black_box(a);
                let b = black_box(b);

                // Arithmetic near field boundaries
                acc = acc.wrapping_add(a.wrapping_add(b) as u64);
                acc = acc.wrapping_add(a.wrapping_sub(b) as u64);
                acc = acc.wrapping_add(a.wrapping_mul(b) as u64);
                acc = acc.wrapping_add((a & b) as u64);
                acc = acc.wrapping_add((a | b) as u64);
                acc = acc.wrapping_add((a ^ b) as u64);

                // Division near field prime
                if b != 0 {
                    acc = acc.wrapping_add((a / b) as u64);
                    acc = acc.wrapping_add((a % b) as u64);
                } else {
                    acc = acc.wrapping_add(0xFFFFFFFF_u64);
                    acc = acc.wrapping_add(a as u64);
                }

                // Widening multiply -- product might be near p^2
                let wide = (a as u64).wrapping_mul(b as u64);
                acc = acc.wrapping_add(wide);

                // Shifts that move bits near bit 31 (where p's MSB is)
                acc = acc.wrapping_add(a.wrapping_shl(b & 31) as u64);
                acc = acc.wrapping_add(a.wrapping_shr(b & 31) as u64);
            }
        }

        // Values that are exact multiples of p
        for k in 0..8u32 {
            let val = BABYBEAR_P.wrapping_mul(black_box(k));
            acc = acc.wrapping_add(val as u64);
            acc = acc.wrapping_add(val.wrapping_add(1) as u64);
            acc = acc.wrapping_add(val.wrapping_sub(1) as u64);
        }

        // Scatter: mix iteration-dependent values near p
        let scatter = BABYBEAR_P.wrapping_add(iter).wrapping_mul(2654435761);
        acc = acc.wrapping_add(scatter as u64);
    }

    risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
}
