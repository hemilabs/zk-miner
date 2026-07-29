//! Segment-boundary stress test.
//!
//! Calls commit_slice repeatedly, interleaved with calibrated computation
//! to push syscalls near segment boundaries (~2^20 cycles per segment).
//! Also tests power-of-2 cycle count padding edge cases.
//!
//! Input: mode (u32), param (u32).
//!   mode 0: Multi-commit with calibrated spacing (param = number of commits)
//!   mode 1: Calibrated NOP sled for exact cycle count targeting (param = cycles/1024)
//!   mode 2: Commit at every iteration of a tight loop (param = commit count)

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use core::hint::black_box;

fn main() {
    let mode: u32 = risc0_zkvm::guest::env::read();
    let param: u32 = risc0_zkvm::guest::env::read();

    match mode {
        // =============================================================
        // Mode 0: Multi-commit with calibrated spacing
        // Each commit is preceded by ~64K cycles of computation to
        // land some commits near segment boundaries.
        // =============================================================
        0 => {
            let commits = param.max(1);
            let mut acc: u64 = 0xDEADBEEF_CAFEBABE;
            for c in 0..commits {
                // ~64K cycles of work per commit
                for i in 0..2048u32 {
                    let v = black_box(i.wrapping_mul(c).wrapping_add(0x9E3779B9));
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(v as u64);
                    // Inner loop to increase cycle count per outer iteration
                    for j in 0..8u32 {
                        acc = acc.wrapping_add(black_box(v.wrapping_shl(j & 31)) as u64);
                    }
                }
                // Commit after each block of work
                risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
            }
        }

        // =============================================================
        // Mode 1: Calibrated NOP sled
        // Generates approximately param*1024 cycles to test trace
        // padding at power-of-2 boundaries (2^N, 2^N+1, 2^N-1).
        // =============================================================
        1 => {
            let iters = param as u64 * 1024;
            let mut acc: u64 = 0x12345678_9ABCDEF0;
            for _ in 0..iters {
                acc = acc.wrapping_add(black_box(1));
            }
            risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
        }

        // =============================================================
        // Mode 2: Rapid-fire commits
        // Commits every single iteration to stress journal buffer management.
        // =============================================================
        2 => {
            let count = param.max(1).min(10000);
            let mut acc: u64 = 0;
            for i in 0..count {
                acc = acc.wrapping_mul(31).wrapping_add(black_box(i) as u64);
                risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
            }
        }

        _ => {
            risc0_zkvm::guest::env::commit_slice(&0xBADC0DEu64.to_le_bytes());
        }
    }
}
