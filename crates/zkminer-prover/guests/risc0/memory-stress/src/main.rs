//! Memory access pattern stress tests.
//!
//! Exercises different memory patterns that stress the zkVM's memory model:
//! sequential sweep, random-access thrash, deep recursion, cross-page reads,
//! unaligned access stress, and heap churn.

#![no_main]
#![no_std]

extern crate alloc;

risc0_zkvm::entry!(main);

use alloc::vec;
use alloc::vec::Vec;
use core::hint::black_box;

/// Simple LCG for deterministic pseudo-random indices.
#[inline(always)]
fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1664525).wrapping_add(1013904223);
    *state
}

fn main() {
    let mode: u32 = risc0_zkvm::guest::env::read();
    let size: u32 = risc0_zkvm::guest::env::read();
    let mut acc: u64 = 0;

    match mode {
        // ===============================================================
        // Mode 0: Sequential sweep -- write then read a large buffer
        // ===============================================================
        0 => {
            let len = (size as usize) * 256;
            let mut buf = vec![0u8; len];
            for i in 0..len {
                buf[i] = ((i as u64).wrapping_mul(7) & 0xFF) as u8;
            }
            for i in 0..len {
                acc = acc.wrapping_mul(31).wrapping_add(buf[i] as u64);
            }
        }

        // ===============================================================
        // Mode 1: Random-access thrash -- scattered reads/writes
        // ===============================================================
        1 => {
            let len = (size as usize) * 256;
            let mut buf = vec![0u32; len / 4];
            let mut rng = 0x12345678u32;
            for _ in 0..len {
                let idx = (lcg(&mut rng) as usize) % (len / 4);
                buf[idx] = buf[idx].wrapping_add(lcg(&mut rng));
            }
            for _ in 0..len {
                let idx = (lcg(&mut rng) as usize) % (len / 4);
                acc = acc.wrapping_add(buf[idx] as u64);
            }
        }

        // ===============================================================
        // Mode 2: Deep recursion -- stack-heavy, crosses page bounds
        // ===============================================================
        2 => {
            let depth = size.min(2000) as usize;
            acc = deep_recurse(depth, 0x42) as u64;
        }

        // ===============================================================
        // Mode 3: Mixed -- interleave sequential + random + compute
        // ===============================================================
        3 => {
            let len = (size as usize) * 128;
            let mut buf = vec![0u32; len];
            let mut rng = 0xDEADBEEFu32;
            for i in 0..len {
                buf[i] = i as u32;
            }
            for _ in 0..len {
                let a = (lcg(&mut rng) as usize) % len;
                let b = (lcg(&mut rng) as usize) % len;
                buf.swap(a, b);
            }
            for i in 0..len {
                acc = acc.wrapping_mul(17).wrapping_add(buf[i] as u64);
            }
        }

        // ===============================================================
        // Mode 4: Unaligned access stress test
        // ===============================================================
        4 => {
            let len = (size as usize).max(16) * 64;
            let mut buf = vec![0u8; len + 8];
            // Fill buffer with deterministic pattern
            for i in 0..buf.len() {
                buf[i] = ((i as u64).wrapping_mul(13).wrapping_add(7) & 0xFF) as u8;
            }
            // Unaligned u32 reads at every byte offset
            for off in 0..4u32 {
                let count = (len / 4).min(1024);
                for i in 0..count {
                    let ptr = unsafe {
                        buf.as_ptr().add(off as usize + i * 4) as *const u32
                    };
                    let val = unsafe { core::ptr::read_unaligned(black_box(ptr)) };
                    acc = acc.wrapping_mul(31).wrapping_add(val as u64);
                }
            }
            // Unaligned u32 writes then read-back
            for off in 1..4u32 {
                let ptr = unsafe {
                    buf.as_mut_ptr().add(off as usize) as *mut u32
                };
                let write_val = black_box(0xDEADBEEF_u32.wrapping_add(off));
                unsafe { core::ptr::write_unaligned(ptr, write_val); }
                let read_back = unsafe { core::ptr::read_unaligned(ptr) };
                acc = acc.wrapping_mul(31).wrapping_add(read_back as u64);
            }
        }

        // ===============================================================
        // Mode 5: Heap churn -- repeated Vec push/drop/reallocate cycles
        // ===============================================================
        5 => {
            let rounds = (size as usize).max(1);
            for r in 0..rounds {
                // Allocate a vec, push elements, accumulate, then drop
                let cap = 64 + (r % 128) * 16;
                let mut v: Vec<u32> = Vec::with_capacity(cap);
                for j in 0..cap {
                    v.push((r as u32).wrapping_mul(31).wrapping_add(j as u32));
                }
                for &val in v.iter() {
                    acc = acc.wrapping_mul(17).wrapping_add(val as u64);
                }
                // Force reallocation by extending beyond capacity
                let extra = cap / 2;
                for j in 0..extra {
                    v.push(black_box(j as u32));
                }
                acc = acc.wrapping_add(v.len() as u64);
                // v is dropped here, freeing memory
            }
        }

        _ => {
            acc = 0xBADC0DE;
        }
    }

    risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
}

/// Recursive function that allocates a local buffer per frame.
/// Forces stack growth across page boundaries.
fn deep_recurse(depth: usize, seed: u32) -> u32 {
    if depth == 0 {
        return seed;
    }
    let mut local = [0u32; 16];
    for i in 0..16 {
        local[i] = black_box(seed.wrapping_add(i as u32).wrapping_mul(depth as u32));
    }
    let sub = deep_recurse(depth - 1, local[depth % 16]);
    sub.wrapping_add(local[(depth + 7) % 16])
}
