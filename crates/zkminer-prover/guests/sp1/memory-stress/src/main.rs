//! SP1 memory stress test.
//! Same logic as the RISC Zero version but uses sp1_zkvm::io for I/O.

use core::hint::black_box;

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1664525).wrapping_add(1013904223); *state
}

fn deep_recurse(depth: usize, seed: u32) -> u32 {
    if depth == 0 { return seed; }
    let mut local = [0u32; 16];
    for i in 0..16 { local[i] = black_box(seed.wrapping_add(i as u32).wrapping_mul(depth as u32)); }
    let sub = deep_recurse(depth - 1, local[depth % 16]);
    sub.wrapping_add(local[(depth + 7) % 16])
}

fn main() {
    // The SP1 worker feeds ALL input as ONE element (SP1Stdin.buffer is Vec<Vec<u8>>,
    // one element per read syscall). Read the whole blob once and parse fields — a
    // 2nd io::read::<u32>() would find no element and halt the guest before commit
    // (empty journal). See zkminer-prove-sp1/src/main.rs.
    let input = sp1_zkvm::io::read_vec();
    let mode = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let size = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    let mut acc: u64 = 0;
    match mode {
        0 => {
            let len = (size as usize) * 256;
            let mut buf = vec![0u8; len];
            for i in 0..len { buf[i] = ((i as u64).wrapping_mul(7) & 0xFF) as u8; }
            for i in 0..len { acc = acc.wrapping_mul(31).wrapping_add(buf[i] as u64); }
        }
        1 => {
            let len = (size as usize) * 256;
            let mut buf = vec![0u32; len / 4];
            let mut rng = 0x12345678u32;
            for _ in 0..len { let idx = (lcg(&mut rng) as usize) % (len/4); buf[idx] = buf[idx].wrapping_add(lcg(&mut rng)); }
            for _ in 0..len { let idx = (lcg(&mut rng) as usize) % (len/4); acc = acc.wrapping_add(buf[idx] as u64); }
        }
        2 => { acc = deep_recurse(size.min(2000) as usize, 0x42) as u64; }
        3 => {
            let len = (size as usize) * 128;
            let mut buf: Vec<u32> = (0..len as u32).collect();
            let mut rng = 0xDEADBEEFu32;
            for _ in 0..len { let a = (lcg(&mut rng) as usize) % len; let b = (lcg(&mut rng) as usize) % len; buf.swap(a, b); }
            for i in 0..len { acc = acc.wrapping_mul(17).wrapping_add(buf[i] as u64); }
        }
        4 => {
            // Unaligned access stress test
            let len = (size as usize).max(16) * 64;
            let mut buf = vec![0u8; len + 8];
            for i in 0..buf.len() {
                buf[i] = ((i as u64).wrapping_mul(13).wrapping_add(7) & 0xFF) as u8;
            }
            for off in 0..4u32 {
                let count = (len / 4).min(1024);
                for i in 0..count {
                    let ptr = unsafe { buf.as_ptr().add(off as usize + i * 4) as *const u32 };
                    let val = unsafe { core::ptr::read_unaligned(black_box(ptr)) };
                    acc = acc.wrapping_mul(31).wrapping_add(val as u64);
                }
            }
            for off in 1..4u32 {
                let ptr = unsafe { buf.as_mut_ptr().add(off as usize) as *mut u32 };
                let write_val = black_box(0xDEADBEEF_u32.wrapping_add(off));
                unsafe { core::ptr::write_unaligned(ptr, write_val); }
                let read_back = unsafe { core::ptr::read_unaligned(ptr) };
                acc = acc.wrapping_mul(31).wrapping_add(read_back as u64);
            }
        }
        5 => {
            // Heap churn
            let rounds = (size as usize).max(1);
            for r in 0..rounds {
                let cap = 64 + (r % 128) * 16;
                let mut v: Vec<u32> = Vec::with_capacity(cap);
                for j in 0..cap {
                    v.push((r as u32).wrapping_mul(31).wrapping_add(j as u32));
                }
                for &val in v.iter() {
                    acc = acc.wrapping_mul(17).wrapping_add(val as u64);
                }
                let extra = cap / 2;
                for j in 0..extra {
                    v.push(black_box(j as u32));
                }
                acc = acc.wrapping_add(v.len() as u64);
            }
        }
        _ => { acc = 0xBADC0DE; }
    }
    sp1_zkvm::io::commit_slice(&acc.to_le_bytes());
}
