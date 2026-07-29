//! SP1 segment-boundary stress test.
//! Same logic as the RISC Zero version but uses sp1_zkvm::io for I/O.

use core::hint::black_box;

fn main() {
    // SP1 worker feeds all input as ONE element; read once and parse (a 2nd
    // io::read::<u32>() would halt the guest before commit). See zkminer-prove-sp1.
    let input = sp1_zkvm::io::read_vec();
    let mode = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let param = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);

    match mode {
        0 => {
            let commits = param.max(1);
            let mut acc: u64 = 0xDEADBEEF_CAFEBABE;
            for c in 0..commits {
                for i in 0..2048u32 {
                    let v = black_box(i.wrapping_mul(c).wrapping_add(0x9E3779B9));
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(v as u64);
                    for j in 0..8u32 {
                        acc = acc.wrapping_add(black_box(v.wrapping_shl(j & 31)) as u64);
                    }
                }
                sp1_zkvm::io::commit_slice(&acc.to_le_bytes());
            }
        }
        1 => {
            let iters = param as u64 * 1024;
            let mut acc: u64 = 0x12345678_9ABCDEF0;
            for _ in 0..iters {
                acc = acc.wrapping_add(black_box(1));
            }
            sp1_zkvm::io::commit_slice(&acc.to_le_bytes());
        }
        2 => {
            let count = param.max(1).min(10000);
            let mut acc: u64 = 0;
            for i in 0..count {
                acc = acc.wrapping_mul(31).wrapping_add(black_box(i) as u64);
                sp1_zkvm::io::commit_slice(&acc.to_le_bytes());
            }
        }
        _ => {
            sp1_zkvm::io::commit_slice(&0xBADC0DEu64.to_le_bytes());
        }
    }
}
