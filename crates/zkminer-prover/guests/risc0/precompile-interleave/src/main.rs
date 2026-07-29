//! Interleaved precompile stress test.
//!
//! Calls SHA-256 (via risc0-forked sha2 crate → SHA-256 precompile),
//! Keccak-256 (via tiny-keccak, pure software — no risc0 keccak precompile),
//! and bigint modular multiply (via risc0-bigint2 → bigint precompile)
//! in rotating permutation order. Each round chains its output into the
//! next call. This catches bugs that appear when different precompile
//! circuits are activated in different orders across segment boundaries.

// STD guest (not no_std): risc0-bigint2 links the std panic handler, so this
// guest runs on risc0's std runtime. Keep `no_main` — the entry! macro still
// provides the guest entry point.
#![no_main]

risc0_zkvm::entry!(main);

use sha2::{Digest as ShaDigest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use risc0_bigint2::field::modmul_256;

/// Hash 32 bytes with SHA-256 (triggers SHA-256 precompile on risc0).
fn sha256_hash(data: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash 32 bytes with Keccak-256 (pure software — no precompile).
fn keccak256_hash(data: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// 256-bit modular multiply via bigint2 precompile.
/// Interprets the 32-byte input as a 256-bit number (little-endian u32 limbs),
/// squares it modulo a fixed prime, then XORs with a rotation to prevent
/// degenerate convergence to zero.
fn bigint_mix(data: &[u8; 32]) -> [u8; 32] {
    // Decompose input into 8 u32 limbs (little-endian)
    let mut a = [0u32; 8];
    for i in 0..8 {
        a[i] = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
    }

    // Use a large prime as modulus (2^256 - 189, a known prime)
    // This ensures the result is always non-zero and well-distributed.
    let modulus: [u32; 8] = [
        0xFFFFFF43, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    ];

    // Ensure input is non-zero for the precompile (zero input → zero output)
    // Set the low bit to guarantee a non-trivial value.
    a[0] |= 1;

    // Create a second operand by rotating limbs
    let mut b = [0u32; 8];
    for i in 0..8 {
        b[i] = a[(i + 3) % 8].wrapping_add(0x9E3779B9);
    }
    b[0] |= 1;

    // Modular multiply: result = (a * b) mod modulus
    // This triggers the bigint2 precompile syscall on the zkVM.
    let mut result = [0u32; 8];
    modmul_256(&a, &b, &modulus, &mut result);

    // Convert back to bytes
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&result[i].to_le_bytes());
    }
    out
}

fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();

    // Start with a fixed seed
    let mut acc = [0u8; 32];
    acc[0] = 0x42;
    acc[1] = 0xDE;
    acc[2] = 0xAD;
    acc[31] = 0xFF;

    // 3 precompile operations, rotated through 6 permutations
    // Order: 0=SHA, 1=Keccak, 2=BigInt
    let permutations: &[[usize; 3]] = &[
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    for i in 0..n {
        let perm = &permutations[(i as usize) % permutations.len()];
        for &op in perm {
            acc = match op {
                0 => sha256_hash(&acc),
                1 => keccak256_hash(&acc),
                _ => bigint_mix(&acc),
            };
        }
    }

    risc0_zkvm::guest::env::commit_slice(&acc);
}
