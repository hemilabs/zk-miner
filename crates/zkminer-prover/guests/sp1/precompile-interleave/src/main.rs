//! SP1 interleaved precompile stress test.
//! Same logic as the RISC Zero version but uses sp1_zkvm::io for I/O.

use sha2::{Digest as ShaDigest, Sha256};
use tiny_keccak::{Hasher, Keccak};

fn sha256_hash(data: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new(); h.update(data);
    let r = h.finalize(); let mut o = [0u8; 32]; o.copy_from_slice(&r); o
}
fn keccak256_hash(data: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak::v256(); h.update(data);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}
const MODULUS: [u32; 8] = [
    0xFFFFFF43, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];

/// Reduce x (< 2^256) mod m = 2^256 - 189 in place. Since x < 2^256 < 2m, a
/// single conditional subtract of m suffices.
fn reduce_mod_m(x: &mut [u32; 8]) {
    let mut ge = true;
    for i in (0..8).rev() {
        if x[i] > MODULUS[i] { break; }
        if x[i] < MODULUS[i] { ge = false; break; }
    }
    if ge {
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let d = x[i] as i64 - MODULUS[i] as i64 + borrow;
            if d < 0 { x[i] = (d + 0x100000000) as u32; borrow = -1; }
            else { x[i] = d as u32; borrow = 0; }
        }
    }
}

/// 256-bit modular multiply via SP1's uint256 mulmod precompile (sys_bigint,
/// op = 0): the SP1 analogue of RISC0's risc0-bigint2 modmul_256, so the
/// cross-backend journals match. Operands are reduced mod m first because the
/// precompile expects canonical inputs; (a mod m)*(b mod m) mod m == (a*b) mod m.
fn bigint_mix(data: &[u8; 32]) -> [u8; 32] {
    let mut a = [0u32; 8];
    for i in 0..8 { a[i] = u32::from_le_bytes([data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]]); }
    a[0] |= 1;

    let mut b = [0u32; 8];
    for i in 0..8 { b[i] = a[(i + 3) % 8].wrapping_add(0x9E3779B9); }
    b[0] |= 1;

    reduce_mod_m(&mut a);
    reduce_mod_m(&mut b);

    // result = (a * b) mod modulus via the uint256 mulmod precompile.
    // [u32; 8] is 4-byte aligned, satisfying sys_bigint's alignment contract.
    let mut result = [0u32; 8];
    unsafe {
        sp1_zkvm::syscalls::sys_bigint(
            result.as_mut_ptr() as *mut [u64; 4],
            0,
            a.as_ptr() as *const [u64; 4],
            b.as_ptr() as *const [u64; 4],
            MODULUS.as_ptr() as *const [u64; 4],
        );
    }

    let mut o = [0u8; 32];
    for i in 0..8 { o[i*4..i*4+4].copy_from_slice(&result[i].to_le_bytes()); }
    o
}

fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    let mut acc = [0u8; 32];
    acc[0] = 0x42; acc[1] = 0xDE; acc[2] = 0xAD; acc[31] = 0xFF;
    let perms: &[[usize; 3]] = &[[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]];
    for i in 0..n {
        for &op in &perms[(i as usize) % perms.len()] {
            acc = match op { 0 => sha256_hash(&acc), 1 => keccak256_hash(&acc), _ => bigint_mix(&acc) };
        }
    }
    sp1_zkvm::io::commit_slice(&acc);
}
