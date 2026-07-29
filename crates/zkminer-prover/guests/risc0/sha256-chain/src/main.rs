#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use sha2::{Sha256, Digest};

/// RISC Zero guest: chain 10,000 SHA-256 hashes and commit the final digest.
fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();
    let mut hash = [0u8; 32];
    for i in 0..n {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hasher.update(i.to_le_bytes());
        hash = hasher.finalize().into();
    }
    risc0_zkvm::guest::env::commit_slice(&hash);
}
