#![no_main]
#![no_std]

openvm::entry!(main);

use sha2::{Sha256, Digest};

/// OpenVM guest: chain N SHA-256 hashes and reveal the final digest.
fn main() {
    let n: u32 = openvm::io::read();
    let mut hash = [0u8; 32];
    for i in 0..n {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hasher.update(i.to_le_bytes());
        hash = hasher.finalize().into();
    }
    openvm::io::reveal_bytes32(hash);
}
