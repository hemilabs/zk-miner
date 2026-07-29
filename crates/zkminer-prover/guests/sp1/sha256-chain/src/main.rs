use sha2::{Sha256, Digest};

/// SP1 guest: chain 10,000 SHA-256 hashes and commit the final digest.
fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    let mut hash = [0u8; 32];
    for i in 0..n {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hasher.update(i.to_le_bytes());
        hash = hasher.finalize().into();
    }
    sp1_zkvm::io::commit_slice(&hash);
}
