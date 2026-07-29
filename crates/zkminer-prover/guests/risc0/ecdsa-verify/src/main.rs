#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use k256::ecdsa::{SigningKey, Signature, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};

/// RISC Zero guest: ECDSA secp256k1 verification benchmark.
/// Signs a message once with a deterministic key, then verifies N times.
fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();

    // Deterministic keypair (private key = 1, public key = generator G)
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);

    let message = b"secp256k1 ecdsa benchmark message";
    let signature: Signature = signing_key.sign(message);

    let mut count = 0u32;
    for _ in 0..n {
        if verifying_key.verify(message, &signature).is_ok() {
            count += 1;
        }
    }

    risc0_zkvm::guest::env::commit(&count);
}
