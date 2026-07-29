#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

risc0_zkvm::entry!(main);

use sha2::{Sha256, Digest};

/// RISC Zero guest: build a binary Merkle tree and commit the root hash.
fn main() {
    let num_leaves: u32 = risc0_zkvm::guest::env::read();

    // Generate deterministic leaves: leaf[i] = SHA256(i.to_le_bytes())
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_leaves as usize);
    for i in 0..num_leaves {
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        leaves.push(hasher.finalize().into());
    }

    let root = build_merkle_tree(&leaves);
    risc0_zkvm::guest::env::commit_slice(&root);
}

fn build_merkle_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to next power of two
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    while layer.len() < n {
        layer.push(*leaves.last().unwrap());
    }

    // Build tree bottom-up
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next.push(hasher.finalize().into());
        }
        layer = next;
    }

    layer[0]
}
