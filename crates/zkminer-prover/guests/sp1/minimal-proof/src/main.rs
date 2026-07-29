//! SP1 minimal proof guest.
//! Same logic as the RISC Zero version but uses sp1_zkvm::io for I/O.

fn main() {
    sp1_zkvm::io::commit_slice(&[0x42u8]);
}
