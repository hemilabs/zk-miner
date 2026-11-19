#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

include!("../../../common/zkop_mix.rs");

/// RISC Zero guest: the zkOP/s workload.
fn main() {
    let iterations: u32 = risc0_zkvm::guest::env::read();
    risc0_zkvm::guest::env::commit_slice(&zkop_mix(iterations));
}
