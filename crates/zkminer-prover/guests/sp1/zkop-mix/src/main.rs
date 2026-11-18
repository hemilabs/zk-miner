include!("../../../common/zkop_mix.rs");

/// SP1 guest: the zkOP/s workload.
fn main() {
    let iterations = sp1_zkvm::io::read::<u32>();
    sp1_zkvm::io::commit_slice(&zkop_mix(iterations));
}
