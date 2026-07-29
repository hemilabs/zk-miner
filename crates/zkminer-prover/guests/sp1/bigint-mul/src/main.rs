/// 4096-bit schoolbook multiplication: [u32; 128] × [u32; 128] → [u32; 256].
fn bigint_mul(a: &[u32; 128], b: &[u32; 128]) -> [u32; 256] {
    let mut result = [0u32; 256];
    for i in 0..128 {
        let mut carry: u64 = 0;
        for j in 0..128 {
            let prod = (a[i] as u64) * (b[j] as u64) + (result[i + j] as u64) + carry;
            result[i + j] = prod as u32;
            carry = prod >> 32;
        }
        result[i + 128] = carry as u32;
    }
    result
}

/// Seed a deterministic 4096-bit integer from an index.
fn seed_bigint(seed: u32) -> [u32; 128] {
    let mut val = [0u32; 128];
    let mut state = seed.wrapping_add(1);
    for limb in val.iter_mut() {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        *limb = state;
    }
    val
}

/// SP1 guest: repeated 4096-bit multiplications.
fn main() {
    let n = sp1_zkvm::io::read::<u32>();

    let mut a = seed_bigint(0);
    let mut b = seed_bigint(1);

    for _ in 0..n {
        let product = bigint_mul(&a, &b);
        a.copy_from_slice(&product[..128]);
        b.copy_from_slice(&product[128..]);
    }

    // Output: low 32 bytes (8 limbs) of final `a`
    let mut output = [0u8; 32];
    for (i, limb) in a[..8].iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
    }
    sp1_zkvm::io::commit_slice(&output);
}
