//! Compare the WP2 unfused commit path with WP3's fused path on one witness.

use risc0_core::field::baby_bear::BabyBearElem;
use risc0_zkp::{
    hal::{metal::MetalHalSha256, Buffer, Hal},
    INV_RATE,
};

fn check(po2: usize, count: usize) {
    let hal = MetalHalSha256::new();
    let rows = 1 << po2;
    let values: Vec<_> = (0..rows * count)
        .map(|i| BabyBearElem::new((i as u32).wrapping_mul(17).wrapping_add(3)))
        .collect();
    let witness = hal.copy_from_elem("witness", &values);

    let old_coeffs = hal.alloc_elem("wp2_coeffs", values.len());
    hal.batch_interpolate_ntt_zk_shift_from(&old_coeffs, &witness, count);
    let old_evaluated = hal.alloc_elem("wp2_evaluated", values.len() * INV_RATE);
    hal.batch_expand_into_evaluate_ntt(&old_evaluated, &old_coeffs, count, 2);
    hal.batch_bit_reverse(&old_coeffs, count);

    let new_coeffs = hal.alloc_elem("wp3_coeffs", values.len());
    let new_evaluated = hal.alloc_elem("wp3_evaluated", values.len() * INV_RATE);
    hal.commit_coeffs_lde(&new_coeffs, &new_evaluated, &witness, count);
    assert_eq!(witness.to_vec(), values, "witness changed");
    assert_eq!(new_coeffs.to_vec(), old_coeffs.to_vec(), "coefficients differ");
    assert_eq!(new_evaluated.to_vec(), old_evaluated.to_vec(), "LDE differs");

    let domain = rows * INV_RATE;
    let old_nodes = hal.alloc_digest("wp2_merkle", domain * 2);
    let new_nodes = hal.alloc_digest("wp3_merkle", domain * 2);
    hal.hash_tree(&old_nodes, &old_evaluated, domain, po2 + 2);
    hal.hash_tree(&new_nodes, &new_evaluated, domain, po2 + 2);
    assert_eq!(new_nodes.to_vec(), old_nodes.to_vec(), "Merkle nodes differ");
    println!("po2={po2} count={count}: witness, coefficients, LDE and Merkle nodes match");
}

fn main() {
    for (po2, count) in [(12, 3), (14, 7), (18, 3)] {
        check(po2, count);
    }
}
