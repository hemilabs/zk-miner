//! Whether a guest that needs two or more keccak batches can be proven here. The miner's execute
//! refuses one as "the guest assumes a claim no proof here resolves": the batcher of a guest built
//! with risc0-zkvm 3.0 (every guest in this repository: crates.io's 3.0.5) names its root of two or
//! more batches under risc0-circuit-recursion 4.0's `ALLOWED_CONTROL_ROOT` (0xa54dc85a…), while the
//! pinned 3.1 prover unions the keccak proofs under its own (0xe6feef13…). One batch is assumed
//! under the keccak circuit's control root, which both share, so it resolves.
//!
//! So the refusal is right: such a guest cannot be proven by this prover, whatever the miner does.
//! A guest built with the 3.1 guest crates names the 3.1 root. These prove for real (risc0's CPU
//! prover, succinct receipts, keccak po2 14: a batch of 81 permutations; about 13 minutes in a
//! debug build), so they are ignored by default:
//!
//! ```text
//! cargo test -p hemiprove-proxy-slots-methods --test keccak_batches -- --ignored --test-threads=1
//! ```

use hemiprove_proxy_slots_methods::{HOSTDEP_ELF, HOSTDEP_ID};
use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts};

/// The hostdep guest's mode 0xA2: `n` permutations through the batcher.
fn prove(n: u16) -> anyhow::Result<risc0_zkvm::Receipt> {
    let mut w = vec![0xa2];
    w.extend_from_slice(&n.to_le_bytes());
    let mut b = ExecutorEnv::builder();
    b.write_slice(&w);
    b.keccak_max_po2(14)?;
    b.segment_limit_po2(18);
    let env = b.build()?;
    Ok(LocalProver::new("local").prove_with_opts(env, HOSTDEP_ELF, &ProverOpts::succinct())?.receipt)
}

#[test]
#[ignore = "proves on the CPU"]
fn one_keccak_batch_proves() {
    let receipt = prove(50).expect("one batch is assumed under the keccak control root, which resolves");
    receipt.verify(HOSTDEP_ID).unwrap();
}

#[test]
#[ignore = "proves on the CPU"]
fn two_keccak_batches_of_a_3_0_guest_do_not_prove_on_the_3_1_prover() {
    let e = format!("{:#}", prove(120).expect_err("the guest's root of two batches is under 3.0's control root"));
    eprintln!("two batches: {e}");
    // risc0 3.1.0: "no receipt available for unresolved assumption: Assumption { claim: …,
    // control_root: Digest(a54dc85a…) }": the 3.0 recursion programs' root, which no union this
    // prover makes is under.
    assert!(e.contains("unresolved assumption") && e.contains("a54dc85ac99f851c"), "{e}");
}
