//! Whether a guest that needs two or more keccak batches can be proven here, by the risc0-zkvm its
//! guest crates are. A guest's keccak batcher assumes one claim per run: a lone batch under the keccak
//! circuit's control root, and the root of two or more under risc0-circuit-recursion's
//! `ALLOWED_CONTROL_ROOT`. The pinned 3.1 prover unions the keccak proofs under its own (0xe6feef13…,
//! recursion 4.1), which a guest built with risc0-zkvm 3.1.0 names too. A guest built with 3.0 names
//! recursion 4.0's (0xa54dc85a…), which no union this prover makes is under: such a guest cannot be
//! proven here, whatever the miner does, and the miner refuses it at execute, naming the cause.
//!
//! The reference guests are on 3.1.0 (`hostdep` here); `keccak-3-0` is a control still on 3.0.5.
//! Executing shows the difference in the claim; proving settles it. The proofs are real (risc0's CPU
//! prover, succinct receipts, keccak po2 14: a batch of 81 permutations; about 13 minutes each in a
//! debug build), so they are ignored by default:
//!
//! ```text
//! cargo test -p hemiprove-proxy-slots-methods --test keccak_batches -- --ignored --test-threads=1
//! ```

use hemiprove_proxy_slots_methods::{HOSTDEP_ELF, HOSTDEP_ID, KECCAK_3_0_ELF};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, LocalProver, Prover, ProverOpts};

/// risc0-circuit-recursion 4.0's `ALLOWED_CONTROL_ROOT` (risc0-zkvm 3.0.x).
const RECURSION_4_0_CONTROL_ROOT: &str = "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";

/// The hostdep guest's mode 0xA2: `n` permutations through the batcher.
fn hostdep_input(n: u16) -> Vec<u8> {
    let mut w = vec![0xa2];
    w.extend_from_slice(&n.to_le_bytes());
    w
}

/// The 3.0 control's input: `n` permutations.
fn keccak_3_0_input(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

fn env(input: &[u8]) -> anyhow::Result<ExecutorEnv<'static>> {
    let mut b = ExecutorEnv::builder();
    b.write_slice(input);
    b.keccak_max_po2(14)?;
    b.segment_limit_po2(18);
    b.build()
}

fn prove(elf: &[u8], input: &[u8]) -> anyhow::Result<risc0_zkvm::Receipt> {
    Ok(LocalProver::new("local").prove_with_opts(env(input)?, elf, &ProverOpts::succinct())?.receipt)
}

/// The control roots of the assumptions an executed session's claim keeps. A session keeps its
/// keccak requests for the prover, and its claim leaves out the root the prover will resolve.
fn kept_assumption_roots(elf: &[u8], input: &[u8]) -> Vec<Digest> {
    let session = ExecutorImpl::from_elf(env(input).unwrap(), elf).unwrap().run().unwrap();
    let output = session.claim().unwrap().output.value().unwrap().unwrap();
    output.assumptions.value().unwrap().0.iter().map(|a| a.as_value().unwrap().control_root).collect()
}

#[test]
fn two_batches_of_a_3_1_guest_leave_no_assumption_and_a_3_0_guests_root_stays() {
    assert_eq!(kept_assumption_roots(HOSTDEP_ELF, &hostdep_input(120)), vec![], "the 3.1 guest's root is the prover's");
    assert_eq!(
        kept_assumption_roots(KECCAK_3_0_ELF, &keccak_3_0_input(120)),
        vec![Digest::try_from(hex::decode(RECURSION_4_0_CONTROL_ROOT).unwrap().as_slice()).unwrap()],
        "the 3.0 guest's root of two batches is under recursion 4.0's control root"
    );
    // One batch: both name the keccak circuit's control root, which both releases share.
    assert_eq!(kept_assumption_roots(KECCAK_3_0_ELF, &keccak_3_0_input(50)), vec![]);
}

#[test]
#[ignore = "proves on the CPU"]
fn one_keccak_batch_proves() {
    let receipt = prove(HOSTDEP_ELF, &hostdep_input(50)).expect("one batch is assumed under the keccak control root");
    receipt.verify(HOSTDEP_ID).unwrap();
}

#[test]
#[ignore = "proves on the CPU"]
fn two_keccak_batches_of_a_3_1_guest_prove() {
    let receipt = prove(HOSTDEP_ELF, &hostdep_input(120)).expect("the 3.1 guest's root of two batches is the prover's");
    receipt.verify(HOSTDEP_ID).unwrap();
}

#[test]
#[ignore = "proves on the CPU"]
fn two_keccak_batches_of_a_3_0_guest_do_not_prove_on_the_3_1_prover() {
    let e = format!(
        "{:#}",
        prove(KECCAK_3_0_ELF, &keccak_3_0_input(120)).expect_err("the guest's root of two batches is under 3.0's control root")
    );
    eprintln!("two batches: {e}");
    // risc0 3.1.0: "no receipt available for unresolved assumption: Assumption { claim: …,
    // control_root: Digest(a54dc85a…) }": the 3.0 recursion programs' root, which no union this
    // prover makes is under.
    assert!(e.contains("unresolved assumption") && e.contains(&RECURSION_4_0_CONTROL_ROOT[..16]), "{e}");
}
