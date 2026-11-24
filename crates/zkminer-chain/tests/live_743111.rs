//! Read-only checks of zkminer's chain code against the LIVE Hemi testnet deployment (handoff §13
//! tests 1-4). Ignored by default (they need the network):
//!
//! ```text
//! cargo test -p zkminer-chain --test live_743111 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `ZKMINER_LIVE_RPC` overrides the RPC (default the public testnet RPC). Nothing is signed or sent:
//! every client here is watch-only (its transport refuses sends), with a random address.

use alloy::primitives::{keccak256, Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use zkminer_chain::auction::ProofSystem;
use zkminer_chain::client::ChainClient;
use zkminer_chain::deployment::{pins, HEMI_TESTNET_743111 as K};
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::IHemiProveAux;

fn config() -> ZkMinerConfig {
    let mut c = ZkMinerConfig::default();
    c.chain.rpc_url = std::env::var("ZKMINER_LIVE_RPC")
        .unwrap_or_else(|_| "https://testnet.rpc.hemi.network/rpc".into());
    c.chain.chain_id = K.chain_id;
    c.chain.max_requests_per_sec = Some(4);
    c.contracts.hemi_prove = K.router.to_string();
    c.contracts.hemi_prove_staking = K.staking.to_string();
    c.contracts.hemi_prove_registry = K.registry.to_string();
    c.contracts.hemi_token = K.token.to_string();
    c.contracts.program_registry = K.program_registry.to_string();
    c
}

/// A fresh pseudo-random word (no `rand` feature here): keccak of the clock and `tag`.
fn fresh(tag: u8) -> B256 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    keccak256([&t.as_nanos().to_be_bytes()[..], &[tag]].concat())
}

async fn client(c: &ZkMinerConfig) -> ChainClient {
    let addr = Address::from_slice(&fresh(0xff)[12..]);
    ChainClient::new_watch_only(c, addr).await.expect("connect")
}

/// Tests 1-2: chain id, addresses, wiring and every code pin; the RISC Zero 3.1 and SP1 Groth16 proof
/// systems verify (adapter status, adapter and verifier code, `SELECTOR()` / `VERIFIER_HASH()`), and a
/// 3.0 seal prefix is refused.
#[tokio::test]
#[ignore]
async fn the_live_deployment_verifies() {
    let c = client(&config()).await;
    assert_eq!(c.chain_id, 743111);
    let report = c.verify_deployment().await.expect("verify_deployment");
    for line in &report {
        eprintln!("verify_deployment: {line}");
    }
    assert!(
        report.iter().any(|l| l.contains("2026-11-16")),
        "{report:?}"
    );
    let r0 = c
        .verify_proof_system(ProofSystem::Risc0Groth16, pins::RISC0_V3_1_SELECTOR)
        .await
        .expect("risczero.groth16.v1 with the 3.1 selector");
    eprintln!("risczero.groth16.v1 adapter {r0}");
    let sp1 = c
        .verify_proof_system(
            ProofSystem::Sp1Groth16,
            pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH[..4]
                .try_into()
                .unwrap(),
        )
        .await
        .expect("sp1.groth16.v1");
    eprintln!("sp1.groth16.v1 adapter {sp1}");
    let old = c
        .verify_proof_system(ProofSystem::Risc0Groth16, pins::RISC0_V3_0_SELECTOR)
        .await
        .expect_err("3.0 selector refused");
    eprintln!("3.0 selector: {old:#}");
    assert!(format!("{old:#}").contains("refused"), "{old:#}");
}

/// The abandoned 2026-10-29 stack is refused, before any other check.
#[tokio::test]
#[ignore]
async fn the_abandoned_stack_is_refused_live() {
    let mut cfg = config();
    cfg.contracts.hemi_prove = "0xE1a492Dc6D57fCC2B6deb5B64087E69666cA470e".into();
    let c = client(&cfg).await;
    let e = c
        .verify_deployment()
        .await
        .expect_err("abandoned stack refused");
    eprintln!("{e:#}");
    assert!(format!("{e:#}").contains("ABANDONED"), "{e:#}");
}

/// Test 3: the offline nonce derivation equals the live router's `getProofNonce`.
#[tokio::test]
#[ignore]
async fn the_proof_nonce_matches_the_live_router() {
    let c = client(&config()).await;
    let aux = IHemiProveAux::new(K.router, &*c.provider);
    for i in 0..4u8 {
        let job = fresh(2 * i);
        let prover = Address::from_slice(&fresh(2 * i + 1)[12..]);
        let live = aux
            .getProofNonce(job, prover)
            .call()
            .await
            .expect("getProofNonce");
        let (nonce, limbs) = zkminer_chain::binding::proof_nonce(743111, K.router, job, prover);
        assert_eq!(live.nonce, nonce, "case {i}");
        assert_eq!(live.limbs, limbs, "case {i}");
    }
}

/// Test 4: every job submitted since the deployment's first block decodes from its submit
/// transaction's calldata, and the descriptor hashes to the `JobSubmitted` log's `descriptorHash`.
#[tokio::test]
#[ignore]
async fn every_live_job_descriptor_decodes() {
    let c = client(&config()).await;
    let head = c.provider.get_block_number().await.unwrap();
    let topic = keccak256(
        "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
    );
    let logs = c
        .provider
        .get_logs(
            &Filter::new()
                .address(K.router)
                .event_signature(topic)
                .from_block(K.scan_from_block)
                .to_block(head),
        )
        .await
        .expect("getLogs");
    eprintln!(
        "{} JobSubmitted logs in {}..={head}",
        logs.len(),
        K.scan_from_block
    );
    assert!(!logs.is_empty());
    for log in &logs {
        let job_id = log.topics()[1];
        // descriptorHash is the 2nd data word (programId, descriptorHash, ...).
        let hash = B256::from_slice(&log.data().data[32..64]);
        let tx = log.transaction_hash.unwrap();
        let d =
            zkminer_chain::descriptor::fetch_job_descriptor_from_submit_tx(&c, job_id, tx, hash)
                .await
                .expect("decode")
                .expect("the tx holds this job's JobSubmitted");
        assert_eq!(zkminer_chain::descriptor::compute_descriptor_hash(&d), hash);
        eprintln!(
            "job {job_id}: proofSystemId {} programId {} journalFields {} decoded, hash ok",
            d.proofSystemId, d.programId, d.journalFields
        );
    }
}
