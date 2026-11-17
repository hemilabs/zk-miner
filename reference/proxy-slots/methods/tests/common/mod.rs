//! Shared by the executor and end-to-end tests: the risc0 executor, and the statement's witness
//! built from hemiprove-eth-prelude's real-chain fixtures.
#![allow(dead_code)]

use std::borrow::Cow;

use hemiprove_eth_prelude::header::Header;
use hemiprove_eth_prelude::scheme1::{AccountProof, ProofKind, TrieProof, Witness};
use hemiprove_proxy_slots::{Rule, RuleKind, Statement, EIP1967_IMPLEMENTATION_SLOT};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, ExitCode};
use serde_json::Value;

pub use hemiprove_proxy_slots_methods::PROXY_SLOTS_ELF;

/// A journal prefix: `abi.encode(jobId, prover)`.
pub fn prefix(job: u8, prover: u8) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[..32].fill(job);
    p[44..].fill(prover);
    p
}

pub fn input(prefix: &[u8; 64], w: &[u8]) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.extend_from_slice(w);
    v
}

/// A run of the guest on the risc0 executor, as the miner's execute worker runs it: the input on
/// stdin, a `sys_rand` seed, a segment po2.
pub struct Executed {
    pub journal: Vec<u8>,
    pub cycles: u64,
    pub segments: usize,
}

/// `Err` when the guest does not halt with code 0 (a panic, a fault).
pub fn execute(input: &[u8], seed: [u8; 32], po2: u32) -> Result<Executed, String> {
    let mut b = ExecutorEnv::builder();
    b.write_slice(input);
    b.random_seed(seed);
    b.segment_limit_po2(po2);
    let env = b.build().map_err(|e| e.to_string())?;
    let session = ExecutorImpl::from_elf(env, PROXY_SLOTS_ELF).map_err(|e| e.to_string())?.run().map_err(|e| e.to_string())?;
    if session.exit_code != ExitCode::Halted(0) {
        return Err(format!("exit {:?}", session.exit_code));
    }
    Ok(Executed {
        journal: session.journal.map(|j| j.bytes).unwrap_or_default(),
        cycles: session.total_cycles,
        segments: session.segments.len(),
    })
}

pub fn fixture(name: &str) -> Value {
    let path = format!("{}/../../eth-prelude/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}

pub fn h32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

pub fn qty(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

pub fn qty256(v: &Value) -> [u8; 32] {
    let s = v.as_str().unwrap().strip_prefix("0x").unwrap();
    hex::decode(format!("{s:0>64}")).unwrap().try_into().unwrap()
}

pub fn header_from_json(b: &Value) -> Header {
    let opt = |k: &str| b.get(k).filter(|v| !v.is_null());
    Header {
        parent_hash: h32(&b["parentHash"]),
        ommers_hash: h32(&b["sha3Uncles"]),
        beneficiary: hex(&b["miner"]).try_into().unwrap(),
        state_root: h32(&b["stateRoot"]),
        transactions_root: h32(&b["transactionsRoot"]),
        receipts_root: h32(&b["receiptsRoot"]),
        logs_bloom: hex(&b["logsBloom"]).try_into().unwrap(),
        difficulty: qty256(&b["difficulty"]),
        number: qty(&b["number"]),
        gas_limit: qty(&b["gasLimit"]),
        gas_used: qty(&b["gasUsed"]),
        timestamp: qty(&b["timestamp"]),
        extra_data: hex(&b["extraData"]),
        mix_hash: h32(&b["mixHash"]),
        nonce: hex(&b["nonce"]).try_into().unwrap(),
        base_fee_per_gas: opt("baseFeePerGas").map(qty256),
        withdrawals_root: opt("withdrawalsRoot").map(h32),
        blob_gas_used: opt("blobGasUsed").map(qty),
        excess_blob_gas: opt("excessBlobGas").map(qty),
        parent_beacon_block_root: opt("parentBeaconBlockRoot").map(h32),
        requests_hash: opt("requestsHash").map(h32),
    }
}

fn nodes(v: &Value) -> Vec<Cow<'static, [u8]>> {
    v.as_array().unwrap().iter().map(|n| Cow::Owned(hex(n))).collect()
}

/// The statement's witness for a fixture's first proof (a proxy) and second (its implementation),
/// rule "consecutive from slot 0", `k` slots.
pub fn real_witness(f: &Value, k: u64) -> (Statement, Witness<'static>) {
    let proxy = &f["proofs"][0];
    let implementation = &f["proofs"][1];
    let s = Statement {
        block_hash: h32(&f["hash"]),
        proxy: hex(&proxy["address"]).try_into().unwrap(),
        rule: Rule::new(RuleKind::Consecutive, &[0; 32]).unwrap(),
        k,
    };
    let storage = proxy["proof"]["storageProof"].as_array().unwrap();
    let mut wanted = vec![EIP1967_IMPLEMENTATION_SLOT];
    wanted.extend(s.rule.slots(&[0; 20], k));
    let storage = wanted
        .iter()
        .map(|slot| {
            let p = storage.iter().find(|p| qty256(&p["key"]) == *slot).expect("the fixture has the slot");
            let kind = if qty256(&p["value"]) == [0; 32] { ProofKind::Exclusion } else { ProofKind::Inclusion };
            TrieProof { kind, nodes: nodes(&p["proof"]) }
        })
        .collect();
    let w = Witness {
        header_words: s.header_words().to_vec(),
        headers: vec![Cow::Owned(header_from_json(&f["block"]).encode().unwrap())],
        accounts: vec![
            AccountProof { proof: TrieProof { kind: ProofKind::Inclusion, nodes: nodes(&proxy["proof"]["accountProof"]) }, storage },
            AccountProof {
                proof: TrieProof { kind: ProofKind::Inclusion, nodes: nodes(&implementation["proof"]["accountProof"]) },
                storage: vec![],
            },
        ],
        receipts: vec![],
        transactions: vec![],
    };
    (s, w)
}
