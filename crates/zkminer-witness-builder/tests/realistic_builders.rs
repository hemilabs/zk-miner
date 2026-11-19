//! Realistic Rust builders against the compile-cost budget: `sdk/test-builders/receipts-proof` and
//! `storage-proof` (serde_json over large RPC shapes, alloy-rlp, alloy-primitives, alloy-trie,
//! alloy-sol-types, tiny-keccak, sha2, a hand-rolled Merkle-Patricia trie; ≥ 300 KB each), built with
//! the SDK's configuration. Each must pass the pre-pass with at least 10× headroom on every cap, and
//! run end to end against canned RPC answers.

mod common;

use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use alloy_primitives::keccak256;
use common::*;
use sha2::{Digest, Sha256};
use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::envelope::{encode_evm_rpc_config, Capability, Limits, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{exit, FetchStatus};
use zkminer_witness::WitnessJobV1;
use zkminer_witness_builder::cost::{
    COMPILE_BUDGET_NS, MAX_CONTROL_DEPTH, MAX_FUNCTION_BRANCH_LOCALS, MAX_TYPES, MAX_TYPE_ARITY,
};
use zkminer_witness_builder::{prepass, RunnerConfig};

fn builders() -> &'static [(&'static str, Vec<u8>); 2] {
    static WASM: OnceLock<[(&'static str, Vec<u8>); 2]> = OnceLock::new();
    WASM.get_or_init(|| {
        let out = build_sdk(
            &["receipts-proof", "storage-proof"],
            &Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-realistic"),
        );
        let read = |n: &str| std::fs::read(out.join(n)).unwrap();
        [("receipts-proof", read("receipts_proof.wasm")), ("storage-proof", read("storage_proof.wasm"))]
    })
}

fn wasm(name: &str) -> &'static [u8] {
    &builders().iter().find(|(n, _)| *n == name).unwrap().1
}

#[test]
fn realistic_builders_pass_with_tenfold_headroom() {
    for (name, wasm) in builders() {
        assert!(wasm.len() >= 300_000, "{name}: {} bytes", wasm.len());
        let c = prepass(wasm, 64 << 20).unwrap_or_else(|e| panic!("{name}: {e}")).cost;
        eprintln!("{name}: {} bytes, estimate {} µs, {c:?}", wasm.len(), c.estimate_ns() / 1_000);
        assert!(c.estimate_ns() * 10 <= COMPILE_BUDGET_NS, "{name}: estimate {} ns", c.estimate_ns());
        assert!(c.max_depth * 10 <= MAX_CONTROL_DEPTH, "{name}: depth {}", c.max_depth);
        assert!(c.max_type_arity as usize * 10 <= MAX_TYPE_ARITY, "{name}: arity {}", c.max_type_arity);
        assert!(c.max_function_branch_locals * 10 <= MAX_FUNCTION_BRANCH_LOCALS, "{name}: {c:?}");
        assert!(c.types * 10 <= MAX_TYPES, "{name}: {} types", c.types);
    }
}

fn evm_rpc() -> Capability {
    Capability { class: CLASS_EVM_RPC_V1, config: encode_evm_rpc_config(1, true, METHOD_SET_STATE_READ, 300).into() }
}

fn context(params: Vec<u8>) -> Vec<u8> {
    let job = WitnessJobV1 {
        builderType: 1,
        builderId: [0x11; 32].into(),
        builderURIs: vec![],
        builderParams: params.into(),
        sources: vec![evm_rpc()],
        limits: Limits {
            maxFetches: 100,
            maxFetchBytes: 1 << 24,
            maxRequestBytes: 65_536,
            maxResponseBytes: 1 << 22,
            maxBuilderFuel: 1 << 32,
            maxBuilderMemoryBytes: 1 << 28,
            maxBuilderSeconds: 60,
            maxWitnessBytes: 1 << 24,
            maxGuestCycles: 1 << 28,
        },
    };
    let d = DescriptorFields {
        program_id: [1; 32].into(),
        proof_system_id: [2; 32].into(),
        expected_journal_hash: [3; 32].into(),
        journal_fields: [4; 32].into(),
    };
    encode_context(&build_context(743_111, [5; 20].into(), &d, &job))
}

/// Room for this test build's unoptimized Cranelift to compile a 300 KB module.
fn roomy() -> RunnerConfig {
    let mut c = cfg();
    c.fuel = 1 << 34;
    c.memory_bytes = 64 << 20;
    c.max_witness_bytes = 1 << 22;
    c.max_request_bytes = 65_536;
    c.deadline = Instant::now() + Duration::from_secs(300);
    c
}

fn rpc(result: &str) -> Reply {
    Reply::Result(FetchStatus::Ok, format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#).into_bytes())
}

fn h(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn addr(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 20]))
}

fn zero_bloom() -> String {
    format!("0x{}", "00".repeat(256))
}

#[test]
fn receipts_proof_runs_end_to_end() {
    let block_hash = h(0xbb);
    let transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let block = format!(
        r#"{{"hash":"{block_hash}","parentHash":"{p}","sha3Uncles":"{p}","miner":"{m}","stateRoot":"{p}",
        "transactionsRoot":"{p}","receiptsRoot":"{p}","logsBloom":"{bloom}","difficulty":"0x0","number":"0x10",
        "gasLimit":"0x1c9c380","gasUsed":"0xd208","timestamp":"0x6553f100","extraData":"0x","mixHash":"{p}",
        "nonce":"0x0000000000000000","baseFeePerGas":"0x7","withdrawalsRoot":"{p}","blobGasUsed":"0x0",
        "excessBlobGas":"0x0","parentBeaconBlockRoot":"{p}","uncles":[],
        "transactions":[
          {{"hash":"{t0}","nonce":"0x1","blockHash":"{block_hash}","blockNumber":"0x10","transactionIndex":"0x0",
            "from":"{a}","to":"{b}","value":"0xde0b6b3a7640000","gas":"0x5208","maxFeePerGas":"0x3b9aca00",
            "maxPriorityFeePerGas":"0x1","input":"0x","r":"0x1","s":"0x2","yParity":"0x1","v":"0x1","chainId":"0x1",
            "accessList":[{{"address":"{b}","storageKeys":["{p}"]}}],"type":"0x2"}},
          {{"hash":"{t1}","nonce":"0x2","blockHash":"{block_hash}","blockNumber":"0x10","transactionIndex":"0x1",
            "from":"{a}","to":"{c}","value":"0x0","gas":"0x10000","gasPrice":"0x3b9aca00",
            "input":"0xa9059cbb","r":"0x3","s":"0x4","v":"0x25","chainId":"0x1","type":"0x0"}}
        ],
        "withdrawals":[{{"index":"0x0","validatorIndex":"0x5","address":"{a}","amount":"0x1"}}]}}"#,
        p = h(0x11),
        m = addr(0x22),
        bloom = zero_bloom(),
        t0 = h(0xa0),
        t1 = h(0xa1),
        a = addr(0xaa),
        b = addr(0xbb),
        c = addr(0xcc),
    );
    let (topic_a, topic_b) =
        (format!("0x{}{}", "00".repeat(12), "aa".repeat(20)), format!("0x{}{}", "00".repeat(12), "bb".repeat(20)));
    let value = format!("{}64", "00".repeat(31));
    let receipts = format!(
        r#"[{{"transactionHash":"{t0}","transactionIndex":"0x0","blockHash":"{block_hash}","blockNumber":"0x10",
            "from":"{a}","to":"{b}","cumulativeGasUsed":"0x5208","gasUsed":"0x5208","contractAddress":null,"logs":[],
            "logsBloom":"{bloom}","type":"0x2","status":"0x1","effectiveGasPrice":"0x8"}},
           {{"transactionHash":"{t1}","transactionIndex":"0x1","blockHash":"{block_hash}","blockNumber":"0x10",
            "from":"{a}","to":"{c}","cumulativeGasUsed":"0xd208","gasUsed":"0x8000","contractAddress":null,
            "logs":[{{"address":"{c}","topics":["{transfer}","{ta}","{tb}"],"data":"0x{value}","blockNumber":"0x10",
              "transactionHash":"{t1}","transactionIndex":"0x1","blockHash":"{block_hash}","logIndex":"0x0",
              "removed":false}}],
            "logsBloom":"{bloom}","type":"0x0","status":"0x1","effectiveGasPrice":"0x3b9aca00"}}]"#,
        t0 = h(0xa0),
        t1 = h(0xa1),
        a = addr(0xaa),
        b = addr(0xbb),
        c = addr(0xcc),
        bloom = zero_bloom(),
        ta = topic_a,
        tb = topic_b,
        value = value,
    );
    // flags 0, block 0x10, receipts 0 and 1.
    let mut params = vec![0u8];
    params.extend_from_slice(&0x10u64.to_be_bytes());
    params.extend_from_slice(&[0, 0, 0, 1]);
    let o = run_full(wasm("receipts-proof"), &context(params), roomy(), vec![rpc(&block), rpc(&receipts)]);
    let log = String::from_utf8_lossy(&o.log);
    assert_eq!(o.code(), exit::OK, "{log}");
    assert_eq!(o.requests.len(), 2);
    assert!(
        String::from_utf8_lossy(&o.requests[0].1).contains(r#""method":"eth_getBlockByNumber","params":["0x10",true]"#)
    );
    assert!(log.contains("block 16: 1 legacy, 0 access-list, 1 dynamic-fee"), "{log}");
    assert!(log.contains("1 logs, 1 contracts with token or DEX events, 0 unrecognized"), "{log}");
    // W: rlp(header), the block hash, the receipts root, the checks, then two proven receipts.
    let w = &o.w;
    let header_len = u32::from_be_bytes(w[..4].try_into().unwrap()) as usize;
    let at = 4 + header_len + 32 + 32 + 1;
    assert_eq!(u32::from_be_bytes(w[at..at + 4].try_into().unwrap()), 2);
    // The fixture's hashes, roots and blooms are made up, so none of the five checks holds (strict mode
    // would refuse the block); the receipt proofs were still built and verified against the receipts
    // root the builder computed.
    assert_eq!(w[4 + header_len + 64], 0);
    assert!(String::from_utf8_lossy(w).contains(r#""transfers":1"#));
}

/// RLP of a byte string.
fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    match b.len() {
        1 if b[0] < 0x80 => b.to_vec(),
        n if n < 56 => [&[0x80 + n as u8][..], b].concat(),
        n => {
            let len = (n as u64).to_be_bytes();
            let len = &len[len.iter().position(|&x| x != 0).unwrap()..];
            [&[0xb7 + len.len() as u8][..], len, b].concat()
        }
    }
}

/// RLP of a list of already-encoded items.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    assert!(payload.len() < 256);
    if payload.len() < 56 {
        [&[0xc0 + payload.len() as u8][..], &payload].concat()
    } else {
        [&[0xf8, payload.len() as u8][..], &payload].concat()
    }
}

/// The only node of a one-leaf trie holding `value` at `keccak(key)`, and the trie's root.
fn one_leaf_trie(key: &[u8], value: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let path = [&[0x20][..], keccak256(key).as_slice()].concat();
    let node = rlp_list(&[rlp_bytes(&path), rlp_bytes(value)]);
    let root = keccak256(&node).0;
    (node, root)
}

#[test]
fn storage_proof_verifies_real_proofs_end_to_end() {
    let address = [0xab; 20];
    let (slot, empty_slot) = ([0x01; 32], [0x02; 32]);
    // Storage: slot → 42 (stored as rlp(42) = 0x2a). The empty slot is proven absent by the same node.
    let (storage_node, storage_root) = one_leaf_trie(&slot, &[0x2a]);
    let code_hash = [0xcd; 32];
    let balance = 0x0de0b6b3a7640000u64.to_be_bytes();
    let account = rlp_list(&[
        rlp_bytes(&[1]),
        rlp_bytes(&balance[balance.iter().position(|&b| b != 0).unwrap()..]),
        rlp_bytes(&storage_root),
        rlp_bytes(&code_hash),
    ]);
    let (account_node, state_root) = one_leaf_trie(&address, &account);
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    let block = format!(
        r#"{{"hash":"{p}","parentHash":"{p}","sha3Uncles":"{p}","miner":"{m}","stateRoot":"{s}","transactionsRoot":"{p}",
        "receiptsRoot":"{p}","logsBloom":"{bloom}","difficulty":"0x0","number":"0x10","gasLimit":"0x1c9c380",
        "gasUsed":"0x0","timestamp":"0x6553f100","extraData":"0x","mixHash":"{p}","nonce":"0x0000000000000000",
        "baseFeePerGas":"0x7"}}"#,
        p = h(0x11),
        m = addr(0x22),
        s = hx(&state_root),
        bloom = zero_bloom(),
    );
    let proof = |balance: &str| {
        format!(
            r#"{{"address":"{a}","balance":"{balance}","codeHash":"{c}","nonce":"0x1","storageHash":"{sr}",
            "accountProof":["{an}"],"storageProof":[
              {{"key":"{k1}","value":"0x2a","proof":["{sn}"]}},{{"key":"{k2}","value":"0x0","proof":["{sn}"]}}]}}"#,
            a = hx(&address),
            c = hx(&code_hash),
            sr = hx(&storage_root),
            an = hx(&account_node),
            k1 = hx(&slot),
            k2 = hx(&empty_slot),
            sn = hx(&storage_node),
        )
    };
    let mut params = address.to_vec();
    params.extend_from_slice(&0x10u64.to_be_bytes());
    params.push(0);
    params.extend_from_slice(&slot);
    params.extend_from_slice(&empty_slot);

    let o = run_full(
        wasm("storage-proof"),
        &context(params.clone()),
        roomy(),
        vec![rpc(&block), rpc(&proof("0xde0b6b3a7640000"))],
    );
    let log = String::from_utf8_lossy(&o.log);
    assert_eq!(o.code(), exit::OK, "{log}");
    assert!(String::from_utf8_lossy(&o.requests[1].1).contains(r#""method":"eth_getProof""#));
    let w = &o.w;
    let header_len = u32::from_be_bytes(w[..4].try_into().unwrap()) as usize;
    assert_eq!(&w[4 + header_len..4 + header_len + 20], &address);
    let at = 4 + header_len + 20;
    assert_eq!(&w[at + 4..at + 4 + account.len()], &account[..], "rlp(account)");
    let (body, digest) = w.split_at(w.len() - 32);
    assert_eq!(digest, &Sha256::digest(body)[..]);

    // The same proof for another balance does not verify against the state root.
    let o = run_full(wasm("storage-proof"), &context(params), roomy(), vec![rpc(&block), rpc(&proof("0x1"))]);
    assert_eq!(o.code(), exit::NONZERO_RETURN);
    assert!(String::from_utf8_lossy(&o.log).contains("the account proof does not verify"));
}
