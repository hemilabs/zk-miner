//! The statement on synthetic states (built with alloy-trie) and on real Ethereum, Base and Hemi
//! blocks, and the witness mutation check: every structural mutation of an honest witness fails,
//! or gives the honest journal byte for byte, or changes a pinned header word (which the binding
//! refuses). Never a different answer under the same header.

use std::borrow::Cow;
use std::collections::BTreeMap;

use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use hemiprove_eth_prelude::header::Header;
use hemiprove_eth_prelude::keccak::{keccak256, EMPTY_ROOT, KECCAK_EMPTY};
use hemiprove_eth_prelude::scheme1::{
    judge, AccountProof, ByteSelection, Mutation, ProofKind, TrieProof, Verdict, Witness,
};
use hemiprove_eth_prelude::state::{encode_storage_value, Account};
use serde_json::Value;

use super::*;

const PREFIX: [u8; 64] = {
    let mut p = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        p[i] = 0xab;
        i += 1;
    }
    let mut i = 44;
    while i < 64 {
        p[i] = 0xcd;
        i += 1;
    }
    p
};

fn input(w: &[u8]) -> Vec<u8> {
    let mut v = PREFIX.to_vec();
    v.extend_from_slice(w);
    v
}

fn word(n: u64) -> [u8; 32] {
    n.to_word()
}

// ---------------------------------------------------------------------------------------------
// Unit checks.

#[test]
fn rules_name_the_documented_slots() {
    let r = Rule::new(RuleKind::Consecutive, &word(7)).unwrap();
    assert_eq!(r.word()[0], 1);
    assert_eq!(r.slots(&[9; 20], 3), vec![word(7), word(8), word(9)]);
    let p = word(3);
    let r = Rule::new(RuleKind::MappingByImplementation, &p).unwrap();
    let i = [0x42u8; 20];
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(&i);
    preimage[32..].copy_from_slice(&p);
    let base = alloy_primitives::keccak256(preimage);
    let got = r.slots(&i, 2);
    assert_eq!(got[0], base.0);
    assert_eq!(alloy_primitives::U256::from_be_bytes(got[1]), alloy_primitives::U256::from_be_bytes(base.0) + alloy_primitives::U256::from(1));
    // Wrapping at 2^256, as Solidity's slot arithmetic does.
    assert_eq!(add_u64(&[0xff; 32], 2), word(1));
    assert_eq!(Rule::decode([3; 32]), Err(Error::BadRule));
    assert_eq!(Rule::decode([0; 32]), Err(Error::BadRule));
    assert_eq!(Rule::new(RuleKind::Consecutive, &[1; 32]), Err(Error::BadRule));
}

#[test]
fn builder_params_and_binding_words() {
    let s = Statement { block_hash: [1; 32], proxy: [2; 20], rule: Rule::new(RuleKind::Consecutive, &word(0)).unwrap(), k: 4 };
    let p = s.builder_params(8453);
    assert_eq!(Statement::from_builder_params(&p), Ok((8453, s)));
    for bad in [&p[..159], &[p.as_slice(), &[0]].concat()[..]] {
        assert_eq!(Statement::from_builder_params(bad), Err(Error::BadParams));
    }
    let mut dirty = p;
    dirty[64] = 1; // the address word's padding
    assert_eq!(Statement::from_builder_params(&dirty), Err(Error::BadParams));
    let mut big_k = p;
    big_k[159] = 0xff;
    big_k[158] = 0x01; // k = 511
    assert_eq!(Statement::from_builder_params(&big_k), Err(Error::BadParams));
    // journalFields: the prefix marker, then (offset 0, length 160) in slot 1.
    let f = journal_fields();
    assert_eq!(&f[..8], &[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0xa0]);
    assert!(f[8..].iter().all(|&b| b == 0));
    assert_eq!(s.expected_journal_hash(), keccak256(&s.header()));
    assert_eq!(&s.header()[64..76], &[0; 12]);
}

// ---------------------------------------------------------------------------------------------
// Synthetic states.

/// A trie of `(key, value)` with hashed keys, and the proofs for `targets` (already hashed).
fn trie(entries: &BTreeMap<[u8; 32], Vec<u8>>, targets: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<Vec<u8>>>) {
    let retain: Vec<Nibbles> = targets.iter().map(|t| Nibbles::unpack(t)).collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(retain.clone()));
    for (k, v) in entries {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    let root = hb.root().0;
    let nodes = hb.take_proof_nodes();
    let proofs = retain
        .iter()
        .map(|t| {
            let all: Vec<Vec<u8>> = nodes.matching_nodes_sorted(t).into_iter().map(|(_, n)| n.to_vec()).collect();
            if root == EMPTY_ROOT {
                return Vec::new();
            }
            all.into_iter().enumerate().filter(|(i, n)| *i == 0 || n.len() >= 32).map(|(_, n)| n).collect()
        })
        .collect();
    (root, proofs)
}

/// An account of a synthetic world: nonce, code hash, storage.
type WorldAccount = (u64, [u8; 32], BTreeMap<[u8; 32], [u8; 32]>);

struct World {
    accounts: BTreeMap<[u8; 20], WorldAccount>,
}

impl World {
    fn storage_root(storage: &BTreeMap<[u8; 32], [u8; 32]>, slots: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<Vec<u8>>>) {
        let entries =
            storage.iter().filter(|(_, v)| **v != [0; 32]).map(|(k, v)| (keccak256(k), encode_storage_value(v))).collect();
        let targets: Vec<[u8; 32]> = slots.iter().map(|s| keccak256(s)).collect();
        trie(&entries, &targets)
    }

    /// The header and `W` for `statement`, with proofs for the slots `slots_of(I)` names.
    fn witness(&self, statement: &Statement) -> (Header, Witness<'static>) {
        let proxy = statement.proxy;
        let impl_value = self.accounts.get(&proxy).and_then(|a| a.2.get(&EIP1967_IMPLEMENTATION_SLOT)).copied().unwrap_or([0; 32]);
        let implementation: [u8; 20] = impl_value[12..].try_into().unwrap();
        let mut slots = vec![EIP1967_IMPLEMENTATION_SLOT];
        slots.extend(statement.rule.slots(&implementation, statement.k));
        // Accounts with their storage roots.
        let mut leaves = BTreeMap::new();
        let mut storage_proofs = Vec::new();
        for (addr, (nonce, code_hash, storage)) in &self.accounts {
            let (root, proofs) = Self::storage_root(storage, &slots);
            if *addr == proxy {
                storage_proofs = proofs;
            }
            let a = Account { nonce: *nonce, balance: word(1000), storage_root: root, code_hash: *code_hash };
            leaves.insert(keccak256(addr), a.encode());
        }
        if !self.accounts.contains_key(&proxy) {
            storage_proofs = vec![Vec::new(); slots.len()];
        }
        let (state_root, account_proofs) = trie(&leaves, &[keccak256(&proxy), keccak256(&implementation)]);
        let header = Header {
            parent_hash: [1; 32],
            ommers_hash: hemiprove_eth_prelude::keccak::EMPTY_OMMERS_HASH,
            beneficiary: [0; 20],
            state_root,
            transactions_root: EMPTY_ROOT,
            receipts_root: EMPTY_ROOT,
            logs_bloom: [0; 256],
            difficulty: [0; 32],
            number: 100,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            mix_hash: [0; 32],
            nonce: [0; 8],
            base_fee_per_gas: Some(word(7)),
            withdrawals_root: Some(EMPTY_ROOT),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some([2; 32]),
            requests_hash: Some([3; 32]),
        };
        let kind = |present: bool| if present { ProofKind::Inclusion } else { ProofKind::Exclusion };
        let proxy_storage = self.accounts.get(&proxy).map(|a| &a.2);
        let storage = slots
            .iter()
            .zip(storage_proofs)
            .map(|(s, nodes)| TrieProof {
                kind: kind(proxy_storage.and_then(|st| st.get(s)).is_some_and(|v| *v != [0; 32])),
                nodes: nodes.into_iter().map(Cow::Owned).collect(),
            })
            .collect();
        let s = Statement { block_hash: keccak256(&header.encode().unwrap()), ..*statement };
        let w = Witness {
            header_words: s.header_words().to_vec(),
            headers: vec![Cow::Owned(header.encode().unwrap())],
            accounts: vec![
                AccountProof {
                    proof: TrieProof {
                        kind: kind(self.accounts.contains_key(&proxy)),
                        nodes: account_proofs[0].clone().into_iter().map(Cow::Owned).collect(),
                    },
                    storage,
                },
                AccountProof {
                    proof: TrieProof {
                        kind: kind(self.accounts.contains_key(&implementation)),
                        nodes: account_proofs[1].clone().into_iter().map(Cow::Owned).collect(),
                    },
                    storage: vec![],
                },
            ],
            receipts: vec![],
            transactions: vec![],
        };
        (header, w)
    }
}

const PROXY: [u8; 20] = [0xc0; 20];
const IMPL: [u8; 20] = [0x11; 20];

fn world(with_impl_account: bool) -> World {
    let mut storage = BTreeMap::new();
    storage.insert(EIP1967_IMPLEMENTATION_SLOT, IMPL.to_word());
    for i in 0..3u64 {
        storage.insert(word(10 + i), word(100 + i));
    }
    // A mapping(address => T) at slot 5, with T's first two words set for IMPL.
    let base = keccak256_concat(&[&IMPL.to_word(), &word(5)]);
    storage.insert(base, word(0xaaaa));
    storage.insert(add_u64(&base, 1), word(0xbbbb));
    let mut accounts = BTreeMap::new();
    accounts.insert(PROXY, (1, keccak256(b"proxy code"), storage));
    if with_impl_account {
        accounts.insert(IMPL, (1, keccak256(b"impl code"), BTreeMap::new()));
    }
    for i in 0..40u8 {
        accounts.insert([0x40 + i; 20], (u64::from(i), KECCAK_EMPTY, BTreeMap::new()));
    }
    World { accounts }
}

fn statement(rule: Rule, k: u64) -> Statement {
    Statement { block_hash: [0; 32], proxy: PROXY, rule, k }
}

#[test]
fn consecutive_slots_including_unset_ones() {
    let w = world(true);
    let s = statement(Rule::new(RuleKind::Consecutive, &word(9)).unwrap(), 5); // 9 unset, 10–12 set, 13 unset
    let (_, wit) = w.witness(&s);
    let journal = run(&input(&wit.encode().unwrap())).unwrap();
    let j = decode_journal(&journal).unwrap();
    assert_eq!(j.prefix.0, PREFIX);
    assert_eq!(j.statement.proxy, PROXY);
    assert_eq!(j.outputs.implementation, IMPL);
    assert_eq!(j.outputs.code_hash, keccak256(b"impl code"));
    let values: Vec<[u8; 32]> = j.outputs.slots.iter().map(|(_, v)| *v).collect();
    assert_eq!(values, vec![[0; 32], word(100), word(101), word(102), [0; 32]]);
    assert_eq!(journal.len(), journal_len(5));
    // The binding: the requester's header is the journal's pinned range.
    assert_eq!(&journal[PREFIX_BYTES..PREFIX_BYTES + HEADER_BYTES], &j.statement.header());
}

#[test]
fn mapping_by_implementation_follows_the_proven_implementation() {
    let w = world(true);
    let s = statement(Rule::new(RuleKind::MappingByImplementation, &word(5)).unwrap(), 3);
    let (_, wit) = w.witness(&s);
    let j = decode_journal(&run(&input(&wit.encode().unwrap())).unwrap()).unwrap();
    let values: Vec<[u8; 32]> = j.outputs.slots.iter().map(|(_, v)| *v).collect();
    assert_eq!(values, vec![word(0xaaaa), word(0xbbbb), [0; 32]]);
}

#[test]
fn an_implementation_without_an_account_has_code_hash_zero() {
    let w = world(false);
    let s = statement(Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), 1);
    let (_, wit) = w.witness(&s);
    let j = decode_journal(&run(&input(&wit.encode().unwrap())).unwrap()).unwrap();
    assert_eq!(j.outputs.implementation, IMPL);
    assert_eq!(j.outputs.code_hash, [0; 32]);
}

#[test]
fn an_absent_proxy_reads_as_implementation_zero() {
    let mut w = world(true);
    w.accounts.remove(&PROXY);
    let s = statement(Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), 2);
    let (_, wit) = w.witness(&s);
    let j = decode_journal(&run(&input(&wit.encode().unwrap())).unwrap()).unwrap();
    assert_eq!(j.outputs.implementation, [0; 20]);
    assert!(j.outputs.slots.iter().all(|(_, v)| *v == [0; 32]));
}

#[test]
fn wrong_layouts_and_inputs_fail() {
    let w = world(true);
    let s = statement(Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), 2);
    let (_, wit) = w.witness(&s);
    // Six header words.
    let mut six = wit.clone();
    six.header_words.push([0; 32]);
    assert_eq!(run(&input(&six.encode().unwrap())), Err(Error::HeaderLayout));
    // An unknown rule.
    let mut bad_rule = wit.clone();
    bad_rule.header_words[3][0] = 9;
    assert_eq!(run(&input(&bad_rule.encode().unwrap())), Err(Error::BadRule));
    // k over the cap.
    let mut big = wit.clone();
    big.header_words[4] = word(256);
    assert!(matches!(run(&input(&big.encode().unwrap())), Err(Error::Witness(ReadError::BadWord { index: 4 }))));
    // No prefix.
    assert_eq!(run(&wit.encode().unwrap()[..63]), Err(Error::Guard(GuardError::BadPrefix)));
    // A storage proof left unread.
    let mut extra = wit.clone();
    let dup = extra.accounts[0].storage[1].clone();
    extra.accounts[0].storage.push(dup);
    assert!(matches!(run(&input(&extra.encode().unwrap())), Err(Error::Witness(ReadError::Unconsumed(_)))));
}

/// Runs every mutation and judges it; panics on an unsound one. Returns the verdict counts.
fn attack(honest_w: &Witness<'_>, extra: Vec<Mutation>, bytes: ByteSelection) -> BTreeMap<String, usize> {
    let honest = run(&input(&honest_w.encode().unwrap())).unwrap();
    let pinned = PREFIX_BYTES + HEADER_BYTES;
    let mut counts = BTreeMap::new();
    let mut mutations = honest_w.standard_mutations(bytes);
    mutations.extend(extra);
    for m in &mutations {
        let mutated = match honest_w.mutate(m) {
            Ok(w) => w,
            Err(e) => panic!("{m:?}: {e}"),
        };
        let out = run(&input(&mutated));
        let verdict = judge(&honest, out.as_deref().ok(), pinned);
        assert_ne!(verdict, Verdict::Unsound, "{m:?} gave a different answer under the same header");
        *counts.entry(format!("{verdict:?}")).or_default() += 1;
    }
    counts
}

#[test]
fn mutations_of_synthetic_witnesses_never_change_the_answer() {
    for (rule, k, with_impl) in [
        (Rule::new(RuleKind::Consecutive, &word(9)).unwrap(), 5, true),
        (Rule::new(RuleKind::MappingByImplementation, &word(5)).unwrap(), 3, true),
        (Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), 1, false),
    ] {
        let (header, wit) = world(with_impl).witness(&statement(rule, k));
        let mut sibling = header.clone();
        sibling.extra_data = b"sibling".to_vec();
        let extra = vec![Mutation::ReplaceHeader { header: 0, rlp: sibling.encode().unwrap() }];
        let counts = attack(&wit, extra, ByteSelection::All);
        assert!(counts["Rejected"] > 1000, "{counts:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Real chains: the fixtures of hemiprove-eth-prelude.

fn fixture(name: &str) -> Value {
    let path = format!("{}/../../eth-prelude/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

fn qty(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

fn qty256(v: &Value) -> [u8; 32] {
    let s = v.as_str().unwrap().strip_prefix("0x").unwrap();
    hex::decode(format!("{s:0>64}")).unwrap().try_into().unwrap()
}

fn header_from_json(b: &Value) -> Header {
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

/// The statement's witness for proxy `proofs[0]`, its implementation `proofs[1]`, rule
/// "consecutive from 0" and `k` slots, from a fixture's raw `eth_getProof` results.
fn real_witness(f: &Value, k: u64) -> (Statement, Witness<'static>, Value) {
    let proxy = &f["proofs"][0];
    let implementation = &f["proofs"][1];
    let s = Statement {
        block_hash: h32(&f["hash"]),
        proxy: hex(&proxy["address"]).try_into().unwrap(),
        rule: Rule::new(RuleKind::Consecutive, &word(0)).unwrap(),
        k,
    };
    let storage = proxy["proof"]["storageProof"].as_array().unwrap();
    // The fixture asked for [EIP-1967, admin, 0, 1, 2, …]: take the implementation slot, then 0.. .
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
    (s, w, proxy["proof"].clone())
}

#[test]
fn real_proxies_on_ethereum_base_and_hemi() {
    for (name, k) in [("ethereum", 3), ("base", 6), ("hemi", 6)] {
        let f = fixture(name);
        let (s, w, proxy_proof) = real_witness(&f, k);
        let journal = run(&input(&w.encode().unwrap())).unwrap_or_else(|e| panic!("{name}: {e}"));
        let j = decode_journal(&journal).unwrap();
        assert_eq!(j.statement, s);
        let impl_json = &f["proofs"][1];
        assert_eq!(j.outputs.implementation.to_vec(), hex(&impl_json["address"]), "{name}");
        assert_eq!(j.outputs.code_hash, h32(&impl_json["proof"]["codeHash"]), "{name}");
        for (slot, value) in &j.outputs.slots {
            let p = proxy_proof["storageProof"].as_array().unwrap().iter().find(|p| qty256(&p["key"]) == *slot).unwrap();
            assert_eq!(*value, qty256(&p["value"]), "{name} slot {slot:?}");
        }
        eprintln!("{name}: proxy {} → {} ({} slots)", proxy_proof["address"], impl_json["address"], k);
    }
}

#[test]
fn mutations_of_real_witnesses_never_change_the_answer() {
    for (name, k) in [("ethereum", 3), ("base", 6), ("hemi", 6)] {
        let f = fixture(name);
        let (_, w, _) = real_witness(&f, k);
        // Swap in the real parent, and a header of another chain.
        let other = if name == "base" { "hemi" } else { "base" };
        let extra = vec![
            Mutation::ReplaceHeader { header: 0, rlp: header_from_json(&f["parent"]).encode().unwrap() },
            Mutation::ReplaceHeader { header: 0, rlp: header_from_json(&fixture(other)["block"]).encode().unwrap() },
        ];
        let counts = attack(&w, extra, ByteSelection::Sample(24));
        eprintln!("{name}: {counts:?}");
        assert!(counts["Rejected"] > 500, "{name}: {counts:?}");
    }
}

/// Every byte of a real witness flipped (every third position; all of the first 300, where the
/// magic, the header words and the first counts sit), and truncations: never a panic, never a
/// different answer under the same header.
#[test]
fn byte_flips_across_a_whole_real_witness() {
    let f = fixture("hemi");
    let (_, w, _) = real_witness(&f, 6);
    let enc = w.encode().unwrap();
    let honest = run(&input(&enc)).unwrap();
    let pinned = PREFIX_BYTES + HEADER_BYTES;
    let mut tried = 0;
    for i in (0..enc.len()).filter(|i| *i < 300 || i % 3 == 0) {
        for mask in [0x01u8, 0x80] {
            let mut m = enc.clone();
            m[i] ^= mask;
            let verdict = judge(&honest, run(&input(&m)).ok().as_deref(), pinned);
            assert_ne!(verdict, Verdict::Unsound, "byte {i} mask {mask:#x}");
            tried += 1;
        }
    }
    for len in (0..enc.len()).step_by(97) {
        assert!(run(&input(&enc[..len])).is_err(), "truncated to {len}");
    }
    assert!(tried > 10_000, "{tried}");
}

/// Arbitrary inputs: never a panic.
#[test]
fn arbitrary_inputs_never_panic() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for n in 0..3000usize {
        let len = n % 700;
        let mut b = Vec::with_capacity(len);
        for _ in 0..len {
            // xorshift: deterministic, no rand crate.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b.push(x as u8);
        }
        if n % 2 == 0 && b.len() > 100 {
            // Half of them start like a scheme-1 witness behind a valid prefix.
            b[..64].copy_from_slice(&PREFIX);
            b[64..69].copy_from_slice(b"HPW\x01\x01");
        }
        let _ = run(&b);
    }
}
