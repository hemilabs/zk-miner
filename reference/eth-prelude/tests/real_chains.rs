//! Vectors from real chains: Ethereum mainnet, Base and Hemi blocks fetched by
//! `tests/fixtures/fetch.sh` (raw JSON-RPC results, committed). Every header, account, storage
//! slot, receipt and transaction is re-encoded from the node's JSON here and checked against the
//! block's own hashes and roots, and cross-checked against alloy (alloy-consensus, alloy-trie).

use std::collections::BTreeMap;

use alloy_primitives::{Bytes, B256};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use hemiprove_eth_prelude::header::{Header, Variant};
use hemiprove_eth_prelude::keccak::{keccak256, EMPTY_ROOT, KECCAK_EMPTY};
use hemiprove_eth_prelude::receipt::{self, Log, Outcome, Receipt};
use hemiprove_eth_prelude::rlp;
use hemiprove_eth_prelude::state::{self, Account};
use hemiprove_eth_prelude::tx::{self, Transaction};
use hemiprove_eth_prelude::scheme1::{scheme_word, Reader, Witness};
use hemiprove_eth_prelude::{anchor, mpt};
use std::borrow::Cow;
use serde_json::Value;

const FIXTURES: [&str; 3] = ["ethereum", "base", "hemi"];

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap_or_else(|| panic!("not a string: {v}"));
    hex::decode(s.strip_prefix("0x").unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

fn qty(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

/// A quantity as 32 big-endian bytes.
fn qty256(v: &Value) -> [u8; 32] {
    let s = v.as_str().unwrap().strip_prefix("0x").unwrap();
    let padded = format!("{s:0>64}");
    hex::decode(padded).unwrap().try_into().unwrap()
}

fn opt<T>(b: &Value, key: &str, f: impl Fn(&Value) -> T) -> Option<T> {
    b.get(key).filter(|v| !v.is_null()).map(f)
}

/// The header from `eth_getBlockBy*` JSON, field by field.
fn header_from_json(b: &Value) -> Header {
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
        base_fee_per_gas: opt(b, "baseFeePerGas", qty256),
        withdrawals_root: opt(b, "withdrawalsRoot", h32),
        blob_gas_used: opt(b, "blobGasUsed", qty),
        excess_blob_gas: opt(b, "excessBlobGas", qty),
        parent_beacon_block_root: opt(b, "parentBeaconBlockRoot", h32),
        requests_hash: opt(b, "requestsHash", h32),
    }
}

fn receipt_from_json(r: &Value) -> Receipt {
    let tx_type = qty(&r["type"]) as u8;
    let outcome = match r.get("status") {
        Some(s) if !s.is_null() => Outcome::Status(qty(s) == 1),
        _ => Outcome::PostState(h32(&r["root"])),
    };
    let logs = r["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| Log {
            address: hex(&l["address"]).try_into().unwrap(),
            topics: l["topics"].as_array().unwrap().iter().map(h32).collect(),
            data: hex(&l["data"]),
        })
        .collect();
    Receipt {
        tx_type,
        outcome,
        cumulative_gas_used: qty(&r["cumulativeGasUsed"]),
        logs_bloom: hex(&r["logsBloom"]).try_into().unwrap(),
        logs,
        deposit_nonce: opt(r, "depositNonce", qty),
        deposit_receipt_version: opt(r, "depositReceiptVersion", qty),
    }
}

/// An index-keyed trie (receipts or transactions) built by alloy-trie, with proofs for `targets`.
fn index_trie(values: &[Vec<u8>], targets: &[u64]) -> ([u8; 32], Vec<Vec<Vec<u8>>>) {
    let entries: BTreeMap<Vec<u8>, &Vec<u8>> =
        values.iter().enumerate().map(|(i, v)| (rlp::index_key(i as u64), v)).collect();
    let retain: Vec<Nibbles> = targets.iter().map(|&t| Nibbles::unpack(rlp::index_key(t))).collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(retain.clone()));
    for (k, v) in &entries {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    let root = hb.root().0;
    let nodes = hb.take_proof_nodes();
    let proofs = retain
        .iter()
        .map(|t| {
            nodes
                .matching_nodes_sorted(t)
                .into_iter()
                .map(|(_, n)| n.to_vec())
                .enumerate()
                .filter(|(i, n)| *i == 0 || n.len() >= 32)
                .map(|(_, n)| n)
                .collect()
        })
        .collect();
    (root, proofs)
}

#[test]
fn headers_hash_to_their_block_hashes() {
    for name in FIXTURES {
        let f = fixture(name);
        for (b, want_variant) in [(&f["block"], Variant::Prague), (&f["parent"], Variant::Prague)] {
            let h = header_from_json(b);
            assert_eq!(h.variant(), Some(want_variant), "{name}");
            let enc = h.encode().unwrap();
            assert_eq!(keccak256(&enc), h32(&b["hash"]), "{name} {}", b["number"]);
            assert_eq!(Header::decode(&enc).unwrap(), h);
            let theirs: alloy_consensus::Header = alloy_rlp::Decodable::decode(&mut &enc[..]).unwrap();
            assert_eq!(theirs.hash_slow().0, keccak256(&enc));
        }
        // Anchor 1 then anchor 2 on the real pair, through a scheme-1 reader: the block hash is a
        // pinned word, the block and its parent are W's headers.
        let block = header_from_json(&f["block"]).encode().unwrap();
        let parent = header_from_json(&f["parent"]).encode().unwrap();
        let w = Witness {
            header_words: vec![scheme_word(), h32(&f["hash"])],
            headers: vec![Cow::Owned(block.clone()), Cow::Owned(parent.clone())],
            accounts: vec![],
            receipts: vec![],
            transactions: vec![],
        }
        .encode()
        .unwrap();
        let mut r = Reader::new(&w).unwrap();
        let mut j = r.journal(None);
        j.commit_pinned(&r.pin_scheme_id().unwrap()).unwrap();
        let hash = r.pin_word().unwrap();
        j.commit_pinned(&hash).unwrap();
        let child = r.block_header(&hash.authenticated()).unwrap();
        let p = r.parent_header(&child).unwrap();
        assert_eq!(p.get().number + 1, child.get().number);
        j.output(&p.derive(|h| h.state_root)).unwrap();
        let journal = r.finish(j).unwrap();
        assert_eq!(&journal[64..96], &header_from_json(&f["parent"]).state_root);
        assert!(anchor::parent_block(&p, &block).is_err());
    }
    // Ethereum's older layouts: Berlin (15), London (16), Shanghai (17), Cancun (20), Prague (21).
    let f = fixture("ethereum");
    let want = [15, 16, 17, 20, 21];
    for (h, n) in f["headers"].as_array().unwrap().iter().zip(want) {
        let header = header_from_json(&h["block"]);
        assert_eq!(header.variant().unwrap().field_count(), n, "block {}", h["number"]);
        let enc = header.encode().unwrap();
        assert_eq!(keccak256(&enc), h32(&h["block"]["hash"]), "block {}", h["number"]);
        assert_eq!(Header::decode(&enc).unwrap(), header);
    }
}

#[test]
fn accounts_and_storage_from_eth_get_proof() {
    for name in FIXTURES {
        let f = fixture(name);
        let state_root = h32(&f["block"]["stateRoot"]);
        let mut seen = (0, 0, 0, 0);
        for entry in f["proofs"].as_array().unwrap() {
            let p = &entry["proof"];
            let address: [u8; 20] = hex(&entry["address"]).try_into().unwrap();
            let nodes: Vec<Vec<u8>> = p["accountProof"].as_array().unwrap().iter().map(hex).collect();
            let account = state::verify_account(&state_root, &address, &nodes).unwrap();
            let json = Account {
                nonce: qty(&p["nonce"]),
                balance: qty256(&p["balance"]),
                storage_root: h32(&p["storageHash"]),
                code_hash: h32(&p["codeHash"]),
            };
            match account {
                Some(a) => {
                    assert_eq!(a, json, "{name} {}", entry["address"]);
                    seen.0 += 1;
                }
                None => {
                    // Nodes report an absent account with zero fields and either the empty or the
                    // zero code hash and storage root.
                    assert_eq!(json.nonce, 0);
                    assert_eq!(json.balance, [0; 32]);
                    assert!(json.storage_root == EMPTY_ROOT || json.storage_root == [0; 32]);
                    assert!(json.code_hash == KECCAK_EMPTY || json.code_hash == [0; 32]);
                    seen.1 += 1;
                }
            }
            let root = state::storage_root(&account);
            for s in p["storageProof"].as_array().unwrap() {
                let slot = qty256(&s["key"]);
                let nodes: Vec<Vec<u8>> = s["proof"].as_array().unwrap().iter().map(hex).collect();
                let value = state::verify_storage(&root, &slot, &nodes).unwrap();
                assert_eq!(value, qty256(&s["value"]), "{name} slot {}", s["key"]);
                if value == [0; 32] {
                    seen.3 += 1;
                } else {
                    seen.2 += 1;
                }
                // alloy-trie agrees.
                let expected = (value != [0; 32]).then(|| state::encode_storage_value(&value));
                let p: Vec<Bytes> = nodes.iter().map(|n| Bytes::from(n.clone())).collect();
                alloy_trie::proof::verify_proof(B256::from(root), Nibbles::unpack(keccak256(&slot)), expected, &p).unwrap();
            }
        }
        // Each chain's fixture has present and absent accounts, set and unset slots.
        assert!(seen.0 >= 2 && seen.1 >= 1 && seen.2 >= 2 && seen.3 >= 1, "{name}: {seen:?}");
    }
}

#[test]
fn every_byte_flip_of_a_real_proof_is_rejected() {
    let f = fixture("base");
    let state_root = h32(&f["block"]["stateRoot"]);
    let entry = &f["proofs"][0];
    let address: [u8; 20] = hex(&entry["address"]).try_into().unwrap();
    let nodes: Vec<Vec<u8>> = entry["proof"]["accountProof"].as_array().unwrap().iter().map(hex).collect();
    let honest = state::verify_account(&state_root, &address, &nodes).unwrap();
    let storage_root = state::storage_root(&honest);
    let s = &entry["proof"]["storageProof"][0];
    let slot = qty256(&s["key"]);
    let snodes: Vec<Vec<u8>> = s["proof"].as_array().unwrap().iter().map(hex).collect();
    let honest_value = state::verify_storage(&storage_root, &slot, &snodes).unwrap();
    let mut checked = 0;
    for n in 0..nodes.len() {
        for b in 0..nodes[n].len() {
            let mut m = nodes.clone();
            m[n][b] ^= 0x01;
            let got = state::verify_account(&state_root, &address, &m);
            assert!(got.is_err() || got == Ok(honest), "account node {n} byte {b}");
            checked += 1;
        }
    }
    for n in 0..snodes.len() {
        for b in 0..snodes[n].len() {
            let mut m = snodes.clone();
            m[n][b] ^= 0x80;
            let got = state::verify_storage(&storage_root, &slot, &m);
            assert!(got.is_err() || got == Ok(honest_value), "storage node {n} byte {b}");
            checked += 1;
        }
    }
    assert!(checked > 3000, "{checked}");
}

#[test]
fn receipts_rebuild_the_receipts_root() {
    let mut types = std::collections::BTreeSet::new();
    for name in FIXTURES {
        let f = fixture(name);
        let receipts: Vec<Receipt> = f["receipts"].as_array().unwrap().iter().map(receipt_from_json).collect();
        let encoded: Vec<Vec<u8>> = receipts.iter().map(|r| r.encode().unwrap()).collect();
        let n = receipts.len() as u64;
        let targets: Vec<u64> = (0..=n).collect(); // every receipt, and one past the end (absent)
        let (root, proofs) = index_trie(&encoded, &targets);
        assert_eq!(root, h32(&f["block"]["receiptsRoot"]), "{name}");
        for (i, proof) in proofs.iter().enumerate() {
            let got = receipt::verify_receipt(&root, i as u64, proof).unwrap();
            if (i as u64) < n {
                let r = got.unwrap();
                assert_eq!(r, receipts[i]);
                assert!(r.bloom_matches(), "{name} receipt {i}");
                types.insert(r.tx_type);
            } else {
                assert_eq!(got, None, "{name}: one past the last receipt is absent");
            }
        }
        // alloy-consensus agrees on every non-deposit receipt's encoding.
        for (r, enc) in receipts.iter().zip(&encoded) {
            if r.tx_type != receipt::TYPE_DEPOSIT {
                let env: alloy_consensus::ReceiptEnvelope =
                    alloy_eips::eip2718::Decodable2718::decode_2718(&mut &enc[..]).unwrap();
                assert_eq!(alloy_eips::eip2718::Encodable2718::encoded_2718(&env), *enc);
            }
        }
    }
    assert!(types.contains(&0x00) && types.contains(&0x02) && types.contains(&0x03) && types.contains(&0x7e), "{types:?}");
}

#[test]
fn transactions_rebuild_the_transactions_root() {
    let mut types = std::collections::BTreeSet::new();
    for name in FIXTURES {
        let f = fixture(name);
        let raw: Vec<Vec<u8>> = f["rawTransactions"].as_array().unwrap().iter().map(hex).collect();
        let hashes: Vec<[u8; 32]> = f["block"]["transactions"].as_array().unwrap().iter().map(h32).collect();
        assert_eq!(raw.len(), hashes.len());
        let n = raw.len() as u64;
        let targets: Vec<u64> = (0..=n).collect();
        let (root, proofs) = index_trie(&raw, &targets);
        assert_eq!(root, h32(&f["block"]["transactionsRoot"]), "{name}");
        for (i, proof) in proofs.iter().enumerate() {
            let got = tx::verify_transaction(&root, i as u64, proof).unwrap();
            if (i as u64) < n {
                let t = got.unwrap();
                assert_eq!(t.hash, hashes[i], "{name} tx {i}");
                assert_eq!(t.tx, Transaction::decode(&raw[i]).unwrap());
                types.insert(t.tx.tx_type);
                if t.tx.tx_type == receipt::TYPE_DEPOSIT {
                    assert!(t.tx.deposit_from.is_some() && t.tx.signature.is_none());
                } else {
                    let chain = qty(&f["chainId"]);
                    // Every signed transaction in these blocks is EIP-155 or typed, for this chain.
                    assert_eq!(t.tx.chain_id, Some(chain), "{name} tx {i}");
                }
            } else {
                assert_eq!(got, None);
            }
        }
        // alloy-consensus decodes the same bytes to the same hash (deposits aside).
        for (r, h) in raw.iter().zip(&hashes) {
            if r[0] != receipt::TYPE_DEPOSIT {
                let env: alloy_consensus::TxEnvelope = alloy_eips::eip2718::Decodable2718::decode_2718(&mut &r[..]).unwrap();
                assert_eq!(env.tx_hash().0, *h);
            }
        }
    }
    assert!(types.contains(&0x00) && types.contains(&0x02) && types.contains(&0x7e), "{types:?}");
}

#[test]
fn mpt_agrees_with_alloy_on_real_account_proofs() {
    for name in FIXTURES {
        let f = fixture(name);
        let state_root = h32(&f["block"]["stateRoot"]);
        for entry in f["proofs"].as_array().unwrap() {
            let address: [u8; 20] = hex(&entry["address"]).try_into().unwrap();
            let nodes: Vec<Vec<u8>> = entry["proof"]["accountProof"].as_array().unwrap().iter().map(hex).collect();
            let ours = mpt::verify(&state_root, &keccak256(&address), &nodes).unwrap().map(<[u8]>::to_vec);
            let p: Vec<Bytes> = nodes.iter().map(|n| Bytes::from(n.clone())).collect();
            alloy_trie::proof::verify_proof(B256::from(state_root), Nibbles::unpack(keccak256(&address)), ours, &p).unwrap();
        }
    }
}
