//! Scheme 1 (`eth-block`, plan §8.1, §8.4): structured mutations of a scheme-1 witness, from the
//! reference prelude's own codec (`hemiprove_eth_prelude::scheme1`): byte flips in header words,
//! block headers and trie nodes; nodes dropped, duplicated and appended; proof kinds flipped
//! (inclusion for exclusion); inclusion proofs replaced by their truncation and by the empty proof;
//! proofs dropped, duplicated and swapped (reordered leaves, another slot's proof); headers dropped;
//! trailing bytes and a cut last byte; and the block header replaced by its **parent** and by the
//! **next block's** header, both fetched through the job's own `evm-rpc/v1` source
//! ([`super::fetch_through_job`]) and checked against their hashes before use.
//!
//! The structural mutations come first and the byte flips after, so a run cut short by its time
//! bound has tried every kind of change.

use alloy_primitives::keccak256;
use hemiprove_eth_prelude::header::Header;
use hemiprove_eth_prelude::scheme1::{is_scheme1, ByteSelection, Mutation as S1, ProofRef, Witness};
use serde_json::{json, Value};

use super::{Mutation, RpcCall, SchemeContext, SchemeMutator};

/// The scheme-1 mutator.
#[derive(Debug, Clone, Copy)]
pub struct Scheme1 {
    /// Which bytes of each header and node are flipped.
    pub bytes: ByteSelection,
}

impl Default for Scheme1 {
    fn default() -> Self {
        Scheme1 { bytes: ByteSelection::Sample(4) }
    }
}

fn decode(w: &[u8]) -> Result<Witness<'_>, String> {
    if !is_scheme1(w) {
        return Err("W is not a scheme-1 witness of this version (no HPW ‖ 1 ‖ 1 magic)".into());
    }
    Witness::decode(w).map_err(|e| format!("W does not decode as a scheme-1 witness: {e}"))
}

fn proof_label(p: ProofRef) -> String {
    match p {
        ProofRef::Account(a) => format!("account{a}"),
        ProofRef::Storage { account, slot } => format!("account{account}.slot{slot}"),
        ProofRef::Receipt(i) => format!("receipt{i}"),
        ProofRef::Transaction(i) => format!("tx{i}"),
    }
}

/// A short, stable id and a kind for a prelude mutation (its `Debug` form carries whole nodes).
fn label(m: &S1) -> (String, &'static str) {
    match m {
        S1::WordByte { word, byte, mask } => (format!("word{word}[{byte}]^{mask:#04x}"), "word-byte"),
        S1::HeaderByte { header, byte, mask } => (format!("header{header}[{byte}]^{mask:#04x}"), "header-byte"),
        S1::ReplaceHeader { header, .. } => (format!("header{header}=other"), "replace-header"),
        S1::DropHeader { header } => (format!("drop-header{header}"), "drop-header"),
        S1::NodeByte { proof, node, byte, mask } => {
            (format!("{}/node{node}[{byte}]^{mask:#04x}", proof_label(*proof)), "node-byte")
        }
        S1::DropNode { proof, node } => (format!("{}/drop-node{node}", proof_label(*proof)), "drop-node"),
        S1::InsertNode { proof, at, .. } => (format!("{}/insert-node@{at}", proof_label(*proof)), "insert-node"),
        S1::FlipKind { proof } => (format!("{}/flip-kind", proof_label(*proof)), "flip-kind"),
        S1::ReplaceProof { proof, kind, nodes } => {
            (format!("{}/replace-{kind:?}-{}-nodes", proof_label(*proof), nodes.len()).to_lowercase(), "replace-proof")
        }
        S1::SwapProofs { a, b } => (format!("swap-{}-{}", proof_label(*a), proof_label(*b)), "swap-proofs"),
        S1::DropProof { proof } => (format!("{}/drop", proof_label(*proof)), "drop-proof"),
        S1::DuplicateProof { proof } => (format!("{}/duplicate", proof_label(*proof)), "duplicate-proof"),
        S1::AppendBytes { bytes } => (format!("append{}", bytes.len()), "append"),
        S1::TruncateBytes { len } => (format!("truncate@{len}"), "truncate"),
    }
}

/// `ms` reordered one of each kind at a time (each kind's own order kept), so a run cut short by
/// `max` or by its time bound has tried every kind.
fn round_robin(ms: Vec<S1>) -> Vec<S1> {
    let mut kinds: Vec<(&'static str, std::collections::VecDeque<S1>)> = Vec::new();
    for m in ms {
        let k = label(&m).1;
        match kinds.iter_mut().find(|(kind, _)| *kind == k) {
            Some((_, q)) => q.push_back(m),
            None => kinds.push((k, std::collections::VecDeque::from([m]))),
        }
    }
    let mut out = Vec::new();
    while kinds.iter().any(|(_, q)| !q.is_empty()) {
        for (_, q) in kinds.iter_mut() {
            out.extend(q.pop_front());
        }
    }
    out
}

fn is_byte_flip(m: &S1) -> bool {
    matches!(m, S1::WordByte { .. } | S1::HeaderByte { .. } | S1::NodeByte { .. })
}

fn hex_field(v: &Value, k: &str) -> Option<Vec<u8>> {
    let s = v.get(k)?.as_str()?.strip_prefix("0x")?;
    hex::decode(s).ok()
}

fn fixed<const N: usize>(v: &Value, k: &str) -> Option<[u8; N]> {
    hex_field(v, k)?.try_into().ok()
}

fn quantity(v: &Value, k: &str) -> Option<u64> {
    u64::from_str_radix(v.get(k)?.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn quantity256(v: &Value, k: &str) -> Option<[u8; 32]> {
    let s = v.get(k)?.as_str()?.strip_prefix("0x")?;
    if s.len() > 64 {
        return None;
    }
    hex::decode(format!("{s:0>64}")).ok()?.try_into().ok()
}

/// A block's header RLP from its JSON-RPC form, `None` unless it re-encodes to the block's own
/// hash (a field this encoder does not know would otherwise yield a header of no block).
pub fn header_rlp(b: &Value) -> Option<Vec<u8>> {
    let present = |k: &str| b.get(k).is_some_and(|v| !v.is_null());
    let header = Header {
        parent_hash: fixed(b, "parentHash")?,
        ommers_hash: fixed(b, "sha3Uncles")?,
        beneficiary: fixed(b, "miner")?,
        state_root: fixed(b, "stateRoot")?,
        transactions_root: fixed(b, "transactionsRoot")?,
        receipts_root: fixed(b, "receiptsRoot")?,
        logs_bloom: fixed(b, "logsBloom")?,
        difficulty: quantity256(b, "difficulty")?,
        number: quantity(b, "number")?,
        gas_limit: quantity(b, "gasLimit")?,
        gas_used: quantity(b, "gasUsed")?,
        timestamp: quantity(b, "timestamp")?,
        extra_data: hex_field(b, "extraData")?,
        mix_hash: fixed(b, "mixHash")?,
        nonce: fixed(b, "nonce")?,
        base_fee_per_gas: if present("baseFeePerGas") { Some(quantity256(b, "baseFeePerGas")?) } else { None },
        withdrawals_root: if present("withdrawalsRoot") { Some(fixed(b, "withdrawalsRoot")?) } else { None },
        blob_gas_used: if present("blobGasUsed") { Some(quantity(b, "blobGasUsed")?) } else { None },
        excess_blob_gas: if present("excessBlobGas") { Some(quantity(b, "excessBlobGas")?) } else { None },
        parent_beacon_block_root: if present("parentBeaconBlockRoot") { Some(fixed(b, "parentBeaconBlockRoot")?) } else { None },
        requests_hash: if present("requestsHash") { Some(fixed(b, "requestsHash")?) } else { None },
    };
    let rlp = header.encode().ok()?;
    let hash: [u8; 32] = fixed(b, "hash")?;
    (keccak256(&rlp).0 == hash).then_some(rlp)
}

impl SchemeMutator for Scheme1 {
    fn scheme_id(&self) -> u64 {
        1
    }

    fn name(&self) -> &'static str {
        "eth-block"
    }

    /// The parent of the witness's first header, by its `parentHash`, and the block after it, by
    /// number.
    fn requests(&self, w: &[u8]) -> Result<Vec<RpcCall>, String> {
        let wit = decode(w)?;
        let Some(first) = wit.headers.first() else { return Ok(Vec::new()) };
        let h = Header::decode(first).map_err(|e| format!("the witness's first header: {e:?}"))?;
        Ok(vec![
            RpcCall {
                method: "eth_getBlockByHash".into(),
                params: json!([format!("0x{}", hex::encode(h.parent_hash)), false]),
            },
            RpcCall {
                method: "eth_getBlockByNumber".into(),
                params: json!([format!("0x{:x}", h.number.saturating_add(1)), false]),
            },
        ])
    }

    fn mutations(&self, w: &[u8], ctx: &SchemeContext<'_>, max: usize) -> Result<Vec<Mutation>, String> {
        let wit = decode(w)?;
        let mut list: Vec<(S1, Option<&'static str>)> = Vec::new();
        for (answer, which) in ctx.answers.iter().zip(["parent", "next-block"]) {
            if let Some(rlp) = answer.as_ref().and_then(header_rlp) {
                list.push((S1::ReplaceHeader { header: 0, rlp }, Some(which)));
            }
        }
        let standard = wit.standard_mutations(self.bytes);
        let (flips, structural): (Vec<S1>, Vec<S1>) = standard.into_iter().partition(is_byte_flip);
        list.extend(round_robin(structural).into_iter().map(|m| (m, None)));
        list.extend(round_robin(flips).into_iter().map(|m| (m, None)));
        let mut out = Vec::new();
        for (m, swapped_in) in list {
            if out.len() >= max {
                break;
            }
            // Mutations that name nothing in this witness, or change nothing, are skipped.
            let Ok(bytes) = wit.mutate(&m) else { continue };
            let (mut id, kind) = label(&m);
            let mut description = format!("{m:?}");
            if let Some(which) = swapped_in {
                id = format!("header0={which}");
                description = format!("the block header replaced by the {which}'s, fetched through the job's evm-rpc source");
            }
            if description.len() > 200 {
                description = format!("{} …", &description[..description.char_indices().nth(200).map_or(description.len(), |(i, _)| i)]);
            }
            out.push(Mutation::new(format!("scheme1:{id}"), kind, description, bytes));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hemiprove_eth_prelude::scheme1::{scheme_word, AccountProof, ProofKind, TrieProof};
    use std::borrow::Cow;

    fn header_json(number: u64) -> (Value, Vec<u8>) {
        let h = Header {
            parent_hash: [1; 32],
            ommers_hash: [2; 32],
            beneficiary: [3; 20],
            state_root: [4; 32],
            transactions_root: [5; 32],
            receipts_root: [6; 32],
            logs_bloom: [0; 256],
            difficulty: [0; 32],
            number,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            mix_hash: [7; 32],
            nonce: [0; 8],
            base_fee_per_gas: Some({
                let mut b = [0u8; 32];
                b[31] = 9;
                b
            }),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };
        let rlp = h.encode().unwrap();
        let x = |b: &[u8]| format!("0x{}", hex::encode(b));
        let v = json!({
            "hash": x(&keccak256(&rlp).0), "parentHash": x(&[1; 32]), "sha3Uncles": x(&[2; 32]), "miner": x(&[3; 20]),
            "stateRoot": x(&[4; 32]), "transactionsRoot": x(&[5; 32]), "receiptsRoot": x(&[6; 32]), "logsBloom": x(&[0; 256]),
            "difficulty": "0x0", "number": format!("0x{number:x}"), "gasLimit": "0x1c9c380", "gasUsed": "0x5208", "timestamp": "0x6553f100",
            "extraData": "0x", "mixHash": x(&[7; 32]), "nonce": "0x0000000000000000", "baseFeePerGas": "0x9",
        });
        (v, rlp)
    }

    fn witness(header: Vec<u8>) -> Vec<u8> {
        let node = |b: u8, n: usize| Cow::Owned(vec![b; n]);
        Witness {
            header_words: vec![scheme_word(), [7; 32]],
            headers: vec![Cow::Owned(header)],
            accounts: vec![AccountProof {
                proof: TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(1, 40), node(2, 50)] },
                storage: vec![
                    TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(3, 40)] },
                    TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(4, 41)] },
                ],
            }],
            receipts: vec![],
            transactions: vec![],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn json_headers_are_used_only_when_they_hash_to_their_block() {
        let (v, rlp) = header_json(77);
        assert_eq!(header_rlp(&v), Some(rlp));
        let mut wrong = v.clone();
        wrong["gasUsed"] = json!("0x5209");
        assert_eq!(header_rlp(&wrong), None, "a header of no block");
        assert_eq!(header_rlp(&json!({})), None);
    }

    #[test]
    fn a_scheme1_witness_gets_structured_mutations_and_the_fetched_headers() {
        let (_, rlp) = header_json(77);
        let (parent, _) = header_json(76);
        let w = witness(rlp.clone());
        let s = Scheme1::default();
        let calls = s.requests(&w).unwrap();
        assert_eq!(calls[0].method, "eth_getBlockByHash");
        assert_eq!(calls[0].params[0], format!("0x{}", "01".repeat(32)));
        assert_eq!(calls[1].params[0], "0x4e", "the block after 77");
        let answers = [Some(parent), None];
        let ms = s.mutations(&w, &SchemeContext { statement: &[], seed: 0, answers: &answers }, 1_000).unwrap();
        assert_eq!(ms[0].id, "scheme1:header0=parent");
        assert!(ms.iter().any(|m| m.kind == "flip-kind"));
        assert!(ms.iter().any(|m| m.kind == "swap-proofs" && m.id == "scheme1:swap-account0.slot0-account0.slot1"));
        assert!(ms.iter().any(|m| m.kind == "replace-proof"));
        assert!(ms.iter().all(|m| m.w != w));
        // Structural ones before every byte flip.
        let first_flip = ms.iter().position(|m| m.kind.ends_with("-byte")).unwrap();
        assert!(ms[first_flip..].iter().all(|m| m.kind.ends_with("-byte")));
        // Bounded, and a short run still tries every structural kind first.
        let few = s.mutations(&w, &SchemeContext { statement: &[], seed: 0, answers: &[] }, 12).unwrap();
        assert_eq!(few.len(), 12);
        let kinds: std::collections::BTreeSet<&str> = few.iter().map(|m| m.kind.as_str()).collect();
        for k in ["drop-header", "drop-node", "insert-node", "flip-kind", "replace-proof", "drop-proof", "duplicate-proof", "swap-proofs"] {
            assert!(kinds.contains(k), "{k} missing from {kinds:?}");
        }
        // Another layout is reported, not mutated.
        assert!(s.requests(b"not a witness").is_err());
        assert!(s.mutations(b"not a witness", &SchemeContext { statement: &[], seed: 0, answers: &[] }, 5).is_err());
    }

    #[test]
    fn the_default_registry_holds_scheme_1() {
        let r = super::super::default_registry();
        assert_eq!(r.ids(), vec![1]);
        assert_eq!(r.get(1).unwrap().name(), "eth-block");
    }
}
