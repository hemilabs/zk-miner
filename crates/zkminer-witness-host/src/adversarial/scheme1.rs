//! Scheme 1 (`eth-block`, plan §8.1, §8.4): structured mutations of a scheme-1 witness, from the
//! reference prelude's own codec (`hemiprove_eth_prelude::scheme1`): byte flips in header words,
//! block headers and trie nodes; nodes dropped, duplicated and appended; proof kinds flipped
//! (inclusion for exclusion); inclusion proofs replaced by their truncation and by the empty proof;
//! proofs dropped, duplicated and swapped (reordered leaves, another slot's proof); headers dropped;
//! trailing bytes and a cut last byte; and the block header replaced by its **parent's** and by the
//! **next block's** header (the block after it on the job's chain, not a sibling at its height), both
//! fetched through the job's own `evm-rpc/v1` source ([`super::fetch_through_job`]) and checked
//! against their hashes before use.
//!
//! The set is the prelude's `Witness::standard_mutations`, made **lazily** here: one iterator per
//! kind over the decoded witness, round robin, so a witness of a million tiny nodes costs no more to
//! attack than its first few hundred mutations (the prelude's list holds every mutation, a node copy
//! in each insertion). The structural kinds come first and the byte flips after, so a run cut short
//! by its bound has tried every kind of change.
//!
//! Not here: a **stale proof** (the same account's or slot's proof at the parent block). A scheme-1
//! `W` carries no addresses or slot keys (the guest derives every key from pinned or authenticated
//! values), so nothing in `W` names what to fetch; and any proof under another state root fails the
//! root check the node flips and proof swaps already exercise.

use std::collections::VecDeque;
use std::sync::Arc;

use alloy_primitives::keccak256;
use hemiprove_eth_prelude::header::Header;
use hemiprove_eth_prelude::scheme1::{
    is_scheme1, ByteSelection, Mutation as S1, ProofKind, ProofRef, Witness, MAX_HEADER_WORDS,
};
use serde_json::{json, Value};

use super::{Mutation, Mutations, RpcCall, SchemeContext, SchemeMutator};

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

/// The journal header's length a scheme-1 `W` declares, `32 × nWords`, from its first 7 bytes
/// (`HPW ‖ 1 ‖ 1 ‖ nWords (u16 BE)`): what a binding must pin (plan §7.2).
pub fn header_bytes(w: &[u8]) -> Option<usize> {
    if !is_scheme1(w) {
        return None;
    }
    let n = usize::from(u16::from_be_bytes(w.get(5..7)?.try_into().ok()?));
    (1..=MAX_HEADER_WORDS).contains(&n).then_some(32 * n)
}

fn proof_label(p: ProofRef) -> String {
    match p {
        ProofRef::Account(a) => format!("account{a}"),
        ProofRef::Storage { account, slot } => format!("account{account}.slot{slot}"),
        ProofRef::Receipt(i) => format!("receipt{i}"),
        ProofRef::Transaction(i) => format!("tx{i}"),
    }
}

/// A short, stable id and a kind for a prelude mutation.
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

/// What a prelude mutation does, without the bytes it carries (a node can be large).
fn describe(m: &S1) -> String {
    match m {
        S1::WordByte { word, byte, mask } => format!("header word {word}, byte {byte} XOR {mask:#04x}"),
        S1::HeaderByte { header, byte, mask } => format!("block header {header}, byte {byte} XOR {mask:#04x}"),
        S1::ReplaceHeader { header, rlp } => format!("block header {header} replaced by a {}-byte header", rlp.len()),
        S1::DropHeader { header } => format!("block header {header} dropped"),
        S1::NodeByte { proof, node, byte, mask } => {
            format!("{} node {node}, byte {byte} XOR {mask:#04x}", proof_label(*proof))
        }
        S1::DropNode { proof, node } => format!("{} node {node} dropped", proof_label(*proof)),
        S1::InsertNode { proof, at, node } => {
            format!("{} a copy of a {}-byte node inserted at {at}", proof_label(*proof), node.len())
        }
        S1::FlipKind { proof } => format!("{} claims the other kind (inclusion for exclusion)", proof_label(*proof)),
        S1::ReplaceProof { proof, kind, nodes } => {
            format!("{} replaced by a {kind:?} proof of {} nodes", proof_label(*proof), nodes.len())
        }
        S1::SwapProofs { a, b } => format!("{} and {} swapped", proof_label(*a), proof_label(*b)),
        S1::DropProof { proof } => format!("{} dropped", proof_label(*proof)),
        S1::DuplicateProof { proof } => format!("{} duplicated", proof_label(*proof)),
        S1::AppendBytes { bytes } => format!("{} trailing byte(s) appended", bytes.len()),
        S1::TruncateBytes { len } => format!("W cut to its first {len} bytes"),
    }
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

/// Prelude mutations of one kind, made as the iterator advances.
type Kind<'a> = Box<dyn Iterator<Item = S1> + Send + 'a>;

/// One mutation of each kind in turn, until every kind is exhausted (each kind's own order kept).
struct RoundRobin<'a> {
    kinds: VecDeque<Kind<'a>>,
}

impl Iterator for RoundRobin<'_> {
    type Item = S1;

    fn next(&mut self) -> Option<S1> {
        while let Some(mut k) = self.kinds.pop_front() {
            if let Some(m) = k.next() {
                self.kinds.push_back(k);
                return Some(m);
            }
        }
        None
    }
}

fn same_list(a: ProofRef, b: ProofRef) -> bool {
    match (a, b) {
        (ProofRef::Account(_), ProofRef::Account(_))
        | (ProofRef::Receipt(_), ProofRef::Receipt(_))
        | (ProofRef::Transaction(_), ProofRef::Transaction(_)) => true,
        (ProofRef::Storage { account: x, .. }, ProofRef::Storage { account: y, .. }) => x == y,
        _ => false,
    }
}

/// The prelude's `standard_mutations(bytes)`, one lazy iterator per kind, as `(byte flips,
/// structural)`, each list in the order the kinds first appear there.
fn kinds<'a>(wit: &Arc<Witness<'a>>, bytes: ByteSelection) -> (Vec<Kind<'a>>, Vec<Kind<'a>>) {
    let proofs: Arc<Vec<ProofRef>> = Arc::new(wit.proofs());
    let n_proofs = proofs.len();
    let node_count = {
        let w = wit.clone();
        move |r: ProofRef| w.proof(r).map_or(0, |p| p.nodes.len())
    };
    // Every (proof, node), in order.
    let nodes = {
        let (proofs, count) = (proofs.clone(), node_count.clone());
        move || {
            let (proofs, count) = (proofs.clone(), count.clone());
            (0..proofs.len()).flat_map(move |i| {
                let r = proofs[i];
                (0..count(r)).map(move |node| (r, node))
            })
        }
    };
    // Every proof, in order.
    let each_proof = {
        let proofs = proofs.clone();
        move || {
            let proofs = proofs.clone();
            (0..proofs.len()).map(move |i| proofs[i])
        }
    };

    let word_byte: Kind<'a> = Box::new(
        (0..wit.header_words.len()).flat_map(|word| [0usize, 31].map(|byte| S1::WordByte { word, byte, mask: 0x01 })),
    );
    let header_byte: Kind<'a> = {
        let w = wit.clone();
        Box::new((0..w.headers.len()).flat_map(move |header| {
            bytes.positions(w.headers[header].len()).into_iter().map(move |byte| S1::HeaderByte {
                header,
                byte,
                mask: 0x01,
            })
        }))
    };
    let drop_header: Kind<'a> = Box::new((0..wit.headers.len()).map(|header| S1::DropHeader { header }));
    let node_byte: Kind<'a> = {
        let w = wit.clone();
        Box::new(nodes().flat_map(move |(r, node)| {
            let len = w.proof(r).expect("listed").nodes[node].len();
            bytes.positions(len).into_iter().map(move |byte| S1::NodeByte { proof: r, node, byte, mask: 0x01 })
        }))
    };
    let drop_node: Kind<'a> = Box::new(nodes().map(|(r, node)| S1::DropNode { proof: r, node }));
    let insert_node: Kind<'a> = {
        let (w, count) = (wit.clone(), node_count.clone());
        // Each node again before itself, then the first node after the last; the copy made now.
        Box::new(each_proof().flat_map(move |r| {
            let n = count(r);
            let w = w.clone();
            (0..n + usize::from(n > 0)).map(move |k| {
                let p = w.proof(r).expect("listed");
                let (at, from) = if k < n { (k, k) } else { (n, 0) };
                S1::InsertNode { proof: r, at, node: p.nodes[from].to_vec() }
            })
        }))
    };
    let flip_kind: Kind<'a> = Box::new(each_proof().map(|r| S1::FlipKind { proof: r }));
    let replace_proof: Kind<'a> = {
        let (w, w2, proofs) = (wit.clone(), wit.clone(), proofs.clone());
        // Each inclusion proof by its truncation and by the empty proof, both claiming exclusion;
        let own = each_proof().flat_map(move |r| {
            let p = w.proof(r).expect("listed");
            let inclusion = p.kind == ProofKind::Inclusion && !p.nodes.is_empty();
            let truncated: Vec<Vec<u8>> =
                if inclusion { p.nodes[..p.nodes.len() - 1].iter().map(|n| n.to_vec()).collect() } else { Vec::new() };
            let both = inclusion.then(|| {
                [
                    S1::ReplaceProof { proof: r, kind: ProofKind::Exclusion, nodes: truncated },
                    S1::ReplaceProof { proof: r, kind: ProofKind::Exclusion, nodes: Vec::new() },
                ]
            });
            both.into_iter().flatten()
        });
        // then each storage proof by the next slot's.
        let next = (0..n_proofs.saturating_sub(1)).filter_map(move |i| match (proofs[i], proofs[i + 1]) {
            (a @ ProofRef::Storage { account: x, .. }, b @ ProofRef::Storage { account: y, .. }) if x == y => {
                let other = w2.proof(b).expect("listed");
                Some(S1::ReplaceProof {
                    proof: a,
                    kind: other.kind,
                    nodes: other.nodes.iter().map(|n| n.to_vec()).collect(),
                })
            }
            _ => None,
        });
        Box::new(own.chain(next))
    };
    let drop_proof: Kind<'a> = Box::new(each_proof().map(|r| S1::DropProof { proof: r }));
    let duplicate_proof: Kind<'a> = Box::new(each_proof().map(|r| S1::DuplicateProof { proof: r }));
    let swap_proofs: Kind<'a> = {
        let (a, b) = (proofs.clone(), proofs.clone());
        let neighbours = (0..n_proofs.saturating_sub(1))
            .filter(move |&i| same_list(a[i], a[i + 1]))
            .map(move |i| S1::SwapProofs { a: b[i], b: b[i + 1] });
        let accounts =
            (1..wit.accounts.len()).map(|a| S1::SwapProofs { a: ProofRef::Account(0), b: ProofRef::Account(a) });
        Box::new(neighbours.chain(accounts))
    };
    let append: Kind<'a> = Box::new([vec![0u8], vec![0u8; 32]].into_iter().map(|bytes| S1::AppendBytes { bytes }));
    let truncate: Kind<'a> = {
        let len = wit.encode().map(|e| e.len()).unwrap_or(1);
        Box::new(std::iter::once(S1::TruncateBytes { len: len.saturating_sub(1) }))
    };
    (
        vec![word_byte, header_byte, node_byte],
        vec![
            drop_header,
            drop_node,
            insert_node,
            flip_kind,
            replace_proof,
            drop_proof,
            duplicate_proof,
            swap_proofs,
            append,
            truncate,
        ],
    )
}

/// Which fetched header replaced the block header: `(id, the block it is from)`.
type SwappedIn = (&'static str, &'static str);

fn to_mutation<'a>(wit: Arc<Witness<'a>>, m: S1, swapped_in: Option<SwappedIn>) -> Mutation<'a> {
    let (mut id, kind) = label(&m);
    let mut description = describe(&m);
    if let Some((which, block)) = swapped_in {
        id = format!("header0={which}");
        description = format!("the block header replaced by {block}'s, fetched through the job's evm-rpc source");
    }
    Mutation::new(format!("scheme1:{id}"), kind, description, move || wit.mutate(&m).ok())
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

    fn header_bytes(&self, w: &[u8]) -> Option<usize> {
        header_bytes(w)
    }

    fn mutations<'a>(&self, w: &'a [u8], ctx: &SchemeContext<'_>) -> Result<Mutations<'a>, String> {
        let wit = Arc::new(decode(w)?);
        let mut swapped: Vec<(S1, Option<SwappedIn>)> = Vec::new();
        let blocks: [SwappedIn; 2] =
            [("parent", "the parent"), ("next-block", "the next block (the one after it, not a sibling)")];
        for (answer, which) in ctx.answers.iter().zip(blocks) {
            if let Some(rlp) = answer.as_ref().and_then(header_rlp) {
                swapped.push((S1::ReplaceHeader { header: 0, rlp }, Some(which)));
            }
        }
        let (flips, structural) = kinds(&wit, self.bytes);
        let lazy = RoundRobin { kinds: structural.into() }.chain(RoundRobin { kinds: flips.into() }).map(|m| (m, None));
        Ok(Box::new(swapped.into_iter().chain(lazy).map(move |(m, which)| to_mutation(wit.clone(), m, which))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hemiprove_eth_prelude::scheme1::{scheme_word, AccountProof, ProofKind, TrieProof};
    use std::borrow::Cow;

    /// The mutations that apply (as the run skips the others), with their bytes.
    fn applied<'a>(ms: Mutations<'a>, max: usize) -> Vec<(Mutation<'a>, Vec<u8>)> {
        ms.filter_map(|m| m.make().map(|b| (m, b))).take(max).collect()
    }

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
        let ms =
            applied(s.mutations(&w, &SchemeContext { statement: &[], seed: 0, answers: &answers }).unwrap(), 1_000);
        assert_eq!(ms[0].0.id, "scheme1:header0=parent");
        assert!(ms.iter().any(|(m, _)| m.kind == "flip-kind"));
        assert!(ms
            .iter()
            .any(|(m, _)| m.kind == "swap-proofs" && m.id == "scheme1:swap-account0.slot0-account0.slot1"));
        assert!(ms.iter().any(|(m, _)| m.kind == "replace-proof"));
        assert!(ms.iter().all(|(_, b)| *b != w));
        // Structural ones before every byte flip.
        let first_flip = ms.iter().position(|(m, _)| m.kind.ends_with("-byte")).unwrap();
        assert!(ms[first_flip..].iter().all(|(m, _)| m.kind.ends_with("-byte")));
        // A short run still tries every structural kind first.
        let few = applied(s.mutations(&w, &SchemeContext { statement: &[], seed: 0, answers: &[] }).unwrap(), 12);
        assert_eq!(few.len(), 12);
        let kinds: std::collections::BTreeSet<&str> = few.iter().map(|(m, _)| m.kind.as_str()).collect();
        for k in ["drop-header", "drop-node", "insert-node", "flip-kind", "replace-proof", "drop-proof", "duplicate-proof", "swap-proofs"] {
            assert!(kinds.contains(k), "{k} missing from {kinds:?}");
        }
        // Another layout is reported, not mutated.
        assert!(s.requests(b"not a witness").is_err());
        assert!(s.mutations(b"not a witness", &SchemeContext { statement: &[], seed: 0, answers: &[] }).is_err());
    }

    /// Every kind of item: headers, accounts with storage, an exclusion proof, receipts, transactions.
    fn full_witness() -> Vec<u8> {
        let node = |b: u8, n: usize| Cow::Owned(vec![b; n]);
        let proof = |b: u8, k: usize| TrieProof {
            kind: ProofKind::Inclusion,
            nodes: (0..k).map(|i| node(b + i as u8, 33 + i)).collect(),
        };
        Witness {
            header_words: vec![scheme_word(), [7; 32], [8; 32]],
            headers: vec![node(0xf9, 600), node(0xf8, 300)],
            accounts: vec![
                AccountProof {
                    proof: proof(1, 3),
                    storage: vec![proof(10, 2), TrieProof { kind: ProofKind::Exclusion, nodes: vec![] }, proof(20, 1)],
                },
                AccountProof { proof: proof(30, 2), storage: vec![] },
                AccountProof {
                    proof: TrieProof { kind: ProofKind::Exclusion, nodes: vec![node(40, 50)] },
                    storage: vec![proof(50, 2)],
                },
            ],
            receipts: vec![proof(60, 2), proof(70, 3)],
            transactions: vec![proof(80, 1)],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn the_lazy_set_is_the_preludes_standard_set() {
        for w in [witness(header_json(5).1), full_witness()] {
            let wit = Witness::decode(&w).unwrap();
            for bytes in [ByteSelection::Sample(4), ByteSelection::All] {
                let mut eager: Vec<String> = wit.standard_mutations(bytes).iter().map(|m| format!("{m:?}")).collect();
                let shared = Arc::new(Witness::decode(&w).unwrap());
                let (flips, structural) = kinds(&shared, bytes);
                let mut lazy: Vec<String> =
                    flips.into_iter().chain(structural).flatten().map(|m| format!("{m:?}")).collect();
                eager.sort();
                lazy.sort();
                assert_eq!(lazy, eager, "{bytes:?}");
                // And each kind keeps the prelude's own order.
                let (flips, structural) = kinds(&shared, bytes);
                for k in flips.into_iter().chain(structural) {
                    let ours: Vec<S1> = k.collect();
                    let kind = label(&ours[0]).1;
                    let theirs: Vec<S1> =
                        wit.standard_mutations(bytes).into_iter().filter(|m| label(m).1 == kind).collect();
                    assert_eq!(ours, theirs, "{kind}");
                }
            }
        }
    }

    #[test]
    fn a_witness_of_many_tiny_nodes_is_mutated_without_listing_it() {
        // 400,000 one-byte nodes: the prelude's list would hold ~2.4M mutations, a node copy in each
        // insertion. The lazy one makes the first few hundred at once.
        let nodes = 400_000;
        let w = Witness {
            header_words: vec![scheme_word()],
            headers: vec![Cow::Owned(vec![0xc0])],
            accounts: vec![AccountProof {
                proof: TrieProof {
                    kind: ProofKind::Inclusion,
                    nodes: (0..nodes).map(|i| Cow::Owned(vec![(i % 251) as u8])).collect(),
                },
                storage: vec![],
            }],
            receipts: vec![],
            transactions: vec![],
        }
        .encode()
        .unwrap();
        let started = std::time::Instant::now();
        let ms: Vec<Mutation<'_>> = Scheme1::default()
            .mutations(&w, &SchemeContext { statement: &[], seed: 0, answers: &[] })
            .unwrap()
            .take(160)
            .collect();
        assert_eq!(ms.len(), 160);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        // Each is made on demand.
        assert!(ms[0].make().is_some_and(|b| b != w));
    }

    #[test]
    fn the_header_length_is_read_from_the_start_of_w() {
        let w = full_witness();
        assert_eq!(header_bytes(&w), Some(96));
        assert_eq!(header_bytes(&w[..7]), Some(96), "seven bytes are enough");
        assert_eq!(header_bytes(&w[..6]), None);
        assert_eq!(header_bytes(b"not a witness"), None);
        let r = super::super::default_registry();
        assert_eq!(r.header_bytes(&w), Some((1, 96)));
    }

    #[test]
    fn the_default_registry_holds_scheme_1() {
        let r = super::super::default_registry();
        assert_eq!(r.ids(), vec![1]);
        assert_eq!(r.get(1).unwrap().name(), "eth-block");
    }
}
