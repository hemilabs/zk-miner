//! Merkle-Patricia proofs: inclusion and exclusion, strictly.
//!
//! [`verify`] walks a key's path from a trusted root through the proof's nodes and returns the
//! leaf's value (`Some`, inclusion) or proves that no leaf has that key (`None`, exclusion). A proof
//! is accepted only in the one form a canonical trie produces:
//!
//! - the root node hashes to the root; every later node is reached through a 32-byte hash its
//!   parent holds and hashes to it, and is at least 32 bytes long (a shorter node is embedded in its
//!   parent, never referenced by hash);
//! - an embedded child is an RLP list under 32 bytes inside its parent, walked without consuming a
//!   proof element;
//! - nodes are canonical RLP: a branch has 17 items, at least two non-empty children and an empty
//!   value (no key of an Ethereum trie is a prefix of another, so no branch holds a value); a leaf or
//!   extension has 2 items and a hex-prefix path with a zero pad nibble when even; an extension has
//!   a non-empty path and a branch child; a leaf has a non-empty value;
//! - the walk ends at an empty branch child, at a leaf (inclusion if its path is the rest of the key,
//!   exclusion otherwise) or where the key leaves an extension's path; **every proof element is used
//!   exactly once**, so no node can be appended, dropped or reordered;
//! - the empty trie (root [`EMPTY_ROOT`]) has exactly one proof: no nodes.
//!
//! The key is the trie key, nibble-expanded here: `keccak256(address)` or `keccak256(slot)` for the
//! state and storage tries, `rlp(index)` for the transactions and receipts tries. Callers compute it
//! from values they authenticated ([`crate::guard`]); a key taken from the witness proves nothing.

use alloc::vec::Vec;
use core::fmt;

use crate::keccak::{keccak256, EMPTY_ROOT};
use crate::rlp::{self, Item, RlpError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    Rlp(RlpError),
    /// Node `index` of the proof does not hash to the reference that leads to it.
    HashMismatch { index: usize },
    /// Node `index` is under 32 bytes but referenced by hash.
    ShortHashedNode { index: usize },
    /// The path continues through a hash the proof has no node for.
    MissingNode,
    /// The walk ended with proof nodes left over.
    TrailingNodes,
    /// The empty trie with a non-empty proof.
    NodesUnderEmptyRoot,
    /// A node with neither 2 nor 17 items.
    BadNode,
    /// A child that is neither empty, a 32-byte hash nor an embedded node under 32 bytes.
    BadChild,
    /// A branch with a value, or with fewer than two children.
    BadBranch,
    /// A hex-prefix path with an unknown flag or a non-zero pad nibble.
    BadPath,
    /// An extension with an empty path, or whose child is not a branch.
    BadExtension,
    /// A leaf with an empty value.
    EmptyLeafValue,
    /// The key ends at a branch (no Ethereum trie has such keys).
    KeyEndsAtBranch,
}

impl From<RlpError> for ProofError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rlp(e) => write!(f, "trie proof: {e}"),
            Self::HashMismatch { index } => write!(f, "trie proof: node {index} does not match its hash"),
            Self::ShortHashedNode { index } => write!(f, "trie proof: node {index} is under 32 bytes but hashed"),
            Self::MissingNode => f.write_str("trie proof: missing node"),
            Self::TrailingNodes => f.write_str("trie proof: nodes after the end of the path"),
            Self::NodesUnderEmptyRoot => f.write_str("trie proof: nodes under the empty root"),
            Self::BadNode => f.write_str("trie proof: node is neither a branch, an extension nor a leaf"),
            Self::BadChild => f.write_str("trie proof: malformed child reference"),
            Self::BadBranch => f.write_str("trie proof: non-canonical branch"),
            Self::BadPath => f.write_str("trie proof: malformed hex-prefix path"),
            Self::BadExtension => f.write_str("trie proof: non-canonical extension"),
            Self::EmptyLeafValue => f.write_str("trie proof: leaf with an empty value"),
            Self::KeyEndsAtBranch => f.write_str("trie proof: key ends at a branch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProofError {}

/// The nibbles of `key`, high nibble first.
pub fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// A hex-prefix encoded path: whether it ends at a leaf, and its nibbles.
fn decode_path(path: &[u8]) -> Result<(bool, Vec<u8>), ProofError> {
    let first = *path.first().ok_or(ProofError::BadPath)?;
    let (leaf, odd) = match first >> 4 {
        0 => (false, false),
        1 => (false, true),
        2 => (true, false),
        3 => (true, true),
        _ => return Err(ProofError::BadPath),
    };
    let mut out = Vec::with_capacity(path.len() * 2);
    if odd {
        out.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err(ProofError::BadPath);
    }
    out.extend(nibbles(&path[1..]));
    Ok((leaf, out))
}

/// Where a child reference leads.
enum Child<'a> {
    Empty,
    Hash([u8; 32]),
    Embedded(&'a [u8]),
}

fn child<'a>(item: &Item<'a>) -> Result<Child<'a>, ProofError> {
    if item.is_list() {
        // An embedded node: only a node whose encoding is under 32 bytes is embedded.
        if item.raw().len() >= 32 {
            return Err(ProofError::BadChild);
        }
        return Ok(Child::Embedded(item.raw()));
    }
    match item.bytes()? {
        [] => Ok(Child::Empty),
        b => Ok(Child::Hash(b.try_into().map_err(|_| ProofError::BadChild)?)),
    }
}

/// Walks `key` from `root` through `proof`: `Some(value)` if a leaf holds the key (the value is the
/// leaf's byte string, borrowed from the proof), `None` if the proof shows that no leaf does.
pub fn verify<'a, N: AsRef<[u8]>>(root: &[u8; 32], key: &[u8], proof: &'a [N]) -> Result<Option<&'a [u8]>, ProofError> {
    if *root == EMPTY_ROOT {
        return if proof.is_empty() { Ok(None) } else { Err(ProofError::NodesUnderEmptyRoot) };
    }
    let key = nibbles(key);
    let mut pos = 0usize;
    let mut used = 0usize;
    // The next node and whether it must be a branch (an extension's child).
    let mut node: &'a [u8] = hashed_node(proof, &mut used, root, true)?;
    let mut must_be_branch = false;
    let result = loop {
        let items = rlp::decode_exact(node)?.to_vec()?;
        let next = if items.len() == 2 {
            // A leaf or an extension.
            let (first, second) = (&items[0], &items[1]);
            let (is_leaf, path) = decode_path(first.bytes()?)?;
            if must_be_branch {
                return Err(ProofError::BadExtension);
            }
            let rest = &key[pos..];
            if is_leaf {
                let value = second.bytes()?;
                if value.is_empty() {
                    return Err(ProofError::EmptyLeafValue);
                }
                break if path == rest { Some(value) } else { None };
            }
            if path.is_empty() {
                return Err(ProofError::BadExtension);
            }
            let next = child(second)?;
            if matches!(next, Child::Empty) {
                return Err(ProofError::BadExtension);
            }
            if !rest.starts_with(&path) {
                break None;
            }
            pos += path.len();
            must_be_branch = true;
            next
        } else if items.len() == 17 {
            // A branch: 16 children, every one well-formed, at least two present; an empty value.
            if !items[16].is_empty_string() {
                return Err(ProofError::BadBranch);
            }
            let Some(&nibble) = key.get(pos) else {
                return Err(ProofError::KeyEndsAtBranch);
            };
            let mut present = 0;
            let mut selected = Child::Empty;
            for (i, c) in items[..16].iter().enumerate() {
                let r = child(c)?;
                if !matches!(r, Child::Empty) {
                    present += 1;
                }
                if i == usize::from(nibble) {
                    selected = r;
                }
            }
            if present < 2 {
                return Err(ProofError::BadBranch);
            }
            must_be_branch = false;
            pos += 1;
            match selected {
                Child::Empty => break None,
                next => next,
            }
        } else {
            return Err(ProofError::BadNode);
        };
        node = match next {
            Child::Hash(h) => hashed_node(proof, &mut used, &h, false)?,
            Child::Embedded(raw) => raw,
            Child::Empty => unreachable!("handled above"),
        };
    };
    if used != proof.len() {
        return Err(ProofError::TrailingNodes);
    }
    Ok(result)
}

/// The next proof element, checked against the hash that references it.
fn hashed_node<'a, N: AsRef<[u8]>>(proof: &'a [N], used: &mut usize, hash: &[u8; 32], root: bool) -> Result<&'a [u8], ProofError> {
    let index = *used;
    let node = proof.get(index).ok_or(ProofError::MissingNode)?.as_ref();
    // The root is hashed whatever its size; any other node under 32 bytes is embedded instead.
    if !root && node.len() < 32 {
        return Err(ProofError::ShortHashedNode { index });
    }
    if keccak256(node) != *hash {
        return Err(ProofError::HashMismatch { index });
    }
    *used += 1;
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloy_primitives::{Bytes, B256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles};
    use proptest::prelude::*;

    /// A trie of `entries` (raw keys, not hashed) built by alloy-trie, with proofs for `targets`.
    pub(crate) fn build(entries: &BTreeMap<Vec<u8>, Vec<u8>>, targets: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<Vec<u8>>>) {
        let retain: Vec<Nibbles> = targets.iter().map(|k| Nibbles::unpack(k)).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(retain.clone()));
        for (k, v) in entries {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        let root = hb.root();
        let nodes = hb.take_proof_nodes();
        let proofs = retain
            .iter()
            .map(|t| nodes.matching_nodes_sorted(t).into_iter().map(|(_, n)| n.to_vec()).collect())
            .collect();
        (root.0, proofs)
    }

    /// alloy-trie's proof retainer lists embedded nodes too; proofs (eth_getProof's, ours and the
    /// ones alloy-trie verifies) carry only hashed ones.
    pub(crate) fn hashed_only(proof: &[Vec<u8>]) -> Vec<Vec<u8>> {
        proof.iter().enumerate().filter(|(i, n)| *i == 0 || n.len() >= 32).map(|(_, n)| n.clone()).collect()
    }

    fn alloy_verify(root: [u8; 32], key: &[u8], value: Option<Vec<u8>>, proof: &[Vec<u8>]) -> bool {
        let p: Vec<Bytes> = proof.iter().map(|n| Bytes::from(n.clone())).collect();
        alloy_trie::proof::verify_proof(B256::from(root), Nibbles::unpack(key), value, &p).is_ok()
    }

    #[test]
    fn empty_trie() {
        let none: [&[u8]; 0] = [];
        assert_eq!(verify(&EMPTY_ROOT, &[1; 32], &none), Ok(None));
        assert_eq!(verify(&EMPTY_ROOT, &[1; 32], &[&[0x80u8][..]]), Err(ProofError::NodesUnderEmptyRoot));
    }

    #[test]
    fn single_short_leaf_at_the_root() {
        // A root under 32 bytes is still referenced by its hash.
        let mut entries = BTreeMap::new();
        entries.insert(vec![0x12], vec![0x34]);
        let (root, proofs) = build(&entries, &[vec![0x12], vec![0x13]]);
        assert!(proofs[0][0].len() < 32);
        assert_eq!(verify(&root, &[0x12], &hashed_only(&proofs[0])), Ok(Some(&[0x34][..])));
        assert_eq!(verify(&root, &[0x13], &hashed_only(&proofs[1])), Ok(None));
    }

    #[test]
    fn embedded_leaves_under_a_deep_branch() {
        // Keys sharing 63 nibbles: a branch at depth 63 whose leaves (empty remaining path, 1-byte
        // value) are 3 bytes long, so they are embedded in it.
        let mut entries = BTreeMap::new();
        for last in [0x00u8, 0x01, 0x0f] {
            let mut k = vec![0xab; 32];
            k[31] = 0xa0 | last;
            entries.insert(k, vec![last + 1]);
        }
        let mut absent = vec![0xab; 32];
        absent[31] = 0xa5;
        let targets: Vec<Vec<u8>> = entries.keys().cloned().chain([absent.clone()]).collect();
        let (root, proofs) = build(&entries, &targets);
        for (t, p) in targets.iter().zip(&proofs) {
            let ours = hashed_only(p);
            assert!(ours.len() < p.len() || t == &absent, "the leaf is embedded, not a proof element");
            let want = entries.get(t).cloned();
            assert_eq!(verify(&root, t, &ours).map(|v| v.map(<[u8]>::to_vec)), Ok(want.clone()));
            assert!(alloy_verify(root, t, want, &ours));
        }
    }

    #[test]
    fn every_byte_flip_of_a_proof_is_rejected() {
        let mut entries = BTreeMap::new();
        for i in 0u32..64 {
            entries.insert(keccak256(&i.to_be_bytes()).to_vec(), vec![0x80 | (i as u8); 1 + (i as usize % 40)]);
        }
        let present = keccak256(&7u32.to_be_bytes()).to_vec();
        let absent = keccak256(&1000u32.to_be_bytes()).to_vec();
        let (root, proofs) = build(&entries, &[present.clone(), absent.clone()]);
        for (key, proof) in [(&present, hashed_only(&proofs[0])), (&absent, hashed_only(&proofs[1]))] {
            let honest = verify(&root, key, &proof).unwrap().map(<[u8]>::to_vec);
            for n in 0..proof.len() {
                for b in 0..proof[n].len() {
                    let mut p = proof.clone();
                    p[n][b] ^= 0x01;
                    let got = verify(&root, key, &p).map(|v| v.map(<[u8]>::to_vec));
                    assert!(got.is_err() || got == Ok(honest.clone()), "node {n} byte {b}: {got:?}");
                }
                let mut dropped = proof.clone();
                dropped.remove(n);
                assert!(verify(&root, key, &dropped).is_err(), "dropping node {n}");
                let mut dup = proof.clone();
                dup.insert(n, proof[n].clone());
                assert!(verify(&root, key, &dup).is_err(), "duplicating node {n}");
            }
            let mut appended = proof.clone();
            appended.push(proof[0].clone());
            assert_eq!(verify(&root, key, &appended), Err(ProofError::TrailingNodes));
        }
    }

    #[test]
    fn a_proof_for_one_key_does_not_prove_another() {
        let mut entries = BTreeMap::new();
        for i in 0u32..32 {
            entries.insert(keccak256(&i.to_be_bytes()).to_vec(), vec![i as u8 + 1]);
        }
        let a = keccak256(&3u32.to_be_bytes()).to_vec();
        let b = keccak256(&4u32.to_be_bytes()).to_vec();
        let (root, proofs) = build(&entries, &[a.clone(), b.clone()]);
        // A's inclusion proof walked with B's key: B's branch child either has no node in the
        // proof (missing), a different hash (mismatch) or the walk ends early (trailing nodes).
        assert!(verify(&root, &b, &hashed_only(&proofs[0])).is_err());
        assert!(verify(&root, &a, &hashed_only(&proofs[1])).is_err());
    }

    #[test]
    fn non_canonical_nodes_are_refused() {
        // A branch with one child, hashed as a root (so only the shape check can refuse it).
        let mut payload = Vec::new();
        rlp::encode_bytes(&mut payload, &[7; 32]);
        payload.extend([0x80; 16]);
        let mut node = Vec::new();
        rlp::encode_list(&mut node, &payload);
        let root = keccak256(&node);
        assert_eq!(verify(&root, &[0; 32], &[node.clone()]), Err(ProofError::BadBranch));
        // A leaf with an odd-flag even path (pad nibble set).
        let mut payload = Vec::new();
        rlp::encode_bytes(&mut payload, &[0x21, 0x23]);
        rlp::encode_bytes(&mut payload, &[0x05]);
        let mut leaf = Vec::new();
        rlp::encode_list(&mut leaf, &payload);
        assert_eq!(verify(&keccak256(&leaf), &[0x23], &[leaf.clone()]), Err(ProofError::BadPath));
        // A leaf with an empty value.
        let mut payload = Vec::new();
        rlp::encode_bytes(&mut payload, &[0x20, 0x23]);
        rlp::encode_bytes(&mut payload, &[]);
        let mut leaf = Vec::new();
        rlp::encode_list(&mut leaf, &payload);
        assert_eq!(verify(&keccak256(&leaf), &[0x23], &[leaf.clone()]), Err(ProofError::EmptyLeafValue));
        // A three-item node.
        let mut node = Vec::new();
        rlp::encode_list(&mut node, &[0x80, 0x80, 0x80]);
        assert_eq!(verify(&keccak256(&node), &[0], &[node.clone()]), Err(ProofError::BadNode));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Random tries of hashed keys and short values (so leaves embed): ours agrees with the
        /// trie's contents and with alloy-trie for present and absent keys.
        #[test]
        fn agrees_with_alloy_trie(
            keys in proptest::collection::btree_set(any::<u16>(), 1..80),
            values in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..40), 80),
            probes in proptest::collection::vec(any::<u16>(), 1..6),
            raw_keys in any::<bool>(),
        ) {
            let key_of = |k: u16| if raw_keys {
                // Unhashed 3-byte keys: long shared prefixes, extensions and embedded nodes.
                let b = k.to_be_bytes();
                vec![0x11, b[0], b[1]]
            } else {
                keccak256(&k.to_be_bytes()).to_vec()
            };
            let entries: BTreeMap<Vec<u8>, Vec<u8>> =
                keys.iter().zip(values.iter()).map(|(&k, v)| (key_of(k), v.clone())).collect();
            let targets: Vec<Vec<u8>> = probes.iter().map(|&p| key_of(p)).collect();
            let (root, proofs) = build(&entries, &targets);
            for (t, p) in targets.iter().zip(&proofs) {
                let ours = hashed_only(p);
                let want = entries.get(t).cloned();
                let got = verify(&root, t, &ours).map(|v| v.map(<[u8]>::to_vec));
                prop_assert_eq!(got, Ok(want.clone()));
                // alloy-trie compares the root node's hash only for nodes of 32 bytes or more; a
                // smaller root (one tiny leaf) never occurs in a state, storage, receipts or
                // transactions trie.
                if ours[0].len() >= 32 {
                    prop_assert!(alloy_verify(root, t, want, &ours));
                }
            }
        }

        /// Arbitrary bytes as proof nodes never panic.
        #[test]
        fn arbitrary_nodes_never_panic(
            nodes in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..120), 0..6),
            key in proptest::collection::vec(any::<u8>(), 0..33),
            root_is_first in any::<bool>(),
        ) {
            let root = if root_is_first && !nodes.is_empty() { keccak256(&nodes[0]) } else { [0x42; 32] };
            let _ = verify(&root, &key, &nodes);
        }
    }
}
