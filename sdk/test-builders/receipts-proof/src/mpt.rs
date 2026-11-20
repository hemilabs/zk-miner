//! A hand-rolled Merkle-Patricia trie: build from (key, value) pairs, compute the root, produce a
//! proof for a key, and verify a proof against a root.

use tiny_keccak::{Hasher, Keccak};

use crate::rlp::{item, list_items, List};

pub fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// `keccak256(rlp(""))`, the empty trie's root.
pub const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0,
    0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

pub fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 15]).collect()
}

/// Hex-prefix encoding of a nibble path (yellow paper appendix C).
fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push(((flag + 1) << 4) | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    out.extend(rest.chunks(2).map(|p| (p[0] << 4) | p[1]));
    out
}

fn decode_hex_prefix(b: &[u8]) -> Result<(Vec<u8>, bool), ProofError> {
    let (&first, rest) = b.split_first().ok_or(ProofError::BadNode)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(ProofError::BadNode);
    }
    let mut path = Vec::with_capacity(rest.len() * 2 + 1);
    if flag & 1 == 1 {
        path.push(first & 15);
    } else if first & 15 != 0 {
        return Err(ProofError::BadNode);
    }
    path.extend(nibbles(rest));
    Ok((path, flag & 2 == 2))
}

#[derive(Debug, Clone, Default)]
pub enum Node {
    #[default]
    Empty,
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, Box<Node>),
    Branch(Box<[Node; 16]>, Option<Vec<u8>>),
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

impl Node {
    fn branch() -> Box<[Node; 16]> {
        Box::default()
    }

    /// Inserts `value` at `path` (nibbles), replacing any value there.
    pub fn insert(self, path: &[u8], value: Vec<u8>) -> Node {
        match self {
            Node::Empty => Node::Leaf(path.to_vec(), value),
            Node::Leaf(p, v) => {
                if p == path {
                    return Node::Leaf(p, value);
                }
                let n = common_prefix(&p, path);
                let mut children = Self::branch();
                let mut here = None;
                for (rest, val) in [(&p[n..], v), (&path[n..], value)] {
                    match rest.split_first() {
                        None => here = Some(val),
                        Some((&i, tail)) => children[i as usize] = Node::Leaf(tail.to_vec(), val),
                    }
                }
                let b = Node::Branch(children, here);
                if n == 0 {
                    b
                } else {
                    Node::Extension(path[..n].to_vec(), Box::new(b))
                }
            }
            Node::Extension(p, child) => {
                let n = common_prefix(&p, path);
                if n == p.len() {
                    return Node::Extension(p, Box::new(child.insert(&path[n..], value)));
                }
                // Split the extension at n.
                let mut children = Self::branch();
                let tail = &p[n + 1..];
                children[p[n] as usize] = if tail.is_empty() { *child } else { Node::Extension(tail.to_vec(), child) };
                let mut b = Node::Branch(children, None);
                b = b.insert(&path[n..], value);
                if n == 0 {
                    b
                } else {
                    Node::Extension(p[..n].to_vec(), Box::new(b))
                }
            }
            Node::Branch(mut children, here) => match path.split_first() {
                None => Node::Branch(children, Some(value)),
                Some((&i, tail)) => {
                    let c = core::mem::take(&mut children[i as usize]);
                    children[i as usize] = c.insert(tail, value);
                    Node::Branch(children, here)
                }
            },
        }
    }

    /// The node's own RLP.
    pub fn encode(&self) -> Vec<u8> {
        let mut l = List::default();
        match self {
            Node::Empty => return vec![0x80],
            Node::Leaf(p, v) => {
                l.bytes(&hex_prefix(p, true)).bytes(v);
            }
            Node::Extension(p, c) => {
                l.bytes(&hex_prefix(p, false)).raw(&c.reference());
            }
            Node::Branch(children, here) => {
                for c in children.iter() {
                    l.raw(&c.reference());
                }
                l.bytes(here.as_deref().unwrap_or(&[]));
            }
        }
        l.finish()
    }

    /// How a parent refers to this node: inline below 32 bytes, else by hash.
    fn reference(&self) -> Vec<u8> {
        if let Node::Empty = self {
            return vec![0x80];
        }
        let enc = self.encode();
        if enc.len() < 32 {
            return enc;
        }
        let mut out = Vec::with_capacity(33);
        out.push(0xa0);
        out.extend_from_slice(&keccak(&enc));
        out
    }

    pub fn root(&self) -> [u8; 32] {
        match self {
            Node::Empty => EMPTY_ROOT,
            n => keccak(&n.encode()),
        }
    }

    /// The nodes from the root towards `path` that a verifier must be given (every node that is
    /// referenced by hash, the root always), in order.
    pub fn prove(&self, path: &[u8], proof: &mut Vec<Vec<u8>>, is_root: bool) {
        let enc = self.encode();
        if is_root || enc.len() >= 32 {
            proof.push(enc);
        }
        match self {
            Node::Empty | Node::Leaf(..) => {}
            Node::Extension(p, c) => {
                if path.starts_with(p) {
                    c.prove(&path[p.len()..], proof, false);
                }
            }
            Node::Branch(children, _) => {
                if let Some((&i, tail)) = path.split_first() {
                    children[i as usize].prove(tail, proof, false);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// A node the proof needs is missing.
    Short,
    /// A node's hash is not the one its parent names.
    HashMismatch(usize),
    BadNode,
    /// Proof nodes left over after the walk ended.
    Trailing,
}

impl From<alloy_rlp::Error> for ProofError {
    fn from(_: alloy_rlp::Error) -> Self {
        ProofError::BadNode
    }
}

enum Next<'a> {
    Hash([u8; 32]),
    Inline(&'a [u8]),
}

/// Walks `proof` from `root` along `key`: the value stored there, or `None` if the proof shows it
/// is absent.
pub fn verify(root: [u8; 32], key: &[u8], proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, ProofError> {
    let path = nibbles(key);
    let mut at = 0usize;
    let mut used = 0usize;
    let mut next = Next::Hash(root);
    loop {
        let node: &[u8] = match next {
            Next::Hash(h) => {
                let n = proof.get(used).ok_or(ProofError::Short)?;
                if keccak(n) != h {
                    return Err(ProofError::HashMismatch(used));
                }
                used += 1;
                n
            }
            Next::Inline(n) => n,
        };
        if node == [0x80] {
            break finish(None, used, proof);
        }
        let items = list_items(node)?;
        match items.len() {
            17 => {
                if at == path.len() {
                    let (_, v, _) = item(items[16])?;
                    break finish((!v.is_empty()).then(|| v.to_vec()), used, proof);
                }
                let raw = items[path[at] as usize];
                at += 1;
                match reference(raw)? {
                    None => break finish(None, used, proof),
                    Some(n) => next = n,
                }
            }
            2 => {
                let (_, hp, _) = item(items[0])?;
                let (p, leaf) = decode_hex_prefix(hp)?;
                if leaf {
                    let (_, v, _) = item(items[1])?;
                    let found = (path[at..] == p[..]).then(|| v.to_vec());
                    break finish(found, used, proof);
                }
                if !path[at..].starts_with(&p) || p.is_empty() {
                    break finish(None, used, proof);
                }
                at += p.len();
                match reference(items[1])? {
                    None => return Err(ProofError::BadNode),
                    Some(n) => next = n,
                }
            }
            _ => return Err(ProofError::BadNode),
        }
    }
}

fn reference(raw: &[u8]) -> Result<Option<Next<'_>>, ProofError> {
    let (is_list, payload, _) = item(raw)?;
    if is_list {
        return Ok(Some(Next::Inline(raw)));
    }
    match payload.len() {
        0 => Ok(None),
        32 => Ok(Some(Next::Hash(payload.try_into().unwrap()))),
        _ => Err(ProofError::BadNode),
    }
}

fn finish(v: Option<Vec<u8>>, used: usize, proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, ProofError> {
    if used != proof.len() {
        return Err(ProofError::Trailing);
    }
    Ok(v)
}

/// The root of a trie keyed by `rlp(index)`, as the receipts and transactions roots are.
pub fn ordered_root(values: &[Vec<u8>]) -> (Node, [u8; 32]) {
    let mut trie = Node::Empty;
    for (i, v) in values.iter().enumerate() {
        trie = trie.insert(&nibbles(&crate::rlp::index_key(i as u64)), v.clone());
    }
    let root = trie.root();
    (trie, root)
}
