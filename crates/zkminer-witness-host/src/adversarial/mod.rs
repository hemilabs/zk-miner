//! Attacking a witness job's guest through its witness and its host inputs (plan §21.1 item 3,
//! `zkminer simulate --adversarial`).
//!
//! A guest must re-validate `W` against values pinned in the binding (§8), so a changed `W` must
//! either fail in the guest or give the very journal the unchanged `W` gave. A journal that changes
//! and still satisfies the binding is a statement the prover chose: a soundness failure. A journal
//! that changes in pinned bytes is refused by the router (the binding is the requester's guarantee,
//! §7.2), which is how a guest that commits what it computed from `W` (a header hash) rejects a
//! changed header.
//!
//! This module holds:
//!
//! - the **mutations**: [`generic_mutations`] for any `W` (byte flips at sampled offsets,
//!   truncations, trailing bytes, and the duplicate / drop / reorder of length-delimited items in
//!   every framing [`framings`] recognises: u32 or u64 length prefixes, risc0's word-padded
//!   `Vec<u8>`, a top-level RLP list), and a **per-scheme hook** ([`SchemeMutator`], registered by
//!   scheme id in a [`SchemeRegistry`]) for structured mutations a scheme's codec knows (§21.1: swap
//!   in the parent header, another slot's proof, inclusion for exclusion, …);
//! - the **classification** of one re-executed `W` ([`classify`]);
//! - the **drivers**, which execute through [`crate::pipeline::execute_once`], the pipeline's own
//!   sandboxed worker, request and seed derivation: [`run_mutations`] and [`host_input_checks`]
//!   (the rule's `sys_rand` seed and a random one, two po2s, two keccak po2s: any journal change is
//!   a dependence on a prover-controlled host input). Both stop at a deadline and report what they
//!   did not run.
//!
//! **Memory.** `W` is the requester's, up to `[witness] max_witness_bytes`, and this runs outside any
//! sandbox. A [`Mutation`] is a description; its changed `W` is made ([`Mutation::make`]) only just
//! before it runs and dropped after, and repeats are recognised by the sha256 of what they made. So a
//! run holds `W`, one changed `W` and the working copies that one change needs, whatever the number
//! of mutations; the scheme mutators enumerate lazily too.
//!
//! **Cycles.** Every re-execution runs under this host's maximum, not the job's `maxGuestCycles`:
//! the router never checks cycles at fulfil, so a changed `W` that runs longer than the job declares
//! can still be proven by a prover with the hardware for it, and its journal is judged like any
//! other. Only a run stopped at the host's maximum, with no journal to judge, is inconclusive.
//!
//! Every mutation is deterministic for a given `W` and run seed, so a failure reproduces.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::{Address, B256};
use hemiprove_eth_prelude::scheme1::{judge_with, Verdict};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zkminer_chain::binding::check_journal_binding;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_prover_protocol::{WitnessExecuteResponse, GUEST_EXIT_HALTED};
use zkminer_witness::binding::PREFIX_BYTES;
use zkminer_witness::verdict::SkipReason;

use crate::abort::AbortToken;
use crate::pipeline::{check_execution, execute_once, ExecuteOnce, HostContext, Skip};

/// One change to `W`, described: [`Mutation::make`] builds the changed bytes only when they are
/// about to run.
pub struct Mutation<'a> {
    /// Unique within a run, and the same for the same `W` and seed: `flip@120^0x04`, `truncate@96`,
    /// `u32le:drop#2`, `scheme1:header0=parent`, …
    pub id: String,
    /// The family (`flip`, `truncate`, `append`, `item-drop`, `item-duplicate`, `item-swap`, or a
    /// scheme's own).
    pub kind: String,
    pub description: String,
    make: Box<dyn Fn() -> Option<Vec<u8>> + Send + Sync + 'a>,
}

impl<'a> Mutation<'a> {
    pub fn new(
        id: impl Into<String>,
        kind: impl Into<String>,
        description: impl Into<String>,
        make: impl Fn() -> Option<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        Mutation { id: id.into(), kind: kind.into(), description: description.into(), make: Box::new(make) }
    }

    /// A mutation whose bytes are already made (a test, a small fixed change).
    pub fn of_bytes(
        id: impl Into<String>,
        kind: impl Into<String>,
        description: impl Into<String>,
        w: Vec<u8>,
    ) -> Self {
        Self::new(id, kind, description, move || Some(w.clone()))
    }

    /// The changed `W`, or `None` when this mutation does not apply to it (it names nothing `W`
    /// has, or changes nothing).
    pub fn make(&self) -> Option<Vec<u8>> {
        (self.make)()
    }
}

impl std::fmt::Debug for Mutation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mutation").field("id", &self.id).field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// Mutations in the order they should run, made lazily.
pub type Mutations<'a> = Box<dyn Iterator<Item = Mutation<'a>> + Send + 'a>;

/// One JSON-RPC call a scheme's mutator wants answered through the job's own `evm-rpc/v1` source
/// (§21.1: the parent's or the next block's header to swap in), sent as a builder's fetch through
/// the broker ([`fetch_through_job`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCall {
    pub method: String,
    pub params: serde_json::Value,
}

/// What a scheme's mutator may read about the job besides `W`.
#[derive(Debug, Clone)]
pub struct SchemeContext<'a> {
    /// The unchanged `W`'s journal after any prefix (the header first, §7.2).
    pub statement: &'a [u8],
    /// The run's seed, for any sampling the mutator does.
    pub seed: u64,
    /// The answers to [`SchemeMutator::requests`], in its order: each call's `result`, or `None`
    /// when it failed or was not sent.
    pub answers: &'a [Option<serde_json::Value>],
}

/// Structured mutations of one scheme's `W` (§8.1, §21.1). A scheme's reference codec knows where
/// headers, trie nodes, proofs and leaves sit; the generic mutations do not. Implementations are
/// registered by scheme id in a [`SchemeRegistry`].
pub trait SchemeMutator: Send + Sync {
    /// The scheme id (§8.1: 1 `eth-block`, 2 `content-hash`, …).
    fn scheme_id(&self) -> u64;
    /// A short name for reports.
    fn name(&self) -> &'static str;
    /// Calls whose answers [`Self::mutations`] uses, sent through the job's first `evm-rpc/v1`
    /// source before it is asked. `Err` when `w` does not decode as this scheme's witness.
    fn requests(&self, _w: &[u8]) -> Result<Vec<RpcCall>, String> {
        Ok(Vec::new())
    }
    /// The length of the journal header `w` declares (scheme 1: `32 × nWords`), the bytes a binding
    /// must pin (§7.2); `None` when `w` is not this scheme's. `w` may be only the start of `W`.
    fn header_bytes(&self, _w: &[u8]) -> Option<usize> {
        None
    }
    /// This scheme's mutations of `w`, most telling first, made lazily: the caller takes as many as
    /// its bound allows and makes each just before it runs. `Err` when `w` does not decode as this
    /// scheme's witness (a report line, not a failure of the run: the guest may use another layout).
    fn mutations<'a>(&self, w: &'a [u8], ctx: &SchemeContext<'_>) -> Result<Mutations<'a>, String>;
}

pub mod scheme1;

/// The scheme mutators this build knows: scheme 1 (`eth-block`), from the reference prelude's
/// codec ([`scheme1::Scheme1`]).
pub fn default_registry() -> SchemeRegistry {
    let mut r = SchemeRegistry::new();
    r.register(Box::new(scheme1::Scheme1::default()));
    r
}

/// Sends `calls` through `broker` as a builder's fetches would go (a job registered with the
/// envelope's `sources` and a budget of exactly these calls, the request on the job socket naming
/// capability `cap`), so they reach only the operator's endpoints for that source, through the
/// miner's connector and network guard. Each answer is the call's `result`, `None` when the fetch
/// or the call failed or `deadline` came first.
pub async fn fetch_through_job(
    broker: &zkminer_witness_broker::client::BrokerClient,
    caller: Address,
    sources: Vec<(B256, Vec<u8>)>,
    cap: u32,
    calls: &[RpcCall],
    deadline: Instant,
) -> Vec<Option<serde_json::Value>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zkminer_witness::ipc::{
        decode_fetch_result, encode_fetch, fetch_result_frame_max, FetchStatus, FRAME_HEADER_BYTES, KIND_FETCH,
        KIND_FETCH_RESULT,
    };
    const MAX_RESPONSE: u32 = 4 << 20;
    const PER_CALL: std::time::Duration = std::time::Duration::from_secs(60);
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut out = vec![None; calls.len()];
    if calls.is_empty() {
        return out;
    }
    let job_key = alloy_primitives::keccak256(
        [b"zkminer/adversarial/fetch".as_slice(), &std::process::id().to_be_bytes(), &N.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_be_bytes()]
            .concat(),
    );
    let Ok((ours, broker_end)) = zkminer_witness_broker::client::job_socketpair() else { return out };
    let reg = zkminer_witness_broker::client::JobRegistration {
        job_key,
        caller,
        sources,
        budget: zkminer_witness::ipc::JobBudget {
            max_fetches: calls.len() as u32,
            max_fetch_bytes: u64::from(MAX_RESPONSE) * calls.len() as u64,
            max_request_bytes: 65_536,
            max_response_bytes: MAX_RESPONSE,
        },
        held_lock: false,
    };
    let within = PER_CALL.min(deadline.saturating_duration_since(Instant::now()));
    if !matches!(tokio::time::timeout(within, broker.register_job(reg, broker_end)).await, Ok(Ok(_))) {
        return out;
    }
    let sock = ours.set_nonblocking(true).ok().and_then(|()| tokio::net::UnixStream::from_std(ours).ok());
    if let Some(mut sock) = sock {
        for (i, c) in calls.iter().enumerate() {
            let body = serde_json::json!({"jsonrpc": "2.0", "id": i + 1, "method": c.method, "params": c.params});
            let payload = encode_fetch(cap, body.to_string().as_bytes());
            let mut frame = vec![KIND_FETCH];
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            let exchange = async {
                sock.write_all(&frame).await.ok()?;
                let mut h = [0u8; FRAME_HEADER_BYTES];
                sock.read_exact(&mut h).await.ok()?;
                let len = u32::from_be_bytes(h[1..].try_into().ok()?);
                if h[0] != KIND_FETCH_RESULT || len > fetch_result_frame_max(MAX_RESPONSE) {
                    return None;
                }
                let mut p = vec![0u8; len as usize];
                sock.read_exact(&mut p).await.ok()?;
                let (status, body) = decode_fetch_result(&p).ok()?;
                if status != FetchStatus::Ok {
                    return None;
                }
                let v: serde_json::Value = serde_json::from_slice(body).ok()?;
                v.get("result").filter(|r| !r.is_null()).cloned()
            };
            let within = PER_CALL.min(deadline.saturating_duration_since(Instant::now()));
            match tokio::time::timeout(within, exchange).await {
                Ok(answer) => out[i] = answer,
                Err(_) => break,
            }
        }
    }
    let _ = tokio::time::timeout(PER_CALL, broker.end_job(job_key)).await;
    out
}

/// Scheme mutators by scheme id.
#[derive(Default)]
pub struct SchemeRegistry {
    by_id: BTreeMap<u64, Box<dyn SchemeMutator>>,
}

impl SchemeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `m`, replacing any mutator registered for its scheme id.
    pub fn register(&mut self, m: Box<dyn SchemeMutator>) {
        self.by_id.insert(m.scheme_id(), m);
    }

    pub fn get(&self, scheme_id: u64) -> Option<&dyn SchemeMutator> {
        self.by_id.get(&scheme_id).map(|b| b.as_ref())
    }

    pub fn ids(&self) -> Vec<u64> {
        self.by_id.keys().copied().collect()
    }

    /// The journal header's length a registered scheme reads from `w` (the start of `W` is
    /// enough), with that scheme's id.
    pub fn header_bytes(&self, w: &[u8]) -> Option<(u64, usize)> {
        self.by_id.iter().find_map(|(id, m)| m.header_bytes(w).map(|h| (*id, h)))
    }
}

/// The scheme id a statement names: its first header word, when it is a small integer (§7.2: the
/// header starts with `schemeId`). `None` for a statement shorter than a word or a first word that is
/// not one (a guest with another layout).
pub fn scheme_id_of(statement: &[u8]) -> Option<u64> {
    let w = statement.get(..32)?;
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().ok()?))
}

/// SplitMix64: a small deterministic generator for sampling offsets (not for anything secret).
#[derive(Debug, Clone)]
pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        SplitMix(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// The run seed for `w`: from its sha256, so the same `W` is mutated the same way.
pub fn seed_for(w: &[u8], salt: u64) -> u64 {
    let h = Sha256::digest(w);
    u64::from_be_bytes(h[..8].try_into().expect("8 bytes")) ^ salt
}

/// A recognised framing of `W` as a sequence of length-delimited items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framing {
    /// `u32le`, `u32be`, `u64le`, `u32le-pad4` (risc0's serde `Vec<u8>`: a u32 length, the bytes
    /// padded to a word), `rlp-list`.
    pub name: &'static str,
    /// Each item's byte range in `W` (prefix included), in order; they tile `W` (for `rlp-list`,
    /// the list payload).
    pub items: Vec<std::ops::Range<usize>>,
}

const MAX_FRAMED_ITEMS: usize = 1 << 16;

/// Splits `w` into length-prefixed items of a fixed prefix width, `pad` aligning each body, or
/// `None` unless they tile `w` exactly with at least two items.
fn split_prefixed(w: &[u8], width: usize, big_endian: bool, pad: usize) -> Option<Vec<std::ops::Range<usize>>> {
    let mut at = 0usize;
    let mut items = Vec::new();
    while at < w.len() {
        let head = w.get(at..at + width)?;
        let len = match (width, big_endian) {
            (4, false) => u32::from_le_bytes(head.try_into().ok()?) as u64,
            (4, true) => u32::from_be_bytes(head.try_into().ok()?) as u64,
            (8, false) => u64::from_le_bytes(head.try_into().ok()?),
            _ => return None,
        };
        let body = usize::try_from(len).ok()?;
        let padded = body.checked_add(pad - 1)? / pad * pad;
        let end = at.checked_add(width)?.checked_add(padded)?;
        if end > w.len() {
            return None;
        }
        items.push(at..end);
        if items.len() > MAX_FRAMED_ITEMS {
            return None;
        }
        at = end;
    }
    (items.len() >= 2).then_some(items)
}

/// One RLP item's header: `(header length, payload length, is a list)`, or `None` if malformed.
fn rlp_header(b: &[u8]) -> Option<(usize, usize, bool)> {
    let first = *b.first()?;
    match first {
        0x00..=0x7f => Some((0, 1, false)),
        0x80..=0xb7 => Some((1, (first - 0x80) as usize, false)),
        0xb8..=0xbf => {
            let n = (first - 0xb7) as usize;
            let len = be_len(b.get(1..1 + n)?)?;
            Some((1 + n, len, false))
        }
        0xc0..=0xf7 => Some((1, (first - 0xc0) as usize, true)),
        0xf8..=0xff => {
            let n = (first - 0xf7) as usize;
            let len = be_len(b.get(1..1 + n)?)?;
            Some((1 + n, len, true))
        }
    }
}

fn be_len(b: &[u8]) -> Option<usize> {
    if b.is_empty() || b.len() > 8 || b[0] == 0 {
        return None;
    }
    let mut v = 0u64;
    for &x in b {
        v = (v << 8) | u64::from(x);
    }
    usize::try_from(v).ok()
}

/// The items of `w` when it is exactly one top-level RLP list of at least two items.
fn split_rlp_list(w: &[u8]) -> Option<(usize, Vec<std::ops::Range<usize>>)> {
    let (h, len, list) = rlp_header(w)?;
    if !list || h + len != w.len() {
        return None;
    }
    let mut at = h;
    let mut items = Vec::new();
    while at < w.len() {
        let (ih, il, _) = rlp_header(&w[at..])?;
        let end = at.checked_add(ih)?.checked_add(il)?;
        if end > w.len() {
            return None;
        }
        items.push(at..end);
        if items.len() > MAX_FRAMED_ITEMS {
            return None;
        }
        at = end;
    }
    (items.len() >= 2).then_some((h, items))
}

/// An RLP list header for a payload of `len` bytes.
fn rlp_list_header(len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![0xc0 + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().position(|&b| b != 0).unwrap_or(7);
        let mut out = vec![0xf7 + (8 - skip) as u8];
        out.extend_from_slice(&be[skip..]);
        out
    }
}

/// Every framing `w` parses as exactly.
pub fn framings(w: &[u8]) -> Vec<Framing> {
    let mut out = Vec::new();
    for (name, width, be, pad) in [("u32le", 4, false, 1), ("u32be", 4, true, 1), ("u64le", 8, false, 1), ("u32le-pad4", 4, false, 4)] {
        if let Some(items) = split_prefixed(w, width, be, pad) {
            // A padded framing that tiles identically to the unpadded one adds nothing.
            if !out.iter().any(|f: &Framing| f.items == items) {
                out.push(Framing { name, items });
            }
        }
    }
    if let Some((_, items)) = split_rlp_list(w) {
        out.push(Framing { name: "rlp-list", items });
    }
    out
}

/// One rearrangement of a framing's items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemOp {
    Drop(usize),
    Duplicate(usize),
    Swap(usize, usize),
}

impl ItemOp {
    /// The new item order for `n` items (indices into the framing's items, repeats allowed).
    fn order(self, n: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..n).collect();
        match self {
            ItemOp::Drop(i) => {
                order.remove(i);
            }
            ItemOp::Duplicate(i) => order.insert(i + 1, i),
            ItemOp::Swap(a, b) => order.swap(a, b),
        }
        order
    }
}

/// `w` with its items rearranged as `order` says (indices into `f.items`, repeats allowed): the
/// bytes before the first item and after the last kept as they are, an RLP list's header rewritten
/// for the new payload.
fn reframe(w: &[u8], f: &Framing, order: &[usize]) -> Vec<u8> {
    let mut payload = Vec::new();
    for &i in order {
        payload.extend_from_slice(&w[f.items[i].clone()]);
    }
    if f.name == "rlp-list" {
        let mut out = rlp_list_header(payload.len());
        out.extend_from_slice(&payload);
        out
    } else {
        let start = f.items.first().map_or(0, |r| r.start);
        let end = f.items.last().map_or(w.len(), |r| r.end);
        let mut out = w[..start].to_vec();
        out.extend_from_slice(&payload);
        out.extend_from_slice(&w[end..]);
        out
    }
}

/// The item mutations of one framing: drop the first, a middle and the last item, duplicate the
/// first and the last, swap the first two and the last two (each once, however few the items).
fn item_mutations<'a>(w: &'a [u8], f: Arc<Framing>) -> Vec<Mutation<'a>> {
    let n = f.items.len();
    let mut ops = Vec::new();
    for i in [0, n / 2, n - 1] {
        ops.push(ItemOp::Drop(i));
    }
    for i in [0, n - 1] {
        ops.push(ItemOp::Duplicate(i));
    }
    for (a, b) in [(0, 1), (n - 2, n - 1)] {
        ops.push(ItemOp::Swap(a, b));
    }
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for op in ops {
        if seen.contains(&op) {
            continue;
        }
        seen.push(op);
        let (id, kind, desc) = match op {
            ItemOp::Drop(i) => {
                (format!("{}:drop#{i}", f.name), "item-drop", format!("drop item {i} of {n} ({} framing)", f.name))
            }
            ItemOp::Duplicate(i) => (
                format!("{}:duplicate#{i}", f.name),
                "item-duplicate",
                format!("duplicate item {i} of {n} ({} framing)", f.name),
            ),
            ItemOp::Swap(a, b) => (
                format!("{}:swap#{a}-{b}", f.name),
                "item-swap",
                format!("swap items {a} and {b} of {n} ({} framing)", f.name),
            ),
        };
        let f = f.clone();
        out.push(Mutation::new(id, kind, desc, move || Some(reframe(w, &f, &op.order(f.items.len())))));
    }
    out
}

/// The generic mutations of `w`: `flips` single-byte changes at sampled offsets (the first and last
/// byte always among them, the rest drawn from `seed`, each XOR a nonzero byte), truncations (to 0,
/// half, all but one word and all but one byte), trailing bytes (one zero, one 0xff, a zero word),
/// and the item mutations of every framing `w` parses as. Each is made only when it runs; a
/// mutation that makes `W` itself or a repeat is recognised then ([`run_mutations`]).
pub fn generic_mutations(w: &[u8], seed: u64, flips: usize) -> Vec<Mutation<'_>> {
    let mut out: Vec<Mutation<'_>> = Vec::new();
    let mut rng = SplitMix::new(seed);
    if !w.is_empty() {
        let mut offsets: Vec<usize> = vec![0];
        if w.len() > 1 {
            offsets.push(w.len() - 1);
        }
        let mut tries = 0;
        while offsets.len() < flips.min(w.len()) && tries < 16 * flips {
            let o = rng.below(w.len());
            if !offsets.contains(&o) {
                offsets.push(o);
            }
            tries += 1;
        }
        offsets.truncate(flips.max(1).min(w.len()));
        offsets.sort_unstable();
        for o in offsets {
            let x = (rng.below(255) + 1) as u8;
            out.push(Mutation::new(
                format!("flip@{o}^{x:#04x}"),
                "flip",
                format!("byte {o} XOR {x:#04x}"),
                move || {
                    let mut m = w.to_vec();
                    m[o] ^= x;
                    Some(m)
                },
            ));
        }
    }
    let mut cuts = vec![0, w.len() / 2, w.len().saturating_sub(32), w.len().saturating_sub(1)];
    cuts.sort_unstable();
    cuts.dedup();
    for c in cuts {
        if c < w.len() {
            out.push(Mutation::new(
                format!("truncate@{c}"),
                "truncate",
                format!("W cut to its first {c} bytes"),
                move || Some(w[..c].to_vec()),
            ));
        }
    }
    for (id, tail) in [("append:00", vec![0u8]), ("append:ff", vec![0xff]), ("append:32x00", vec![0u8; 32])] {
        let desc = format!("{} trailing byte(s) appended", tail.len());
        out.push(Mutation::new(id, "append", desc, move || {
            let mut m = w.to_vec();
            m.extend_from_slice(&tail);
            Some(m)
        }));
    }
    for f in framings(w) {
        out.extend(item_mutations(w, Arc::new(f)));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Classification.

/// How one re-executed `W` came out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MutationOutcome {
    /// The guest refused it: a non-zero exit, a fault, a panic.
    RejectedInGuest { why: String },
    /// The guest committed the unchanged `W`'s journal, byte for byte.
    IdenticalJournal,
    /// The journal changed in bytes the binding pins: the router refuses that proof.
    BindingRejects { journal_sha256: B256 },
    /// The journal changed and still satisfies the binding: the prover chose the statement. A
    /// soundness failure of the guest (or of the binding).
    SoundnessFailure { journal_sha256: B256, first_difference: usize },
    /// This host could not run it to a journal (sandbox, worker, memory, time, or its own cycle
    /// maximum): says nothing about the guest.
    Inconclusive { why: String },
    /// Not run: the run's time ran out first.
    NotRun,
}

impl MutationOutcome {
    pub fn is_soundness_failure(&self) -> bool {
        matches!(self, MutationOutcome::SoundnessFailure { .. })
    }
}

/// The job facts a classification needs.
#[derive(Clone)]
pub struct Judge<'a> {
    pub descriptor: &'a JobDescriptor,
    pub job_id: B256,
    pub prover: Address,
    /// The unchanged `W`'s journal (prefix included, as the worker reports it).
    pub baseline_journal: &'a [u8],
}

/// The cycle limits a re-execution is judged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleLimits {
    /// This host's maximum: the cap every re-execution runs under.
    pub host: u64,
    /// The job's `maxGuestCycles`: a run past it is reported as such, and judged all the same.
    pub job: u64,
}

fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()))
}

fn sha(b: &[u8]) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::digest(b)))
}

fn over_host_cap(limits: CycleLimits) -> String {
    format!(
        "ran past this host's maximum of {} sized cycles (the job declares {}): no journal to judge",
        limits.host, limits.job
    )
}

/// Classifies one execute of a changed `W` (see [`MutationOutcome`]), with the largest sized cycle
/// count of its po2s when it halted.
pub fn classify(
    judge: &Judge<'_>,
    result: Result<WitnessExecuteResponse, Skip>,
    po2s: &[u8],
    limits: CycleLimits,
) -> (MutationOutcome, Option<u64>) {
    let resp = match result {
        Ok(r) => r,
        Err(Skip::Aborted { reason, .. }) => {
            return (MutationOutcome::Inconclusive { why: format!("aborted: {reason:?}") }, None)
        }
        Err(Skip::Verdict { reason, detail, .. }) => {
            let outcome = match reason {
                SkipReason::GuestFailed => {
                    MutationOutcome::RejectedInGuest { why: format!("{reason:?}: {}", tail(&detail)) }
                }
                SkipReason::GuestCyclesAboveLimit => MutationOutcome::Inconclusive { why: over_host_cap(limits) },
                _ => MutationOutcome::Inconclusive { why: format!("{reason:?}: {}", tail(&detail)) },
            };
            return (outcome, None);
        }
    };
    if resp.results.iter().any(|r| r.exit_kind != GUEST_EXIT_HALTED || r.exit_code != 0) {
        return (MutationOutcome::RejectedInGuest { why: "the guest did not halt with 0".into() }, None);
    }
    let cycles = resp.results.iter().map(|r| r.cycles).max();
    let journal = match check_execution(&resp, po2s, judge.descriptor.programId, limits.host) {
        Ok(j) => j,
        Err((SkipReason::GuestCyclesAboveLimit, _)) => {
            return (MutationOutcome::Inconclusive { why: over_host_cap(limits) }, cycles)
        }
        Err((SkipReason::GuestFailed, d)) => return (MutationOutcome::RejectedInGuest { why: d }, cycles),
        Err((r, d)) => return (MutationOutcome::Inconclusive { why: format!("{r:?}: {d}") }, cycles),
    };
    // The reference prelude's judgement, under the job's real binding as the router checks it.
    let verdict = judge_with(judge.baseline_journal, Some(&journal), |j| {
        check_journal_binding(judge.descriptor, j, judge.job_id, judge.prover).is_ok()
    });
    let outcome = match verdict {
        Verdict::Identical => MutationOutcome::IdenticalJournal,
        Verdict::BindingRejects => MutationOutcome::BindingRejects { journal_sha256: sha(&journal) },
        Verdict::Unsound => MutationOutcome::SoundnessFailure {
            journal_sha256: sha(&journal),
            first_difference: first_difference(&journal, judge.baseline_journal),
        },
        Verdict::Rejected => MutationOutcome::RejectedInGuest { why: "no journal".into() },
    };
    (outcome, cycles)
}

fn tail(s: &str) -> String {
    const MAX: usize = 512;
    let mut at = s.len().saturating_sub(MAX);
    while !s.is_char_boundary(at) {
        at += 1;
    }
    s[at..].to_string()
}

// ---------------------------------------------------------------------------------------------
// The drivers.

/// The unchanged run every attack is compared with.
pub struct Baseline<'a> {
    pub ctx: &'a HostContext,
    pub token: &'a AbortToken,
    pub elf: &'a [u8],
    pub judge: Judge<'a>,
    pub prefix: Option<[u8; PREFIX_BYTES]>,
    pub w: &'a [u8],
    /// The po2 mutations execute at (one is enough to judge a journal).
    pub po2: u8,
    /// The po2s the run was asked to execute at (`--po2`): the po2 check's alternative is one of
    /// them when there are two.
    pub po2s: &'a [u8],
    pub keccak_po2: u8,
    pub cycles: CycleLimits,
    /// The run's time bound: every execute gets at most what is left of it, and is killed there.
    pub deadline: Instant,
}

impl Baseline<'_> {
    fn late(&self) -> bool {
        Instant::now() >= self.deadline || self.token.reason().is_some()
    }

    /// One execution of `w`, under the rule's `sys_rand` seed unless `seed` names another.
    async fn execute(
        &self,
        w: &[u8],
        po2s: &[u8],
        keccak_po2: u8,
        seed: Option<[u8; 32]>,
    ) -> Result<WitnessExecuteResponse, Skip> {
        let spec = ExecuteOnce {
            elf: self.elf,
            program_id: self.judge.descriptor.programId,
            prefix: self.prefix,
            po2s,
            keccak_po2,
            sys_rand_seed: seed,
            max_cycles: self.cycles.host,
            timeout: Some(self.deadline.saturating_duration_since(Instant::now())),
        };
        execute_once(self.ctx, self.token, w, &spec).await
    }
}

/// One mutation's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult {
    pub id: String,
    pub kind: String,
    pub description: String,
    /// The changed `W`'s length (not known for one that did not run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub w_bytes: Option<usize>,
    /// The largest sized cycle count over its po2s, when it halted (a decimal string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<String>,
    /// It ran past the job's `maxGuestCycles`: a miner skips such a `W`, but the router does not
    /// check cycles, so its journal is judged all the same.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub over_job_cycles: bool,
    #[serde(flatten)]
    pub outcome: MutationOutcome,
}

/// Executes `mutations` in order at the baseline's po2 until `max` have a result or the deadline
/// passes; those left after the deadline (up to `max`) are [`MutationOutcome::NotRun`]. Each is made
/// just before it runs and dropped after. One that does not apply, or makes `W` or the bytes of an
/// earlier one (by sha256), is skipped without a result.
pub async fn run_mutations<'m>(
    b: &Baseline<'_>,
    mutations: impl IntoIterator<Item = Mutation<'m>>,
    max: usize,
) -> Vec<MutationResult> {
    let mut seen: HashSet<B256> = HashSet::from([sha(b.w)]);
    let mut out = Vec::new();
    for m in mutations {
        if out.len() >= max {
            break;
        }
        let result = |w_bytes, cycles: Option<u64>, outcome: MutationOutcome| MutationResult {
            id: m.id.clone(),
            kind: m.kind.clone(),
            description: m.description.clone(),
            w_bytes,
            over_job_cycles: cycles.is_some_and(|c| c > b.cycles.job),
            cycles: cycles.map(|c| c.to_string()),
            outcome,
        };
        if b.late() {
            out.push(result(None, None, MutationOutcome::NotRun));
            continue;
        }
        let Some(bytes) = m.make() else { continue };
        if !seen.insert(sha(&bytes)) {
            continue;
        }
        let r = b.execute(&bytes, &[b.po2], b.keccak_po2, None).await;
        // An execute the deadline cut short says nothing.
        let cut =
            Instant::now() >= b.deadline && matches!(&r, Err(Skip::Verdict { reason: SkipReason::ProveResources, .. }));
        let (outcome, cycles) =
            if cut { (MutationOutcome::NotRun, None) } else { classify(&b.judge, r, &[b.po2], b.cycles) };
        tracing::debug!(mutation = %m.id, ?outcome, "adversarial: mutation judged");
        out.push(result(Some(bytes.len()), cycles, outcome));
    }
    out
}

/// A host input a prover controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostInput {
    /// The `sys_rand` seed: zkminer seeds by a public rule, but the proof binds no seed, so a
    /// prover on other software can answer `sys_rand` with anything.
    SysRandSeed,
    /// The segment size.
    Po2,
    /// `RISC0_KECCAK_PO2`.
    KeccakPo2,
}

/// One host-input check: the same `W` under two values of one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInputResult {
    pub input: HostInput,
    /// The two values, as text (`rule`/`random` for seeds).
    pub values: [String; 2],
    /// Each value's journal sha256, when it ran to a journal.
    pub journal_sha256: [Option<B256>; 2],
    /// The journals differ, or the guest fails under one value only: the guest depends on this
    /// input, which the prover controls.
    pub dependent: bool,
    /// What else there is to know: a value whose run passed the job's `maxGuestCycles` or this
    /// host's maximum, or did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Both values were compared (a failure in the guest under one counts).
    pub ran: bool,
}

/// The alternative to `p` among the job po2s (16..=22), for the po2 check when the run was given
/// one po2: the far end of the range.
pub fn other_po2(p: u8) -> u8 {
    use zkminer_prover_protocol::{RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    if p - RISC0_JOB_PO2_MIN >= RISC0_JOB_PO2_MAX - p {
        RISC0_JOB_PO2_MIN
    } else {
        RISC0_JOB_PO2_MAX
    }
}

/// The po2 the po2 check compares `p` with: the one of `asked` farthest from it, else
/// [`other_po2`].
pub fn alternative_po2(p: u8, asked: &[u8]) -> u8 {
    asked.iter().copied().filter(|&q| q != p).max_by_key(|&q| (q.abs_diff(p), q)).unwrap_or_else(|| other_po2(p))
}

/// The alternative keccak po2 to `k`, within 14..=18 (the range the pipeline accepts).
pub fn other_keccak_po2(k: u8) -> u8 {
    if k > 14 {
        k - 1
    } else {
        k + 1
    }
}

/// Why one value of a host-input pair produced no journal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NoJournal {
    /// The guest refused it: under one value only, a dependence.
    Guest(String),
    /// It ran past this host's cycle maximum: no journal to compare, and no dependence shown.
    CycleCap(String),
    /// This host could not run it (time, memory, the sandbox, the deadline).
    Host(String),
}

/// One value's journal and its largest sized cycle count.
type Ran = Result<(B256, Vec<u8>, u64), NoJournal>;

fn journal_of(resp: &Result<WitnessExecuteResponse, Skip>, i: usize) -> Ran {
    match resp {
        Ok(r) => match r.results.get(i) {
            Some(p) if p.exit_kind == GUEST_EXIT_HALTED && p.exit_code == 0 => {
                Ok((sha(&p.journal), p.journal.clone(), p.cycles))
            }
            Some(p) => Err(NoJournal::Guest(format!("po2 {}: exit kind {} code {}", p.po2, p.exit_kind, p.exit_code))),
            None => Err(NoJournal::Host("no result".into())),
        },
        Err(Skip::Verdict { reason: SkipReason::GuestFailed, detail, .. }) => Err(NoJournal::Guest(tail(detail))),
        Err(Skip::Verdict { reason: SkipReason::GuestCyclesAboveLimit, detail, .. }) => {
            Err(NoJournal::CycleCap(tail(detail)))
        }
        Err(s) => Err(NoJournal::Host(tail(&s.to_string()))),
    }
}

fn pair_result(input: HostInput, values: [String; 2], a: Ran, b: Ran, limits: CycleLimits) -> HostInputResult {
    let (ja, jb) = (a.as_ref().ok().map(|x| x.0), b.as_ref().ok().map(|x| x.0));
    let mut notes = Vec::new();
    for (v, r) in values.iter().zip([&a, &b]) {
        match r {
            Ok((_, _, c)) if *c > limits.job => notes.push(format!(
                "{v}: {c} sized cycles, past the job's maxGuestCycles {} (a miner executing at it skips the job)",
                limits.job
            )),
            Err(NoJournal::CycleCap(e)) => {
                notes.push(format!("{v}: past this host's cycle maximum ({}): {e}", limits.host))
            }
            Err(NoJournal::Host(e)) => notes.push(format!("{v}: not run: {e}")),
            _ => {}
        }
    }
    let (dependent, ran) = match (&a, &b) {
        (Ok(x), Ok(y)) => (x.1 != y.1, true),
        (Err(NoJournal::Guest(e)), Ok(_)) => {
            notes.push(format!("only {} ran: {e}", values[1]));
            (true, true)
        }
        (Ok(_), Err(NoJournal::Guest(e))) => {
            notes.push(format!("only {} ran: {e}", values[0]));
            (true, true)
        }
        (Err(NoJournal::Guest(e)), Err(NoJournal::Guest(_))) => {
            notes.push(format!("neither ran: {e}"));
            (false, false)
        }
        _ => (false, false),
    };
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    HostInputResult { input, values, journal_sha256: [ja, jb], dependent, note, ran }
}

/// Re-executes the baseline `W` under two `sys_rand` seeds, two po2s and two keccak po2s (§21.1),
/// each value in a request of its own, each pair compared by journal, until the deadline. The seed
/// pair is the rule's (every other run's) and `other_seed`, a fresh random one: what a prover on
/// other software may answer with. The po2 pair is the baseline's po2 and [`alternative_po2`] of
/// the asked ones.
pub async fn host_input_checks(b: &Baseline<'_>, other_seed: [u8; 32]) -> Vec<HostInputResult> {
    let mut out = Vec::new();
    let skipped = |input, values: [String; 2]| HostInputResult {
        input,
        values,
        journal_sha256: [None, None],
        dependent: false,
        note: Some("not run: the run's time ran out first".into()),
        ran: false,
    };
    // The baseline's own execution at its po2, keccak po2 and the rule's seed: the first value of
    // every pair.
    let base = if b.late() {
        None
    } else {
        Some(journal_of(&b.execute(b.w, &[b.po2], b.keccak_po2, None).await, 0))
    };
    let values = ["rule (zkminer's)".to_string(), "random (another prover's)".to_string()];
    match &base {
        Some(a) if !b.late() => {
            let c = b
                .execute(b.w, &[b.po2], b.keccak_po2, Some(other_seed))
                .await;
            out.push(pair_result(HostInput::SysRandSeed, values, a.clone(), journal_of(&c, 0), b.cycles));
        }
        _ => out.push(skipped(HostInput::SysRandSeed, values)),
    }
    let p2 = alternative_po2(b.po2, b.po2s);
    let values = [b.po2.to_string(), p2.to_string()];
    match &base {
        Some(a) if !b.late() => {
            let c = b.execute(b.w, &[p2], b.keccak_po2, None).await;
            out.push(pair_result(HostInput::Po2, values, a.clone(), journal_of(&c, 0), b.cycles));
        }
        _ => out.push(skipped(HostInput::Po2, values)),
    }
    let k2 = other_keccak_po2(b.keccak_po2);
    let values = [b.keccak_po2.to_string(), k2.to_string()];
    match &base {
        Some(a) if !b.late() => {
            let c = b.execute(b.w, &[b.po2], k2, None).await;
            out.push(pair_result(HostInput::KeccakPo2, values, a.clone(), journal_of(&c, 0), b.cycles));
        }
        _ => out.push(skipped(HostInput::KeccakPo2, values)),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkminer_chain::auction::risc_zero_groth16_v1_id;
    use zkminer_prover_protocol::WitnessExecutePo2;
    use zkminer_witness::binding::{journal_fields_for_header, journal_prefix};

    fn made(ms: &[Mutation<'_>]) -> Vec<(String, Option<Vec<u8>>)> {
        ms.iter().map(|m| (m.id.clone(), m.make())).collect()
    }

    #[test]
    fn generic_mutations_are_deterministic_distinct_and_never_the_original() {
        let w: Vec<u8> = (0..200u8).collect();
        let a = generic_mutations(&w, 7, 16);
        let b = generic_mutations(&w, 7, 16);
        assert_eq!(made(&a), made(&b), "the same W and seed give the same mutations");
        let bytes: Vec<Vec<u8>> = a.iter().map(|m| m.make().unwrap()).collect();
        assert!(bytes.iter().all(|m| *m != w));
        for (i, m) in a.iter().enumerate() {
            assert!(a[..i].iter().all(|x| x.id != m.id), "{}", m.id);
            assert!(bytes[..i].iter().all(|x| *x != bytes[i]), "{}", m.id);
        }
        let flips: Vec<(&Mutation<'_>, &Vec<u8>)> = a.iter().zip(&bytes).filter(|(m, _)| m.kind == "flip").collect();
        assert_eq!(flips.len(), 16);
        assert!(
            flips.iter().any(|(m, _)| m.id.starts_with("flip@0^"))
                && flips.iter().any(|(m, _)| m.id.starts_with("flip@199^"))
        );
        for (_, m) in &flips {
            assert_eq!(m.len(), w.len());
            assert_eq!(m.iter().zip(&w).filter(|(x, y)| x != y).count(), 1);
        }
        assert!(a.iter().any(|m| m.id == "truncate@0") && a.iter().any(|m| m.id == "truncate@199"));
        assert!(a.iter().zip(&bytes).any(|(m, b)| m.id == "append:32x00" && b.len() == 232));
        assert_ne!(made(&generic_mutations(&w, 8, 16)), made(&a), "another seed samples other offsets");
        // A one-byte W: one flip, never two of the same byte.
        let one = generic_mutations(&[9], 3, 16);
        assert_eq!(one.iter().filter(|m| m.kind == "flip").count(), 1);
        // An empty W: only the appends.
        let e = generic_mutations(&[], 1, 16);
        assert_eq!(e.iter().map(|m| m.kind.as_str()).collect::<Vec<_>>(), ["append", "append", "append"]);
    }

    fn u32le_items(items: &[&[u8]]) -> Vec<u8> {
        let mut w = Vec::new();
        for i in items {
            w.extend_from_slice(&(i.len() as u32).to_le_bytes());
            w.extend_from_slice(i);
        }
        w
    }

    #[test]
    fn length_prefixed_items_are_found_and_rearranged() {
        let w = u32le_items(&[b"header", b"node-a", b"node-bb"]);
        let f = framings(&w);
        assert_eq!(f[0].name, "u32le");
        assert_eq!(f[0].items.len(), 3);
        let ms = item_mutations(&w, Arc::new(f[0].clone()));
        let get = |id: &str| ms.iter().find(|m| m.id == id).unwrap().make().unwrap();
        assert_eq!(get("u32le:drop#0"), u32le_items(&[b"node-a", b"node-bb"]));
        assert_eq!(get("u32le:drop#2"), u32le_items(&[b"header", b"node-a"]));
        assert_eq!(get("u32le:duplicate#2"), u32le_items(&[b"header", b"node-a", b"node-bb", b"node-bb"]));
        assert_eq!(get("u32le:swap#0-1"), u32le_items(&[b"node-a", b"header", b"node-bb"]));
        // Two items: each operation once.
        let two = u32le_items(&[b"a", b"b"]);
        let ms = item_mutations(&two, Arc::new(framings(&two)[0].clone()));
        let ids: Vec<&str> = ms.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["u32le:drop#0", "u32le:drop#1", "u32le:duplicate#0", "u32le:duplicate#1", "u32le:swap#0-1"]);
        // Something that does not tile is not framed.
        let mut bad = w.clone();
        bad.push(1);
        assert!(framings(&bad).iter().all(|f| f.name != "u32le"));
        assert!(framings(&u32le_items(&[b"only-one"])).is_empty(), "one item is no sequence");
        // risc0's serde Vec<u8>: a u32 length, the bytes padded to a word.
        let mut padded = Vec::new();
        for item in [&b"abc"[..], b"defgh"] {
            padded.extend_from_slice(&(item.len() as u32).to_le_bytes());
            padded.extend_from_slice(item);
            padded.resize(padded.len().div_ceil(4) * 4, 0);
        }
        assert!(framings(&padded).iter().any(|f| f.name == "u32le-pad4" && f.items.len() == 2));
    }

    #[test]
    fn rlp_lists_are_rearranged_with_a_fresh_header() {
        // rlp([b"cat", b"dog", 0x05])
        let w = vec![0xc9, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g', 0x05];
        let f = framings(&w);
        let rlp = f.iter().find(|f| f.name == "rlp-list").expect("an RLP list");
        assert_eq!(rlp.items, vec![1..5, 5..9, 9..10]);
        let ms = item_mutations(&w, Arc::new(rlp.clone()));
        let drop0 = ms.iter().find(|m| m.id == "rlp-list:drop#0").unwrap().make().unwrap();
        assert_eq!(drop0, vec![0xc5, 0x83, b'd', b'o', b'g', 0x05]);
        // A long payload gets a long-form header.
        assert_eq!(rlp_list_header(56), vec![0xf8, 56]);
        assert_eq!(rlp_list_header(300), vec![0xf9, 0x01, 0x2c]);
        assert!(split_rlp_list(&[0xc3, 0x01]).is_none(), "truncated");
    }

    #[test]
    fn the_scheme_id_is_the_first_header_word() {
        let mut s = vec![0u8; 64];
        s[31] = 1;
        assert_eq!(scheme_id_of(&s), Some(1));
        s[0] = 1;
        assert_eq!(scheme_id_of(&s), None, "not a small integer");
        assert_eq!(scheme_id_of(&[0u8; 31]), None);
    }

    struct Fake;
    impl SchemeMutator for Fake {
        fn scheme_id(&self) -> u64 {
            1
        }
        fn name(&self) -> &'static str {
            "fake"
        }
        fn mutations<'a>(&self, w: &'a [u8], _: &SchemeContext<'_>) -> Result<Mutations<'a>, String> {
            Ok(Box::new(
                (0..)
                    .map(move |i: u8| Mutation::new(format!("fake{i}"), "fake", "x", move || Some([w, &[i]].concat()))),
            ))
        }
    }

    #[test]
    fn schemes_register_by_id() {
        let mut r = SchemeRegistry::new();
        assert!(r.get(1).is_none());
        r.register(Box::new(Fake));
        assert_eq!(r.ids(), vec![1]);
        let m: Vec<_> = r
            .get(1)
            .unwrap()
            .mutations(b"w", &SchemeContext { statement: &[], seed: 0, answers: &[] })
            .unwrap()
            .take(2)
            .collect();
        assert_eq!(m.len(), 2);
        assert_eq!(m[1].make(), Some(b"w\x01".to_vec()));
        assert_eq!(r.header_bytes(b"w"), None);
    }

    fn resp(journal: &[u8], exit_code: u32, id: B256, cycles: u64) -> WitnessExecuteResponse {
        WitnessExecuteResponse {
            image_id: id.0,
            results: vec![WitnessExecutePo2 {
                po2: 20,
                cycles,
                journal: journal.to_vec(),
                journal_len: journal.len() as u32,
                journal_sha256: Sha256::digest(journal).into(),
                exit_kind: GUEST_EXIT_HALTED,
                exit_code,
                segment_bytes: 1,
                peak_host_bytes: 1,
            }],
            sdk_version: "s".into(),
            worker_version: "w".into(),
        }
    }

    #[test]
    fn a_changed_journal_is_a_failure_only_when_the_binding_still_holds() {
        let header = [7u8; 64];
        let (job, prover) = (B256::repeat_byte(1), Address::repeat_byte(2));
        let pid = B256::repeat_byte(3);
        let d = JobDescriptor {
            programId: pid,
            proofSystemId: risc_zero_groth16_v1_id(),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Default::default(),
            callbackExtraData: Default::default(),
            extraVerifierData: Default::default(),
            expectedJournalHash: alloy_primitives::keccak256(header),
            journalFields: journal_fields_for_header(64, true).unwrap(),
        };
        let mut journal = journal_prefix(job, prover).to_vec();
        journal.extend_from_slice(&header);
        journal.extend_from_slice(b"out=1");
        let judge = Judge { descriptor: &d, job_id: job, prover, baseline_journal: &journal };
        let limits = CycleLimits { host: 1 << 30, job: 1 << 22 };
        let run = |j: &[u8], code: u32, cycles: u64| classify(&judge, Ok(resp(j, code, pid, cycles)), &[20], limits);
        assert_eq!(run(&journal, 0, 1 << 20), (MutationOutcome::IdenticalJournal, Some(1 << 20)));
        assert!(matches!(run(&journal, 1, 1 << 20).0, MutationOutcome::RejectedInGuest { .. }));
        // The outputs changed under the same header: the prover chose them.
        let mut out2 = journal.clone();
        *out2.last_mut().unwrap() = b'2';
        assert!(
            matches!(run(&out2, 0, 1 << 20).0, MutationOutcome::SoundnessFailure { first_difference, .. } if first_difference == journal.len() - 1)
        );
        // … and so they did past the job's maxGuestCycles: the router does not check cycles.
        assert!(matches!(run(&out2, 0, 1 << 25), (MutationOutcome::SoundnessFailure { .. }, Some(c)) if c == 1 << 25));
        assert_eq!(
            run(&journal, 0, 1 << 25).0,
            MutationOutcome::IdenticalJournal,
            "judged on its journal, never 'rejected'"
        );
        // A changed header: the router refuses it.
        let mut hdr = journal.clone();
        hdr[70] ^= 1;
        assert!(matches!(run(&hdr, 0, 1 << 20).0, MutationOutcome::BindingRejects { .. }));
        // Past the host's own maximum there is no journal to judge: inconclusive, never a rejection.
        assert!(matches!(run(&out2, 0, (1 << 30) + 1).0, MutationOutcome::Inconclusive { .. }));
        let skip = |r| Err(Skip::Verdict { reason: r, step: crate::pipeline::Step::Execute, detail: "d".into() });
        assert!(matches!(
            classify(&judge, skip(SkipReason::GuestCyclesAboveLimit), &[20], limits).0,
            MutationOutcome::Inconclusive { .. }
        ));
        // Host trouble is inconclusive; a guest failure is a rejection.
        assert!(matches!(
            classify(&judge, skip(SkipReason::GuestFailed), &[20], limits).0,
            MutationOutcome::RejectedInGuest { .. }
        ));
        assert!(matches!(
            classify(&judge, skip(SkipReason::ProveResources), &[20], limits).0,
            MutationOutcome::Inconclusive { .. }
        ));
    }

    #[test]
    fn host_input_alternatives_stay_in_range() {
        assert_eq!(other_po2(16), 22);
        assert_eq!(other_po2(22), 16);
        assert_eq!(other_po2(20), 16);
        // From the asked po2s when there are two: the farthest.
        assert_eq!(alternative_po2(16, &[16, 17, 18, 19, 20, 21, 22]), 22);
        assert_eq!(alternative_po2(16, &[16, 20]), 20);
        assert_eq!(alternative_po2(20, &[20]), 16);
        assert_eq!(other_keccak_po2(17), 16);
        assert_eq!(other_keccak_po2(14), 15);
        let limits = CycleLimits { host: 1 << 30, job: 1 << 20 };
        let ok = |j: &[u8]| -> Ran { Ok((sha(j), j.to_vec(), 1000)) };
        let v = || ["a".to_string(), "b".to_string()];
        assert!(!pair_result(HostInput::Po2, v(), ok(b"x"), ok(b"x"), limits).dependent);
        assert!(pair_result(HostInput::Po2, v(), ok(b"x"), ok(b"y"), limits).dependent);
        assert!(pair_result(HostInput::Po2, v(), ok(b"x"), Err(NoJournal::Guest("boom".into())), limits).dependent);
        assert!(
            !pair_result(
                HostInput::Po2,
                v(),
                Err(NoJournal::Guest("a".into())),
                Err(NoJournal::Guest("b".into())),
                limits
            )
            .dependent
        );
        // A cycle cap at one po2 is reported as such: no dependence, not compared.
        let cap = pair_result(HostInput::Po2, v(), ok(b"x"), Err(NoJournal::CycleCap("over".into())), limits);
        assert!(!cap.dependent && !cap.ran);
        assert!(cap.note.unwrap().contains("past this host's cycle maximum"));
        // Past the job's cap at one po2, the journals still compare, with a note.
        let over: Ran = Ok((sha(b"x"), b"x".to_vec(), 1 << 21));
        let r = pair_result(HostInput::Po2, v(), ok(b"x"), over, limits);
        assert!(r.ran && !r.dependent);
        assert!(r.note.unwrap().contains("past the job's maxGuestCycles"));
        // Host trouble is not a dependence.
        let host = pair_result(HostInput::KeccakPo2, v(), ok(b"x"), Err(NoJournal::Host("timeout".into())), limits);
        assert!(!host.dependent && !host.ran);
    }
}
