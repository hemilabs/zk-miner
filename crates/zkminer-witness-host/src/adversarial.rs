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
//!   (two `sys_rand` seed keys, two po2s, two keccak po2s: any journal change is a dependence on a
//!   prover-controlled host input). Both stop at a deadline and report what they did not run.
//!
//! Every mutation is deterministic for a given `W` and run seed, so a failure reproduces.

use std::collections::BTreeMap;
use std::time::Instant;

use alloy_primitives::{Address, B256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zkminer_chain::binding::check_journal_binding;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_prover_protocol::{WitnessExecuteResponse, GUEST_EXIT_HALTED};
use zkminer_witness::binding::PREFIX_BYTES;
use zkminer_witness::verdict::SkipReason;

use crate::abort::AbortToken;
use crate::pipeline::{check_execution, execute_once, ExecuteOnce, HostContext, Skip};

/// One changed `W`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    /// Unique within a run, and the same for the same `W` and seed: `flip@120^0x04`, `truncate@96`,
    /// `u32le:drop#2`, `scheme1:parent-header`, …
    pub id: String,
    /// The family (`flip`, `truncate`, `append`, `item-drop`, `item-duplicate`, `item-swap`, or a
    /// scheme's own).
    pub kind: String,
    pub description: String,
    pub w: Vec<u8>,
}

impl Mutation {
    pub fn new(id: impl Into<String>, kind: impl Into<String>, description: impl Into<String>, w: Vec<u8>) -> Self {
        Mutation { id: id.into(), kind: kind.into(), description: description.into(), w }
    }
}

/// What a scheme's mutator may read about the job besides `W`.
#[derive(Debug, Clone)]
pub struct SchemeContext<'a> {
    /// The unchanged `W`'s journal after any prefix (the header first, §7.2).
    pub statement: &'a [u8],
    /// The run's seed, for any sampling the mutator does.
    pub seed: u64,
}

/// Structured mutations of one scheme's `W` (§8.1, §21.1). A scheme's reference codec knows where
/// headers, trie nodes, proofs and leaves sit; the generic mutations do not. Implementations are
/// registered by scheme id in a [`SchemeRegistry`].
pub trait SchemeMutator: Send + Sync {
    /// The scheme id (§8.1: 1 `eth-block`, 2 `content-hash`, …).
    fn scheme_id(&self) -> u64;
    /// A short name for reports.
    fn name(&self) -> &'static str;
    /// At most `max` mutations of `w`. `Err` when `w` does not decode as this scheme's witness (a
    /// report line, not a failure of the run: the guest may use another layout).
    fn mutations(&self, w: &[u8], ctx: &SchemeContext<'_>, max: usize) -> Result<Vec<Mutation>, String>;
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
/// first and the last, swap the first two and the last two.
fn item_mutations(w: &[u8], f: &Framing) -> Vec<Mutation> {
    let n = f.items.len();
    let all: Vec<usize> = (0..n).collect();
    let mut out = Vec::new();
    let mut push = |id: String, kind: &str, desc: String, order: Vec<usize>| {
        let m = reframe(w, f, &order);
        if m != w && !out.iter().any(|x: &Mutation| x.w == m) {
            out.push(Mutation::new(id, kind, desc, m));
        }
    };
    for i in [0, n / 2, n - 1] {
        let order: Vec<usize> = all.iter().copied().filter(|&j| j != i).collect();
        push(format!("{}:drop#{i}", f.name), "item-drop", format!("drop item {i} of {n} ({} framing)", f.name), order);
    }
    for i in [0, n - 1] {
        let mut order = all.clone();
        order.insert(i + 1, i);
        push(format!("{}:duplicate#{i}", f.name), "item-duplicate", format!("duplicate item {i} of {n} ({} framing)", f.name), order);
    }
    for (a, b) in [(0, 1), (n - 2, n - 1)] {
        let mut order = all.clone();
        order.swap(a, b);
        push(format!("{}:swap#{a}-{b}", f.name), "item-swap", format!("swap items {a} and {b} of {n} ({} framing)", f.name), order);
    }
    out
}

/// The generic mutations of `w`: `flips` single-byte changes at sampled offsets (the first and last
/// byte always among them, the rest drawn from `seed`, each XOR a nonzero byte), truncations (to 0,
/// half, all but one word and all but one byte), trailing bytes (one zero, one 0xff, a zero word),
/// and the item mutations of every framing `w` parses as. Duplicates and no-ops are dropped.
pub fn generic_mutations(w: &[u8], seed: u64, flips: usize) -> Vec<Mutation> {
    let mut out: Vec<Mutation> = Vec::new();
    let push = |m: Mutation, out: &mut Vec<Mutation>| {
        if m.w != w && !out.iter().any(|x| x.w == m.w) {
            out.push(m);
        }
    };
    let mut rng = SplitMix::new(seed);
    if !w.is_empty() {
        let mut offsets: Vec<usize> = vec![0, w.len() - 1];
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
            let mut m = w.to_vec();
            m[o] ^= x;
            push(Mutation::new(format!("flip@{o}^{x:#04x}"), "flip", format!("byte {o} XOR {x:#04x}"), m), &mut out);
        }
    }
    let mut cuts = vec![0, w.len() / 2, w.len().saturating_sub(32), w.len().saturating_sub(1)];
    cuts.sort_unstable();
    cuts.dedup();
    for c in cuts {
        if c < w.len() {
            push(Mutation::new(format!("truncate@{c}"), "truncate", format!("W cut to its first {c} bytes"), w[..c].to_vec()), &mut out);
        }
    }
    for (id, tail) in [("append:00", vec![0u8]), ("append:ff", vec![0xff]), ("append:32x00", vec![0u8; 32])] {
        let mut m = w.to_vec();
        m.extend_from_slice(&tail);
        push(Mutation::new(id, "append", format!("{} trailing byte(s) appended", tail.len()), m), &mut out);
    }
    for f in framings(w) {
        for m in item_mutations(w, &f) {
            push(m, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Classification.

/// How one re-executed `W` came out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MutationOutcome {
    /// The guest refused it (a non-zero exit, a fault, a panic), or it ran past `maxGuestCycles`:
    /// the miner skips such a job before any lock.
    RejectedInGuest { why: String },
    /// The guest committed the unchanged `W`'s journal, byte for byte.
    IdenticalJournal,
    /// The journal changed in bytes the binding pins: the router refuses that proof.
    BindingRejects { journal_sha256: B256 },
    /// The journal changed and still satisfies the binding: the prover chose the statement. A
    /// soundness failure of the guest (or of the binding).
    SoundnessFailure { journal_sha256: B256, first_difference: usize },
    /// This host could not run it (sandbox, worker, memory, time): says nothing about the guest.
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

fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()))
}

fn sha(b: &[u8]) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::digest(b)))
}

/// Classifies one execute of a changed `W` (see [`MutationOutcome`]).
pub fn classify(judge: &Judge<'_>, result: Result<WitnessExecuteResponse, Skip>, po2s: &[u8], max_cycles: u64) -> MutationOutcome {
    let resp = match result {
        Ok(r) => r,
        Err(Skip::Aborted { reason, .. }) => return MutationOutcome::Inconclusive { why: format!("aborted: {reason:?}") },
        Err(Skip::Verdict { reason, detail, .. }) => {
            return match reason {
                SkipReason::GuestFailed | SkipReason::GuestCyclesAboveLimit => {
                    MutationOutcome::RejectedInGuest { why: format!("{reason:?}: {}", tail(&detail)) }
                }
                _ => MutationOutcome::Inconclusive { why: format!("{reason:?}: {}", tail(&detail)) },
            }
        }
    };
    if resp.results.iter().any(|r| r.exit_kind != GUEST_EXIT_HALTED || r.exit_code != 0) {
        return MutationOutcome::RejectedInGuest { why: "the guest did not halt with 0".into() };
    }
    let journal = match check_execution(&resp, po2s, judge.descriptor.programId, max_cycles) {
        Ok(j) => j,
        Err((SkipReason::GuestCyclesAboveLimit, d)) | Err((SkipReason::GuestFailed, d)) => {
            return MutationOutcome::RejectedInGuest { why: d };
        }
        Err((r, d)) => return MutationOutcome::Inconclusive { why: format!("{r:?}: {d}") },
    };
    if journal == judge.baseline_journal {
        return MutationOutcome::IdenticalJournal;
    }
    match check_journal_binding(judge.descriptor, &journal, judge.job_id, judge.prover) {
        Ok(()) => MutationOutcome::SoundnessFailure {
            journal_sha256: sha(&journal),
            first_difference: first_difference(&journal, judge.baseline_journal),
        },
        Err(_) => MutationOutcome::BindingRejects { journal_sha256: sha(&journal) },
    }
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
    pub keccak_po2: u8,
    pub sys_rand_key: [u8; 32],
    pub max_cycles: u64,
}

impl Baseline<'_> {
    async fn execute(&self, w: &[u8], po2s: &[u8], keccak_po2: u8, key: [u8; 32]) -> Result<WitnessExecuteResponse, Skip> {
        let spec = ExecuteOnce {
            elf: self.elf,
            program_id: self.judge.descriptor.programId,
            prefix: self.prefix,
            po2s,
            keccak_po2,
            sys_rand_key: key,
            max_cycles: self.max_cycles,
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
    pub w_bytes: usize,
    #[serde(flatten)]
    pub outcome: MutationOutcome,
}

/// Executes each mutation at the baseline's po2 until `deadline`; those left are [`MutationOutcome::NotRun`].
pub async fn run_mutations(b: &Baseline<'_>, mutations: Vec<Mutation>, deadline: Instant) -> Vec<MutationResult> {
    let mut out = Vec::with_capacity(mutations.len());
    for m in mutations {
        let outcome = if Instant::now() >= deadline || b.token.reason().is_some() {
            MutationOutcome::NotRun
        } else {
            let r = b.execute(&m.w, &[b.po2], b.keccak_po2, b.sys_rand_key).await;
            classify(&b.judge, r, &[b.po2], b.max_cycles)
        };
        tracing::debug!(mutation = %m.id, ?outcome, "adversarial: mutation judged");
        out.push(MutationResult { id: m.id, kind: m.kind, description: m.description, w_bytes: m.w.len(), outcome });
    }
    out
}

/// A host input a prover controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostInput {
    /// The `sys_rand` seed (its key: the prover's own secret).
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
    /// The two values, as text (`key A`/`key B` for seeds).
    pub values: [String; 2],
    /// Each value's journal sha256, when it ran to a journal.
    pub journal_sha256: [Option<B256>; 2],
    /// The journals differ: the guest depends on this input, which the prover controls.
    pub dependent: bool,
    /// Why a value did not produce a journal (a failure under one value only is a dependence too).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub ran: bool,
}

/// The alternative to `p` among the job po2s (16..=22), for the po2 check: the far end of the range.
pub fn other_po2(p: u8) -> u8 {
    use zkminer_prover_protocol::{RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    if p - RISC0_JOB_PO2_MIN >= RISC0_JOB_PO2_MAX - p {
        RISC0_JOB_PO2_MIN
    } else {
        RISC0_JOB_PO2_MAX
    }
}

/// The alternative keccak po2 to `k`, within 14..=18 (the range the pipeline accepts).
pub fn other_keccak_po2(k: u8) -> u8 {
    if k > 14 {
        k - 1
    } else {
        k + 1
    }
}

fn journal_of(resp: &Result<WitnessExecuteResponse, Skip>, i: usize) -> Result<(B256, Vec<u8>), String> {
    match resp {
        Ok(r) => match r.results.get(i) {
            Some(p) if p.exit_kind == GUEST_EXIT_HALTED && p.exit_code == 0 => Ok((sha(&p.journal), p.journal.clone())),
            Some(p) => Err(format!("po2 {}: exit kind {} code {}", p.po2, p.exit_kind, p.exit_code)),
            None => Err("no result".into()),
        },
        Err(s) => Err(s.to_string()),
    }
}

fn pair_result(input: HostInput, values: [String; 2], a: Result<(B256, Vec<u8>), String>, b: Result<(B256, Vec<u8>), String>) -> HostInputResult {
    let (ja, jb) = (a.as_ref().ok().map(|x| x.0), b.as_ref().ok().map(|x| x.0));
    let (dependent, note) = match (&a, &b) {
        (Ok(x), Ok(y)) => (x.1 != y.1, None),
        (Err(e), Ok(_)) => (true, Some(format!("only {} ran: {}", values[1], tail(e)))),
        (Ok(_), Err(e)) => (true, Some(format!("only {} ran: {}", values[0], tail(e)))),
        (Err(e), Err(_)) => (false, Some(format!("neither ran: {}", tail(e)))),
    };
    HostInputResult { input, values, journal_sha256: [ja, jb], dependent, note, ran: a.is_ok() || b.is_ok() }
}

/// Re-executes the baseline `W` under two `sys_rand` seed keys, two po2s and two keccak po2s
/// (§21.1), each pair compared by journal, until `deadline`. `other_key` is a key unrelated to the
/// baseline's (the seed a different prover derives).
pub async fn host_input_checks(b: &Baseline<'_>, other_key: [u8; 32], deadline: Instant) -> Vec<HostInputResult> {
    let mut out = Vec::new();
    let skipped = |input, values: [String; 2]| HostInputResult {
        input,
        values,
        journal_sha256: [None, None],
        dependent: false,
        note: Some("not run: the run's time ran out first".into()),
        ran: false,
    };
    let late = || Instant::now() >= deadline || b.token.reason().is_some();
    // The baseline's own execution at its po2, keccak po2 and key: the first value of the seed and
    // keccak pairs.
    let base = if late() { None } else { Some(journal_of(&b.execute(b.w, &[b.po2], b.keccak_po2, b.sys_rand_key).await, 0)) };
    let values = ["key A (this run's)".to_string(), "key B (another prover's)".to_string()];
    match &base {
        Some(a) if !late() => {
            let c = b.execute(b.w, &[b.po2], b.keccak_po2, other_key).await;
            out.push(pair_result(HostInput::SysRandSeed, values, a.clone(), journal_of(&c, 0)));
        }
        _ => out.push(skipped(HostInput::SysRandSeed, values)),
    }
    // Two po2s in one request (the worker runs each in turn).
    let p2 = other_po2(b.po2);
    let values = [b.po2.to_string(), p2.to_string()];
    if late() {
        out.push(skipped(HostInput::Po2, values));
    } else {
        let mut both = [b.po2, p2];
        both.sort_unstable();
        let r = b.execute(b.w, &both, b.keccak_po2, b.sys_rand_key).await;
        let (ia, ib) = if both[0] == b.po2 { (0, 1) } else { (1, 0) };
        out.push(pair_result(HostInput::Po2, values, journal_of(&r, ia), journal_of(&r, ib)));
    }
    // Two keccak po2s.
    let k2 = other_keccak_po2(b.keccak_po2);
    let values = [b.keccak_po2.to_string(), k2.to_string()];
    match &base {
        Some(a) if !late() => {
            let c = b.execute(b.w, &[b.po2], k2, b.sys_rand_key).await;
            out.push(pair_result(HostInput::KeccakPo2, values, a.clone(), journal_of(&c, 0)));
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

    #[test]
    fn generic_mutations_are_deterministic_distinct_and_never_the_original() {
        let w: Vec<u8> = (0..200u8).collect();
        let a = generic_mutations(&w, 7, 16);
        let b = generic_mutations(&w, 7, 16);
        assert_eq!(a, b, "the same W and seed give the same mutations");
        assert!(a.iter().all(|m| m.w != w));
        for (i, m) in a.iter().enumerate() {
            assert!(a[..i].iter().all(|x| x.w != m.w && x.id != m.id), "{}", m.id);
        }
        let flips: Vec<&Mutation> = a.iter().filter(|m| m.kind == "flip").collect();
        assert_eq!(flips.len(), 16);
        assert!(flips.iter().any(|m| m.id.starts_with("flip@0^")) && flips.iter().any(|m| m.id.starts_with("flip@199^")));
        for m in &flips {
            assert_eq!(m.w.len(), w.len());
            assert_eq!(m.w.iter().zip(&w).filter(|(x, y)| x != y).count(), 1);
        }
        assert!(a.iter().any(|m| m.id == "truncate@0") && a.iter().any(|m| m.id == "truncate@199"));
        assert!(a.iter().any(|m| m.id == "append:32x00" && m.w.len() == 232));
        assert_ne!(generic_mutations(&w, 8, 16), a, "another seed samples other offsets");
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
        let ms = item_mutations(&w, &f[0]);
        let get = |id: &str| ms.iter().find(|m| m.id == id).unwrap().w.clone();
        assert_eq!(get("u32le:drop#0"), u32le_items(&[b"node-a", b"node-bb"]));
        assert_eq!(get("u32le:drop#2"), u32le_items(&[b"header", b"node-a"]));
        assert_eq!(get("u32le:duplicate#2"), u32le_items(&[b"header", b"node-a", b"node-bb", b"node-bb"]));
        assert_eq!(get("u32le:swap#0-1"), u32le_items(&[b"node-a", b"header", b"node-bb"]));
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
        let ms = item_mutations(&w, rlp);
        let drop0 = &ms.iter().find(|m| m.id == "rlp-list:drop#0").unwrap().w;
        assert_eq!(drop0, &vec![0xc5, 0x83, b'd', b'o', b'g', 0x05]);
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
        fn mutations(&self, w: &[u8], _: &SchemeContext<'_>, max: usize) -> Result<Vec<Mutation>, String> {
            Ok((0..max).map(|i| Mutation::new(format!("fake{i}"), "fake", "x", [w, &[i as u8]].concat())).collect())
        }
    }

    #[test]
    fn schemes_register_by_id() {
        let mut r = SchemeRegistry::new();
        assert!(r.get(1).is_none());
        r.register(Box::new(Fake));
        assert_eq!(r.ids(), vec![1]);
        let m = r.get(1).unwrap().mutations(b"w", &SchemeContext { statement: &[], seed: 0 }, 2).unwrap();
        assert_eq!(m.len(), 2);
    }

    fn resp(journal: &[u8], exit_code: u32, id: B256) -> WitnessExecuteResponse {
        WitnessExecuteResponse {
            image_id: id.0,
            results: vec![WitnessExecutePo2 {
                po2: 20,
                cycles: 1 << 20,
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
        let run = |j: &[u8], code: u32| classify(&judge, Ok(resp(j, code, pid)), &[20], 1 << 30);
        assert_eq!(run(&journal, 0), MutationOutcome::IdenticalJournal);
        assert!(matches!(run(&journal, 1), MutationOutcome::RejectedInGuest { .. }));
        // The outputs changed under the same header: the prover chose them.
        let mut out2 = journal.clone();
        *out2.last_mut().unwrap() = b'2';
        assert!(matches!(run(&out2, 0), MutationOutcome::SoundnessFailure { first_difference, .. } if first_difference == journal.len() - 1));
        // A changed header: the router refuses it.
        let mut hdr = journal.clone();
        hdr[70] ^= 1;
        assert!(matches!(run(&hdr, 0), MutationOutcome::BindingRejects { .. }));
        // Host trouble is inconclusive; a guest failure is a rejection.
        let skip = |r| Err(Skip::Verdict { reason: r, step: crate::pipeline::Step::Execute, detail: "d".into() });
        assert!(matches!(classify(&judge, skip(SkipReason::GuestFailed), &[20], 1), MutationOutcome::RejectedInGuest { .. }));
        assert!(matches!(classify(&judge, skip(SkipReason::ProveResources), &[20], 1), MutationOutcome::Inconclusive { .. }));
        assert!(matches!(classify(&judge, Ok(resp(&journal, 0, pid)), &[20], 1), MutationOutcome::RejectedInGuest { .. }), "cycles over the cap");
    }

    #[test]
    fn host_input_alternatives_stay_in_range() {
        assert_eq!(other_po2(16), 22);
        assert_eq!(other_po2(22), 16);
        assert_eq!(other_po2(20), 16);
        assert_eq!(other_keccak_po2(17), 16);
        assert_eq!(other_keccak_po2(14), 15);
        let ok = |j: &[u8]| Ok((sha(j), j.to_vec()));
        assert!(!pair_result(HostInput::Po2, ["a".into(), "b".into()], ok(b"x"), ok(b"x")).dependent);
        assert!(pair_result(HostInput::Po2, ["a".into(), "b".into()], ok(b"x"), ok(b"y")).dependent);
        assert!(pair_result(HostInput::Po2, ["a".into(), "b".into()], ok(b"x"), Err("boom".into())).dependent);
        assert!(!pair_result(HostInput::Po2, ["a".into(), "b".into()], Err("a".into()), Err("b".into())).dependent);
    }
}
