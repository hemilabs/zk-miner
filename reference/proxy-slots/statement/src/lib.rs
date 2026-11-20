//! Plan §12's worked example as one statement: "at block `B`, proxy `C`'s EIP-1967 implementation
//! is `I` (code hash `H`), and the `k` slots rule `R` names hold `V1..Vk`".
//!
//! The same code runs in three places: the risc0 guest calls [`run`] on its input and commits what
//! it returns; the builder (`sdk/examples/proxy-slots`) uses [`Rule::slots`] to fetch the proofs the
//! guest will ask for, and [`run`] to check its own witness before writing it; requester tooling
//! uses [`Statement`] for the envelope's `builderParams`, the binding and the expected journal, and
//! [`decode_journal`] to read a proof's outputs.
//!
//! # The journal (plan §7.2, journal-prefix jobs)
//!
//! ```text
//! offset   0  abi.encode(jobId, prover)        64 bytes, copied from the guest input
//! offset  64  header, 5 words, pinned by FIELDS (160 bytes):
//!               schemeId = 1
//!               B         block hash
//!               C         proxy address (left-padded)
//!               R         rule word (below)
//!               k         slot count, at most 255
//! offset 224  outputs (free):
//!               I         implementation: the low 20 bytes of C's slot
//!                         0x3608…2bbc (EIP-1967), left-padded
//!               H         EXTCODEHASH(I): 0 if I has no account or an EIP-161-empty one,
//!                         keccak("") if it has no code
//!               k × (slot, value)   in rule order; an unset slot reads 0
//! ```
//!
//! `journalFields` = `0xffffffff ‖ 0x000000a0 ‖ 0…` (the prefix marker, then slot 1 = offset 0,
//! length 160), and `expectedJournalHash` = `keccak256(header)`: both from [`Statement`], from the
//! requester's own parameters.
//!
//! # The rule `R`
//!
//! One word: byte 0 is the rule id, bytes 1..32 a 248-bit parameter `p`.
//!
//! - `0x01` **consecutive**: slots `p, p + 1, …, p + k − 1` of `C` (a fixed layout: a struct or
//!   array at slot `p`).
//! - `0x02` **mapping by implementation**: the `k` words of the value `C` stores in a
//!   `mapping(address => T)` at slot `p` under the key `I`: slots `keccak256(pad32(I) ‖ pad32(p)) + j`
//!   (mod 2^256), Solidity's layout. The slot set depends on the proven implementation, so a
//!   builder must discover `I` before it can fetch them (plan §12.2, "adaptive").
//!
//! Any other rule id fails the guest.
//!
//! # The witness `W` (scheme 1, `hemiprove_eth_prelude::scheme1`)
//!
//! - header words: the five above;
//! - headers: `[header(B)]` (anchor 1: `B` is pinned);
//! - accounts, in order: `C`, with storage proofs for the EIP-1967 slot and then the rule's `k`
//!   slots in rule order; then `I`, with no storage proofs;
//! - no receipts, no transactions.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use hemiprove_eth_prelude::guard::{split_prefixed, GuardError, GuestPrefix, ToWord};
use hemiprove_eth_prelude::hex32;
use hemiprove_eth_prelude::keccak::{keccak256, keccak256_concat};
use hemiprove_eth_prelude::scheme1::{self, ReadError, Reader};

/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
pub const EIP1967_IMPLEMENTATION_SLOT: [u8; 32] =
    hex32("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
/// Header words: schemeId, B, C, R, k.
pub const HEADER_WORDS: usize = 5;
pub const HEADER_BYTES: usize = 32 * HEADER_WORDS;
/// The journal-prefix bytes before the header.
pub const PREFIX_BYTES: usize = 64;
/// `eth_getProof` takes at most 256 storage keys, one of them the EIP-1967 slot. The fulfil's DA
/// cap is lower still: about 20 slot/value pairs at the default 2,048-byte cap.
pub const MAX_SLOTS: u64 = 255;
/// The journal's length for `k` slots.
pub const fn journal_len(k: u64) -> usize {
    PREFIX_BYTES + HEADER_BYTES + 64 + 64 * k as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The witness failed a check (malformed, unauthenticated, not consumed).
    Witness(ReadError),
    /// The input has no valid journal prefix, or the journal was assembled out of order.
    Guard(GuardError),
    /// `W` carries another number of header words than five.
    HeaderLayout,
    /// The rule word names no known rule, or its slot count is out of range.
    BadRule,
    /// `builderParams` are not `abi.encode(uint64, bytes32, address, bytes32, uint64)`.
    BadParams,
    /// A journal of the wrong length or layout (decoding only).
    BadJournal,
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        Self::Witness(e)
    }
}

impl From<GuardError> for Error {
    fn from(e: GuardError) -> Self {
        Self::Guard(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Witness(e) => e.fmt(f),
            Self::Guard(e) => e.fmt(f),
            Self::HeaderLayout => f.write_str("proxy-slots: W does not carry five header words"),
            Self::BadRule => f.write_str("proxy-slots: unknown rule"),
            Self::BadParams => f.write_str("proxy-slots: malformed builderParams"),
            Self::BadJournal => f.write_str("proxy-slots: malformed journal"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Which slots a rule names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Consecutive = 1,
    MappingByImplementation = 2,
}

/// A rule word: a [`RuleKind`] and a 248-bit parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    word: [u8; 32],
}

/// `a + b` modulo 2^256, big-endian.
fn add_u64(a: &[u8; 32], b: u64) -> [u8; 32] {
    let mut out = *a;
    let mut carry = u128::from(b);
    for byte in out.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        let sum = u128::from(*byte) + (carry & 0xff);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    out
}

impl Rule {
    /// The rule with id `kind` and parameter `p` (the parameter's top byte must be zero).
    pub fn new(kind: RuleKind, p: &[u8; 32]) -> Result<Self, Error> {
        if p[0] != 0 {
            return Err(Error::BadRule);
        }
        let mut word = *p;
        word[0] = kind as u8;
        Ok(Self { word })
    }

    /// A rule from its word.
    pub fn decode(word: [u8; 32]) -> Result<Self, Error> {
        match word[0] {
            1 | 2 => Ok(Self { word }),
            _ => Err(Error::BadRule),
        }
    }

    pub fn word(&self) -> [u8; 32] {
        self.word
    }

    pub fn kind(&self) -> RuleKind {
        if self.word[0] == 1 {
            RuleKind::Consecutive
        } else {
            RuleKind::MappingByImplementation
        }
    }

    /// The parameter `p`, as a 256-bit number.
    pub fn param(&self) -> [u8; 32] {
        let mut p = self.word;
        p[0] = 0;
        p
    }

    /// The `k` slots this rule names when the implementation is `implementation`, in order.
    pub fn slots(&self, implementation: &[u8; 20], k: u64) -> Vec<[u8; 32]> {
        let base = match self.kind() {
            RuleKind::Consecutive => self.param(),
            RuleKind::MappingByImplementation => keccak256_concat(&[&implementation.to_word(), &self.param()]),
        };
        (0..k).map(|j| add_u64(&base, j)).collect()
    }
}

/// The requester's parameters: everything the header pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statement {
    pub block_hash: [u8; 32],
    pub proxy: [u8; 20],
    pub rule: Rule,
    pub k: u64,
}

impl Statement {
    /// The five header words, in order.
    pub fn header_words(&self) -> [[u8; 32]; HEADER_WORDS] {
        [scheme1::scheme_word(), self.block_hash, self.proxy.to_word(), self.rule.word(), self.k.to_word()]
    }

    /// The 160-byte header the binding pins.
    pub fn header(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        for (chunk, w) in out.chunks_exact_mut(32).zip(self.header_words()) {
            chunk.copy_from_slice(&w);
        }
        out
    }

    /// `expectedJournalHash` for the FIELDS binding: `keccak256(header)`.
    pub fn expected_journal_hash(&self) -> [u8; 32] {
        keccak256(&self.header())
    }

    /// `builderParams` = `abi.encode(uint64 chainId, bytes32 B, address C, bytes32 R, uint64 k)`:
    /// what the builder needs to know (they bind nothing; the header does).
    pub fn builder_params(&self, chain_id: u64) -> [u8; 160] {
        let mut out = [0u8; 160];
        for (chunk, w) in out
            .chunks_exact_mut(32)
            .zip([chain_id.to_word(), self.block_hash, self.proxy.to_word(), self.rule.word(), self.k.to_word()])
        {
            chunk.copy_from_slice(&w);
        }
        out
    }

    /// Strictly decodes [`builder_params`](Self::builder_params): exactly 160 bytes, zero padding, a
    /// known rule, `k` within [`MAX_SLOTS`].
    pub fn from_builder_params(p: &[u8]) -> Result<(u64, Self), Error> {
        if p.len() != 160 {
            return Err(Error::BadParams);
        }
        let word = |i: usize| -> [u8; 32] { p[32 * i..32 * i + 32].try_into().expect("32 bytes") };
        let small = |w: [u8; 32], max: u64| -> Result<u64, Error> {
            let v = u64::from_be_bytes(w[24..].try_into().expect("8 bytes"));
            if w[..24].iter().any(|&b| b != 0) || v > max {
                return Err(Error::BadParams);
            }
            Ok(v)
        };
        let proxy = word(2);
        if proxy[..12].iter().any(|&b| b != 0) {
            return Err(Error::BadParams);
        }
        let statement = Self {
            block_hash: word(1),
            proxy: proxy[12..].try_into().expect("20 bytes"),
            rule: Rule::decode(word(3))?,
            k: small(word(4), MAX_SLOTS)?,
        };
        Ok((small(word(0), u64::MAX)?, statement))
    }
}

/// `journalFields` for this statement: the journal-prefix marker, then the 160-byte header at
/// offset 0 of the statement.
pub fn journal_fields() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..4].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    w[4..8].copy_from_slice(&(HEADER_BYTES as u32).to_be_bytes());
    w
}

/// What the proof says about the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outputs {
    pub implementation: [u8; 20],
    /// `EXTCODEHASH(implementation)`.
    pub code_hash: [u8; 32],
    /// `(slot, value)` in rule order.
    pub slots: Vec<([u8; 32], [u8; 32])>,
}

/// A decoded journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    pub prefix: GuestPrefix,
    pub statement: Statement,
    pub outputs: Outputs,
}

/// Decodes a journal this statement wrote.
pub fn decode_journal(j: &[u8]) -> Result<Journal, Error> {
    if j.len() < journal_len(0) {
        return Err(Error::BadJournal);
    }
    let (prefix, rest) = split_prefixed(j)?;
    let w = |i: usize| -> [u8; 32] { rest[32 * i..32 * i + 32].try_into().expect("32 bytes") };
    let mut params = [0u8; 160];
    params[..32].copy_from_slice(&0u64.to_word());
    params[32..].copy_from_slice(&rest[32..160]);
    if w(0) != scheme1::scheme_word() {
        return Err(Error::BadJournal);
    }
    let (_, statement) = Statement::from_builder_params(&params).map_err(|_| Error::BadJournal)?;
    if j.len() != journal_len(statement.k) || w(5)[..12].iter().any(|&b| b != 0) {
        return Err(Error::BadJournal);
    }
    let slots = (0..statement.k as usize).map(|i| (w(7 + 2 * i), w(8 + 2 * i))).collect();
    Ok(Journal {
        prefix,
        statement,
        outputs: Outputs { implementation: w(5)[12..].try_into().expect("20 bytes"), code_hash: w(6), slots },
    })
}

/// The statement: checks the witness in `input` (`abi.encode(jobId, prover) ‖ W`) and returns the
/// journal to commit. Every failure is an `Err`; the guest panics on it, so no journal exists.
pub fn run(input: &[u8]) -> Result<Vec<u8>, Error> {
    let (prefix, w) = split_prefixed(input)?;
    // The prelude's entry check: scheme 1, format version 1, word 0 = the scheme id.
    let mut r = Reader::new(w)?;
    if r.header_words() != HEADER_WORDS {
        return Err(Error::HeaderLayout);
    }
    let mut journal = r.journal(Some(&prefix));

    // The header: every question-defining parameter, pinned by the binding.
    let scheme = r.pin_scheme_id()?;
    journal.commit_pinned(&scheme)?;
    let block_hash = r.pin_word()?;
    journal.commit_pinned(&block_hash)?;
    let proxy = r.pin_address()?;
    journal.commit_pinned(&proxy)?;
    // The rule stays its pinned word (the guards hold only the prelude's plain data, never a type of
    // this crate's own); it is checked here and decoded again where the slots are derived.
    let rule = r.pin_word()?.try_map(|w| Rule::decode(w).map(|rule| rule.word()))?;
    journal.commit_pinned(&rule)?;
    let k = r.pin_u64(MAX_SLOTS)?;
    journal.commit_pinned(&k)?;

    // Anchor 1: the header hashes to the pinned B; everything below is under its state root.
    let header = r.block_header(&block_hash.authenticated())?;
    let state_root = header.derive(|h| h.state_root);

    // C's account, then its EIP-1967 slot: the implementation, as the proxy itself would read it
    // (`address(uint160(value))`).
    let proxy_account = r.account(&state_root, &proxy.authenticated())?;
    let slot = hemiprove_eth_prelude::constant!([u8; 32] = EIP1967_IMPLEMENTATION_SLOT);
    let implementation = r.storage(&proxy_account, &slot)?.map(|v| <[u8; 20]>::try_from(&v[12..]).expect("20 bytes"));

    // I's account: its code hash, with EXTCODEHASH semantics.
    let implementation_account = r.account(&state_root, &implementation)?;
    let code_hash = implementation_account.derive(|a| a.extcodehash());

    journal.output(&implementation)?;
    journal.output(&code_hash)?;

    // The slot set, from the pinned rule and count and the proven implementation; then each slot
    // of C, in rule order.
    let slots = rule
        .authenticated()
        .zip(implementation)
        .zip(k.authenticated())
        .try_map(|((rule, i), k)| Rule::decode(rule).map(|rule| rule.slots(&i, k)))?;
    for slot in slots.into_items() {
        let value = r.storage(&proxy_account, &slot)?;
        journal.output(&slot)?;
        journal.output(&value)?;
    }

    // Nothing in W may go unread.
    Ok(r.finish(journal)?)
}

#[cfg(test)]
mod tests;
