//! The scheme-1 (`eth-block`) witness format: the exact `W` a builder writes and a guest consumes,
//! its strict codec, the guest-side [`Reader`] that authenticates what it hands out and checks that
//! `W` is consumed in full, and the structural mutations requester tooling uses to attack a
//! witness (plan §21.1, `simulate --adversarial`).
//!
//! # Layout (version 1)
//!
//! Every integer is big-endian; every `bytes` is `len (u32) ‖ len bytes` with `len ≥ 1`.
//!
//! ```text
//! W        = "HPW" ‖ scheme (u8 = 1) ‖ version (u8 = 1)
//!            ‖ nWords (u16, 1..=1022) ‖ nWords × word (32 bytes)   journal-header words, word 0 = schemeId = 1
//!            ‖ nHeaders (u32) ‖ nHeaders × bytes                    RLP block headers
//!            ‖ nAccounts (u32) ‖ nAccounts × account
//!            ‖ nReceipts (u32) ‖ nReceipts × proof                  receipts-trie proofs
//!            ‖ nTxs (u32) ‖ nTxs × proof                            transactions-trie proofs
//! account  = proof ‖ nSlots (u32) ‖ nSlots × proof                  state-trie proof, then its storage proofs
//! proof    = kind (u8: 0 inclusion, 1 exclusion) ‖ nNodes (u32) ‖ nNodes × bytes
//! ```
//!
//! Nothing may follow the last section. Every field has one encoding, so a `W` that decodes
//! re-encodes to the same bytes.
//!
//! **What `W` does not carry: keys and values.** No address, slot, index or leaf value is in `W`:
//! the guest computes every trie key from pinned or authenticated values and takes every value from
//! a verified leaf (plan §8.4). The only claims `W` makes are the header words (which the binding
//! pins) and each proof's kind, which the guest checks against what the proof shows.
//!
//! **Order is the guest's.** Headers, accounts, each account's storage proofs, receipts and
//! transactions are consumed in the order the guest asks for them; the statement documents that
//! order (for plan §12's statement: `hemiprove-proxy-slots`).
//!
//! # Guards
//!
//! [`Reader::new`] is the prelude's entry check (plan §8.3, "Wrong prelude"): the magic, scheme 1,
//! format version 1 and header word 0 = 1, or nothing is read. Header words come out as
//! [`Pinned`] values in order; headers, accounts, slots, receipts and transactions come out as
//! [`Authenticated`] values, each verified against an authenticated root and key; [`Reader::finish`]
//! refuses a witness with anything left unread, a header word uncommitted or a section unconsumed.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::anchor;
use crate::guard::{Authenticated, GuardError, GuestPrefix, JournalWriter, Pinned};
use crate::header::{Header, HeaderError};
use crate::receipt::{self, Receipt, ReceiptError};
use crate::state::{self, Account, StateError};
use crate::tx::{self, HashedTransaction, TxError};

/// The first three bytes of every scheme-1 witness.
pub const MAGIC: [u8; 3] = *b"HPW";
/// The scheme this format belongs to (plan §8.1: `eth-block`).
pub const SCHEME_ID: u8 = 1;
/// This module's format version.
pub const VERSION: u8 = 1;
/// The header must fit one FIELDS range under the journal-prefix cap: 32,704 bytes.
pub const MAX_HEADER_WORDS: usize = 1022;

/// Whether `w` starts like a scheme-1 witness of this version (tools use it to pick the mutation set).
pub fn is_scheme1(w: &[u8]) -> bool {
    w.len() >= 5 && w[..3] == MAGIC && w[3] == SCHEME_ID && w[4] == VERSION
}

/// What a proof claims to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// A leaf holds the key.
    Inclusion = 0,
    /// No leaf holds the key.
    Exclusion = 1,
}

impl ProofKind {
    pub fn flipped(self) -> Self {
        match self {
            Self::Inclusion => Self::Exclusion,
            Self::Exclusion => Self::Inclusion,
        }
    }
}

/// One trie proof: its kind and its hashed nodes, root first (`eth_getProof`'s form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieProof<'a> {
    pub kind: ProofKind,
    pub nodes: Vec<Cow<'a, [u8]>>,
}

/// An account proof and the storage proofs under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProof<'a> {
    pub proof: TrieProof<'a>,
    pub storage: Vec<TrieProof<'a>>,
}

/// A decoded scheme-1 witness. Decoding borrows from the bytes; [`Witness::into_owned`] detaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness<'a> {
    /// The journal-header words, in order; word 0 is the scheme id (1).
    pub header_words: Vec<[u8; 32]>,
    /// RLP headers: the block the commitment names first, then (anchor 2) its ancestors, each the
    /// previous one's parent.
    pub headers: Vec<Cow<'a, [u8]>>,
    pub accounts: Vec<AccountProof<'a>>,
    pub receipts: Vec<TrieProof<'a>>,
    pub transactions: Vec<TrieProof<'a>>,
}

/// The scheme-id word: `uint256(1)`.
pub fn scheme_word() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = SCHEME_ID;
    w
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// Not "HPW" ‖ 1 ‖ 1: another scheme, another version, or not a scheme-1 witness.
    BadMagic,
    /// Header word 0 is not the scheme id 1.
    SchemeWord,
    /// No header words, or more than [`MAX_HEADER_WORDS`].
    WordCount,
    /// The input ends inside a field.
    Truncated,
    /// A count larger than the bytes left could hold.
    CountTooLarge,
    /// A zero-length header or node.
    EmptyBytes,
    /// A proof kind other than 0 or 1.
    BadKind,
    /// Bytes after the last section.
    TrailingBytes,
    /// A field too long for its u32 length (encoding only).
    TooLong,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadMagic => "W: not a scheme-1 version-1 witness",
            Self::SchemeWord => "W: header word 0 is not scheme id 1",
            Self::WordCount => "W: header word count out of range",
            Self::Truncated => "W: ends inside a field",
            Self::CountTooLarge => "W: count larger than the bytes left",
            Self::EmptyBytes => "W: empty header or node",
            Self::BadKind => "W: proof kind is neither 0 nor 1",
            Self::TrailingBytes => "W: bytes after the last section",
            Self::TooLong => "W: field too long to encode",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FormatError {}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.rest.len() < n {
            return Err(FormatError::Truncated);
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<usize, FormatError> {
        let v = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes"));
        usize::try_from(v).map_err(|_| FormatError::CountTooLarge)
    }

    /// A count of items each taking at least `min` bytes.
    fn count(&mut self, min: usize) -> Result<usize, FormatError> {
        let n = self.u32()?;
        if n > self.rest.len() / min {
            return Err(FormatError::CountTooLarge);
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<Cow<'a, [u8]>, FormatError> {
        let n = self.u32()?;
        if n == 0 {
            return Err(FormatError::EmptyBytes);
        }
        Ok(Cow::Borrowed(self.take(n)?))
    }

    fn proof(&mut self) -> Result<TrieProof<'a>, FormatError> {
        let kind = match self.u8()? {
            0 => ProofKind::Inclusion,
            1 => ProofKind::Exclusion,
            _ => return Err(FormatError::BadKind),
        };
        let n = self.count(5)?;
        let mut nodes = Vec::with_capacity(n);
        for _ in 0..n {
            nodes.push(self.bytes()?);
        }
        Ok(TrieProof { kind, nodes })
    }

    fn proofs(&mut self) -> Result<Vec<TrieProof<'a>>, FormatError> {
        let n = self.count(5)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.proof()?);
        }
        Ok(out)
    }
}

fn put_u32(out: &mut Vec<u8>, n: usize) -> Result<(), FormatError> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| FormatError::TooLong)?.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), FormatError> {
    if b.is_empty() {
        return Err(FormatError::EmptyBytes);
    }
    put_u32(out, b.len())?;
    out.extend_from_slice(b);
    Ok(())
}

fn put_proof(out: &mut Vec<u8>, p: &TrieProof<'_>) -> Result<(), FormatError> {
    out.push(p.kind as u8);
    put_u32(out, p.nodes.len())?;
    for n in &p.nodes {
        put_bytes(out, n)?;
    }
    Ok(())
}

fn owned_proof(p: TrieProof<'_>) -> TrieProof<'static> {
    TrieProof { kind: p.kind, nodes: p.nodes.into_iter().map(|n| Cow::Owned(n.into_owned())).collect() }
}

impl<'a> Witness<'a> {
    /// Strictly decodes a scheme-1 witness.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, FormatError> {
        let mut c = Cursor { rest: bytes };
        if c.take(3)? != MAGIC || c.u8()? != SCHEME_ID || c.u8()? != VERSION {
            return Err(FormatError::BadMagic);
        }
        let n_words = usize::from(c.u16()?);
        if n_words == 0 || n_words > MAX_HEADER_WORDS {
            return Err(FormatError::WordCount);
        }
        let mut header_words = Vec::with_capacity(n_words);
        for _ in 0..n_words {
            header_words.push(<[u8; 32]>::try_from(c.take(32)?).expect("32 bytes"));
        }
        if header_words[0] != scheme_word() {
            return Err(FormatError::SchemeWord);
        }
        let n = c.count(5)?;
        let mut headers = Vec::with_capacity(n);
        for _ in 0..n {
            headers.push(c.bytes()?);
        }
        let n = c.count(9)?;
        let mut accounts = Vec::with_capacity(n);
        for _ in 0..n {
            let proof = c.proof()?;
            let storage = c.proofs()?;
            accounts.push(AccountProof { proof, storage });
        }
        let receipts = c.proofs()?;
        let transactions = c.proofs()?;
        if !c.rest.is_empty() {
            return Err(FormatError::TrailingBytes);
        }
        Ok(Self { header_words, headers, accounts, receipts, transactions })
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.header_words.is_empty() || self.header_words.len() > MAX_HEADER_WORDS {
            return Err(FormatError::WordCount);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(SCHEME_ID);
        out.push(VERSION);
        out.extend_from_slice(&(self.header_words.len() as u16).to_be_bytes());
        for w in &self.header_words {
            out.extend_from_slice(w);
        }
        put_u32(&mut out, self.headers.len())?;
        for h in &self.headers {
            put_bytes(&mut out, h)?;
        }
        put_u32(&mut out, self.accounts.len())?;
        for a in &self.accounts {
            put_proof(&mut out, &a.proof)?;
            put_u32(&mut out, a.storage.len())?;
            for s in &a.storage {
                put_proof(&mut out, s)?;
            }
        }
        for section in [&self.receipts, &self.transactions] {
            put_u32(&mut out, section.len())?;
            for p in section {
                put_proof(&mut out, p)?;
            }
        }
        Ok(out)
    }

    /// The same witness, owning its bytes.
    pub fn into_owned(self) -> Witness<'static> {
        Witness {
            header_words: self.header_words,
            headers: self.headers.into_iter().map(|h| Cow::Owned(h.into_owned())).collect(),
            accounts: self
                .accounts
                .into_iter()
                .map(|a| AccountProof { proof: owned_proof(a.proof), storage: a.storage.into_iter().map(owned_proof).collect() })
                .collect(),
            receipts: self.receipts.into_iter().map(owned_proof).collect(),
            transactions: self.transactions.into_iter().map(owned_proof).collect(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The guest side.

/// Which part of `W` an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Words,
    Headers,
    Accounts,
    /// The storage proofs of account `n` (in `W` order).
    Storage(usize),
    Receipts,
    Transactions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    Format(FormatError),
    Header(HeaderError),
    State(StateError),
    Receipt(ReceiptError),
    Tx(TxError),
    Guard(GuardError),
    /// The guest asked for more items than the section holds.
    Exhausted(Section),
    /// Item `index` claims inclusion and proves exclusion, or the reverse.
    KindMismatch { section: Section, index: usize },
    /// A header word that does not encode the type asked for (an address or `u64` with non-zero
    /// high bytes, a value over its bound).
    BadWord { index: usize },
    /// The scheme-id word was not the first one pinned.
    SchemeWordNotFirst,
    /// [`Reader::finish`] with items of this section unread.
    Unconsumed(Section),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(e) => e.fmt(f),
            Self::Header(e) => e.fmt(f),
            Self::State(e) => e.fmt(f),
            Self::Receipt(e) => e.fmt(f),
            Self::Tx(e) => e.fmt(f),
            Self::Guard(e) => e.fmt(f),
            Self::Exhausted(s) => write!(f, "W: no more items in {s:?}"),
            Self::KindMismatch { section, index } => {
                write!(f, "W: {section:?} item {index} proves the opposite of its kind")
            }
            Self::BadWord { index } => write!(f, "W: header word {index} does not encode its type"),
            Self::SchemeWordNotFirst => f.write_str("W: the scheme-id word must be pinned first"),
            Self::Unconsumed(s) => write!(f, "W: {s:?} not consumed in full"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadError {}

macro_rules! from_error {
    ($($t:ty => $v:ident),*) => {$(
        impl From<$t> for ReadError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    )*};
}
from_error!(FormatError => Format, HeaderError => Header, StateError => State, ReceiptError => Receipt, TxError => Tx, GuardError => Guard);

/// An account a proof established: present (with its leaf) or absent. Carries its position in `W`
/// so that [`Reader::storage`] reads the storage proofs filed under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenAccount {
    index: usize,
    pub address: [u8; 20],
    pub account: Option<Account>,
}

impl ProvenAccount {
    /// [`EMPTY_ROOT`](crate::keccak::EMPTY_ROOT) for an absent account.
    pub fn storage_root(&self) -> [u8; 32] {
        state::storage_root(&self.account)
    }

    /// `EXTCODEHASH` semantics: 0 when absent.
    pub fn extcodehash(&self) -> [u8; 32] {
        state::extcodehash(&self.account)
    }
}

/// Reads a scheme-1 witness in the guest: pins header words, verifies everything else, and checks
/// at [`finish`](Self::finish) that nothing was left unread.
#[derive(Debug)]
pub struct Reader<'a> {
    w: Witness<'a>,
    next_word: usize,
    next_header: usize,
    next_account: usize,
    next_storage: Vec<usize>,
    next_receipt: usize,
    next_tx: usize,
}

fn check_kind(kind: ProofKind, found: bool, section: Section, index: usize) -> Result<(), ReadError> {
    if found == (kind == ProofKind::Inclusion) {
        Ok(())
    } else {
        Err(ReadError::KindMismatch { section, index })
    }
}

impl<'a> Reader<'a> {
    /// Decodes `w` and runs the entry check: a scheme-1 version-1 witness whose word 0 is the
    /// scheme id.
    pub fn new(w: &'a [u8]) -> Result<Self, ReadError> {
        let w = Witness::decode(w)?;
        let accounts = w.accounts.len();
        Ok(Self { w, next_word: 0, next_header: 0, next_account: 0, next_storage: alloc::vec![0; accounts], next_receipt: 0, next_tx: 0 })
    }

    /// The number of journal-header words `W` carries.
    pub fn header_words(&self) -> usize {
        self.w.header_words.len()
    }

    /// A journal writer for this witness's header, starting with `prefix`.
    pub fn journal(&self, prefix: Option<&GuestPrefix>) -> JournalWriter {
        JournalWriter::new(prefix, self.header_words())
    }

    fn next_word(&mut self) -> Result<(usize, [u8; 32]), ReadError> {
        let i = self.next_word;
        let w = *self.w.header_words.get(i).ok_or(ReadError::Exhausted(Section::Words))?;
        self.next_word += 1;
        Ok((i, w))
    }

    /// Word 0, the scheme id (always 1: [`Reader::new`] checked it).
    pub fn pin_scheme_id(&mut self) -> Result<Pinned<u64>, ReadError> {
        if self.next_word != 0 {
            return Err(ReadError::SchemeWordNotFirst);
        }
        let (i, w) = self.next_word()?;
        Ok(Pinned::new(i, w, u64::from(SCHEME_ID)))
    }

    /// The next header word, as raw bytes (a hash, a rule).
    pub fn pin_word(&mut self) -> Result<Pinned<[u8; 32]>, ReadError> {
        let (i, w) = self.next_word()?;
        Ok(Pinned::new(i, w, w))
    }

    /// The next header word as an address: 12 zero bytes, then 20.
    pub fn pin_address(&mut self) -> Result<Pinned<[u8; 20]>, ReadError> {
        let (i, w) = self.next_word()?;
        if w[..12].iter().any(|&b| b != 0) {
            return Err(ReadError::BadWord { index: i });
        }
        Ok(Pinned::new(i, w, w[12..].try_into().expect("20 bytes")))
    }

    /// The next header word as a `u64` of at most `max`.
    pub fn pin_u64(&mut self, max: u64) -> Result<Pinned<u64>, ReadError> {
        let (i, w) = self.next_word()?;
        let v = u64::from_be_bytes(w[24..].try_into().expect("8 bytes"));
        if w[..24].iter().any(|&b| b != 0) || v > max {
            return Err(ReadError::BadWord { index: i });
        }
        Ok(Pinned::new(i, w, v))
    }

    fn next_header_bytes(&mut self) -> Result<&Cow<'a, [u8]>, ReadError> {
        let h = self.w.headers.get(self.next_header).ok_or(ReadError::Exhausted(Section::Headers))?;
        self.next_header += 1;
        Ok(h)
    }

    /// Anchor 1: the next header is the block whose hash is `hash`.
    pub fn block_header(&mut self, hash: &Authenticated<[u8; 32]>) -> Result<Authenticated<Header>, ReadError> {
        let rlp = self.next_header_bytes()?;
        Ok(anchor::pinned_block(rlp, hash)?)
    }

    /// Anchor 2, one step: the next header is `child`'s parent.
    pub fn parent_header(&mut self, child: &Authenticated<Header>) -> Result<Authenticated<Header>, ReadError> {
        let rlp = self.next_header_bytes()?;
        Ok(anchor::parent_block(child, rlp)?)
    }

    /// The next account proof, for `address` under `state_root`.
    pub fn account(
        &mut self,
        state_root: &Authenticated<[u8; 32]>,
        address: &Authenticated<[u8; 20]>,
    ) -> Result<Authenticated<ProvenAccount>, ReadError> {
        let index = self.next_account;
        let a = self.w.accounts.get(index).ok_or(ReadError::Exhausted(Section::Accounts))?;
        self.next_account += 1;
        let account = state::verify_account(state_root.get(), address.get(), &a.proof.nodes)?;
        check_kind(a.proof.kind, account.is_some(), Section::Accounts, index)?;
        Ok(Authenticated::new(ProvenAccount { index, address: *address.get(), account }))
    }

    /// The next storage proof of `account`, for `slot`: its value (0 when absent).
    pub fn storage(
        &mut self,
        account: &Authenticated<ProvenAccount>,
        slot: &Authenticated<[u8; 32]>,
    ) -> Result<Authenticated<[u8; 32]>, ReadError> {
        let a = account.get();
        let section = Section::Storage(a.index);
        let next = self.next_storage.get_mut(a.index).ok_or(ReadError::Exhausted(section))?;
        let index = *next;
        let p = self.w.accounts[a.index].storage.get(index).ok_or(ReadError::Exhausted(section))?;
        *next += 1;
        let root = a.storage_root();
        let found = crate::mpt::verify(&root, &crate::keccak::keccak256(slot.get()), &p.nodes).map_err(StateError::from)?;
        check_kind(p.kind, found.is_some(), section, index)?;
        let value = match found {
            Some(v) => state::decode_storage_value(v)?,
            None => [0; 32],
        };
        Ok(Authenticated::new(value))
    }

    /// The next receipts-trie proof, for transaction `index` under `receipts_root`.
    pub fn receipt(
        &mut self,
        receipts_root: &Authenticated<[u8; 32]>,
        index: &Authenticated<u64>,
    ) -> Result<Authenticated<Option<Receipt>>, ReadError> {
        let i = self.next_receipt;
        let p = self.w.receipts.get(i).ok_or(ReadError::Exhausted(Section::Receipts))?;
        self.next_receipt += 1;
        let r = receipt::verify_receipt(receipts_root.get(), *index.get(), &p.nodes)?;
        check_kind(p.kind, r.is_some(), Section::Receipts, i)?;
        Ok(Authenticated::new(r))
    }

    /// The next transactions-trie proof, for `index` under `transactions_root`: the transaction and
    /// its hash.
    pub fn transaction(
        &mut self,
        transactions_root: &Authenticated<[u8; 32]>,
        index: &Authenticated<u64>,
    ) -> Result<Authenticated<Option<HashedTransaction>>, ReadError> {
        let i = self.next_tx;
        let p = self.w.transactions.get(i).ok_or(ReadError::Exhausted(Section::Transactions))?;
        self.next_tx += 1;
        let t = tx::verify_transaction(transactions_root.get(), *index.get(), &p.nodes)?;
        check_kind(p.kind, t.is_some(), Section::Transactions, i)?;
        Ok(Authenticated::new(t))
    }

    /// Ends the guest's use of `W`: every header word committed, every header, account, storage,
    /// receipt and transaction proof read. Returns the journal bytes to commit.
    pub fn finish(self, journal: JournalWriter) -> Result<Vec<u8>, ReadError> {
        if journal.header_words() != self.w.header_words.len() || self.next_word != self.w.header_words.len() {
            return Err(ReadError::Unconsumed(Section::Words));
        }
        if self.next_header != self.w.headers.len() {
            return Err(ReadError::Unconsumed(Section::Headers));
        }
        if self.next_account != self.w.accounts.len() {
            return Err(ReadError::Unconsumed(Section::Accounts));
        }
        for (i, (a, &n)) in self.w.accounts.iter().zip(&self.next_storage).enumerate() {
            if n != a.storage.len() {
                return Err(ReadError::Unconsumed(Section::Storage(i)));
            }
        }
        if self.next_receipt != self.w.receipts.len() {
            return Err(ReadError::Unconsumed(Section::Receipts));
        }
        if self.next_tx != self.w.transactions.len() {
            return Err(ReadError::Unconsumed(Section::Transactions));
        }
        Ok(journal.into_bytes()?)
    }
}

// ---------------------------------------------------------------------------------------------
// Structural mutations, for requester tooling (plan §21.1: `simulate --adversarial`).

/// A proof in a witness, by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofRef {
    Account(usize),
    Storage { account: usize, slot: usize },
    Receipt(usize),
    Transaction(usize),
}

/// One structural change to a witness. [`Witness::mutate`] applies it and returns the new `W`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// XOR `mask` into a header word: the journal header then differs, so the *binding* must
    /// refuse it (the guest may accept it).
    WordByte { word: usize, byte: usize, mask: u8 },
    /// XOR `mask` into a byte of a block header.
    HeaderByte { header: usize, byte: usize, mask: u8 },
    /// Replace a block header (with its parent, a sibling, a header from another chain).
    ReplaceHeader { header: usize, rlp: Vec<u8> },
    DropHeader { header: usize },
    /// XOR `mask` into a byte of a proof node.
    NodeByte { proof: ProofRef, node: usize, byte: usize, mask: u8 },
    DropNode { proof: ProofRef, node: usize },
    /// Insert `node` before position `at` (`at` = the node count appends).
    InsertNode { proof: ProofRef, at: usize, node: Vec<u8> },
    /// Claim inclusion for an exclusion proof or the reverse.
    FlipKind { proof: ProofRef },
    /// Replace a proof wholesale (another slot's proof, a truncated proof claiming exclusion).
    ReplaceProof { proof: ProofRef, kind: ProofKind, nodes: Vec<Vec<u8>> },
    /// Exchange two proofs (reordered leaves, swapped slots).
    SwapProofs { a: ProofRef, b: ProofRef },
    DropProof { proof: ProofRef },
    /// Insert a copy of a proof right after it.
    DuplicateProof { proof: ProofRef },
    /// Append raw bytes to the encoding.
    AppendBytes { bytes: Vec<u8> },
    /// Keep only the first `len` bytes of the encoding.
    TruncateBytes { len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationError {
    /// The mutation names a word, header, proof, node or byte the witness does not have.
    OutOfRange,
    /// Swapping a proof with itself, or a mutation that leaves the bytes unchanged.
    NoChange,
    Format(FormatError),
}

impl fmt::Display for MutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange => f.write_str("mutation: out of range"),
            Self::NoChange => f.write_str("mutation: changes nothing"),
            Self::Format(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MutationError {}

/// Which bytes of a header or node the standard mutations flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteSelection {
    /// Every byte.
    All,
    /// At most this many positions per item: both ends (where RLP headers and lengths sit) and an
    /// even spread between them.
    Sample(usize),
}

impl ByteSelection {
    fn positions(self, len: usize) -> Vec<usize> {
        match self {
            Self::All => (0..len).collect(),
            Self::Sample(n) if len <= n => (0..len).collect(),
            Self::Sample(n) => {
                let mut v: Vec<usize> = [0, 1, 2, 3, len - 3, len - 2, len - 1].into_iter().filter(|&i| i < len).collect();
                let spread = n.saturating_sub(v.len()).max(1);
                v.extend((1..=spread).map(|i| i * len / (spread + 1)));
                v.sort_unstable();
                v.dedup();
                v
            }
        }
    }
}

impl<'a> Witness<'a> {
    /// Every proof, in `W` order.
    pub fn proofs(&self) -> Vec<ProofRef> {
        let mut v = Vec::new();
        for (a, acc) in self.accounts.iter().enumerate() {
            v.push(ProofRef::Account(a));
            v.extend((0..acc.storage.len()).map(|s| ProofRef::Storage { account: a, slot: s }));
        }
        v.extend((0..self.receipts.len()).map(ProofRef::Receipt));
        v.extend((0..self.transactions.len()).map(ProofRef::Transaction));
        v
    }

    pub fn proof(&self, r: ProofRef) -> Option<&TrieProof<'a>> {
        match r {
            ProofRef::Account(a) => self.accounts.get(a).map(|x| &x.proof),
            ProofRef::Storage { account, slot } => self.accounts.get(account)?.storage.get(slot),
            ProofRef::Receipt(i) => self.receipts.get(i),
            ProofRef::Transaction(i) => self.transactions.get(i),
        }
    }

    fn proof_mut(&mut self, r: ProofRef) -> Option<&mut TrieProof<'a>> {
        match r {
            ProofRef::Account(a) => self.accounts.get_mut(a).map(|x| &mut x.proof),
            ProofRef::Storage { account, slot } => self.accounts.get_mut(account)?.storage.get_mut(slot),
            ProofRef::Receipt(i) => self.receipts.get_mut(i),
            ProofRef::Transaction(i) => self.transactions.get_mut(i),
        }
    }

    /// Removes a proof, or inserts one before position `at` of its list (account proofs move with
    /// their storage proofs; an inserted account proof gets none).
    fn edit_list(&mut self, r: ProofRef, insert: Option<TrieProof<'a>>) -> Option<()> {
        match (r, insert) {
            (ProofRef::Account(a), None) => (a < self.accounts.len()).then(|| {
                self.accounts.remove(a);
            }),
            (ProofRef::Account(a), Some(p)) => {
                (a <= self.accounts.len()).then(|| self.accounts.insert(a, AccountProof { proof: p, storage: Vec::new() }))
            }
            (ProofRef::Storage { account, slot }, ins) => {
                let list = &mut self.accounts.get_mut(account)?.storage;
                edit(list, slot, ins)
            }
            (ProofRef::Receipt(i), ins) => edit(&mut self.receipts, i, ins),
            (ProofRef::Transaction(i), ins) => edit(&mut self.transactions, i, ins),
        }
    }

    /// The encoding of this witness with `m` applied.
    pub fn mutate(&self, m: &Mutation) -> Result<Vec<u8>, MutationError> {
        let original = self.encode().map_err(MutationError::Format)?;
        let mut w = self.clone();
        let oob = MutationError::OutOfRange;
        let flip = |b: &mut [u8], at: usize, mask: u8| -> Result<(), MutationError> {
            *b.get_mut(at).ok_or(MutationError::OutOfRange)? ^= mask;
            Ok(())
        };
        match m {
            Mutation::WordByte { word, byte, mask } => flip(w.header_words.get_mut(*word).ok_or(oob)?, *byte, *mask)?,
            Mutation::HeaderByte { header, byte, mask } => flip(w.headers.get_mut(*header).ok_or(oob)?.to_mut(), *byte, *mask)?,
            Mutation::ReplaceHeader { header, rlp } => *w.headers.get_mut(*header).ok_or(oob)? = Cow::Owned(rlp.clone()),
            Mutation::DropHeader { header } => {
                if *header >= w.headers.len() {
                    return Err(oob);
                }
                w.headers.remove(*header);
            }
            Mutation::NodeByte { proof, node, byte, mask } => {
                let p = w.proof_mut(*proof).ok_or(oob)?;
                flip(p.nodes.get_mut(*node).ok_or(oob)?.to_mut(), *byte, *mask)?;
            }
            Mutation::DropNode { proof, node } => {
                let p = w.proof_mut(*proof).ok_or(oob)?;
                if *node >= p.nodes.len() {
                    return Err(oob);
                }
                p.nodes.remove(*node);
            }
            Mutation::InsertNode { proof, at, node } => {
                let p = w.proof_mut(*proof).ok_or(oob)?;
                if *at > p.nodes.len() {
                    return Err(oob);
                }
                p.nodes.insert(*at, Cow::Owned(node.clone()));
            }
            Mutation::FlipKind { proof } => {
                let p = w.proof_mut(*proof).ok_or(oob)?;
                p.kind = p.kind.flipped();
            }
            Mutation::ReplaceProof { proof, kind, nodes } => {
                *w.proof_mut(*proof).ok_or(oob)? =
                    TrieProof { kind: *kind, nodes: nodes.iter().map(|n| Cow::Owned(n.clone())).collect() };
            }
            Mutation::SwapProofs { a, b } => {
                let pa = w.proof(*a).ok_or(oob)?.clone();
                let pb = w.proof(*b).ok_or(oob)?.clone();
                *w.proof_mut(*a).ok_or(oob)? = pb;
                *w.proof_mut(*b).ok_or(oob)? = pa;
            }
            Mutation::DropProof { proof } => w.edit_list(*proof, None).ok_or(oob)?,
            Mutation::DuplicateProof { proof } => {
                let copy = w.proof(*proof).ok_or(oob)?.clone();
                let after = match *proof {
                    ProofRef::Account(a) => ProofRef::Account(a + 1),
                    ProofRef::Storage { account, slot } => ProofRef::Storage { account, slot: slot + 1 },
                    ProofRef::Receipt(i) => ProofRef::Receipt(i + 1),
                    ProofRef::Transaction(i) => ProofRef::Transaction(i + 1),
                };
                w.edit_list(after, Some(copy)).ok_or(oob)?;
            }
            Mutation::AppendBytes { bytes } => {
                let mut out = original.clone();
                out.extend_from_slice(bytes);
                return if bytes.is_empty() { Err(MutationError::NoChange) } else { Ok(out) };
            }
            Mutation::TruncateBytes { len } => {
                return if *len >= original.len() { Err(MutationError::NoChange) } else { Ok(original[..*len].to_vec()) };
            }
        }
        let out = w.encode().map_err(MutationError::Format)?;
        if out == original {
            return Err(MutationError::NoChange);
        }
        Ok(out)
    }

    /// The standard structural mutations of plan §21.1 that need nothing from outside the witness:
    /// byte flips in header words, headers and nodes (per `bytes`); every node dropped and
    /// duplicated; a node appended to every proof; every kind flipped; every inclusion proof
    /// replaced by its truncation and by the empty proof, both claiming exclusion; every proof
    /// dropped and duplicated; adjacent proofs of a list swapped (reordered leaves); each storage
    /// proof replaced by the next slot's (another slot's proof); every header dropped; trailing bytes
    /// appended and the last byte cut. Swapping in a parent or sibling header needs that header:
    /// add [`Mutation::ReplaceHeader`] for it.
    pub fn standard_mutations(&self, bytes: ByteSelection) -> Vec<Mutation> {
        let mut out = Vec::new();
        for word in 0..self.header_words.len() {
            for byte in [0usize, 31] {
                out.push(Mutation::WordByte { word, byte, mask: 0x01 });
            }
        }
        for (header, h) in self.headers.iter().enumerate() {
            for byte in bytes.positions(h.len()) {
                out.push(Mutation::HeaderByte { header, byte, mask: 0x01 });
            }
            out.push(Mutation::DropHeader { header });
        }
        let proofs = self.proofs();
        for &r in &proofs {
            let p = self.proof(r).expect("listed");
            for (node, n) in p.nodes.iter().enumerate() {
                for byte in bytes.positions(n.len()) {
                    out.push(Mutation::NodeByte { proof: r, node, byte, mask: 0x01 });
                }
                out.push(Mutation::DropNode { proof: r, node });
                out.push(Mutation::InsertNode { proof: r, at: node, node: n.to_vec() });
            }
            if let Some(first) = p.nodes.first() {
                out.push(Mutation::InsertNode { proof: r, at: p.nodes.len(), node: first.to_vec() });
            }
            out.push(Mutation::FlipKind { proof: r });
            if p.kind == ProofKind::Inclusion && !p.nodes.is_empty() {
                let truncated = p.nodes[..p.nodes.len() - 1].iter().map(|n| n.to_vec()).collect();
                out.push(Mutation::ReplaceProof { proof: r, kind: ProofKind::Exclusion, nodes: truncated });
                out.push(Mutation::ReplaceProof { proof: r, kind: ProofKind::Exclusion, nodes: Vec::new() });
            }
            out.push(Mutation::DropProof { proof: r });
            out.push(Mutation::DuplicateProof { proof: r });
        }
        // Neighbours in the same list: swapped, and (storage) one slot's proof for another's.
        for pair in proofs.windows(2) {
            let same_list = match (pair[0], pair[1]) {
                (ProofRef::Account(_), ProofRef::Account(_))
                | (ProofRef::Receipt(_), ProofRef::Receipt(_))
                | (ProofRef::Transaction(_), ProofRef::Transaction(_)) => true,
                (ProofRef::Storage { account: a, .. }, ProofRef::Storage { account: b, .. }) => a == b,
                _ => false,
            };
            if same_list {
                out.push(Mutation::SwapProofs { a: pair[0], b: pair[1] });
            }
            if let (ProofRef::Storage { account: a, .. }, ProofRef::Storage { account: b, .. }) = (pair[0], pair[1]) {
                if a == b {
                    let other = self.proof(pair[1]).expect("listed");
                    out.push(Mutation::ReplaceProof {
                        proof: pair[0],
                        kind: other.kind,
                        nodes: other.nodes.iter().map(|n| n.to_vec()).collect(),
                    });
                }
            }
        }
        // One account's trie proof in another's place (their storage proofs stay where they are).
        for a in 1..self.accounts.len() {
            out.push(Mutation::SwapProofs { a: ProofRef::Account(0), b: ProofRef::Account(a) });
        }
        out.push(Mutation::AppendBytes { bytes: alloc::vec![0] });
        out.push(Mutation::AppendBytes { bytes: alloc::vec![0; 32] });
        out.push(Mutation::TruncateBytes { len: self.encode().map(|e| e.len()).unwrap_or(1).saturating_sub(1) });
        out
    }
}

fn edit<T>(list: &mut Vec<T>, at: usize, insert: Option<T>) -> Option<()> {
    match insert {
        None => (at < list.len()).then(|| {
            list.remove(at);
        }),
        Some(x) => (at <= list.len()).then(|| list.insert(at, x)),
    }
}

/// How a mutated witness fared against the honest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The guest refused it.
    Rejected,
    /// The guest produced the honest journal, byte for byte.
    Identical,
    /// The journal differs within the pinned bytes (prefix and header), so the binding refuses it.
    BindingRejects,
    /// The pinned bytes match and the outputs differ: a prover could fulfil the job with a
    /// different answer. A soundness bug in the guest or the prelude.
    Unsound,
}

/// Judges a mutated run: `mutated` is the journal the guest produced, or `None` if it failed;
/// `pinned_len` is the number of journal bytes the binding pins (prefix and header: 64 + 32 × k),
/// for the plan's layout where they are a prefix of the journal.
pub fn judge(honest: &[u8], mutated: Option<&[u8]>, pinned_len: usize) -> Verdict {
    judge_with(honest, mutated, |j| j.get(..pinned_len) == honest.get(..pinned_len))
}

/// [`judge`] for any binding: `satisfies_binding(journal)` says whether the job's binding accepts a
/// journal (for FIELDS, whether the router's fields hash of it equals `expectedJournalHash`).
pub fn judge_with(honest: &[u8], mutated: Option<&[u8]>, satisfies_binding: impl Fn(&[u8]) -> bool) -> Verdict {
    match mutated {
        None => Verdict::Rejected,
        Some(j) if j == honest => Verdict::Identical,
        Some(j) if !satisfies_binding(j) => Verdict::BindingRejects,
        Some(_) => Verdict::Unsound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn sample() -> Witness<'static> {
        let node = |b: u8, n: usize| Cow::Owned(vec![b; n]);
        Witness {
            header_words: vec![scheme_word(), [7; 32]],
            headers: vec![node(0xf9, 600)],
            accounts: vec![
                AccountProof {
                    proof: TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(1, 532), node(2, 100)] },
                    storage: vec![
                        TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(3, 40)] },
                        TrieProof { kind: ProofKind::Exclusion, nodes: vec![] },
                    ],
                },
                AccountProof { proof: TrieProof { kind: ProofKind::Exclusion, nodes: vec![node(4, 33)] }, storage: vec![] },
            ],
            receipts: vec![TrieProof { kind: ProofKind::Inclusion, nodes: vec![node(5, 70)] }],
            transactions: vec![],
        }
    }

    #[test]
    fn layout_is_exactly_as_documented() {
        let w = Witness {
            header_words: vec![scheme_word()],
            headers: vec![Cow::Borrowed(&[0xc0][..])],
            accounts: vec![AccountProof {
                proof: TrieProof { kind: ProofKind::Exclusion, nodes: vec![Cow::Borrowed(&[0xaa, 0xbb][..])] },
                storage: vec![],
            }],
            receipts: vec![],
            transactions: vec![],
        };
        let mut want = b"HPW\x01\x01\x00\x01".to_vec();
        want.extend(scheme_word());
        want.extend([0, 0, 0, 1, 0, 0, 0, 1, 0xc0]); // one header: len 1, 0xc0
        want.extend([0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 0]); // one account
        want.extend([0, 0, 0, 0, 0, 0, 0, 0]); // no receipts, no transactions
        assert_eq!(w.encode().unwrap(), want);
        assert_eq!(Witness::decode(&want).unwrap(), w);
        assert!(is_scheme1(&want));
    }

    #[test]
    fn round_trip_and_strictness() {
        let w = sample();
        let enc = w.encode().unwrap();
        assert_eq!(Witness::decode(&enc).unwrap(), w);
        let mut trailing = enc.clone();
        trailing.push(0);
        assert_eq!(Witness::decode(&trailing), Err(FormatError::TrailingBytes));
        assert_eq!(Witness::decode(&enc[..enc.len() - 1]), Err(FormatError::Truncated));
        let mut bad = enc.clone();
        bad[3] = 2;
        assert_eq!(Witness::decode(&bad), Err(FormatError::BadMagic));
        let mut bad = enc.clone();
        bad[4] = 2;
        assert_eq!(Witness::decode(&bad), Err(FormatError::BadMagic));
        let mut bad = enc.clone();
        bad[7 + 31] = 2;
        assert_eq!(Witness::decode(&bad), Err(FormatError::SchemeWord));
        let mut no_words = enc[..5].to_vec();
        no_words.extend([0, 0]);
        assert_eq!(Witness::decode(&no_words), Err(FormatError::WordCount));
        let mut w0 = w.clone();
        w0.headers[0] = Cow::Owned(vec![]);
        assert_eq!(w0.encode(), Err(FormatError::EmptyBytes));
    }

    #[test]
    fn every_standard_mutation_changes_the_bytes() {
        let w = sample();
        let enc = w.encode().unwrap();
        let ms = w.standard_mutations(ByteSelection::Sample(8));
        assert!(ms.len() > 50);
        for m in &ms {
            match w.mutate(m) {
                Ok(out) => assert_ne!(out, enc, "{m:?}"),
                Err(e) => panic!("{m:?}: {e}"),
            }
        }
        assert_eq!(w.mutate(&Mutation::SwapProofs { a: ProofRef::Account(0), b: ProofRef::Account(0) }), Err(MutationError::NoChange));
        assert_eq!(w.mutate(&Mutation::DropNode { proof: ProofRef::Receipt(3), node: 0 }), Err(MutationError::OutOfRange));
    }

    #[test]
    fn byte_selection() {
        assert_eq!(ByteSelection::Sample(10).positions(5), vec![0, 1, 2, 3, 4]);
        let p = ByteSelection::Sample(10).positions(532);
        assert!(p.len() <= 11 && p.contains(&0) && p.contains(&531) && p.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ByteSelection::All.positions(3), vec![0, 1, 2]);
    }

    #[test]
    fn judging() {
        let honest = [1u8, 2, 3, 4];
        assert_eq!(judge(&honest, None, 2), Verdict::Rejected);
        assert_eq!(judge(&honest, Some(&honest), 2), Verdict::Identical);
        assert_eq!(judge(&honest, Some(&[1, 9, 3, 4]), 2), Verdict::BindingRejects);
        assert_eq!(judge(&honest, Some(&[1, 2]), 3), Verdict::BindingRejects);
        assert_eq!(judge(&honest, Some(&[1, 2, 3, 5]), 2), Verdict::Unsound);
        assert_eq!(judge(&honest, Some(&[1, 2, 3, 4, 5]), 2), Verdict::Unsound);
        // A binding over the last byte only.
        let last_is_4 = |j: &[u8]| j.last() == Some(&4);
        assert_eq!(judge_with(&honest, Some(&[9, 9, 9, 4]), last_is_4), Verdict::Unsound);
        assert_eq!(judge_with(&honest, Some(&[1, 2, 3, 5]), last_is_4), Verdict::BindingRejects);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = Witness::decode(&bytes);
            let mut b = b"HPW\x01\x01\x00\x01".to_vec();
            b.extend(scheme_word());
            b.extend(&bytes);
            if let Ok(w) = Witness::decode(&b) {
                prop_assert_eq!(w.encode().unwrap(), b);
            }
        }
    }
}
