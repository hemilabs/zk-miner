//! The guards of plan §8.3, "commit what you checked", as types.
//!
//! A guest may put only two kinds of value into its journal, and use only those to choose a trie
//! key or a selection:
//!
//! - [`Pinned<T>`]: a journal-header word read from `W`. The binding pins the header, so a pinned
//!   value is the requester's, whatever `W` says; it is committed exactly once, in header order,
//!   by [`JournalWriter::commit_pinned`].
//! - [`Authenticated<T>`]: a value a verifier produced (a header that hashes to a pinned hash, a
//!   leaf a trie proof reaches from an authenticated root), a pinned value
//!   ([`Pinned::authenticated`]), a guest constant ([`constant!`](crate::constant)), or a function
//!   of those ([`Authenticated::map`], [`Authenticated::zip`]).
//!
//! Nothing outside this crate can construct either from a runtime value: the constructors are
//! private, and the one public way in, [`constant!`](crate::constant), takes a `const` item.
//! Both types hold only [`PlainData`] (integers, `bool`, byte arrays, and `Vec`s, `Option`s,
//! arrays and tuples of plain data, and this crate's own value types), and every derivation's
//! result must be plain data too: nothing with interior mutability (`Cell`, `RefCell`,
//! `OnceCell`, `OnceLock`, `LazyCell`, `LazyLock`, `Mutex`, `RwLock`, the atomics), no reference
//! or pointer, no function and no type of the guest's own. So a value inside an `Authenticated`
//! cannot be changed through the shared borrow [`Authenticated::get`] gives, and what a
//! derivation made is what reaches the journal. [`ToWord`], what an output may be, is sealed the
//! same way, so a guest cannot define an output type that writes what it likes. So a value read
//! from `W` without verification cannot reach a trie key or the journal by accident.
//!
//! The derivations take plain `fn` pointers, so a closure that captures a value (from `W`, a
//! counter) does not compile into one. What the types do **not** stop, and the guest lints and an
//! audit must: a non-capturing function that reads a `static` or a `thread_local!` the guest
//! filled from `W` or from a host input (the lints refuse both, and every interior-mutable type, in
//! a guest's sources: `reference/proxy-slots/methods/tests/guest_lints.rs`), `unsafe` code that
//! reads memory the guest wrote, and control flow: a guest that branches on an unverified value to
//! choose which derivation runs, or derives with a function that returns a constant it made up.
//! The types make accidents hard; the lints and an audit of every derivation catch the rest.
//! [`indices`] gives the loop counters a pinned count allows.
//!
//! What does not compile (each a way a guest once turned an unverified value into an output):
//!
//! ```compile_fail
//! // No public constructor from a runtime value.
//! use hemiprove_eth_prelude::guard::Authenticated;
//! fn smuggle(hint: u64) -> Authenticated<u64> {
//!     Authenticated::__from_guest_constant(hint)
//! }
//! ```
//!
//! ```compile_fail
//! // A constant with interior mutability, set at run time.
//! use hemiprove_eth_prelude::constant;
//! use std::cell::Cell;
//! let cell = constant!(Cell<u64> = Cell::new(0));
//! cell.get().set(7);
//! ```
//!
//! ```compile_fail
//! // An output type of the guest's own, which could write anything.
//! use hemiprove_eth_prelude::guard::ToWord;
//! struct FromAnywhere;
//! impl ToWord for FromAnywhere {
//!     fn to_word(&self) -> [u8; 32] {
//!         [7; 32]
//!     }
//! }
//! ```
//!
//! ```compile_fail
//! // A closure that captures a value is not a derivation.
//! use hemiprove_eth_prelude::constant;
//! let hint = 7u64;
//! let a = constant!(u64 = 1).map(|x| x + hint);
//! ```
//!
//! An interior-mutable value derived into an `Authenticated`, written through `get` (a shared
//! borrow) and mapped back out: a `OnceCell`,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::cell::OnceCell;
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let cell = a.derive(|_| OnceCell::<u64>::new());
//! cell.get().set(hint).unwrap();
//! let smuggled: Authenticated<u64> = cell.map(|c| c.into_inner().unwrap());
//! ```
//!
//! a `Mutex`,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::sync::Mutex;
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let m = a.derive(|_| Mutex::new(0u64));
//! *m.get().lock().unwrap() = hint;
//! let smuggled: Authenticated<u64> = m.map(|m| m.into_inner().unwrap());
//! ```
//!
//! an atomic,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::sync::atomic::{AtomicU64, Ordering};
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let at = a.derive(|_| AtomicU64::new(0));
//! at.get().store(hint, Ordering::Relaxed);
//! let smuggled: Authenticated<u64> = at.map(AtomicU64::into_inner);
//! ```
//!
//! a `OnceLock`,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::sync::OnceLock;
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let ol = a.derive(|_| OnceLock::<u64>::new());
//! ol.get().set(hint).unwrap();
//! let smuggled: Authenticated<u64> = ol.map(|c| c.into_inner().unwrap());
//! ```
//!
//! an atomic behind a leaked reference (a reference is no more plain data than the cell),
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::sync::atomic::{AtomicU64, Ordering};
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let at = a.derive(|_| &*Box::leak(Box::new(AtomicU64::new(0))));
//! at.get().store(hint, Ordering::Relaxed);
//! let smuggled: Authenticated<u64> = at.map(|a| a.load(Ordering::Relaxed));
//! ```
//!
//! a type of the guest's own, which could hold any of those,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::{constant, guard::Authenticated};
//! use std::cell::OnceCell;
//! struct Mine(OnceCell<u64>);
//! let hint = 7u64;
//! let a: Authenticated<u64> = constant!(u64 = 1);
//! let mine = a.derive(|_| Mine(OnceCell::new()));
//! mine.get().0.set(hint).unwrap();
//! let smuggled: Authenticated<u64> = mine.map(|m| m.0.into_inner().unwrap());
//! ```
//!
//! which cannot be declared plain data either,
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::guard::PlainData;
//! struct Mine(std::cell::OnceCell<u64>);
//! impl PlainData for Mine {}
//! ```
//!
//! and a pinned word parsed into a `OnceCell` (it is `Clone`, so it would pass
//! [`Pinned::authenticated`] too):
//!
//! ```compile_fail
//! use hemiprove_eth_prelude::scheme1::{scheme_word, Reader, Witness};
//! use std::cell::OnceCell;
//! let w = Witness { header_words: vec![scheme_word(), [7; 32]], headers: vec![], accounts: vec![], receipts: vec![], transactions: vec![] }
//!     .encode()
//!     .unwrap();
//! let mut r = Reader::new(&w).unwrap();
//! let _scheme = r.pin_scheme_id().unwrap();
//! let pinned = r.pin_word().unwrap().try_map(|_| Ok::<_, ()>(OnceCell::<u64>::new())).unwrap();
//! pinned.get().set(7).unwrap();
//! let smuggled = pinned.authenticated().map(|c| c.into_inner().unwrap());
//! ```
//!
//! The derivations a guest does make still compile: a header's field, a pair, a list's items, an
//! optional account.
//!
//! ```
//! use hemiprove_eth_prelude::{constant, guard::Authenticated, state::Account};
//! let root: Authenticated<[u8; 32]> = constant!([u8; 32] = [3; 32]);
//! let count: Authenticated<u64> = constant!(u64 = 2);
//! let pair: Authenticated<([u8; 32], u64)> = root.zip(count);
//! let slots: Authenticated<Vec<[u8; 32]>> = pair.map(|(r, k)| (0..k).map(|i| [r[0] + i as u8; 32]).collect());
//! let items: Vec<Authenticated<[u8; 32]>> = slots.into_items().collect();
//! assert_eq!(*items[1].get(), [4; 32]);
//! let account: Authenticated<Option<Account>> = constant!(Option<Account> = Some(Account::ABSENT));
//! let nonce: Authenticated<u64> = account.derive(|a| a.map_or(0, |a| a.nonce));
//! let parsed: Result<Authenticated<u8>, ()> = nonce.try_map(|n| u8::try_from(n).map_err(|_| ()));
//! assert_eq!(parsed.unwrap().into_inner(), 0);
//! ```
//!
//! The journal ([`JournalWriter`]) is `prefix ‖ header ‖ outputs` (plan §7.2): the 64-byte
//! `abi.encode(jobId, prover)` prefix copied from the guest input, every pinned word in order, then
//! outputs, which accept only authenticated values. [`crate::scheme1::Reader::finish`] returns the
//! bytes only once `W` is consumed in full; the guest commits them with one `env::commit_slice`.

use alloc::vec::Vec;
use core::fmt;

/// A journal-header word read from `W`, with the value it encodes. Not `Clone`: each word exists
/// once and is committed once.
#[derive(Debug)]
pub struct Pinned<T: PlainData> {
    index: usize,
    word: [u8; 32],
    value: T,
}

impl<T: PlainData> Pinned<T> {
    pub(crate) fn new(index: usize, word: [u8; 32], value: T) -> Self {
        Self { index, word, value }
    }

    pub fn get(&self) -> &T {
        &self.value
    }

    /// The header word exactly as `W` carries it and the journal commits it.
    pub fn word(&self) -> &[u8; 32] {
        &self.word
    }

    /// Its position in the header.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl<T: PlainData> Pinned<T> {
    /// The same word, its value parsed further (a rule id and parameter from a raw word); the word
    /// and its position stay as they were.
    pub fn try_map<U: PlainData, E>(self, f: fn(T) -> Result<U, E>) -> Result<Pinned<U>, E> {
        Ok(Pinned { index: self.index, word: self.word, value: f(self.value)? })
    }
}

impl<T: PlainData + Clone> Pinned<T> {
    /// The value as an authenticated input: the binding fixes it to the requester's.
    pub fn authenticated(&self) -> Authenticated<T> {
        Authenticated(self.value.clone())
    }
}

/// A value a verifier produced, or derived only from such values, pinned values and guest
/// constants. Always [`PlainData`], so nothing can change it through [`get`](Self::get).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated<T: PlainData>(T);

impl<T: PlainData> Authenticated<T> {
    /// Only this crate's verifiers construct authenticated values.
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }

    /// A value derived from this one by a function that sees nothing else.
    pub fn map<U: PlainData>(self, f: fn(T) -> U) -> Authenticated<U> {
        Authenticated(f(self.0))
    }

    /// A value derived from a borrow of this one by a function that sees nothing else.
    pub fn derive<U: PlainData>(&self, f: fn(&T) -> U) -> Authenticated<U> {
        Authenticated(f(&self.0))
    }

    /// Two authenticated values as one, for derivations with two inputs.
    pub fn zip<U: PlainData>(self, other: Authenticated<U>) -> Authenticated<(T, U)> {
        Authenticated((self.0, other.0))
    }

    /// A derivation that can fail (a fallible decode of an authenticated byte string).
    pub fn try_map<U: PlainData, E>(self, f: fn(T) -> Result<U, E>) -> Result<Authenticated<U>, E> {
        f(self.0).map(Authenticated)
    }
}

impl<T: PlainData> Authenticated<T> {
    /// For [`constant!`](crate::constant): `C::VALUE` is an associated constant, evaluated when the
    /// guest is compiled, so no runtime value (and nothing from `W`) can pass through; a guest
    /// constant is part of the image, so it is as fixed as the binding. `T` is [`PlainData`], so the
    /// constant cannot be changed afterwards either.
    #[doc(hidden)]
    pub fn __constant<C: GuestConstant<Value = T>>() -> Self {
        Self(C::VALUE)
    }
}

pub(crate) mod sealed {
    /// Implemented only in this crate: what [`super::PlainData`] and [`super::ToWord`] require.
    pub trait Sealed {}
}

/// Plain data: what a [`Pinned`] or [`Authenticated`] value, every derivation's result and a guest
/// constant may be. Integers, `bool`, `()`, and arrays, `Vec`s, `Option`s and tuples (up to six
/// elements) of plain data, and this crate's own value types, each of whose fields is plain data
/// (checked where the type is declared). Nothing with interior mutability (`Cell`, `RefCell`,
/// `OnceCell`, `OnceLock`, `LazyCell`, `LazyLock`, `Mutex`, `RwLock`, the atomics): a guest could
/// derive one into an `Authenticated`, set it from `W` through the shared borrow
/// [`Authenticated::get`] gives, and map it back out. No reference or pointer either (a leaked
/// `&'static AtomicU64` is as good as the cell), no function, and no type of the guest's own, which
/// could hold any of those. Sealed: a guest cannot add a type.
pub trait PlainData: sealed::Sealed {}

macro_rules! plain_data_primitives {
    ($($t:ty),*) => {$(
        impl sealed::Sealed for $t {}
        impl PlainData for $t {}
    )*};
}
plain_data_primitives!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char, ());

impl<T: PlainData, const N: usize> sealed::Sealed for [T; N] {}
impl<T: PlainData, const N: usize> PlainData for [T; N] {}
impl<T: PlainData> sealed::Sealed for Vec<T> {}
impl<T: PlainData> PlainData for Vec<T> {}
impl<T: PlainData> sealed::Sealed for Option<T> {}
impl<T: PlainData> PlainData for Option<T> {}

macro_rules! plain_data_tuples {
    ($(($($t:ident),+)),*) => {$(
        impl<$($t: PlainData),+> sealed::Sealed for ($($t,)+) {}
        impl<$($t: PlainData),+> PlainData for ($($t,)+) {}
    )*};
}
plain_data_tuples!((A, B), (A, B, C), (A, B, C, D), (A, B, C, D, E), (A, B, C, D, E, F));

/// Declares one of this crate's own value types [`PlainData`], next to its definition. The pattern
/// names every field (or every variant and its fields), so a field added later breaks the build
/// until it is listed here, and each must be plain data itself.
macro_rules! plain_data {
    (struct $t:ident { $($f:ident),* $(,)? }) => {
        impl $crate::guard::sealed::Sealed for $t {}
        impl $crate::guard::PlainData for $t {}
        const _: () = {
            #[allow(dead_code)]
            fn every_field_is_plain_data(v: &$t) {
                let $t { $($f),* } = v;
                $($crate::guard::is_plain_data($f);)*
            }
        };
    };
    (enum $t:ident { $($v:ident $(($($f:ident),*))?),* $(,)? }) => {
        impl $crate::guard::sealed::Sealed for $t {}
        impl $crate::guard::PlainData for $t {}
        const _: () = {
            #[allow(dead_code)]
            fn every_field_is_plain_data(v: &$t) {
                match v {
                    $($t::$v $(($($f),*))? => { $($($crate::guard::is_plain_data($f);)*)? })*
                }
            }
        };
    };
}
pub(crate) use plain_data;

/// Compiles only for plain data: [`plain_data!`]'s field check.
pub(crate) fn is_plain_data<T: PlainData>(_: &T) {}

/// A guest constant: [`constant!`](crate::constant) implements it for a type of its own, with the
/// expression as `VALUE`.
#[doc(hidden)]
pub trait GuestConstant {
    type Value: PlainData;
    const VALUE: Self::Value;
}

/// A guest constant as an [`Authenticated`] value. The expression must be a constant expression
/// (it is an associated `const`), so no runtime value, and nothing from `W`, can pass through; the
/// type must be [`PlainData`].
///
/// ```
/// use hemiprove_eth_prelude::{constant, guard::Authenticated};
/// let slot: Authenticated<[u8; 32]> = constant!([u8; 32] = [0x11; 32]);
/// ```
///
/// A runtime value does not compile:
///
/// ```compile_fail
/// use hemiprove_eth_prelude::constant;
/// fn smuggle(hint: u64) {
///     let _ = constant!(u64 = hint);
/// }
/// ```
#[macro_export]
macro_rules! constant {
    ($ty:ty = $value:expr) => {{
        struct GuestConstant;
        impl $crate::guard::GuestConstant for GuestConstant {
            type Value = $ty;
            const VALUE: $ty = $value;
        }
        $crate::guard::Authenticated::<$ty>::__constant::<GuestConstant>()
    }};
}

impl<T: PlainData> Authenticated<alloc::vec::Vec<T>> {
    /// The elements of an authenticated list, each authenticated.
    pub fn into_items(self) -> impl Iterator<Item = Authenticated<T>> {
        self.0.into_iter().map(Authenticated)
    }
}

/// `0, 1, …, count − 1` as authenticated counters, for loops whose bound is pinned or proven.
pub fn indices(count: &Authenticated<u64>) -> impl Iterator<Item = Authenticated<u64>> {
    (0..count.0).map(Authenticated)
}

/// A value that fills one 32-byte journal word, big-endian and left-padded like `abi.encode`.
/// Sealed: an output is one of these types, never a guest's own (whose `to_word` could read
/// anything).
pub trait ToWord: PlainData {
    fn to_word(&self) -> [u8; 32];
}

impl ToWord for [u8; 32] {
    fn to_word(&self) -> [u8; 32] {
        *self
    }
}

impl ToWord for [u8; 20] {
    fn to_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(self);
        w
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&self.to_be_bytes());
        w
    }
}

impl ToWord for bool {
    fn to_word(&self) -> [u8; 32] {
        u64::from(*self).to_word()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// A pinned word committed out of header order (or twice).
    PinnedOutOfOrder { expected: usize, found: usize },
    /// An output before every header word was committed.
    OutputBeforeHeader,
    /// The journal finished with header words uncommitted.
    HeaderIncomplete,
    /// A guest input shorter than the 64-byte prefix, or a prefix whose padding is not zero.
    BadPrefix,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinnedOutOfOrder { expected, found } => {
                write!(f, "journal: header word {found} committed where word {expected} belongs")
            }
            Self::OutputBeforeHeader => f.write_str("journal: output before the header is complete"),
            Self::HeaderIncomplete => f.write_str("journal: header words left uncommitted"),
            Self::BadPrefix => f.write_str("guest input: no valid abi.encode(jobId, prover) prefix"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GuardError {}

/// The journal-prefix bytes `abi.encode(jobId, prover)` the miner puts before `W` (plan §7.2), and
/// which the guest copies to the start of its journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPrefix(pub [u8; 64]);

impl GuestPrefix {
    pub fn job_id(&self) -> [u8; 32] {
        self.0[..32].try_into().expect("32 bytes")
    }

    pub fn prover(&self) -> [u8; 20] {
        self.0[44..].try_into().expect("20 bytes")
    }
}

/// Splits a journal-prefix job's guest input into the prefix and `W`. The prefix is not
/// authenticated here (the router checks it against the job and the caller); the guest only copies
/// it, and refuses one whose address word has non-zero padding, which no router would accept.
pub fn split_prefixed(input: &[u8]) -> Result<(GuestPrefix, &[u8]), GuardError> {
    if input.len() < 64 || input[32..44].iter().any(|&b| b != 0) {
        return Err(GuardError::BadPrefix);
    }
    Ok((GuestPrefix(input[..64].try_into().expect("64 bytes")), &input[64..]))
}

/// The journal, in the order plan §7.2 fixes. Buffered: nothing reaches the real journal until the
/// whole witness is verified and consumed.
#[derive(Debug)]
pub struct JournalWriter {
    buf: Vec<u8>,
    header_words: usize,
    next_pinned: usize,
}

impl JournalWriter {
    /// Starts a journal with `prefix` (journal-prefix jobs) and a header of `header_words` words.
    pub fn new(prefix: Option<&GuestPrefix>, header_words: usize) -> Self {
        let mut buf = Vec::with_capacity(64 + 32 * header_words + 256);
        if let Some(p) = prefix {
            buf.extend_from_slice(&p.0);
        }
        Self { buf, header_words, next_pinned: 0 }
    }

    /// Commits the next header word. Words go in header order, each once.
    pub fn commit_pinned<T: PlainData>(&mut self, p: &Pinned<T>) -> Result<(), GuardError> {
        if p.index != self.next_pinned {
            return Err(GuardError::PinnedOutOfOrder { expected: self.next_pinned, found: p.index });
        }
        self.buf.extend_from_slice(&p.word);
        self.next_pinned += 1;
        Ok(())
    }

    /// Appends an output word, once the header is complete.
    pub fn output<T: ToWord>(&mut self, v: &Authenticated<T>) -> Result<(), GuardError> {
        if self.next_pinned != self.header_words {
            return Err(GuardError::OutputBeforeHeader);
        }
        self.buf.extend_from_slice(&v.0.to_word());
        Ok(())
    }

    /// The journal bytes; refused unless every header word was committed. Called by
    /// [`crate::scheme1::Reader::finish`], which also checks that `W` was consumed.
    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, GuardError> {
        if self.next_pinned != self.header_words {
            return Err(GuardError::HeaderIncomplete);
        }
        Ok(self.buf)
    }

    pub(crate) fn header_words(&self) -> usize {
        self.header_words
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_words_commit_in_order_once() {
        let a = Pinned::new(0, [1; 32], ());
        let b = Pinned::new(1, [2; 32], ());
        let mut j = JournalWriter::new(None, 2);
        assert_eq!(j.output(&Authenticated::new(7u64)), Err(GuardError::OutputBeforeHeader));
        assert_eq!(j.commit_pinned(&b), Err(GuardError::PinnedOutOfOrder { expected: 0, found: 1 }));
        j.commit_pinned(&a).unwrap();
        assert_eq!(j.commit_pinned(&a), Err(GuardError::PinnedOutOfOrder { expected: 1, found: 0 }));
        j.commit_pinned(&b).unwrap();
        j.output(&Authenticated::new([9u8; 20])).unwrap();
        let bytes = j.into_bytes().unwrap();
        assert_eq!(&bytes[..32], &[1; 32]);
        assert_eq!(&bytes[32..64], &[2; 32]);
        assert_eq!(&bytes[64..76], &[0; 12]);
        assert_eq!(&bytes[76..96], &[9; 20]);
        let mut j = JournalWriter::new(None, 1);
        assert_eq!(j.output(&Authenticated::new(true)), Err(GuardError::OutputBeforeHeader));
        assert_eq!(JournalWriter::new(None, 1).into_bytes(), Err(GuardError::HeaderIncomplete));
    }

    #[test]
    fn prefix_split() {
        let mut input = [0u8; 70];
        input[..32].fill(0xaa);
        input[44..64].fill(0xbb);
        input[64..].fill(0xcc);
        let (p, w) = split_prefixed(&input).unwrap();
        assert_eq!(p.job_id(), [0xaa; 32]);
        assert_eq!(p.prover(), [0xbb; 20]);
        assert_eq!(w, &[0xcc; 6]);
        let mut j = JournalWriter::new(Some(&p), 0);
        j.output(&Authenticated::new(1u64)).unwrap();
        assert_eq!(&j.into_bytes().unwrap()[..64], &input[..64]);
        input[40] = 1;
        assert_eq!(split_prefixed(&input), Err(GuardError::BadPrefix));
        assert_eq!(split_prefixed(&[0; 63]), Err(GuardError::BadPrefix));
    }

    #[test]
    fn derivations() {
        let a = Authenticated::new(3u64);
        let b: Authenticated<u64> = crate::constant!(u64 = 4);
        let sum = a.zip(b).map(|(x, y)| x + y);
        assert_eq!(*sum.get(), 7);
        assert_eq!(indices(&sum).map(Authenticated::into_inner).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5, 6]);
        let p = Pinned::new(0, 5u64.to_word(), 5u64);
        assert_eq!(p.authenticated().into_inner(), 5);
    }
}
