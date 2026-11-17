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
//! Nothing outside this crate can construct either from raw bytes, so a value read from `W`
//! without verification cannot reach a trie key or the journal by accident. The derivations take
//! plain `fn` pointers: a closure that captures anything (a value from `W`, a counter) does not
//! coerce to one, so a derivation cannot smuggle in an unauthenticated input. [`indices`] gives the
//! loop counters a pinned count allows.
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
pub struct Pinned<T> {
    index: usize,
    word: [u8; 32],
    value: T,
}

impl<T> Pinned<T> {
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

impl<T: Clone> Pinned<T> {
    /// The value as an authenticated input: the binding fixes it to the requester's.
    pub fn authenticated(&self) -> Authenticated<T> {
        Authenticated(self.value.clone())
    }
}

/// A value a verifier produced, or derived only from such values, pinned values and guest
/// constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated<T>(T);

impl<T> Authenticated<T> {
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
    pub fn map<U>(self, f: fn(T) -> U) -> Authenticated<U> {
        Authenticated(f(self.0))
    }

    /// A value derived from a borrow of this one by a function that sees nothing else.
    pub fn derive<U>(&self, f: fn(&T) -> U) -> Authenticated<U> {
        Authenticated(f(&self.0))
    }

    /// Two authenticated values as one, for derivations with two inputs.
    pub fn zip<U>(self, other: Authenticated<U>) -> Authenticated<(T, U)> {
        Authenticated((self.0, other.0))
    }

    /// A derivation that can fail (a fallible decode of an authenticated byte string).
    pub fn try_map<U, E>(self, f: fn(T) -> Result<U, E>) -> Result<Authenticated<U>, E> {
        f(self.0).map(Authenticated)
    }

    #[doc(hidden)]
    /// For [`constant!`](crate::constant) only, which passes a `const` item: a guest constant is part
    /// of the image, so it is as fixed as the binding.
    pub const fn __from_guest_constant(value: T) -> Self {
        Self(value)
    }
}

/// A guest constant as an [`Authenticated`] value. The expression must be a constant expression
/// (it initialises a `const` item), so no runtime value, and nothing from `W`, can pass through.
///
/// ```
/// use hemiprove_eth_prelude::{constant, guard::Authenticated};
/// let slot: Authenticated<[u8; 32]> = constant!([u8; 32] = [0x11; 32]);
/// ```
#[macro_export]
macro_rules! constant {
    ($ty:ty = $value:expr) => {{
        const VALUE: $ty = $value;
        $crate::guard::Authenticated::<$ty>::__from_guest_constant(VALUE)
    }};
}

/// `0, 1, …, count − 1` as authenticated counters, for loops whose bound is pinned or proven.
pub fn indices(count: &Authenticated<u64>) -> impl Iterator<Item = Authenticated<u64>> {
    (0..count.0).map(Authenticated)
}

/// A value that fills one 32-byte journal word, big-endian and left-padded like `abi.encode`.
pub trait ToWord {
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
    pub fn commit_pinned<T>(&mut self, p: &Pinned<T>) -> Result<(), GuardError> {
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
