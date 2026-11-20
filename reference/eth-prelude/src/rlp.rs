//! Strict, canonical RLP.
//!
//! Every byte string has exactly one accepted encoding, so a decoder that accepts a value also
//! pins the bytes that encoded it: a prover cannot re-encode a header or a trie node differently
//! and keep its hash, and two different inputs never decode to one value. Refused:
//!
//! - a single byte below `0x80` wrapped as a one-byte string (`0x81 0x00`…`0x81 0x7f`);
//! - a long-form length (`0xb8`…, `0xf8`…) for a payload under 56 bytes, or with leading zero
//!   bytes in the length;
//! - an item that runs past its input, or a list whose items run past the list;
//! - bytes after the top-level item ([`decode_exact`]);
//! - integers with leading zero bytes (zero is the empty string), or longer than their type.
//!
//! Decoding borrows from the input and never allocates; the walk is iterative, so nesting depth
//! costs no stack.

use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlpError {
    /// The input ends inside an item.
    Truncated,
    /// A length in long form that fits the short form, or with leading zero bytes.
    NonCanonicalLength,
    /// A single byte below `0x80` encoded as a one-byte string.
    NonCanonicalByte,
    /// Bytes remain after the item.
    TrailingBytes,
    /// A list where a byte string is required.
    ExpectedString,
    /// A byte string where a list is required.
    ExpectedList,
    /// An integer with leading zero bytes.
    LeadingZeros,
    /// An integer longer than its type.
    IntegerTooLarge,
    /// A fixed-size byte string of the wrong length.
    WrongLength,
    /// A list with the wrong number of items.
    WrongCount,
    /// A length beyond this platform's address space (it cannot fit in any input).
    TooLong,
    /// A boolean other than `0x80` (false) or `0x01` (true).
    NotBool,
}

impl fmt::Display for RlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "RLP: input ends inside an item",
            Self::NonCanonicalLength => "RLP: non-canonical length",
            Self::NonCanonicalByte => "RLP: single byte below 0x80 encoded as a string",
            Self::TrailingBytes => "RLP: bytes after the item",
            Self::ExpectedString => "RLP: a list where a byte string is required",
            Self::ExpectedList => "RLP: a byte string where a list is required",
            Self::LeadingZeros => "RLP: integer with leading zero bytes",
            Self::IntegerTooLarge => "RLP: integer too large for its type",
            Self::WrongLength => "RLP: fixed-size field of the wrong length",
            Self::WrongCount => "RLP: list with the wrong number of items",
            Self::TooLong => "RLP: length beyond the address space",
            Self::NotBool => "RLP: boolean other than 0x80 or 0x01",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RlpError {}

/// One decoded item: a byte string or a list, borrowing its payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item<'a> {
    list: bool,
    payload: &'a [u8],
    raw: &'a [u8],
}

/// Decodes the item at the start of `buf`; returns it and the bytes after it.
pub fn decode_item(buf: &[u8]) -> Result<(Item<'_>, &[u8]), RlpError> {
    let first = *buf.first().ok_or(RlpError::Truncated)?;
    let (list, header, len) = match first {
        0x00..=0x7f => {
            return Ok((Item { list: false, payload: &buf[..1], raw: &buf[..1] }, &buf[1..]));
        }
        0x80..=0xb7 => (false, 1, usize::from(first - 0x80)),
        0xb8..=0xbf => {
            let (h, l) = long_length(buf, usize::from(first - 0xb7))?;
            (false, h, l)
        }
        0xc0..=0xf7 => (true, 1, usize::from(first - 0xc0)),
        0xf8..=0xff => {
            let (h, l) = long_length(buf, usize::from(first - 0xf7))?;
            (true, h, l)
        }
    };
    let end = header.checked_add(len).ok_or(RlpError::TooLong)?;
    let raw = buf.get(..end).ok_or(RlpError::Truncated)?;
    let payload = &raw[header..];
    if !list && len == 1 && payload[0] < 0x80 {
        return Err(RlpError::NonCanonicalByte);
    }
    Ok((Item { list, payload, raw }, &buf[end..]))
}

/// The header size and payload length of a long-form item whose length takes `len_of_len` bytes.
fn long_length(buf: &[u8], len_of_len: usize) -> Result<(usize, usize), RlpError> {
    let bytes = buf.get(1..1 + len_of_len).ok_or(RlpError::Truncated)?;
    if bytes[0] == 0 {
        return Err(RlpError::NonCanonicalLength);
    }
    let mut len = 0usize;
    for &b in bytes {
        len = len.checked_mul(256).and_then(|l| l.checked_add(usize::from(b))).ok_or(RlpError::TooLong)?;
    }
    if len < 56 {
        return Err(RlpError::NonCanonicalLength);
    }
    Ok((1 + len_of_len, len))
}

/// Decodes `buf` as exactly one item, with nothing after it.
pub fn decode_exact(buf: &[u8]) -> Result<Item<'_>, RlpError> {
    let (item, rest) = decode_item(buf)?;
    if !rest.is_empty() {
        return Err(RlpError::TrailingBytes);
    }
    Ok(item)
}

impl<'a> Item<'a> {
    pub fn is_list(&self) -> bool {
        self.list
    }

    /// The item's whole encoding, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// A byte string's contents.
    pub fn bytes(&self) -> Result<&'a [u8], RlpError> {
        if self.list {
            return Err(RlpError::ExpectedString);
        }
        Ok(self.payload)
    }

    /// Whether this is the empty byte string (`0x80`).
    pub fn is_empty_string(&self) -> bool {
        !self.list && self.payload.is_empty()
    }

    /// A byte string of exactly `N` bytes.
    pub fn fixed<const N: usize>(&self) -> Result<[u8; N], RlpError> {
        self.bytes()?.try_into().map_err(|_| RlpError::WrongLength)
    }

    /// A canonical unsigned integer of at most `max` bytes, as its big-endian bytes (empty for 0).
    pub fn uint_bytes(&self, max: usize) -> Result<&'a [u8], RlpError> {
        let b = self.bytes()?;
        if b.first() == Some(&0) {
            return Err(RlpError::LeadingZeros);
        }
        if b.len() > max {
            return Err(RlpError::IntegerTooLarge);
        }
        Ok(b)
    }

    /// A canonical `u64`.
    pub fn u64(&self) -> Result<u64, RlpError> {
        Ok(self.uint_bytes(8)?.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// A canonical 256-bit unsigned integer, left-padded to 32 big-endian bytes.
    pub fn u256(&self) -> Result<[u8; 32], RlpError> {
        Ok(left_pad(self.uint_bytes(32)?))
    }

    /// A boolean: `0x80` is false, `0x01` true, anything else refused.
    pub fn bool(&self) -> Result<bool, RlpError> {
        match self.bytes()? {
            [] => Ok(false),
            [1] => Ok(true),
            _ => Err(RlpError::NotBool),
        }
    }

    /// A list's items, in order.
    pub fn list(&self) -> Result<List<'a>, RlpError> {
        if !self.list {
            return Err(RlpError::ExpectedList);
        }
        Ok(List { rest: self.payload })
    }

    /// A list of exactly `N` items.
    pub fn items<const N: usize>(&self) -> Result<[Item<'a>; N], RlpError> {
        let mut list = self.list()?;
        let mut out = [Item { list: false, payload: &[], raw: &[] }; N];
        for slot in out.iter_mut() {
            *slot = list.next_item()?.ok_or(RlpError::WrongCount)?;
        }
        list.finish()?;
        Ok(out)
    }

    /// A list's items, collected.
    pub fn to_vec(&self) -> Result<Vec<Item<'a>>, RlpError> {
        let mut list = self.list()?;
        let mut out = Vec::new();
        while let Some(item) = list.next_item()? {
            out.push(item);
        }
        Ok(out)
    }
}

/// The items of a list, decoded one at a time.
#[derive(Debug, Clone)]
pub struct List<'a> {
    rest: &'a [u8],
}

impl<'a> List<'a> {
    /// The next item, `None` at the end of the list, or the error that ends the walk.
    pub fn next_item(&mut self) -> Result<Option<Item<'a>>, RlpError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (item, rest) = decode_item(self.rest)?;
        self.rest = rest;
        Ok(Some(item))
    }

    /// The next item, required.
    pub fn required(&mut self) -> Result<Item<'a>, RlpError> {
        self.next_item()?.ok_or(RlpError::WrongCount)
    }

    /// Ends the walk: no item may remain.
    pub fn finish(self) -> Result<(), RlpError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(RlpError::WrongCount)
        }
    }

    /// Whether every item has been read.
    pub fn is_done(&self) -> bool {
        self.rest.is_empty()
    }
}

/// `b` left-padded with zeros to 32 bytes (`b` is at most 32 bytes).
pub fn left_pad(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    out
}

/// `b` without leading zero bytes: the canonical integer encoding's payload.
pub fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

// ---------------------------------------------------------------------------------------------
// Encoding: always canonical.

fn put_length(out: &mut Vec<u8>, len: usize, short: u8, long: u8) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let be = trim_leading_zeros(&be);
        out.push(long + be.len() as u8);
        out.extend_from_slice(be);
    }
}

/// Appends a byte string.
pub fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        put_length(out, b.len(), 0x80, 0xb7);
        out.extend_from_slice(b);
    }
}

/// Appends an unsigned integer given as big-endian bytes (any leading zeros are dropped).
pub fn encode_uint(out: &mut Vec<u8>, be: &[u8]) {
    encode_bytes(out, trim_leading_zeros(be));
}

/// Appends a `u64`.
pub fn encode_u64(out: &mut Vec<u8>, v: u64) {
    encode_uint(out, &v.to_be_bytes());
}

/// Appends a boolean (`0x80` or `0x01`).
pub fn encode_bool(out: &mut Vec<u8>, v: bool) {
    out.push(if v { 0x01 } else { 0x80 });
}

/// Appends a list header for a payload of `payload_len` bytes.
pub fn encode_list_header(out: &mut Vec<u8>, payload_len: usize) {
    put_length(out, payload_len, 0xc0, 0xf7);
}

/// Appends a list whose items' encodings are `payload`.
pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    encode_list_header(out, payload.len());
    out.extend_from_slice(payload);
}

/// `rlp(index)`: the key of transaction or receipt `index` in its block's trie.
pub fn index_key(index: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    encode_u64(&mut out, index);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_rlp::{Decodable, Encodable};
    use proptest::prelude::*;

    fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_bytes(&mut v, b);
        v
    }

    #[test]
    fn canonical_short_forms() {
        assert_eq!(enc_bytes(&[]), vec![0x80]);
        assert_eq!(enc_bytes(&[0x00]), vec![0x00]);
        assert_eq!(enc_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(enc_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(index_key(0), vec![0x80]);
        assert_eq!(index_key(1), vec![0x01]);
        assert_eq!(index_key(127), vec![0x7f]);
        assert_eq!(index_key(128), vec![0x81, 0x80]);
        assert_eq!(index_key(256), vec![0x82, 0x01, 0x00]);
        let s = [7u8; 56];
        let e = enc_bytes(&s);
        assert_eq!(&e[..2], &[0xb8, 56]);
        assert_eq!(decode_exact(&e).unwrap().bytes().unwrap(), &s);
    }

    #[test]
    fn refuses_every_non_canonical_form() {
        let cases: &[(&[u8], RlpError)] = &[
            (&[], RlpError::Truncated),
            (&[0x81, 0x00], RlpError::NonCanonicalByte),
            (&[0x81, 0x7f], RlpError::NonCanonicalByte),
            (&[0xb8, 0x01, 0x80], RlpError::NonCanonicalLength),
            (&[0xb8, 55], RlpError::NonCanonicalLength),
            (&[0xb9, 0x00, 0x40], RlpError::NonCanonicalLength),
            (&[0xf8, 0x00], RlpError::NonCanonicalLength),
            (&[0xf8, 0x02, 0x01, 0x02], RlpError::NonCanonicalLength),
            (&[0x82, 0x01], RlpError::Truncated),
            (&[0xc2, 0x01], RlpError::Truncated),
            (&[0x01, 0x02], RlpError::TrailingBytes),
            (&[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], RlpError::Truncated),
        ];
        for (bytes, want) in cases {
            let got = decode_exact(bytes).err();
            // An 8-byte length overflows a 32-bit usize before it is found truncated.
            let ok = got == Some(*want) || (*want == RlpError::Truncated && got == Some(RlpError::TooLong));
            assert!(ok, "{bytes:02x?}: {got:?}, want {want:?}");
        }
    }

    #[test]
    fn integers_are_canonical() {
        let item = |b: &'static [u8]| decode_exact(b).unwrap();
        assert_eq!(item(&[0x80]).u64(), Ok(0));
        assert_eq!(item(&[0x00]).u64(), Err(RlpError::LeadingZeros));
        assert_eq!(item(&[0x82, 0x00, 0x01]).u64(), Err(RlpError::LeadingZeros));
        assert_eq!(item(&[0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]).u64(), Err(RlpError::IntegerTooLarge));
        assert_eq!(item(&[0x88, 0xff, 0, 0, 0, 0, 0, 0, 1]).u64(), Ok(0xff00_0000_0000_0001));
        assert_eq!(item(&[0xc0]).u64(), Err(RlpError::ExpectedString));
        assert_eq!(item(&[0x80]).bool(), Ok(false));
        assert_eq!(item(&[0x01]).bool(), Ok(true));
        assert_eq!(item(&[0x02]).bool(), Err(RlpError::NotBool));
        assert_eq!(item(&[0x00]).bool(), Err(RlpError::NotBool));
    }

    #[test]
    fn lists() {
        let mut payload = Vec::new();
        encode_u64(&mut payload, 1);
        encode_bytes(&mut payload, b"dog");
        let mut v = Vec::new();
        encode_list(&mut v, &payload);
        let item = decode_exact(&v).unwrap();
        let [a, b] = item.items::<2>().unwrap();
        assert_eq!(a.u64(), Ok(1));
        assert_eq!(b.bytes(), Ok(&b"dog"[..]));
        assert_eq!(item.items::<3>().err(), Some(RlpError::WrongCount));
        assert_eq!(item.items::<1>().err(), Some(RlpError::WrongCount));
        // An item running past its list's end.
        assert_eq!(decode_exact(&[0xc1, 0x82, 0x01, 0x02]).err(), Some(RlpError::TrailingBytes));
        assert_eq!(decode_exact(&[0xc2, 0x82, 0x01]).unwrap().to_vec().err(), Some(RlpError::Truncated));
    }

    proptest! {
        /// Anything accepted all the way down re-encodes to the same bytes, and agrees with
        /// alloy-rlp. (`decode_exact` checks a list's own framing; its items are decoded when they
        /// are read, and an item that does not decode is an error then.)
        #[test]
        fn decode_then_encode_is_identity(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            if let Some(again) = decode_exact(&bytes).ok().as_ref().and_then(reencode) {
                prop_assert_eq!(again, bytes.clone());
                let item = decode_exact(&bytes).unwrap();
                if !item.is_list() {
                    let mut buf = &bytes[..];
                    let a = alloy_primitives::Bytes::decode(&mut buf);
                    prop_assert!(a.is_ok() && buf.is_empty());
                    prop_assert_eq!(&a.unwrap()[..], item.bytes().unwrap());
                }
            }
        }

        #[test]
        fn strings_round_trip_and_match_alloy(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mine = enc_bytes(&b);
            let mut theirs = Vec::new();
            b.as_slice().encode(&mut theirs);
            prop_assert_eq!(&mine, &theirs);
            prop_assert_eq!(decode_exact(&mine).unwrap().bytes().unwrap(), &b[..]);
        }

        #[test]
        fn u64_round_trips_and_matches_alloy(v in any::<u64>()) {
            let mut mine = Vec::new();
            encode_u64(&mut mine, v);
            let mut theirs = Vec::new();
            v.encode(&mut theirs);
            prop_assert_eq!(&mine, &theirs);
            prop_assert_eq!(decode_exact(&mine).unwrap().u64(), Ok(v));
        }
    }

    /// The canonical encoding of `item`, or `None` if an item inside it does not decode.
    fn reencode(item: &Item<'_>) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        if item.is_list() {
            let mut payload = Vec::new();
            for i in item.to_vec().ok()? {
                payload.extend(reencode(&i)?);
            }
            encode_list(&mut out, &payload);
        } else {
            encode_bytes(&mut out, item.bytes().ok()?);
        }
        Some(out)
    }

    #[test]
    fn a_list_framing_is_checked_first_and_its_items_when_read() {
        // 27 bytes of payload: 26 one-byte strings, then a string header with no byte after it.
        let mut bytes = vec![0xdb];
        bytes.extend([0u8; 26]);
        bytes.push(0x81);
        let item = decode_exact(&bytes).unwrap();
        assert_eq!(item.to_vec().err(), Some(RlpError::Truncated));
        assert_eq!(item.items::<27>().err(), Some(RlpError::Truncated));
    }
}
