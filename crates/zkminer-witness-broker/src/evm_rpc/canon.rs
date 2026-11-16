//! The streaming response canonicaliser (§11.2, §11.4): a token-level JSON re-emitter that writes the
//! canonical form of each answer straight into its output buffer and never builds a value tree, so a
//! 1 MB `eth_getProof` costs about 1 MB of output and nothing per node.
//!
//! Canonical form (what [`Scanner::value`] writes):
//!
//! - no whitespace outside strings; object keys in the order the node sent them (not sorted: sorting
//!   would mean buffering whole objects);
//! - strings re-encoded from their decoded value, RFC 8785 style: `"` and `\` escaped, U+0008, U+0009,
//!   U+000A, U+000C, U+000D as `\b \t \n \f \r`, other controls below U+0020 as `\u00xx` (lowercase
//!   hex), everything else (`/`, DEL, non-ASCII) literally in UTF-8. `\uXXXX` escapes are decoded,
//!   surrogate pairs combined; a lone surrogate, an unknown escape, a raw control byte or invalid
//!   UTF-8 is malformed;
//! - numbers must be JSON integers (`-?(0|[1-9][0-9]*)`, not `-0`) and are copied as given, any
//!   length; a fraction or exponent is malformed (no `evm-rpc/v1` result carries one: quantities are
//!   hex strings);
//! - `true`, `false`, `null`;
//! - duplicate keys (compared after decoding, so `"a"` and `"a"` collide) are malformed at every
//!   level of an answer;
//! - nesting deeper than [`MAX_JSON_DEPTH`] counted from the top of the body (a batch array is depth
//!   1, its response objects depth 2) is malformed, checked before recursing.

use super::{ResponseError, MAX_JSON_DEPTH};
use std::collections::HashSet;

type R<T> = Result<T, ResponseError>;
const MALFORMED: ResponseError = ResponseError::Malformed;

/// The most keys a response envelope or error object may have.
const MAX_ENVELOPE_KEYS: usize = 16;
/// How much of an error message is kept for the lagging heuristics (the message is never output).
const MESSAGE_HEAD: usize = 4096;

/// The canonical output budget shared by every answer of one response.
pub(super) struct Budget {
    pub used: usize,
    pub max: usize,
}

impl Budget {
    pub fn charge(&mut self, n: usize) -> R<()> {
        self.used = self.used.saturating_add(n);
        if self.used > self.max {
            Err(ResponseError::TooLarge)
        } else {
            Ok(())
        }
    }

    pub fn refund(&mut self, n: usize) {
        self.used = self.used.saturating_sub(n);
    }
}

/// Where canonical bytes go.
pub(super) trait Sink {
    /// Whether objects written here are checked for duplicate keys.
    const CHECK_KEYS: bool;
    fn put(&mut self, b: &[u8]) -> R<()>;
}

/// Validates without keeping anything (unknown envelope fields, error messages' tails).
pub(super) struct Discard;

impl Sink for Discard {
    const CHECK_KEYS: bool = false;
    fn put(&mut self, _: &[u8]) -> R<()> {
        Ok(())
    }
}

/// An answer's canonical bytes, charged to the shared budget as they are written.
pub(super) struct Out<'b> {
    pub buf: Vec<u8>,
    budget: &'b mut Budget,
}

impl Sink for Out<'_> {
    const CHECK_KEYS: bool = true;
    fn put(&mut self, b: &[u8]) -> R<()> {
        self.budget.charge(b.len())?;
        self.buf.extend_from_slice(b);
        Ok(())
    }
}

/// Unbudgeted scratch for short-lived pieces (an object key, `jsonrpc`, an error's `data`); each is
/// bounded by the body and dropped or charged before the next.
pub(super) struct Scratch(pub Vec<u8>);

impl Sink for Scratch {
    const CHECK_KEYS: bool = true;
    fn put(&mut self, b: &[u8]) -> R<()> {
        self.0.extend_from_slice(b);
        Ok(())
    }
}

/// Keeps the first `cap` bytes only.
struct Head {
    buf: Vec<u8>,
    cap: usize,
}

impl Sink for Head {
    const CHECK_KEYS: bool = false;
    fn put(&mut self, b: &[u8]) -> R<()> {
        let room = self.cap.saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&b[..b.len().min(room)]);
        Ok(())
    }
}

/// What kind of value was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Null,
    Object,
    Other,
}

/// One response envelope's payload, canonical.
#[derive(Debug)]
pub(super) enum Body {
    Result {
        canon: Vec<u8>,
        kind: Kind,
    },
    /// `{"code":…}` or `{"code":…,"data":"0x…"}`; `hint` per the module's heuristics.
    Error {
        canon: Vec<u8>,
        hint: super::ErrorHint,
    },
}

pub(super) struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(super) fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl<'a> Scanner<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Scanner { b, i: 0 }
    }

    pub fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    pub fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    pub fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    /// True if only whitespace is left.
    pub fn at_end(&mut self) -> bool {
        self.ws();
        self.i == self.b.len()
    }

    /// Skips whitespace and consumes `c`.
    pub fn expect(&mut self, c: u8) -> R<()> {
        self.ws();
        if self.bump() == Some(c) {
            Ok(())
        } else {
            Err(MALFORMED)
        }
    }

    /// One value inside a container at `depth` (0 at the top level), written canonically to `s`.
    pub fn value<S: Sink>(&mut self, s: &mut S, depth: usize) -> R<Kind> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(s, depth + 1).map(|()| Kind::Object),
            Some(b'[') => self.array(s, depth + 1).map(|()| Kind::Other),
            Some(b'"') => self.string(s).map(|()| Kind::Other),
            Some(b't') => self.literal(s, b"true").map(|()| Kind::Other),
            Some(b'f') => self.literal(s, b"false").map(|()| Kind::Other),
            Some(b'n') => self.literal(s, b"null").map(|()| Kind::Null),
            Some(b'-' | b'0'..=b'9') => self.number(s).map(|_| Kind::Other),
            _ => Err(MALFORMED),
        }
    }

    fn object<S: Sink>(&mut self, s: &mut S, depth: usize) -> R<()> {
        if depth > MAX_JSON_DEPTH {
            return Err(MALFORMED);
        }
        self.i += 1;
        s.put(b"{")?;
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return s.put(b"}");
        }
        // Allocates on the first insert only.
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(MALFORMED);
            }
            if S::CHECK_KEYS {
                let mut k = Scratch(Vec::new());
                self.string(&mut k)?;
                if seen.contains(&k.0) {
                    return Err(MALFORMED);
                }
                s.put(&k.0)?;
                seen.insert(k.0);
            } else {
                self.string(s)?;
            }
            self.expect(b':')?;
            s.put(b":")?;
            self.value(s, depth)?;
            self.ws();
            match self.bump() {
                Some(b',') => s.put(b",")?,
                Some(b'}') => return s.put(b"}"),
                _ => return Err(MALFORMED),
            }
        }
    }

    fn array<S: Sink>(&mut self, s: &mut S, depth: usize) -> R<()> {
        if depth > MAX_JSON_DEPTH {
            return Err(MALFORMED);
        }
        self.i += 1;
        s.put(b"[")?;
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return s.put(b"]");
        }
        loop {
            self.value(s, depth)?;
            self.ws();
            match self.bump() {
                Some(b',') => s.put(b",")?,
                Some(b']') => return s.put(b"]"),
                _ => return Err(MALFORMED),
            }
        }
    }

    /// At `"`: one string, re-encoded canonically.
    pub fn string<S: Sink>(&mut self, s: &mut S) -> R<()> {
        self.i += 1;
        s.put(b"\"")?;
        loop {
            // A run without `"`, `\` or controls is copied as is (after a UTF-8 check: the run's ends
            // are ASCII, so no character straddles them).
            let start = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            let run = &self.b[start..self.i];
            if std::str::from_utf8(run).is_err() {
                return Err(MALFORMED);
            }
            if !run.is_empty() {
                s.put(run)?;
            }
            match self.bump() {
                Some(b'"') => return s.put(b"\""),
                Some(b'\\') => {
                    let c = self.escape()?;
                    put_char(s, c)?;
                }
                _ => return Err(MALFORMED),
            }
        }
    }

    /// After `\`: the escaped character.
    fn escape(&mut self) -> R<char> {
        Ok(match self.bump() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let hi = self.hex4()?;
                let cp = match hi {
                    0xd800..=0xdbff => {
                        if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                            return Err(MALFORMED);
                        }
                        let lo = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&lo) {
                            return Err(MALFORMED);
                        }
                        0x10000 + ((u32::from(hi) - 0xd800) << 10) + (u32::from(lo) - 0xdc00)
                    }
                    0xdc00..=0xdfff => return Err(MALFORMED),
                    _ => u32::from(hi),
                };
                return char::from_u32(cp).ok_or(MALFORMED);
            }
            _ => return Err(MALFORMED),
        })
    }

    fn hex4(&mut self) -> R<u16> {
        let mut v = 0u16;
        for _ in 0..4 {
            let d = self.bump().and_then(hex_val).ok_or(MALFORMED)?;
            v = (v << 4) | u16::from(d);
        }
        Ok(v)
    }

    /// One JSON integer, copied as given; returns its token.
    fn number<S: Sink>(&mut self, s: &mut S) -> R<&'a [u8]> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(MALFORMED),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(MALFORMED);
        }
        let tok = &self.b[start..self.i];
        if tok == b"-0" {
            return Err(MALFORMED);
        }
        s.put(tok)?;
        Ok(tok)
    }

    fn literal<S: Sink>(&mut self, s: &mut S, lit: &'static [u8]) -> R<()> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            s.put(lit)
        } else {
            Err(MALFORMED)
        }
    }

    /// One object key, canonical with its quotes, in fresh scratch.
    fn key(&mut self) -> R<Vec<u8>> {
        self.ws();
        if self.peek() != Some(b'"') {
            return Err(MALFORMED);
        }
        let mut k = Scratch(Vec::new());
        self.string(&mut k)?;
        Ok(k.0)
    }

    /// One response object at `depth`: `(id, payload)`. The id is `None` when it is absent or not an
    /// unsigned integer that fits `u64` (the caller's `Mismatch`). `jsonrpc` must be `"2.0"`; exactly
    /// one of `result` and `error`; other keys are validated and ignored; duplicates are malformed.
    /// `reserve` pre-sizes the result buffer.
    pub fn envelope(
        &mut self,
        depth: usize,
        budget: &mut Budget,
        reserve: usize,
    ) -> R<(Option<u64>, Body)> {
        self.ws();
        if self.peek() != Some(b'{') || depth > MAX_JSON_DEPTH {
            return Err(MALFORMED);
        }
        self.i += 1;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut version_ok = false;
        let mut id: Option<u64> = None;
        let mut body: Option<Body> = None;
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
        } else {
            loop {
                let k = self.key()?;
                if seen.len() == MAX_ENVELOPE_KEYS || seen.contains(&k) {
                    return Err(MALFORMED);
                }
                self.expect(b':')?;
                self.ws();
                match k.as_slice() {
                    b"\"jsonrpc\"" => {
                        if self.peek() != Some(b'"') {
                            return Err(MALFORMED);
                        }
                        let mut v = Scratch(Vec::new());
                        self.string(&mut v)?;
                        if v.0 != b"\"2.0\"" {
                            return Err(MALFORMED);
                        }
                        version_ok = true;
                    }
                    b"\"id\"" => id = self.id(depth)?,
                    b"\"result\"" => {
                        if body.is_some() {
                            return Err(MALFORMED);
                        }
                        let mut out = Out {
                            buf: Vec::with_capacity(reserve),
                            budget: &mut *budget,
                        };
                        let kind = self.value(&mut out, depth)?;
                        body = Some(Body::Result {
                            canon: out.buf,
                            kind,
                        });
                    }
                    b"\"error\"" => {
                        if body.is_some() {
                            return Err(MALFORMED);
                        }
                        body = Some(self.error_object(depth, budget)?);
                    }
                    _ => {
                        self.value(&mut Discard, depth)?;
                    }
                }
                seen.push(k);
                self.ws();
                match self.bump() {
                    Some(b',') => {}
                    Some(b'}') => break,
                    _ => return Err(MALFORMED),
                }
            }
        }
        if !version_ok {
            return Err(MALFORMED);
        }
        Ok((id, body.ok_or(MALFORMED)?))
    }

    /// An id value: `Some` only for an unsigned integer that fits `u64`; anything else is validated
    /// and gives `None`.
    fn id(&mut self, depth: usize) -> R<Option<u64>> {
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            let tok = self.number(&mut Discard)?;
            Ok(parse_u64(tok))
        } else {
            self.value(&mut Discard, depth)?;
            Ok(None)
        }
    }

    /// An error object inside an envelope at `depth`, reduced to `{"code":…[,"data":"0x…"]}`.
    fn error_object(&mut self, depth: usize, budget: &mut Budget) -> R<Body> {
        let depth = depth + 1;
        if self.peek() != Some(b'{') || depth > MAX_JSON_DEPTH {
            return Err(MALFORMED);
        }
        self.i += 1;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut code: Option<i64> = None;
        let mut data: Option<Vec<u8>> = None;
        let mut message = Head {
            buf: Vec::new(),
            cap: MESSAGE_HEAD,
        };
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
        } else {
            loop {
                let k = self.key()?;
                if seen.len() == MAX_ENVELOPE_KEYS || seen.contains(&k) {
                    return Err(MALFORMED);
                }
                self.expect(b':')?;
                self.ws();
                match k.as_slice() {
                    b"\"code\"" => {
                        if !matches!(self.peek(), Some(b'-' | b'0'..=b'9')) {
                            return Err(MALFORMED);
                        }
                        let tok = self.number(&mut Discard)?;
                        code = Some(parse_i64(tok).ok_or(MALFORMED)?);
                    }
                    b"\"message\"" if self.peek() == Some(b'"') => self.string(&mut message)?,
                    b"\"data\"" if self.peek() == Some(b'"') => {
                        let mut d = Scratch(Vec::new());
                        self.string(&mut d)?;
                        data = hex_string_lower(&d.0);
                    }
                    _ => {
                        self.value(&mut Discard, depth)?;
                    }
                }
                seen.push(k);
                self.ws();
                match self.bump() {
                    Some(b',') => {}
                    Some(b'}') => break,
                    _ => return Err(MALFORMED),
                }
            }
        }
        let code = code.ok_or(MALFORMED)?;
        let mut canon = Vec::with_capacity(24 + data.as_ref().map_or(0, Vec::len));
        canon.extend_from_slice(b"{\"code\":");
        canon.extend_from_slice(code.to_string().as_bytes());
        if let Some(d) = data {
            canon.extend_from_slice(b",\"data\":");
            canon.extend_from_slice(&d);
        }
        canon.push(b'}');
        budget.charge(canon.len())?;
        Ok(Body::Error {
            canon,
            hint: super::error_hint(code, &message.buf),
        })
    }
}

/// A canonical string (with quotes) that is `0x` plus an even number of hex digits, lowercased.
fn hex_string_lower(quoted: &[u8]) -> Option<Vec<u8>> {
    let inner = quoted.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let digits = inner.strip_prefix(b"0x")?;
    if digits.len() % 2 != 0 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(quoted.to_ascii_lowercase())
}

/// Writes `c` canonically (see the module doc).
pub(super) fn put_char<S: Sink>(s: &mut S, c: char) -> R<()> {
    match c {
        '"' => s.put(b"\\\""),
        '\\' => s.put(b"\\\\"),
        '\u{8}' => s.put(b"\\b"),
        '\u{c}' => s.put(b"\\f"),
        '\n' => s.put(b"\\n"),
        '\r' => s.put(b"\\r"),
        '\t' => s.put(b"\\t"),
        c if (c as u32) < 0x20 => {
            let n = c as u8;
            s.put(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(n >> 4)],
                HEX[usize::from(n & 15)],
            ])
        }
        c => s.put(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
    }
}

/// `s` as a canonical JSON string, quotes included.
pub(super) fn put_str(out: &mut Vec<u8>, s: &str) {
    let mut sink = Scratch(std::mem::take(out));
    sink.0.push(b'"');
    for c in s.chars() {
        // Scratch never fails.
        let _ = put_char(&mut sink, c);
    }
    sink.0.push(b'"');
    *out = sink.0;
}

pub(super) fn parse_u64(tok: &[u8]) -> Option<u64> {
    tok.iter().try_fold(0u64, |n, &d| {
        if !d.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

fn parse_i64(tok: &[u8]) -> Option<i64> {
    match tok.strip_prefix(b"-") {
        Some(digits) => {
            let m = parse_u64(digits)?;
            if m <= i64::MAX as u64 + 1 {
                Some((m as i64).wrapping_neg())
            } else {
                None
            }
        }
        None => i64::try_from(parse_u64(tok)?).ok(),
    }
}

/// In a canonical object (as [`Scanner::value`] wrote it), the canonical value of top-level `key`.
pub(super) fn top_level_field<'b>(obj: &'b [u8], key: &str) -> Option<&'b [u8]> {
    let mut sc = Scanner::new(obj);
    if sc.bump() != Some(b'{') || sc.peek() == Some(b'}') {
        return None;
    }
    loop {
        let ks = sc.i;
        sc.string(&mut Discard).ok()?;
        let k = &obj[ks..sc.i];
        if sc.bump() != Some(b':') {
            return None;
        }
        let vs = sc.i;
        sc.value(&mut Discard, 1).ok()?;
        if k.len() == key.len() + 2 && &k[1..k.len() - 1] == key.as_bytes() {
            return Some(&obj[vs..sc.i]);
        }
        if sc.bump() != Some(b',') {
            return None;
        }
    }
}
