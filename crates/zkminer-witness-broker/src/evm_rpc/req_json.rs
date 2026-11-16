//! The strict request reader (§11.2, §14.4). Builder requests are small (the frame layer caps them at
//! `max(maxRequestBytes, 64 KiB)`), so this builds a borrowed tree; the response path never does (see
//! `canon`).
//!
//! The grammar is RFC 8259 JSON narrowed so that every accepted text has one meaning to every parser:
//!
//! - whitespace (space, TAB, LF, CR) between tokens; no BOM; nothing after the value;
//! - strings are printable ASCII (`0x20..=0x7e`) with **no escapes at all** (no `\`), so a key or
//!   value has one spelling and is compared as raw bytes;
//! - numbers are non-negative integers in canonical decimal (`0` or `[1-9][0-9]*`) that fit `u64`; no
//!   sign, fraction or exponent, and no `NaN`/`Infinity`;
//! - no duplicate keys at any level, at most [`MAX_OBJECT_KEYS`] keys per object;
//! - at most [`MAX_JSON_DEPTH`] nested arrays/objects (the top-level value is depth 1), checked before
//!   recursing, so the recursion is bounded.

use super::{Denied, MAX_JSON_DEPTH};

/// Most keys any request object has (the call object has nine); more is malformed.
pub(super) const MAX_OBJECT_KEYS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum V<'a> {
    Null,
    Bool(bool),
    /// A non-negative integer written in canonical decimal.
    Num(u64),
    /// The bytes between the quotes: printable ASCII without `"` or `\`.
    Str(&'a [u8]),
    Arr(Vec<V<'a>>),
    Obj(Vec<(&'a [u8], V<'a>)>),
}

impl<'a> V<'a> {
    pub(super) fn str(&self) -> Result<&'a [u8], Denied> {
        match self {
            V::Str(s) => Ok(s),
            _ => Err(Denied::Malformed),
        }
    }

    pub(super) fn arr(&self) -> Result<&[V<'a>], Denied> {
        match self {
            V::Arr(a) => Ok(a),
            _ => Err(Denied::Malformed),
        }
    }

    pub(super) fn obj(&self) -> Result<&[(&'a [u8], V<'a>)], Denied> {
        match self {
            V::Obj(o) => Ok(o),
            _ => Err(Denied::Malformed),
        }
    }

    pub(super) fn boolean(&self) -> Result<bool, Denied> {
        match self {
            V::Bool(b) => Ok(*b),
            _ => Err(Denied::Malformed),
        }
    }
}

/// Parses one complete JSON text under the narrowed grammar.
pub(super) fn parse(b: &[u8]) -> Result<V<'_>, Denied> {
    let mut p = Parser { b, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != b.len() {
        return Err(Denied::Malformed);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    /// A value inside a container at `depth` (0 for the top level).
    fn value(&mut self, depth: usize) -> Result<V<'a>, Denied> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(V::Str),
            Some(b't') => self.literal(b"true", V::Bool(true)),
            Some(b'f') => self.literal(b"false", V::Bool(false)),
            Some(b'n') => self.literal(b"null", V::Null),
            Some(b'0'..=b'9') => self.number(),
            _ => Err(Denied::Malformed),
        }
    }

    fn object(&mut self, depth: usize) -> Result<V<'a>, Denied> {
        if depth > MAX_JSON_DEPTH {
            return Err(Denied::TooDeep);
        }
        self.i += 1;
        let mut fields: Vec<(&'a [u8], V<'a>)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(V::Obj(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(Denied::Malformed);
            }
            let k = self.string()?;
            if fields.len() == MAX_OBJECT_KEYS || fields.iter().any(|(f, _)| *f == k) {
                return Err(Denied::Malformed);
            }
            self.ws();
            if self.bump() != Some(b':') {
                return Err(Denied::Malformed);
            }
            self.ws();
            let v = self.value(depth)?;
            fields.push((k, v));
            self.ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(V::Obj(fields)),
                _ => return Err(Denied::Malformed),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<V<'a>, Denied> {
        if depth > MAX_JSON_DEPTH {
            return Err(Denied::TooDeep);
        }
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(V::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth)?);
            self.ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(V::Arr(items)),
                _ => return Err(Denied::Malformed),
            }
        }
    }

    /// At `"`: the raw bytes up to the closing quote, which must all be printable ASCII but `\`.
    fn string(&mut self) -> Result<&'a [u8], Denied> {
        self.i += 1;
        let start = self.i;
        loop {
            match self.bump() {
                Some(b'"') => return Ok(&self.b[start..self.i - 1]),
                Some(b'\\') | None => return Err(Denied::Malformed),
                Some(0x20..=0x7e) => {}
                Some(_) => return Err(Denied::Malformed),
            }
        }
    }

    fn number(&mut self) -> Result<V<'a>, Denied> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = &self.b[start..self.i];
        if matches!(self.peek(), Some(b'.' | b'e' | b'E'))
            || (digits.len() > 1 && digits[0] == b'0')
        {
            return Err(Denied::Malformed);
        }
        let mut n: u64 = 0;
        for &d in digits {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(d - b'0')))
                .ok_or(Denied::Malformed)?;
        }
        Ok(V::Num(n))
    }

    fn literal(&mut self, lit: &[u8], v: V<'a>) -> Result<V<'a>, Denied> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(v)
        } else {
            Err(Denied::Malformed)
        }
    }
}
