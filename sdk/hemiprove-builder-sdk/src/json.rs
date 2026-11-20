//! Minimal JSON field extraction for the canonical responses the broker returns (zkminer
//! docs/witness-construction-jobs.md §11.2): `{"jsonrpc":"2.0","id":…,"result":…}` or
//! `{"jsonrpc":"2.0","id":…,"error":{"code":…,"data":"0x…"}}`.
//!
//! No value tree is built: [`get`] walks an object's top-level members, skipping each value with a
//! depth-limited scanner, and returns the raw bytes of the one asked for. Strings are returned only
//! when they hold no escapes, which canonical hex strings never do.

use core::fmt;

/// Nesting deeper than this is refused (the broker caps responses at depth 32).
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Malformed JSON at this byte offset.
    Syntax(usize),
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A required member is absent (or `null`).
    Missing,
    /// Not a string, or a string with escapes.
    NotString,
    /// Not `0x`-prefixed hex of the expected size.
    NotHex,
    /// The response is a JSON-RPC error.
    RpcError,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(at) => write!(f, "malformed JSON at byte {at}"),
            Self::TooDeep => write!(f, "JSON nested deeper than {MAX_DEPTH}"),
            Self::Missing => write!(f, "missing JSON member"),
            Self::NotString => write!(f, "not a plain JSON string"),
            Self::NotHex => write!(f, "not 0x-prefixed hex of the expected size"),
            Self::RpcError => write!(f, "JSON-RPC error response"),
        }
    }
}

fn ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// `b[i]` is `"`; returns the index just past the closing quote.
fn skip_string(b: &[u8], i: usize) -> Result<usize, JsonError> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'"' => return Ok(j + 1),
            b'\\' => j += 2,
            c if c < 0x20 => return Err(JsonError::Syntax(j)),
            _ => j += 1,
        }
    }
    Err(JsonError::Syntax(i))
}

/// Skips the value starting at `i` (no leading whitespace); returns the index just past it.
fn skip_value(b: &[u8], i: usize) -> Result<usize, JsonError> {
    match b.get(i) {
        None => Err(JsonError::Syntax(i)),
        Some(b'"') => skip_string(b, i),
        Some(b'{' | b'[') => {
            let mut closers = Vec::new();
            let mut j = i;
            loop {
                match b.get(j) {
                    None => return Err(JsonError::Syntax(j)),
                    Some(b'"') => j = skip_string(b, j)?,
                    Some(&c @ (b'{' | b'[')) => {
                        if closers.len() == MAX_DEPTH {
                            return Err(JsonError::TooDeep);
                        }
                        closers.push(if c == b'{' { b'}' } else { b']' });
                        j += 1;
                    }
                    Some(&c @ (b'}' | b']')) => {
                        if closers.pop() != Some(c) {
                            return Err(JsonError::Syntax(j));
                        }
                        j += 1;
                        if closers.is_empty() {
                            return Ok(j);
                        }
                    }
                    Some(_) => j += 1,
                }
            }
        }
        Some(_) => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            if j == i {
                return Err(JsonError::Syntax(i));
            }
            Ok(j)
        }
    }
}

/// The raw bytes of member `key` among the top-level members of the object `obj` (the first one, if
/// repeated), or `None`.
pub fn get<'a>(obj: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, JsonError> {
    let mut i = ws(obj, 0);
    if obj.get(i) != Some(&b'{') {
        return Err(JsonError::Syntax(i));
    }
    i = ws(obj, i + 1);
    if obj.get(i) == Some(&b'}') {
        return Ok(None);
    }
    loop {
        if obj.get(i) != Some(&b'"') {
            return Err(JsonError::Syntax(i));
        }
        let key_end = skip_string(obj, i)?;
        let k = &obj[i + 1..key_end - 1];
        i = ws(obj, key_end);
        if obj.get(i) != Some(&b':') {
            return Err(JsonError::Syntax(i));
        }
        let start = ws(obj, i + 1);
        let end = skip_value(obj, start)?;
        if k == key.as_bytes() {
            return Ok(Some(&obj[start..end]));
        }
        i = ws(obj, end);
        match obj.get(i) {
            Some(b',') => i = ws(obj, i + 1),
            Some(b'}') => return Ok(None),
            _ => return Err(JsonError::Syntax(i)),
        }
    }
}

/// The raw bytes of each element of the array `arr`, in order.
pub fn elements(arr: &[u8]) -> Result<Vec<&[u8]>, JsonError> {
    let mut i = ws(arr, 0);
    if arr.get(i) != Some(&b'[') {
        return Err(JsonError::Syntax(i));
    }
    let mut out = Vec::new();
    i = ws(arr, i + 1);
    if arr.get(i) == Some(&b']') {
        return if ws(arr, i + 1) == arr.len() { Ok(out) } else { Err(JsonError::Syntax(i + 1)) };
    }
    loop {
        let end = skip_value(arr, i)?;
        out.push(&arr[i..end]);
        i = ws(arr, end);
        match arr.get(i) {
            Some(b',') => i = ws(arr, i + 1),
            Some(b']') if ws(arr, i + 1) == arr.len() => return Ok(out),
            _ => return Err(JsonError::Syntax(i)),
        }
    }
}

/// Member `key`, required and not `null`.
pub fn required<'a>(obj: &'a [u8], key: &str) -> Result<&'a [u8], JsonError> {
    match get(obj, key)? {
        Some(v) if v != b"null" => Ok(v),
        _ => Err(JsonError::Missing),
    }
}

/// The contents of a JSON string value without escapes.
pub fn as_str(v: &[u8]) -> Result<&str, JsonError> {
    if v.len() < 2 || v[0] != b'"' || v[v.len() - 1] != b'"' || v[1..v.len() - 1].contains(&b'\\') {
        return Err(JsonError::NotString);
    }
    core::str::from_utf8(&v[1..v.len() - 1]).map_err(|_| JsonError::NotString)
}

/// Member `key` as a plain string.
pub fn str_member<'a>(obj: &'a [u8], key: &str) -> Result<&'a str, JsonError> {
    as_str(required(obj, key)?)
}

/// A JSON-RPC response's `result`; [`JsonError::RpcError`] for an `error` response.
pub fn rpc_result(response: &[u8]) -> Result<&[u8], JsonError> {
    match get(response, "result")? {
        Some(v) if v != b"null" => Ok(v),
        Some(_) => Err(JsonError::Missing),
        None if get(response, "error")?.is_some() => Err(JsonError::RpcError),
        None => Err(JsonError::Missing),
    }
}

fn nibble(c: u8) -> Result<u8, JsonError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(JsonError::NotHex),
    }
}

/// A hex quantity (`"0x1b4"`) of at most 64 bits.
pub fn quantity_u64(s: &str) -> Result<u64, JsonError> {
    let digits = s.strip_prefix("0x").ok_or(JsonError::NotHex)?.as_bytes();
    if digits.is_empty() || digits.len() > 16 {
        return Err(JsonError::NotHex);
    }
    digits.iter().try_fold(0u64, |acc, &c| Ok((acc << 4) | u64::from(nibble(c)?)))
}

/// A hex quantity of at most 256 bits, as 32 big-endian bytes. Also accepts zero-padded 32-byte
/// data (`eth_getProof` storage keys come back in either form).
pub fn quantity_u256(s: &str) -> Result<[u8; 32], JsonError> {
    let digits = s.strip_prefix("0x").ok_or(JsonError::NotHex)?.as_bytes();
    if digits.is_empty() || digits.len() > 64 {
        return Err(JsonError::NotHex);
    }
    let mut out = [0u8; 32];
    for (i, &c) in digits.iter().rev().enumerate() {
        out[31 - i / 2] |= nibble(c)? << (4 * (i % 2));
    }
    Ok(out)
}

/// `0x`-prefixed lower-case hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Hex data (`"0x…"`, an even number of digits).
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, JsonError> {
    let digits = s.strip_prefix("0x").ok_or(JsonError::NotHex)?.as_bytes();
    if digits.len() % 2 != 0 {
        return Err(JsonError::NotHex);
    }
    digits.chunks(2).map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?)).collect()
}

/// Exactly 32 bytes of hex data.
pub fn bytes32(s: &str) -> Result<[u8; 32], JsonError> {
    hex_bytes(s)?.try_into().map_err(|_| JsonError::NotHex)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"baseFeePerGas":"0x7","hash":"0x00000000000000000000000000000000000000000000000000000000000000ff","withdrawals":[{"index":"0x1","number":"0xdead"}],"logsBloom":"0x00","nested":{"hash":"0x1"},"number":"0x1b4","transactions":["0xaa","0xbb"],"uncles":[]}}"#;

    #[test]
    fn extracts_top_level_members_only() {
        let result = rpc_result(BLOCK).unwrap();
        assert_eq!(quantity_u64(str_member(result, "number").unwrap()).unwrap(), 0x1b4);
        let mut hash = [0u8; 32];
        hash[31] = 0xff;
        assert_eq!(bytes32(str_member(result, "hash").unwrap()).unwrap(), hash);
        assert_eq!(get(result, "transactions").unwrap(), Some(&br#"["0xaa","0xbb"]"#[..]));
        assert_eq!(get(result, "uncles").unwrap(), Some(&b"[]"[..]));
        assert_eq!(get(result, "index").unwrap(), None, "nested members are not top-level");
        assert_eq!(get(BLOCK, "id").unwrap(), Some(&b"1"[..]));
    }

    #[test]
    fn errors_and_nulls() {
        let err = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"data":"0x01"}}"#;
        assert_eq!(rpc_result(err), Err(JsonError::RpcError));
        assert_eq!(rpc_result(br#"{"jsonrpc":"2.0","id":1,"result":null}"#), Err(JsonError::Missing));
        assert_eq!(rpc_result(br#"{"jsonrpc":"2.0","id":1}"#), Err(JsonError::Missing));
        assert_eq!(required(br#"{"a":null}"#, "a"), Err(JsonError::Missing));
    }

    #[test]
    fn whitespace_strings_and_escapes() {
        let obj = br#" { "a\"b" : "x" , "k" : "v\n", "s": "plain" } "#;
        assert_eq!(str_member(obj, "s").unwrap(), "plain");
        assert_eq!(str_member(obj, "k"), Err(JsonError::NotString));
        assert_eq!(get(obj, "missing").unwrap(), None);
        assert_eq!(get(b"{}", "a").unwrap(), None);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        for bad in [
            &b""[..],
            b"[]",
            b"{",
            b"{\"a\"",
            b"{\"a\":",
            b"{\"a\":}",
            b"{\"a\":[1,2}",
            b"{\"a\":\"unterminated}",
            b"{\"a\":1 \"b\":2}",
            b"{a:1}",
        ] {
            assert!(get(bad, "b").is_err(), "{:?}", core::str::from_utf8(bad));
        }
        let deep = format!("{{\"a\":{}{}}}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(get(deep.as_bytes(), "a"), Err(JsonError::TooDeep));
        let ok = format!("{{\"a\":{}{}}}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(get(ok.as_bytes(), "a").unwrap().is_some());
    }

    #[test]
    fn arrays() {
        assert_eq!(elements(br#"[]"#).unwrap(), Vec::<&[u8]>::new());
        assert_eq!(elements(br#" [ "0xaa" , {"a":[1,2]}, 3 ] "#.trim_ascii()).unwrap(), vec![&br#""0xaa""#[..], br#"{"a":[1,2]}"#, b"3"]);
        for bad in [&b"[1,]"[..], b"[1 2]", b"[1", b"{}", b"[1]x", b"[,1]"] {
            assert!(elements(bad).is_err(), "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn hex() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(quantity_u256("0x1"), Ok(one));
        assert_eq!(quantity_u256(&format!("0x{}", "0".repeat(63) + "1")), Ok(one));
        assert_eq!(quantity_u256(&format!("0x{}", "f".repeat(64))), Ok([0xff; 32]));
        assert_eq!(quantity_u256(&format!("0x1{}", "0".repeat(64))), Err(JsonError::NotHex));
        assert_eq!(quantity_u256("0x"), Err(JsonError::NotHex));
        assert_eq!(quantity_u256("0x1ab").unwrap()[30..], [0x01, 0xab]);
        assert_eq!(to_hex(&[0x00, 0xab, 0x10]), "0x00ab10");
        assert_eq!(to_hex(&[]), "0x");
        assert_eq!(quantity_u64("0x0"), Ok(0));
        assert_eq!(quantity_u64("0xffffffffffffffff"), Ok(u64::MAX));
        for bad in ["0x", "1b4", "0x1ffffffffffffffff", "0xg"] {
            assert_eq!(quantity_u64(bad), Err(JsonError::NotHex), "{bad}");
        }
        assert_eq!(hex_bytes("0x"), Ok(vec![]));
        assert_eq!(hex_bytes("0xAbcd"), Ok(vec![0xab, 0xcd]));
        assert_eq!(hex_bytes("0xabc"), Err(JsonError::NotHex));
        assert_eq!(bytes32("0x00"), Err(JsonError::NotHex));
    }
}
