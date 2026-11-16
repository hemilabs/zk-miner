//! JSON-RPC hex values as typed newtypes, deserialized straight from their strings.

use core::fmt;

use serde::de::{self, Deserialize, Deserializer, Visitor};

fn strip(s: &str) -> Result<&str, &'static str> {
    s.strip_prefix("0x").ok_or("not 0x-prefixed")
}

fn nibble(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("not a hex digit"),
    }
}

/// `0x`-prefixed, even-length hex data.
pub fn data(s: &str) -> Result<Vec<u8>, &'static str> {
    let h = strip(s)?.as_bytes();
    if h.len() % 2 != 0 {
        return Err("odd-length hex data");
    }
    h.chunks(2).map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?)).collect()
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    data(s)?.try_into().map_err(|_| "hex data of the wrong length")
}

/// A JSON-RPC quantity (no leading zeros, `0x0` for zero), up to 256 bits, as 32 big-endian bytes.
pub fn quantity(s: &str) -> Result<[u8; 32], &'static str> {
    let h = strip(s)?.as_bytes();
    if h.is_empty() || h.len() > 64 {
        return Err("quantity of the wrong length");
    }
    if h.len() > 1 && h[0] == b'0' {
        return Err("quantity with a leading zero");
    }
    let mut out = [0u8; 32];
    for (i, &c) in h.iter().rev().enumerate() {
        out[31 - i / 2] |= nibble(c)? << (4 * (i % 2));
    }
    Ok(out)
}

macro_rules! hex_newtype {
    ($(#[$m:meta])* $name:ident($inner:ty), $parse:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $name(pub $inner);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($what)
                    }
                    fn visit_str<E: de::Error>(self, s: &str) -> Result<$name, E> {
                        let parse: fn(&str) -> Result<$inner, &'static str> = $parse;
                        parse(s).map($name).map_err(E::custom)
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

hex_newtype!(
    /// Arbitrary `0x` data.
    Bytes(Vec<u8>), data, "0x-prefixed hex data"
);
hex_newtype!(
    /// A 32-byte hash.
    H256([u8; 32]), fixed::<32>, "a 32-byte hex hash"
);
hex_newtype!(
    /// A 20-byte address.
    Address([u8; 20]), fixed::<20>, "a 20-byte hex address"
);
hex_newtype!(
    /// A 256-byte logs bloom.
    Bloom(Vec<u8>), |s| data(s).and_then(|b| if b.len() == 256 { Ok(b) } else { Err("bloom is not 256 bytes") }), "a 256-byte hex bloom"
);
hex_newtype!(
    /// An 8-byte block nonce.
    Nonce8([u8; 8]), fixed::<8>, "an 8-byte hex nonce"
);
hex_newtype!(
    /// A quantity up to 256 bits.
    Quantity([u8; 32]), quantity, "a hex quantity"
);

impl Quantity {
    /// The minimal big-endian bytes (empty for zero): an RLP integer's payload.
    pub fn trimmed(&self) -> &[u8] {
        let first = self.0.iter().position(|&b| b != 0).unwrap_or(32);
        &self.0[first..]
    }

    /// The value, if it fits a `u64`.
    pub fn as_u64(&self) -> Option<u64> {
        if self.0[..24].iter().any(|&b| b != 0) {
            return None;
        }
        Some(u64::from_be_bytes(self.0[24..].try_into().unwrap()))
    }
}

/// Lowercase `0x` hex, for logs and requests.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
