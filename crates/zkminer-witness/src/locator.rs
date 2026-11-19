//! The `hemi-code` locator (plan §13.2): exactly `hemi-code://` ‖ chainId ‖ `/0x` ‖ 40 lowercase hex
//! digits, where chainId is the canonical decimal of a nonzero uint64 (no leading zero). Matching is
//! byte-exact; any other spelling is malformed.

use alloy_primitives::Address;

pub const HEMI_CODE_PREFIX: &str = "hemi-code://";
/// The longest locator: `hemi-code://` + 20 digits + `/0x` + 40 hex digits.
pub const MAX_LOCATOR_LEN: usize = 12 + 20 + 3 + 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HemiCodeLocator {
    pub chain_id: u64,
    pub manifest: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocatorError {
    #[error("locator does not start with hemi-code://")]
    Prefix,
    #[error("chain id is not the canonical decimal of a nonzero uint64")]
    ChainId,
    #[error("missing /0x separator")]
    Separator,
    #[error("address is not exactly 40 lowercase hex digits")]
    Address,
    #[error("locator longer than the maximum")]
    TooLong,
}

impl HemiCodeLocator {
    pub fn parse(s: &str) -> Result<Self, LocatorError> {
        let b = s.as_bytes();
        if b.len() > MAX_LOCATOR_LEN {
            return Err(LocatorError::TooLong);
        }
        let rest = b.strip_prefix(HEMI_CODE_PREFIX.as_bytes()).ok_or(LocatorError::Prefix)?;
        let digits_end = rest.iter().position(|c| !c.is_ascii_digit()).unwrap_or(rest.len());
        let digits = &rest[..digits_end];
        if digits.is_empty() || digits.len() > 20 || digits[0] == b'0' {
            return Err(LocatorError::ChainId);
        }
        let mut chain_id: u64 = 0;
        for d in digits {
            chain_id = chain_id
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(d - b'0')))
                .ok_or(LocatorError::ChainId)?;
        }
        let rest = rest[digits_end..].strip_prefix(b"/0x").ok_or(LocatorError::Separator)?;
        if rest.len() != 40 || !rest.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(LocatorError::Address);
        }
        let mut addr = [0u8; 20];
        for (i, pair) in rest.chunks(2).enumerate() {
            let hi = hex_val(pair[0]);
            let lo = hex_val(pair[1]);
            addr[i] = (hi << 4) | lo;
        }
        Ok(Self { chain_id, manifest: Address::from(addr) })
    }

    /// The canonical string form.
    pub fn to_uri(&self) -> String {
        format!("{HEMI_CODE_PREFIX}{}/0x{}", self.chain_id, hex::encode(self.manifest.as_slice()))
    }
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "00112233445566778899aabbccddeeff00112233";

    #[test]
    fn parses_the_canonical_form_and_round_trips() {
        let s = format!("hemi-code://743111/0x{A}");
        let l = HemiCodeLocator::parse(&s).unwrap();
        assert_eq!(l.chain_id, 743111);
        assert_eq!(l.to_uri(), s);
        let longest = format!("hemi-code://{}/0x{A}", u64::MAX);
        assert_eq!(longest.len(), MAX_LOCATOR_LEN);
        assert!(HemiCodeLocator::parse(&longest).is_ok());
    }

    #[test]
    fn rejects_every_other_spelling() {
        let bad = [
            format!("HEMI-CODE://743111/0x{A}"),
            format!("hemi-code://0743111/0x{A}"),
            format!("hemi-code://0/0x{A}"),
            format!("hemi-code://+743111/0x{A}"),
            format!("hemi-code://18446744073709551616/0x{A}"),
            format!("hemi-code://743111/0X{A}"),
            format!("hemi-code://743111/0x{}", A.to_uppercase()),
            format!("hemi-code://743111/0x{A}/"),
            format!("hemi-code://743111/0x{A}?x=1"),
            format!("hemi-code://743111/0x{A}#f"),
            format!("hemi-code://u@743111/0x{A}"),
            format!("hemi-code://743111:80/0x{A}"),
            format!("hemi-code://743111/0x{}", &A[..39]),
            format!("hemi-code://743111/0x%30{}", &A[1..]),
            format!(" hemi-code://743111/0x{A}"),
            "hemi-code://743111/0x".to_string(),
        ];
        for s in bad {
            assert!(HemiCodeLocator::parse(&s).is_err(), "{s}");
        }
    }
}
