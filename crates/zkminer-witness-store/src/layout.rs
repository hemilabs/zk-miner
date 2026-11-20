//! Entry names under the store root, and their strict parsing. Hashes and addresses are lowercase
//! hex without `0x`; versions are `v<n>` with `n ≥ 1` and no leading zero.

use alloy_primitives::{Address, B256};

use crate::store::BundleKey;

pub(crate) const LOCK: &str = ".lock";
pub(crate) const IDENTITY: &str = "identity.json";
pub(crate) const NEXT_VERSION: &str = "next_version";
pub(crate) const TMP: &str = "tmp";
pub(crate) const BUNDLES: &str = "bundles";
pub(crate) const PINS: &str = "pins";
pub(crate) const ELFS: &str = "elfs";
pub(crate) const VERDICTS: &str = "verdicts";
pub(crate) const W_BIN: &str = "w.bin";
pub(crate) const BUNDLE_JSON: &str = "bundle.json";
/// Entries an uninitialised root may hold.
pub(crate) const LOST_FOUND: &str = "lost+found";

/// Every top-level entry the store owns, in the order usage is counted.
pub(crate) const OWNED: [&str; 8] = [LOCK, IDENTITY, NEXT_VERSION, TMP, BUNDLES, PINS, ELFS, VERDICTS];
/// Directories created at open.
pub(crate) const AREAS: [&str; 5] = [TMP, BUNDLES, PINS, ELFS, VERDICTS];

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn b256_name(x: &B256) -> String {
    hex::encode(x)
}

pub(crate) fn addr_name(a: &Address) -> String {
    hex::encode(a)
}

pub(crate) fn parse_b256_name(s: &str) -> Option<B256> {
    if s.len() != 64 || !is_lower_hex(s) {
        return None;
    }
    let b: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
    Some(B256::from(b))
}

pub(crate) fn parse_addr_name(s: &str) -> Option<Address> {
    if s.len() != 40 || !is_lower_hex(s) {
        return None;
    }
    let b: [u8; 20] = hex::decode(s).ok()?.try_into().ok()?;
    Some(Address::from(b))
}

pub(crate) fn version_name(n: u32) -> String {
    format!("v{n}")
}

pub(crate) fn parse_version_name(s: &str) -> Option<u32> {
    let d = s.strip_prefix('v')?;
    if d.is_empty() || d.starts_with('0') || !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    d.parse().ok()
}

/// `<jobId>.<descriptorHash>.<prover>.json`
pub(crate) fn pin_name(k: &BundleKey) -> String {
    format!("{}.{}.{}.json", b256_name(&k.job_id), b256_name(&k.descriptor_hash), addr_name(&k.prover))
}

pub(crate) fn parse_pin_name(s: &str) -> Option<BundleKey> {
    let s = s.strip_suffix(".json")?;
    let mut it = s.split('.');
    let (j, d, p) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    Some(BundleKey { job_id: parse_b256_name(j)?, descriptor_hash: parse_b256_name(d)?, prover: parse_addr_name(p)? })
}

/// `<imageId>`
pub(crate) fn elf_name(image_id: &B256) -> String {
    b256_name(image_id)
}

/// `<jobId>.json`
pub(crate) fn verdict_name(job_id: &B256) -> String {
    format!("{}.json", b256_name(job_id))
}

pub(crate) fn parse_verdict_name(s: &str) -> Option<B256> {
    parse_b256_name(s.strip_suffix(".json")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_parse_strictly() {
        let k = BundleKey {
            job_id: B256::repeat_byte(0xab),
            descriptor_hash: B256::repeat_byte(0x01),
            prover: Address::repeat_byte(0xcd),
        };
        assert_eq!(parse_pin_name(&pin_name(&k)), Some(k));
        assert_eq!(parse_verdict_name(&verdict_name(&k.job_id)), Some(k.job_id));
        assert_eq!(parse_version_name("v1"), Some(1));
        assert_eq!(parse_version_name("v4294967295"), Some(u32::MAX));
        for bad in ["v0", "v01", "v", "1", "v1x", "v-1", "v4294967296", "V1"] {
            assert_eq!(parse_version_name(bad), None, "{bad}");
        }
        let upper = b256_name(&k.job_id).to_uppercase();
        assert_eq!(parse_b256_name(&upper), None);
        assert_eq!(parse_b256_name(&format!("0x{}", &b256_name(&k.job_id)[2..])), None);
        assert_eq!(parse_addr_name(&b256_name(&k.job_id)), None);
        assert_eq!(parse_pin_name("x.json"), None);
        assert_eq!(parse_pin_name(&format!("{}.extra.json", pin_name(&k).trim_end_matches(".json"))), None);
    }
}
