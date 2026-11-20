//! Gateway URLs for content-addressed storage: the requester names content (an IPFS CID, an Arweave
//! transaction id, an optional path inside it) and never any part of the URL's scheme, host or port.
//!
//! The id and the path are syntax-checked against a closed alphabet that has no URL metacharacter
//! (`/` only as the separator, never `?`, `#`, `%`, `@`, `:`, `\` or whitespace), and `.`/`..`
//! segments are refused, so the URL built is `<gateway>/<fixed prefix>/<id>[/<path>]` exactly as
//! written: it cannot leave the gateway or its prefix. The built URL still goes through
//! [`crate::check_url`] and the guarded resolver like any other.
//!
//! - **IPFS:** `[ipfs://|/ipfs/]<cid>[/<path>]`, where the CID is CIDv0 (`Qm` and 44 base58btc
//!   characters) or CIDv1 in base32 (`b` and 8 to 200 characters of `a-z2-7`).
//! - **Arweave:** `[ar://]<id>[/<path>]`, where the id is 43 characters of base64url.
//! - **Path:** at most 16 segments, each 1 to 255 characters of `A-Z a-z 0-9 . _ -`, never `.` or
//!   `..`.

use std::fmt;

/// Why a content reference was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentIdDenied {
    /// Not a CIDv0 or base32 CIDv1.
    BadCid,
    /// Not a 43-character base64url Arweave id.
    BadArweaveId,
    /// A path segment that is empty, `.`, `..`, too long, or has a character outside the alphabet;
    /// or too many segments.
    BadPath,
}

impl fmt::Display for ContentIdDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ContentIdDenied::BadCid => "not an IPFS CID (CIDv0, or CIDv1 in base32)",
            ContentIdDenied::BadArweaveId => {
                "not an Arweave transaction id (43 base64url characters)"
            }
            ContentIdDenied::BadPath => "the path inside the content is malformed",
        })
    }
}

impl std::error::Error for ContentIdDenied {}

const BASE58BTC: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_cid(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix("Qm") {
        return s.len() == 46 && rest.bytes().all(|b| BASE58BTC.contains(&b));
    }
    if let Some(rest) = s.strip_prefix('b') {
        return (8..=200).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    }
    false
}

fn is_arweave_id(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `""` or `/seg/seg…` under the path rules of the module doc.
fn check_path(path: &str) -> Result<(), ContentIdDenied> {
    if path.is_empty() {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(ContentIdDenied::BadPath);
    };
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() > 16 {
        return Err(ContentIdDenied::BadPath);
    }
    for seg in segments {
        let ok = !seg.is_empty()
            && seg.len() <= 255
            && seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(ContentIdDenied::BadPath);
        }
    }
    Ok(())
}

fn split_id(s: &str) -> (&str, &str) {
    match s.find('/') {
        Some(i) => s.split_at(i),
        None => (s, ""),
    }
}

/// `<gateway>/ipfs/<cid>[/<path>]` for an IPFS reference (see the module doc). `gateway` is the
/// operator's or the build's fixed base URL (`https://ipfs.io`), without a trailing slash.
pub fn ipfs_gateway_url(gateway: &str, reference: &str) -> Result<String, ContentIdDenied> {
    let r = reference
        .strip_prefix("ipfs://")
        .or_else(|| reference.strip_prefix("/ipfs/"))
        .unwrap_or(reference);
    let (cid, path) = split_id(r);
    if !is_cid(cid) {
        return Err(ContentIdDenied::BadCid);
    }
    check_path(path)?;
    Ok(format!("{gateway}/ipfs/{cid}{path}"))
}

/// `<gateway>/<id>[/<path>]` for an Arweave reference (see the module doc). `gateway` is a fixed base
/// URL (`https://arweave.net`), without a trailing slash.
pub fn arweave_gateway_url(gateway: &str, reference: &str) -> Result<String, ContentIdDenied> {
    let r = reference.strip_prefix("ar://").unwrap_or(reference);
    let (id, path) = split_id(r);
    if !is_arweave_id(id) {
        return Err(ContentIdDenied::BadArweaveId);
    }
    check_path(path)?;
    Ok(format!("{gateway}/{id}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V0: &str = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    const V1: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    const AR: &str = "bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U";
    const GW: &str = "https://ipfs.io";

    #[test]
    fn content_references_build_urls_on_the_gateway() {
        assert_eq!(ipfs_gateway_url(GW, V0).unwrap(), format!("{GW}/ipfs/{V0}"));
        assert_eq!(ipfs_gateway_url(GW, V1).unwrap(), format!("{GW}/ipfs/{V1}"));
        assert_eq!(
            ipfs_gateway_url(GW, &format!("ipfs://{V1}/dir/guest.elf")).unwrap(),
            format!("{GW}/ipfs/{V1}/dir/guest.elf")
        );
        assert_eq!(
            ipfs_gateway_url(GW, &format!("/ipfs/{V0}/a_b-c.1")).unwrap(),
            format!("{GW}/ipfs/{V0}/a_b-c.1")
        );
        assert_eq!(
            arweave_gateway_url("https://arweave.net", AR).unwrap(),
            format!("https://arweave.net/{AR}")
        );
        assert_eq!(
            arweave_gateway_url("https://arweave.net", &format!("ar://{AR}/guest.bin")).unwrap(),
            format!("https://arweave.net/{AR}/guest.bin")
        );
    }

    #[test]
    fn references_that_could_leave_the_gateway_or_its_prefix_are_refused() {
        use ContentIdDenied::*;
        for (r, why) in [
            ("", BadCid),
            ("@evil.example.com/x", BadCid),
            ("../../etc/passwd", BadCid),
            ("Qm", BadCid),
            ("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbd0", BadCid), // 0 is not base58
            ("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdGx", BadCid), // too long
            ("bafy", BadCid),
            (
                "BAFYBEIGDYRZT5SFP7UDM7HU76UH7Y26NF3EFUYLQABF3OCLGTQY55FBZDI",
                BadCid,
            ),
            (
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzd1",
                BadCid,
            ),
            (
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi?x=1",
                BadCid,
            ),
            (
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi#x",
                BadCid,
            ),
            (
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi%2f..",
                BadCid,
            ),
            ("https://evil.example.com/x", BadCid),
            ("ipfs://ipfs://x", BadCid),
            (
                " bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                BadCid,
            ),
        ] {
            assert_eq!(ipfs_gateway_url(GW, r), Err(why), "{r:?}");
        }
        for path in [
            "/", "//x", "/..", "/.", "/a/../b", "/a/./b", "/a b", "/a?b", "/a#b", "/a%2fb",
            "/a\\b", "/a:b", "/a@b", "/é",
        ] {
            assert_eq!(
                ipfs_gateway_url(GW, &format!("{V1}{path}")),
                Err(BadPath),
                "{path:?}"
            );
            assert_eq!(
                arweave_gateway_url("https://arweave.net", &format!("{AR}{path}")),
                Err(BadPath),
                "{path:?}"
            );
        }
        let deep = format!("{V1}{}", "/a".repeat(17));
        assert_eq!(ipfs_gateway_url(GW, &deep), Err(BadPath));
        for r in [
            "",
            "short",
            "bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U_",
            "bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt.U",
            "@evil.example.com:443/xxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert_eq!(
                arweave_gateway_url("https://arweave.net", r),
                Err(BadArweaveId),
                "{r:?}"
            );
        }
    }
}
