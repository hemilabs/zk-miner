//! [`check_url`]: the gate for every URL a requester controls (a storage URI, a redirect's target).
//!
//! The URL is read twice: once strictly, by the grammar below, and once by the URL standard's parser
//! (the `url` crate, which reqwest connects with). Both readings must agree on the scheme, the host
//! and the port, so nothing the standard's leniency does (strip tabs and newlines, read `\` as `/`,
//! percent-decode or IDNA-map a host, read `0x7f.1` as `127.0.0.1`, skip extra slashes) can make the
//! connection go somewhere the checks did not look at. The strict grammar:
//!
//! - at most [`MAX_URL_LEN`] bytes, every one printable ASCII other than `\` (no space, no control
//!   byte, nothing non-ASCII: percent-encode it);
//! - `http://` or `https://` (either case), then an authority up to the first `/`, `?` or `#`;
//! - no user information (no `@` in the authority);
//! - a host that is a bracketed IPv6 literal without a zone id, a dotted-quad IPv4 literal in
//!   canonical form (four decimal octets, no leading zeros), or a name of ASCII letters, digits,
//!   `-` and `.`; then optionally `:` and a port of 1 to 65535 without leading zeros.
//!
//! Then the destination: in [`NetMode::Public`] an IP literal must pass [`crate::admit`] (the
//! resolver never sees a literal, so this is its only check) and a name must pass
//! [`crate::check_host_name`]. [`NetMode::DevPrivate`] skips the destination checks and keeps the
//! rest.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::host::{check_host_name, is_numeric_label, HostDenied};
use crate::policy::{Denied, NetMode, NetPolicy, UrlDenied};

/// The longest URL [`check_url`] accepts.
pub const MAX_URL_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrictHost {
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug)]
struct Strict {
    scheme: &'static str,
    host: StrictHost,
    port: Option<u16>,
}

/// Checks a requester-controlled URL under `policy` (see the module doc) and returns it parsed.
pub fn check_url(policy: &NetPolicy, raw: &str) -> Result<Url, Denied> {
    let strict = parse_strict(raw)?;
    let url = Url::parse(raw).map_err(|_| Denied::Url(UrlDenied::Unparseable))?;
    if !agrees(&strict, &url) {
        return Err(Denied::Url(UrlDenied::Ambiguous));
    }
    match &strict.host {
        StrictHost::Ip(ip) => policy.admit(*ip)?,
        StrictHost::Name(name) => {
            if policy.mode() == NetMode::Public {
                check_host_name(name).map_err(|why| Denied::Host {
                    host: crate::printable(name, 128),
                    why,
                })?;
            }
        }
    }
    Ok(url)
}

/// Whether the standard parser read the same scheme, host and port as the strict grammar, and no
/// user information.
fn agrees(strict: &Strict, url: &Url) -> bool {
    if url.scheme() != strict.scheme || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let host_ok = match (url.host(), &strict.host) {
        (Some(Host::Domain(d)), StrictHost::Name(n)) => d == n.to_ascii_lowercase(),
        (Some(Host::Ipv4(a)), StrictHost::Ip(IpAddr::V4(b))) => a == *b,
        (Some(Host::Ipv6(a)), StrictHost::Ip(IpAddr::V6(b))) => a == *b,
        _ => false,
    };
    let default = if strict.scheme == "https" { 443 } else { 80 };
    host_ok && url.port_or_known_default() == Some(strict.port.unwrap_or(default))
}

fn parse_strict(raw: &str) -> Result<Strict, Denied> {
    let url_err = |why| Err(Denied::Url(why));
    if raw.len() > MAX_URL_LEN {
        return url_err(UrlDenied::TooLong);
    }
    if !raw
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && b != b'\\')
    {
        return url_err(UrlDenied::BadCharacter);
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        // `file:/etc/passwd`, `javascript:…`, `data:…`: name the scheme when there is one.
        return match raw.split_once(':') {
            Some((s, _)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()) => {
                url_err(UrlDenied::Scheme(s.to_ascii_lowercase()))
            }
            _ => url_err(UrlDenied::Unparseable),
        };
    };
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "http" => "http",
        "https" => "https",
        other => return url_err(UrlDenied::Scheme(other.to_string())),
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return url_err(UrlDenied::UserInfo);
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((inside, after)) = inner.split_once(']') else {
            return url_err(UrlDenied::BadAuthority);
        };
        if inside.contains('%') {
            return url_err(UrlDenied::ZoneId);
        }
        let Ok(v6) = inside.parse::<Ipv6Addr>() else {
            return url_err(UrlDenied::BadAuthority);
        };
        (StrictHost::Ip(IpAddr::V6(v6)), parse_port(after)?)
    } else {
        if authority.contains(['[', ']']) {
            return url_err(UrlDenied::BadAuthority);
        }
        let (h, after) = match authority.find(':') {
            Some(i) => authority.split_at(i),
            None => (authority, ""),
        };
        (strict_host(h)?, parse_port(after)?)
    };
    Ok(Strict { scheme, host, port })
}

/// `""` (no port) or `:` and 1..=65535 in canonical decimal.
fn parse_port(s: &str) -> Result<Option<u16>, Denied> {
    if s.is_empty() {
        return Ok(None);
    }
    let bad = Err(Denied::Url(UrlDenied::BadPort));
    let Some(digits) = s.strip_prefix(':') else {
        return Err(Denied::Url(UrlDenied::BadAuthority));
    };
    if digits.is_empty()
        || digits.len() > 5
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.starts_with('0')
    {
        return bad;
    }
    match digits.parse::<u16>() {
        Ok(p) if p > 0 => Ok(Some(p)),
        _ => bad,
    }
}

/// A host outside brackets: a canonical dotted-quad literal, or a name of letters, digits, `-`
/// and `.` (whose destination rules are checked later, by mode). A name whose last label is a
/// number is an IPv4 address in another form, refused in every mode.
fn strict_host(h: &str) -> Result<StrictHost, Denied> {
    let host_err = |why| {
        Err(Denied::Host {
            host: crate::printable(h, 128),
            why,
        })
    };
    if h.is_empty() {
        return Err(Denied::Url(UrlDenied::BadAuthority));
    }
    if !h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return host_err(HostDenied::BadCharacter);
    }
    let last = h.rsplit('.').next().unwrap_or(h);
    if is_numeric_label(last) {
        return match h.parse::<Ipv4Addr>() {
            // Rust's parser takes four decimal octets without leading zeros only; the round trip
            // makes the canonical form explicit.
            Ok(v4) if v4.to_string() == h => Ok(StrictHost::Ip(IpAddr::V4(v4))),
            _ => host_err(HostDenied::NonCanonicalIp),
        };
    }
    Ok(StrictHost::Name(h.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::HostFacts;
    use crate::ip::Prefix;

    fn public() -> NetPolicy {
        NetPolicy::with_facts(
            NetMode::Public,
            HostFacts::new(
                vec!["9.9.9.0/24".parse().unwrap()],
                vec!["9.9.9.10".parse().unwrap()],
            ),
            vec!["8.8.4.4/32".parse::<Prefix>().unwrap()],
        )
    }

    fn dev() -> NetPolicy {
        NetPolicy::with_facts(NetMode::DevPrivate, HostFacts::empty(), Vec::new())
    }

    #[test]
    fn public_urls_pass_in_both_modes() {
        for raw in [
            "https://arweave.net/bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U",
            "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            "http://elfs.example.com:8080/guest.bin?v=1#frag",
            "HTTPS://Release-Assets.GitHubUserContent.com/x",
            "https://1.1.1.1/elf",
            "https://1.1.1.1:443/elf",
            "http://[2606:4700:4700::1111]:8080/elf",
            "https://[2606:4700:4700:0:0:0:0:1111]/", // IPv6 text in another form is the same address
            "https://example.com",
            "https://example.com?q",
            "https://elfs.example.com/a%20b/%2e%2e/c", // percent-encoding in the path is fine
        ] {
            for p in [public(), dev()] {
                let url = check_url(&p, raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
                assert!(matches!(url.scheme(), "http" | "https"));
            }
        }
    }

    #[test]
    fn non_http_schemes_userinfo_and_malformed_urls_are_refused_in_both_modes() {
        use UrlDenied::*;
        for (raw, why) in [
            ("file:///etc/passwd", Denied::Url(Scheme("file".into()))),
            ("file:/etc/passwd", Denied::Url(Scheme("file".into()))),
            (
                "ftp://elfs.example.com/x",
                Denied::Url(Scheme("ftp".into())),
            ),
            (
                "gopher://elfs.example.com:70/_x",
                Denied::Url(Scheme("gopher".into())),
            ),
            (
                "dict://elfs.example.com:11211/stat",
                Denied::Url(Scheme("dict".into())),
            ),
            (
                "redis://elfs.example.com/",
                Denied::Url(Scheme("redis".into())),
            ),
            (
                "ldap://elfs.example.com/",
                Denied::Url(Scheme("ldap".into())),
            ),
            ("ws://elfs.example.com/", Denied::Url(Scheme("ws".into()))),
            (
                "javascript:alert(1)",
                Denied::Url(Scheme("javascript".into())),
            ),
            ("data:text/plain,x", Denied::Url(Scheme("data".into()))),
            ("//elfs.example.com/x", Denied::Url(Unparseable)),
            ("elfs.example.com/x", Denied::Url(Unparseable)),
            ("https://user:pw@elfs.example.com/", Denied::Url(UserInfo)),
            ("https://user@elfs.example.com/", Denied::Url(UserInfo)),
            ("https://@elfs.example.com/", Denied::Url(UserInfo)),
            ("https://elfs.example.com@127.0.0.1/", Denied::Url(UserInfo)),
            ("https:///elfs.example.com/x", Denied::Url(BadAuthority)),
            ("https://", Denied::Url(BadAuthority)),
            ("https://:443/", Denied::Url(BadAuthority)),
            ("https://elfs.example.com:/", Denied::Url(BadPort)),
            ("https://elfs.example.com:0/", Denied::Url(BadPort)),
            ("https://elfs.example.com:65536/", Denied::Url(BadPort)),
            ("https://elfs.example.com:0443/", Denied::Url(BadPort)),
            ("https://elfs.example.com:+443/", Denied::Url(BadPort)),
            ("https://elfs.example.com:443:443/", Denied::Url(BadPort)),
            ("https://[fe80::1%25eth0]/", Denied::Url(ZoneId)),
            ("https://[fe80::1%eth0]/", Denied::Url(ZoneId)),
            ("https://[::1/", Denied::Url(BadAuthority)),
            ("https://[not-v6]/", Denied::Url(BadAuthority)),
            ("https://[::1]x/", Denied::Url(BadAuthority)),
            ("https://a]b.com/", Denied::Url(BadAuthority)),
            // What the standard parser would quietly rewrite.
            (
                "https://elfs.example.com\\@127.0.0.1/",
                Denied::Url(BadCharacter),
            ),
            ("https:\\\\127.0.0.1\\", Denied::Url(BadCharacter)),
            ("https://elfs.exa\tmple.com/", Denied::Url(BadCharacter)),
            ("https://elfs.example.com/\n", Denied::Url(BadCharacter)),
            (" https://elfs.example.com/", Denied::Url(BadCharacter)),
            ("https://elfs.example.com/ x", Denied::Url(BadCharacter)),
            ("https://bücher.de/", Denied::Url(BadCharacter)),
            ("https://ｌｏｃａｌｈｏｓｔ/", Denied::Url(BadCharacter)),
            ("https://elfs.example.com/\u{0}", Denied::Url(BadCharacter)),
        ] {
            for p in [public(), dev()] {
                assert_eq!(check_url(&p, raw), Err(why.clone()), "{raw:?}");
            }
        }
        let long = format!("https://elfs.example.com/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(check_url(&public(), &long), Err(Denied::Url(TooLong)));
    }

    #[test]
    fn non_canonical_ip_literals_are_refused_in_both_modes() {
        for raw in [
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0x7f.0.0.1/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://127.0.1/",
            "http://010.0.0.1/",
            "http://1.2.3.4.5/",
            "http://8.8.8.010/", // what the standard reads as 8.8.8.8
            "http://0x08.0x08.0x08.0x08/",
            "http://%31%32%37.0.0.1/",
            "http://127.0.0.1%2f@example.com/",
        ] {
            for p in [public(), dev()] {
                let e = check_url(&p, raw).expect_err(raw);
                assert!(
                    matches!(
                        e,
                        Denied::Host {
                            why: HostDenied::NonCanonicalIp | HostDenied::BadCharacter,
                            ..
                        } | Denied::Url(UrlDenied::UserInfo)
                    ),
                    "{raw}: {e:?}"
                );
            }
        }
    }

    #[test]
    fn local_destinations_are_refused_in_public_mode_and_admitted_in_dev_mode() {
        for raw in [
            "http://127.0.0.1:8080/elf",
            "http://127.0.0.1/",
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:0:a9fe:a9fe]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://100.100.100.200/",
            "http://[fd00:ec2::254]/",
            "http://[fe80::1]/",
            "http://0.0.0.0/",
            "http://localhost:8080/elf",
            "http://LOCALHOST/",
            "http://foo.localhost/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata/",
            "http://printer.local/",
            "http://kubernetes.default.svc/",
            "http://9.9.9.10/",           // the host's own address
            "http://9.9.9.11/",           // a neighbour on its connected prefix
            "http://8.8.4.4/",            // in the operator's deny CIDRs
            "http://[64:ff9b::808:404]/", // the same, through NAT64
            "http://elfs.example.com./",  // trailing dot
            "http://store.invalid:8080/",
        ] {
            let e = check_url(&public(), raw).expect_err(raw);
            assert!(
                e.to_string().starts_with("refused by the network guard: "),
                "{raw}: {e}"
            );
            check_url(&dev(), raw).unwrap_or_else(|e| panic!("dev mode refused {raw}: {e}"));
        }
    }

    #[test]
    fn the_parsed_url_is_what_was_checked() {
        let url = check_url(&public(), "HTTP://ELFS.Example.COM:80/A?b#c").unwrap();
        assert_eq!(url.as_str(), "http://elfs.example.com/A?b#c");
        let url = check_url(&public(), "https://[2606:4700:4700:0:0:0:0:1111]:8443/").unwrap();
        assert_eq!(url.host_str(), Some("[2606:4700:4700::1111]"));
        assert_eq!(url.port(), Some(8443));
    }
}
