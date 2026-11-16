//! Host-name hygiene for names a requester controls (a URL's host, a redirect's target).
//!
//! The address check ([`crate::admit`]) is what keeps a connection on the public internet: whatever a
//! name resolves to, only admitted addresses are connected to. These rules come first, so a name that
//! can only mean something local is refused before any resolver sees it (a resolver can answer such a
//! name from `/etc/hosts`, mDNS, a search domain or a split-horizon zone, and a lookup of it already
//! tells the requester something). [`check_host_name`] takes the name as written, lower-cases it,
//! and refuses:
//!
//! - an empty name, one over 253 bytes, an empty label (`a..b`, `.a`), a label over 63 bytes;
//! - **a trailing dot** (`localhost.`, `metadata.google.internal.`): the absolute form of a name,
//!   which skips search domains and slips past suffix checks that compare strings;
//! - any byte other than ASCII letters, digits, `-` and `.`, so `_`, `%` (percent-encoding, IPv6
//!   zone ids), whitespace, control bytes and non-ASCII (write an internationalised name in its
//!   `xn--` form); and a label that starts or ends with `-`;
//! - **a single-label name** (`localhost`, `metadata`, `instance-data`, `wpad`, `kubernetes`): only
//!   a search domain or a local resolver can answer one;
//! - **a last label that is a number** (all digits, or `0x` and hex digits): an IPv4 address in a
//!   form other than dotted-quad decimal (`2130706433`, `0x7f.1`, `127.1`, `1.2.3.4.5`), which
//!   parsers disagree about. A dotted-quad literal is an address, not a name, and is judged as one;
//!   a last label of letters and digits (`a1`) is no top-level domain and is refused too;
//! - **a name equal to or under a suffix in [`INTERNAL_SUFFIXES`]**: the special-use and
//!   private-use names that only a local resolver answers.
//!
//! What it does not do: refuse public names that resolve to private addresses (`localtest.me`,
//! `127.0.0.1.nip.io`, a requester's own zone). Those are caught where the answer is, by the
//! address check, on every connection.

use std::fmt;

/// Suffixes of names that only a local resolver answers. A name equal to one, or ending in `.` and
/// one, is refused.
pub const INTERNAL_SUFFIXES: &[&str] = &[
    // RFC 6761 special-use names.
    "localhost",
    "test",
    "invalid",
    "example",
    // mDNS (RFC 6762), and Kubernetes' cluster domain `cluster.local` under it.
    "local",
    // Tor (RFC 7686) and other non-DNS namespaces (RFC 9476).
    "onion",
    "alt",
    // Reverse-mapping zones and `home.arpa` (RFC 8375): no program store lives under `.arpa`.
    "arpa",
    // ICANN's private-use top-level domain: GCE (`metadata.google.internal`,
    // `*.c.<project>.internal`), AWS (`*.ec2.internal`, `*.compute.internal`), Docker
    // (`host.docker.internal`).
    "internal",
    // Private names in common use that are never delegated (ICANN's name-collision list) or are
    // a de-facto local suffix.
    "lan",
    "home",
    "corp",
    "mail",
    "intranet",
    "private",
    "localdomain",
    "workgroup",
    // Kubernetes services through a cluster search path (`<svc>.<namespace>.svc`).
    "svc",
    // HashiCorp Consul's DNS interface.
    "consul",
    // Azure's internal DNS suffix for virtual machines.
    "internal.cloudapp.net",
    // Google Compute Engine's metadata server, by its other name.
    "metadata.goog",
];

/// Why a requester's host name was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostDenied {
    Empty,
    TooLong,
    /// A byte other than ASCII letters, digits, `-` and `.`.
    BadCharacter,
    /// `a..b` or a leading dot.
    EmptyLabel,
    TrailingDot,
    LabelTooLong,
    /// A label that starts or ends with `-`.
    HyphenAtLabelEdge,
    SingleLabel,
    /// An IPv4 address written other than as dotted-quad decimal (integer, octal, hex, shortened,
    /// or more than four parts).
    NonCanonicalIp,
    /// A last label that is neither letters nor an `xn--` label.
    BadTopLevelDomain,
    /// Equal to or under this suffix in [`INTERNAL_SUFFIXES`].
    InternalName(&'static str),
}

impl fmt::Display for HostDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostDenied::Empty => f.write_str("the host name is empty"),
            HostDenied::TooLong => f.write_str("the host name is longer than 253 bytes"),
            HostDenied::BadCharacter => f.write_str(
                "the host name has a character other than ASCII letters, digits, '-' and '.'",
            ),
            HostDenied::EmptyLabel => f.write_str("the host name has an empty label"),
            HostDenied::TrailingDot => f.write_str("the host name ends with a dot"),
            HostDenied::LabelTooLong => f.write_str("a label of the host name is over 63 bytes"),
            HostDenied::HyphenAtLabelEdge => {
                f.write_str("a label of the host name starts or ends with '-'")
            }
            HostDenied::SingleLabel => f.write_str("the host name has a single label"),
            HostDenied::NonCanonicalIp => {
                f.write_str("the host is an IPv4 address written other than as four decimal octets")
            }
            HostDenied::BadTopLevelDomain => {
                f.write_str("the host name's last label is not a top-level domain")
            }
            HostDenied::InternalName(s) => write!(f, "the host name is under .{s}, a local name"),
        }
    }
}

impl std::error::Error for HostDenied {}

/// Checks a requester's host name (not an IP literal: see [`crate::check_url`]) against the rules in
/// the module doc, and returns it lower-cased.
pub fn check_host_name(name: &str) -> Result<String, HostDenied> {
    if name.is_empty() {
        return Err(HostDenied::Empty);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(HostDenied::BadCharacter);
    }
    if name.ends_with('.') {
        return Err(HostDenied::TrailingDot);
    }
    if name.len() > 253 {
        return Err(HostDenied::TooLong);
    }
    let name = name.to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err(HostDenied::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(HostDenied::LabelTooLong);
        }
    }
    let last = labels[labels.len() - 1];
    if is_numeric_label(last) {
        return Err(HostDenied::NonCanonicalIp);
    }
    for label in &labels {
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostDenied::HyphenAtLabelEdge);
        }
    }
    if labels.len() < 2 {
        return Err(HostDenied::SingleLabel);
    }
    let tld_ok = (last.len() >= 2 && last.bytes().all(|b| b.is_ascii_lowercase()))
        || (last.len() > 4 && last.starts_with("xn--"));
    if !tld_ok {
        return Err(HostDenied::BadTopLevelDomain);
    }
    if let Some(s) = internal_suffix(&name) {
        return Err(HostDenied::InternalName(s));
    }
    Ok(name)
}

/// The suffix of [`INTERNAL_SUFFIXES`] that `name` (lower case, no trailing dot) is equal to or
/// under, if any.
pub(crate) fn internal_suffix(name: &str) -> Option<&'static str> {
    INTERNAL_SUFFIXES.iter().copied().find(|s| {
        name == *s
            || (name.len() > s.len()
                && name.ends_with(s)
                && name.as_bytes()[name.len() - s.len() - 1] == b'.')
    })
}

/// Whether a label is what the URL standard reads as a number when it ends a host: decimal digits,
/// or `0x`/`0X` and hex digits (`0x` alone included).
pub(crate) fn is_numeric_label(label: &str) -> bool {
    if !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    match label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_names_pass_lower_cased() {
        for (name, want) in [
            ("arweave.net", "arweave.net"),
            ("IPFS.io", "ipfs.io"),
            (
                "release-assets.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ),
            (
                "risc0-artifacts.s3.us-west-2.amazonaws.com",
                "risc0-artifacts.s3.us-west-2.amazonaws.com",
            ),
            ("xn--bcher-kva.de", "xn--bcher-kva.de"),
            ("example.xn--p1ai", "example.xn--p1ai"),
            ("a.b.c.d.example.com", "a.b.c.d.example.com"),
            ("1.2.3.4.nip.io", "1.2.3.4.nip.io"), // a public name: its answer is judged instead
            ("my-store.example.org", "my-store.example.org"),
            ("123.example.com", "123.example.com"),
            ("example.com", "example.com"), // a real domain, not the `.example` TLD
            ("notlocal.com", "notlocal.com"),
            ("mylocal.dev", "mylocal.dev"),
        ] {
            assert_eq!(check_host_name(name).as_deref(), Ok(want), "{name}");
        }
    }

    #[test]
    fn local_and_malformed_names_are_refused() {
        use HostDenied::*;
        for (name, why) in [
            ("", Empty),
            ("localhost", SingleLabel),
            ("LOCALHOST", SingleLabel),
            ("metadata", SingleLabel),
            ("instance-data", SingleLabel),
            ("wpad", SingleLabel),
            ("localhost.", TrailingDot),
            ("example.com.", TrailingDot),
            ("metadata.google.internal.", TrailingDot),
            ("a..b.com", EmptyLabel),
            (".example.com", EmptyLabel),
            ("foo.localhost", InternalName("localhost")),
            ("a.b.LOCALHOST", InternalName("localhost")),
            ("printer.local", InternalName("local")),
            (
                "kube-dns.kube-system.svc.cluster.local",
                InternalName("local"),
            ),
            ("my-svc.my-ns.svc", InternalName("svc")),
            ("metadata.google.internal", InternalName("internal")),
            ("ip-10-0-0-1.ec2.internal", InternalName("internal")),
            ("host.docker.internal", InternalName("internal")),
            ("nas.lan", InternalName("lan")),
            ("router.home", InternalName("home")),
            ("router.home.arpa", InternalName("arpa")),
            ("1.0.0.127.in-addr.arpa", InternalName("arpa")),
            ("dc.corp", InternalName("corp")),
            ("wiki.intranet", InternalName("intranet")),
            ("db.private", InternalName("private")),
            ("box.localdomain", InternalName("localdomain")),
            ("vault.service.consul", InternalName("consul")),
            (
                "vm1.internal.cloudapp.net",
                InternalName("internal.cloudapp.net"),
            ),
            ("metadata.goog", InternalName("metadata.goog")),
            ("store.test", InternalName("test")),
            ("store.invalid", InternalName("invalid")),
            ("store.example", InternalName("example")),
            ("abc.onion", InternalName("onion")),
            ("x.alt", InternalName("alt")),
            ("pc.workgroup", InternalName("workgroup")),
            ("host.mail", InternalName("mail")),
            // Non-canonical IPv4: the URL standard reads these as 127.0.0.1 and friends.
            ("2130706433", NonCanonicalIp),
            ("0x7f000001", NonCanonicalIp),
            ("0x7f.0.0.1", NonCanonicalIp),
            ("0177.0.0.1", NonCanonicalIp),
            ("127.1", NonCanonicalIp),
            ("127.0.1", NonCanonicalIp),
            ("1.2.3.4.5", NonCanonicalIp),
            ("127.0.0.0x1", NonCanonicalIp),
            ("foo.0x", NonCanonicalIp),
            ("foo.123", NonCanonicalIp),
            ("8.8.8.8", NonCanonicalIp), // a literal is no name: check_url judges it as an address
            ("foo.a1", BadTopLevelDomain),
            ("foo.c", BadTopLevelDomain),
            ("foo.xn--", HyphenAtLabelEdge),
            ("-foo.com", HyphenAtLabelEdge),
            ("foo-.com", HyphenAtLabelEdge),
            ("under_score.com", BadCharacter),
            ("%31%32%37.0.0.1", BadCharacter),
            ("fe80::1%25eth0", BadCharacter),
            ("exa mple.com", BadCharacter),
            ("exa\tmple.com", BadCharacter),
            ("ex\u{0430}mple.com", BadCharacter), // Cyrillic a
            ("ｌｏｃａｌｈｏｓｔ", BadCharacter), // fullwidth, which IDNA maps to localhost
            ("bücher.de", BadCharacter),
            ("[::1]", BadCharacter),
            ("user@host.com", BadCharacter),
            ("host.com:80", BadCharacter),
        ] {
            assert_eq!(check_host_name(name), Err(why), "{name:?}");
        }
        assert_eq!(
            check_host_name(&format!("{}.com", "a".repeat(64))),
            Err(LabelTooLong)
        );
        let long = format!("{}.com", vec!["a".repeat(62); 4].join("."));
        assert_eq!(check_host_name(&long), Err(TooLong));
    }

    #[test]
    fn suffixes_match_whole_labels_only() {
        assert_eq!(internal_suffix("local"), Some("local"));
        assert_eq!(internal_suffix("a.local"), Some("local"));
        assert_eq!(internal_suffix("alocal"), None);
        assert_eq!(internal_suffix("a.notlocal"), None);
        assert_eq!(
            internal_suffix("vm.internal.cloudapp.net"),
            Some("internal.cloudapp.net")
        );
        assert_eq!(internal_suffix("cloudapp.net"), None);
        assert_eq!(internal_suffix("xinternal.cloudapp.net"), None);
    }

    #[test]
    fn every_listed_suffix_is_refused_alone_and_under_a_label() {
        for s in INTERNAL_SUFFIXES {
            let under = format!("host.{s}");
            assert!(check_host_name(&under).is_err(), "{under}");
            assert!(check_host_name(s).is_err(), "{s}");
        }
    }
}
