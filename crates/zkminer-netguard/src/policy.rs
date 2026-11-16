//! The one admission decision ([`admit`]) and the policy value callers hold ([`NetPolicy`]).

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::facts::HostFacts;
use crate::host::HostDenied;
use crate::ip::{canonical_ip, is_global, prefix_is_global, Prefix};

/// Whether connections a requester causes may reach non-public destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetMode {
    /// The only mode a miner on a market runs in: a requester-caused connection goes only to a
    /// globally routable address that is not the host's own, not on a prefix the host is connected
    /// to, and not in the operator's deny CIDRs; requester host names pass the hygiene rules.
    #[default]
    Public,
    /// Developer mode (`[dev] private_network = true`): every destination is admitted, loopback and
    /// the LAN included, so a local test network can serve programs. Never on a public market.
    DevPrivate,
}

/// Why a destination or URL was refused. The `Display` of each says so in the guard's own words
/// (`refused by the network guard: …`), and prints only what is safe to log: addresses, prefixes,
/// and requester text escaped and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Not globally routable unicast ([`crate::is_global`]).
    NotGlobal(IpAddr),
    /// One of the host's own addresses.
    OwnAddress(IpAddr),
    /// On a prefix one of the host's interfaces is connected to.
    ConnectedPrefix { ip: IpAddr, prefix: Prefix },
    /// In one of the operator's deny CIDRs.
    DenyCidr { ip: IpAddr, prefix: Prefix },
    /// The URL is malformed or uses something refused (see [`UrlDenied`]).
    Url(UrlDenied),
    /// The URL's host name failed the hygiene rules.
    Host { host: String, why: HostDenied },
    /// The name resolved, but to no admitted address.
    NoAdmittedAddress { host: String, refused: Vec<Denied> },
    /// A prefix (an operator's role entry) holds an address that is not global.
    PrefixNotGlobal(Prefix),
    /// A prefix holds one of the host's own addresses.
    PrefixHoldsOwnAddress { prefix: Prefix, ip: IpAddr },
    /// A prefix overlaps a network the host is connected to.
    PrefixOverlapsConnected { prefix: Prefix, connected: Prefix },
    /// A prefix overlaps one of the operator's deny CIDRs.
    PrefixOverlapsDeny { prefix: Prefix, deny: Prefix },
}

/// What is wrong with a URL, apart from where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlDenied {
    /// Longer than [`crate::MAX_URL_LEN`].
    TooLong,
    /// A byte outside printable ASCII, a space, or a backslash.
    BadCharacter,
    /// Not `http` or `https`.
    Scheme(String),
    /// User information (`user:pass@`) in the authority.
    UserInfo,
    /// No host, or a malformed authority.
    BadAuthority,
    /// A malformed or zero port.
    BadPort,
    /// An IPv6 literal with a zone id (`[fe80::1%eth0]`).
    ZoneId,
    /// The URL parser read it differently from the strict reading (scheme, host or port).
    Ambiguous,
    /// The URL did not parse.
    Unparseable,
}

impl fmt::Display for UrlDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlDenied::TooLong => write!(f, "the URL is longer than {} bytes", crate::MAX_URL_LEN),
            UrlDenied::BadCharacter => {
                f.write_str("the URL has a byte outside printable ASCII, a space, or a backslash")
            }
            UrlDenied::Scheme(s) => write!(
                f,
                "the URL's scheme is {:?}, not http or https",
                crate::printable(s, 16)
            ),
            UrlDenied::UserInfo => f.write_str("the URL carries user information"),
            UrlDenied::BadAuthority => f.write_str("the URL has no host or a malformed authority"),
            UrlDenied::BadPort => f.write_str("the URL's port is malformed or zero"),
            UrlDenied::ZoneId => f.write_str("the URL's IPv6 literal has a zone id"),
            UrlDenied::Ambiguous => {
                f.write_str("the URL parser reads the URL differently from its strict reading")
            }
            UrlDenied::Unparseable => f.write_str("the URL does not parse"),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refused by the network guard: ")?;
        self.reason(f)
    }
}

impl Denied {
    fn reason(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::NotGlobal(ip) => write!(f, "{ip} is not a public internet address"),
            Denied::OwnAddress(ip) => write!(f, "{ip} is this host's own address"),
            Denied::ConnectedPrefix { ip, prefix } => {
                write!(
                    f,
                    "{ip} is on {prefix}, a network this host is connected to"
                )
            }
            Denied::DenyCidr { ip, prefix } => {
                write!(f, "{ip} is in the operator's deny CIDR {prefix}")
            }
            Denied::Url(why) => fmt::Display::fmt(why, f),
            Denied::Host { host, why } => write!(f, "host {host:?}: {why}"),
            Denied::PrefixNotGlobal(p) => {
                write!(f, "{p} holds addresses that are not on the public internet")
            }
            Denied::PrefixHoldsOwnAddress { prefix, ip } => {
                write!(f, "{prefix} holds {ip}, this host's own address")
            }
            Denied::PrefixOverlapsConnected { prefix, connected } => {
                write!(
                    f,
                    "{prefix} overlaps {connected}, a network this host is connected to"
                )
            }
            Denied::PrefixOverlapsDeny { prefix, deny } => {
                write!(f, "{prefix} overlaps the operator's deny CIDR {deny}")
            }
            Denied::NoAdmittedAddress { host, refused } => {
                write!(f, "{host:?} resolves to no admitted address (")?;
                for (i, d) in refused.iter().enumerate() {
                    if i > 0 {
                        f.write_str("; ")?;
                    }
                    d.reason(f)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl std::error::Error for Denied {}

/// The single admission decision for one destination address of a connection a requester caused.
///
/// [`NetMode::DevPrivate`] admits everything. [`NetMode::Public`] admits `ip` only if it is globally
/// routable ([`crate::is_global`], judged on `ip` as given) and, judged on its [`canonical_ip`] (so
/// an IPv4-mapped, SIIT or NAT64 spelling of an address is that address), it is none of the host's
/// own addresses, on none of its connected prefixes, and in none of `extra_deny`.
pub fn admit(
    mode: NetMode,
    ip: IpAddr,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    if mode == NetMode::DevPrivate {
        return Ok(());
    }
    if !is_global(ip) {
        return Err(Denied::NotGlobal(ip));
    }
    let c = canonical_ip(ip);
    if facts.own_addresses().iter().any(|o| canonical_ip(*o) == c) {
        return Err(Denied::OwnAddress(ip));
    }
    if let Some(p) = facts.connected().iter().find(|p| p.contains(c)) {
        return Err(Denied::ConnectedPrefix { ip, prefix: *p });
    }
    if let Some(p) = extra_deny.iter().find(|p| p.contains(c)) {
        return Err(Denied::DenyCidr { ip, prefix: *p });
    }
    Ok(())
}

/// [`admit`] for every address of a prefix at once (an operator's role entry, which admits
/// connections to any address inside it): in [`NetMode::Public`] the whole prefix must be global
/// ([`crate::ip::prefix_is_global`]), hold none of the host's own addresses, and overlap none of its
/// connected prefixes and none of `extra_deny`, each compared in canonical form
/// ([`Prefix::canonical_prefix`]). [`NetMode::DevPrivate`] admits every prefix.
pub fn admit_prefix(
    mode: NetMode,
    prefix: Prefix,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    if mode == NetMode::DevPrivate {
        return Ok(());
    }
    let prefix = Prefix::new(prefix.addr, prefix.len);
    if !prefix_is_global(prefix) {
        return Err(Denied::PrefixNotGlobal(prefix));
    }
    if let Some(ip) = facts
        .own_addresses()
        .iter()
        .find(|o| prefix.overlaps(&Prefix::host(**o)))
    {
        return Err(Denied::PrefixHoldsOwnAddress { prefix, ip: *ip });
    }
    if let Some(c) = facts.connected().iter().find(|c| prefix.overlaps(c)) {
        return Err(Denied::PrefixOverlapsConnected {
            prefix,
            connected: *c,
        });
    }
    if let Some(d) = extra_deny.iter().find(|d| prefix.overlaps(d)) {
        return Err(Denied::PrefixOverlapsDeny { prefix, deny: *d });
    }
    Ok(())
}

/// How long gathered host facts are trusted before they are read again.
pub const FACTS_TTL: Duration = Duration::from_secs(30);

/// The host facts a policy judges with: gathered from the interfaces and re-read once older than
/// [`FACTS_TTL`], or fixed by the caller.
#[derive(Debug)]
struct FactsCell {
    current: RwLock<Arc<HostFacts>>,
    refresh: bool,
}

impl FactsCell {
    fn get(&self) -> Arc<HostFacts> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !self.refresh || current.gathered_at().elapsed() < FACTS_TTL {
            return current;
        }
        match HostFacts::gather() {
            Ok(fresh) => {
                let fresh = Arc::new(fresh);
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = fresh.clone();
                fresh
            }
            Err(e) => {
                // The last good facts stay in force (an interface read that fails says nothing about
                // the interfaces), and the next call tries again.
                tracing::warn!("network guard: re-reading this host's interfaces failed: {e}");
                current
            }
        }
    }
}

/// A network policy: the mode, the host's facts, and the operator's extra deny CIDRs. Cheap to clone
/// (shared state). Every requester-caused connection is judged by one: [`NetPolicy::admit`] for an
/// address, [`NetPolicy::check_url`] for a URL, and the guarded resolver and client built from it.
#[derive(Debug, Clone)]
pub struct NetPolicy {
    mode: NetMode,
    facts: Arc<FactsCell>,
    deny: Arc<[Prefix]>,
}

impl NetPolicy {
    /// A policy over this host's own facts, gathered now (in [`NetMode::Public`]) and re-read when
    /// stale. Fails if the interfaces cannot be read: a public-mode policy that does not know the
    /// host's addresses cannot refuse them.
    pub fn new(mode: NetMode, deny: Vec<Prefix>) -> io::Result<Self> {
        let (facts, refresh) = match mode {
            NetMode::Public => (HostFacts::gather()?, true),
            NetMode::DevPrivate => (HostFacts::empty(), false),
        };
        Ok(Self::build(mode, facts, refresh, deny))
    }

    /// A policy over fixed facts, never re-read: for tests, and for a caller that refreshes the
    /// facts itself (and builds a new policy when they change).
    pub fn with_facts(mode: NetMode, facts: HostFacts, deny: Vec<Prefix>) -> Self {
        Self::build(mode, facts, false, deny)
    }

    fn build(mode: NetMode, facts: HostFacts, refresh: bool, deny: Vec<Prefix>) -> Self {
        NetPolicy {
            mode,
            facts: Arc::new(FactsCell {
                current: RwLock::new(Arc::new(facts)),
                refresh,
            }),
            deny: deny.into(),
        }
    }

    pub fn mode(&self) -> NetMode {
        self.mode
    }

    /// The operator's extra deny CIDRs.
    pub fn deny(&self) -> &[Prefix] {
        &self.deny
    }

    /// The host facts in force (re-read first if stale).
    pub fn facts(&self) -> Arc<HostFacts> {
        self.facts.get()
    }

    /// [`admit`] under this policy.
    pub fn admit(&self, ip: IpAddr) -> Result<(), Denied> {
        if self.mode == NetMode::DevPrivate {
            return Ok(());
        }
        admit(self.mode, ip, &self.facts(), &self.deny)
    }

    /// [`crate::check_url`] under this policy.
    pub fn check_url(&self, raw: &str) -> Result<url::Url, Denied> {
        crate::url::check_url(self, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn facts() -> HostFacts {
        HostFacts::new(
            vec![
                pfx("127.0.0.0/8"),
                pfx("192.168.1.0/24"),
                pfx("9.9.9.0/24"),          // a public subnet the host sits on
                pfx("2606:4700:aaaa::/64"), // the host's global /64 (on-link neighbours)
                pfx("fe80::/64"),
            ],
            vec![
                ip("127.0.0.1"),
                ip("192.168.1.10"),
                ip("9.9.9.10"),
                ip("2606:4700:aaaa::10"),
                ip("203.0.113.9"), // not global, but its own address all the same
                ip("2a01:4f8:1::77"), // a global address with a host route only
            ],
        )
    }

    #[test]
    fn public_mode_admits_only_public_strangers() {
        let f = facts();
        let deny = [pfx("8.8.4.4/32"), pfx("2a02:1234::/32")];
        let a = |s: &str| admit(NetMode::Public, ip(s), &f, &deny);
        for s in [
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::101:101",
            "::ffff:1.1.1.1",
            "9.9.10.1",
        ] {
            assert_eq!(a(s), Ok(()), "{s}");
        }
        assert_eq!(a("127.0.0.1"), Err(Denied::NotGlobal(ip("127.0.0.1"))));
        assert_eq!(a("10.0.0.1"), Err(Denied::NotGlobal(ip("10.0.0.1"))));
        assert_eq!(
            a("169.254.169.254"),
            Err(Denied::NotGlobal(ip("169.254.169.254")))
        );
        assert_eq!(
            a("::ffff:192.168.1.1"),
            Err(Denied::NotGlobal(ip("::ffff:192.168.1.1")))
        );
        assert_eq!(
            a("fd00:ec2::254"),
            Err(Denied::NotGlobal(ip("fd00:ec2::254")))
        );
        // Hairpin: the host's own global addresses, in any spelling.
        assert_eq!(
            a("2a01:4f8:1::77"),
            Err(Denied::OwnAddress(ip("2a01:4f8:1::77")))
        );
        assert_eq!(a("9.9.9.10"), Err(Denied::OwnAddress(ip("9.9.9.10"))));
        assert_eq!(
            a("64:ff9b::909:90a"),
            Err(Denied::OwnAddress(ip("64:ff9b::909:90a")))
        );
        assert_eq!(
            a("::ffff:9.9.9.10"),
            Err(Denied::OwnAddress(ip("::ffff:9.9.9.10")))
        );
        // On-link neighbours with global addresses.
        assert_eq!(
            a("9.9.9.11"),
            Err(Denied::ConnectedPrefix {
                ip: ip("9.9.9.11"),
                prefix: pfx("9.9.9.0/24")
            })
        );
        assert_eq!(
            a("2606:4700:aaaa::1"),
            Err(Denied::ConnectedPrefix {
                ip: ip("2606:4700:aaaa::1"),
                prefix: pfx("2606:4700:aaaa::/64")
            })
        );
        assert_eq!(
            a("64:ff9b::909:901"),
            Err(Denied::ConnectedPrefix {
                ip: ip("64:ff9b::909:901"),
                prefix: pfx("9.9.9.0/24")
            })
        );
        // The operator's deny CIDRs (a NAT'd public address).
        assert_eq!(
            a("8.8.4.4"),
            Err(Denied::DenyCidr {
                ip: ip("8.8.4.4"),
                prefix: pfx("8.8.4.4/32")
            })
        );
        assert_eq!(
            a("::ffff:0:808:404"),
            Err(Denied::DenyCidr {
                ip: ip("::ffff:0:808:404"),
                prefix: pfx("8.8.4.4/32")
            })
        );
        assert_eq!(
            a("2a02:1234::5"),
            Err(Denied::DenyCidr {
                ip: ip("2a02:1234::5"),
                prefix: pfx("2a02:1234::/32")
            })
        );
    }

    /// Review r1 broker F6 (PoC t6): a deny CIDR written in an embedded-IPv4 form (NAT64, SIIT,
    /// IPv4-compatible) denied the prefix at load (`admit_prefix`) but not the address at connect
    /// time (`admit`), which compared only the IPv4-mapped spelling. Both refuse it now, in every
    /// spelling of the address.
    #[test]
    fn deny_cidrs_in_any_embedded_form_deny_at_connect_time() {
        let f = HostFacts::empty();
        for deny in [
            "64:ff9b::808:808/128",
            "::ffff:0:808:808/128",
            "::808:808/128",
            "::ffff:8.8.8.8/128",
            "64:ff9b::808:800/120",
        ] {
            let d = [pfx(deny)];
            for a in [
                "8.8.8.8",
                "::ffff:8.8.8.8",
                "::ffff:0:808:808",
                "64:ff9b::808:808",
            ] {
                assert!(
                    matches!(
                        admit(NetMode::Public, ip(a), &f, &d),
                        Err(Denied::DenyCidr { .. })
                    ),
                    "deny {deny}: {a}"
                );
            }
            assert!(matches!(
                admit_prefix(NetMode::Public, pfx("8.8.8.8/32"), &f, &d),
                Err(Denied::PrefixOverlapsDeny { .. })
            ));
            assert_eq!(admit(NetMode::Public, ip("1.1.1.1"), &f, &d), Ok(()));
        }
        // A connected prefix or an own address in NAT64 form is the IPv4 one, too.
        let f = HostFacts::new(vec![pfx("64:ff9b::909:900/120")], vec![]);
        assert!(matches!(
            admit(NetMode::Public, ip("9.9.9.20"), &f, &[]),
            Err(Denied::ConnectedPrefix { .. })
        ));
    }

    #[test]
    fn dev_mode_admits_everything() {
        let f = facts();
        let deny = [pfx("0.0.0.0/0"), pfx("::/0")];
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "9.9.9.10",
            "8.8.8.8",
            "fe80::1",
        ] {
            assert_eq!(admit(NetMode::DevPrivate, ip(s), &f, &deny), Ok(()), "{s}");
        }
        let p = NetPolicy::with_facts(NetMode::DevPrivate, f, deny.to_vec());
        assert_eq!(p.admit(ip("127.0.0.1")), Ok(()));
    }

    #[test]
    fn a_policy_over_fixed_facts_judges_with_them() {
        let p = NetPolicy::with_facts(NetMode::Public, facts(), vec![pfx("8.8.4.0/24")]);
        assert_eq!(p.mode(), NetMode::Public);
        assert_eq!(p.admit(ip("1.1.1.1")), Ok(()));
        assert!(matches!(
            p.admit(ip("9.9.9.10")),
            Err(Denied::OwnAddress(_))
        ));
        assert!(matches!(
            p.admit(ip("8.8.4.8")),
            Err(Denied::DenyCidr { .. })
        ));
        assert_eq!(p.deny(), &[pfx("8.8.4.0/24")]);
    }

    #[test]
    fn a_gathered_public_policy_refuses_this_hosts_own_addresses() {
        let p = NetPolicy::new(NetMode::Public, Vec::new()).expect("read the interfaces");
        for a in p.facts().own_addresses() {
            assert!(p.admit(*a).is_err(), "{a} is this host's");
        }
    }

    #[test]
    fn whole_prefixes_are_admitted_only_when_public_and_apart_from_the_host() {
        let f = facts();
        let deny = [pfx("8.8.4.4/32"), pfx("2a02:1234::/32")];
        let a = |s: &str| admit_prefix(NetMode::Public, pfx(s), &f, &deny);
        for s in [
            "1.1.1.0/24",
            "1.1.1.1/32",
            "2606:4700:4700::/48",
            "64:ff9b::101:100/120",
            "8.8.8.0/24",
        ] {
            assert_eq!(a(s), Ok(()), "{s}");
        }
        for (s, why) in [
            ("0.0.0.0/0", "not on the public internet"),
            ("::/0", "not on the public internet"),
            ("8.0.0.0/6", "not on the public internet"), // holds 10.0.0.0/8
            ("127.0.0.1/32", "not on the public internet"),
            ("::ffff:127.0.0.1/128", "not on the public internet"),
            ("10.0.0.5/32", "not on the public internet"),
            ("2a01:4f8:1::77/128", "this host's own address"),
            ("2a01:4f8::/32", "this host's own address"),
            ("9.9.9.16/28", "a network this host is connected to"),
            ("9.0.0.0/8", "this host's own address"),
            (
                "2606:4700:aaaa:0:8000::/65",
                "a network this host is connected to",
            ),
            ("2606:4700:aaaa::/48", "this host's own address"),
            ("8.8.4.0/24", "deny CIDR"),
            ("::ffff:8.8.4.4/128", "deny CIDR"),
            ("2a02:1234:5::/48", "deny CIDR"),
        ] {
            let e = a(s).expect_err(s).to_string();
            assert!(e.contains(why), "{s}: {e}");
        }
        assert_eq!(
            admit_prefix(NetMode::DevPrivate, pfx("0.0.0.0/0"), &f, &deny),
            Ok(())
        );
    }

    #[test]
    fn denials_say_what_and_why_in_the_guards_words() {
        let d = Denied::NoAdmittedAddress {
            host: "elf.example.com".into(),
            refused: vec![
                Denied::NotGlobal(ip("127.0.0.1")),
                Denied::OwnAddress(ip("9.9.9.10")),
            ],
        };
        assert_eq!(
            d.to_string(),
            "refused by the network guard: \"elf.example.com\" resolves to no admitted address \
             (127.0.0.1 is not a public internet address; 9.9.9.10 is this host's own address)"
        );
        assert_eq!(
            Denied::Url(UrlDenied::Scheme("file".into())).to_string(),
            "refused by the network guard: the URL's scheme is \"file\", not http or https"
        );
    }
}
