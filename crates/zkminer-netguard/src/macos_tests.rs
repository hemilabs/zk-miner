//! macOS, on this host's real facts (the routing table and kernel over the routing socket, the
//! interfaces, the DNS servers, the public addresses): everything the guard exists to refuse is
//! refused, for the same reason as on Linux, and an ordinary public host is admitted and passes
//! the real near-hop probe. Read-only; needs a network with a default route, as the Linux
//! real-host tests do.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::nearhop::{ConfirmOutcome, NearProbe, ProbeOutcome};
use crate::routes::{Hop, Link, Route};
use crate::{
    admit, is_global, Denied, FactsOptions, HostFacts, NetMode, NetPolicy, Prefix, RawFacts,
    RouteKind, TtlProbe,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn policy() -> NetPolicy {
    NetPolicy::new(NetMode::Public, Vec::new()).expect("a public-mode policy on this Mac")
}

/// Loopback, link-local, the LAN and the router's private address are not public internet
/// addresses: refused before any fact is consulted, as on Linux.
#[test]
fn loopback_link_local_the_lan_and_the_router_are_refused() {
    let p = policy();
    let f = p.facts();
    let mut checked = vec![
        ip("127.0.0.1"),
        ip("::1"),
        ip("fe80::1"),
        ip("169.254.169.254"),
        ip("192.168.1.50"),
        ip("10.0.0.1"),
    ];
    // The default routes' gateways: the home router.
    let gateways: Vec<IpAddr> = f.routes().uplinks().iter().map(|(gw, _)| *gw).collect();
    assert!(!gateways.is_empty(), "no uplink: {:?}", f.routes().routes());
    checked.extend(&gateways);
    // On a private LAN the address checks refuse all of these before any macOS code runs, so the
    // macOS route reading and kernel query are checked on their own here (review round 1,
    // cross-2): the IPv4 router is on-link to the kernel, and a LAN neighbour to the table.
    let mut kernel_checked = 0;
    for gw in gateways.iter().filter(|g| g.is_ipv4()) {
        assert!(
            matches!(
                f.kernel_verdict(*gw, Some(80)),
                Err(Denied::OffDefaultRoute {
                    kind: RouteKind::OnLink,
                    ..
                })
            ),
            "{gw}: {:?}",
            f.kernel_verdict(*gw, Some(80))
        );
        kernel_checked += 1;
    }
    let lan: Vec<IpAddr> = f
        .connected()
        .iter()
        .filter(|c| c.addr.is_ipv4() && !c.addr.is_loopback() && c.len <= 29)
        .filter(|c| gateways.iter().any(|g| c.contains(*g)))
        .map(|c| match c.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) | 6).into()),
            v6 => v6,
        })
        .filter(|n| !f.own_addresses().contains(n) && !gateways.contains(n))
        .collect();
    for n in &lan {
        assert_eq!(
            f.routes().off_default_path(*n).map(|r| r.kind),
            Some(RouteKind::OnLink),
            "{n}"
        );
        assert!(
            matches!(
                f.kernel_verdict(*n, Some(80)),
                Err(Denied::OffDefaultRoute {
                    kind: RouteKind::OnLink,
                    ..
                })
            ),
            "{n}: {:?}",
            f.kernel_verdict(*n, Some(80))
        );
        checked.push(*n);
        kernel_checked += 1;
    }
    if gateways.iter().any(|g| g.is_ipv4()) {
        assert!(
            !lan.is_empty(),
            "no LAN prefix holds the router: {:?}",
            f.connected()
        );
    }
    eprintln!("{kernel_checked} router and LAN verdicts checked on the macOS route code");
    for a in checked {
        let d = p.admit(a).unwrap_err();
        if is_global(a) {
            assert!(
                matches!(
                    d,
                    Denied::ConnectedPrefix { .. }
                        | Denied::OffDefaultRoute {
                            kind: RouteKind::OnLink,
                            ..
                        }
                ),
                "{a}: {d}"
            );
        } else {
            assert_eq!(d, Denied::NotGlobal(a), "{a}");
        }
        eprintln!("{a}: {d}");
    }
}

/// A global neighbour on every connected network (the IPv6 /64 the router advertises), this
/// host's own addresses, the rest of its site, and its DNS servers are refused, each for its
/// reason; so is every address of an operator's deny CIDR.
#[test]
fn neighbours_own_addresses_site_resolvers_and_deny_cidrs_are_refused() {
    let p = policy();
    let f = p.facts();
    let mut neighbours = 0;
    let global_prefixes = f
        .connected()
        .iter()
        .filter(|c| is_global(c.addr) && c.len + 3 <= if c.addr.is_ipv4() { 32 } else { 128 })
        .count();
    for c in f.connected() {
        let width = if c.addr.is_ipv4() { 32 } else { 128 };
        if !is_global(c.addr) || c.len + 3 > width {
            continue;
        }
        let n = match c.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) | 6).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) | 0x5ee).into()),
        };
        if f.own_addresses().contains(&n) {
            continue;
        }
        let d = p.admit(n).unwrap_err();
        assert!(matches!(d, Denied::ConnectedPrefix { .. }), "{n}: {d}");
        // The kernel says the same on its own: on-link.
        assert!(matches!(
            f.kernel_verdict(n, Some(443)),
            Err(Denied::OffDefaultRoute {
                kind: RouteKind::OnLink,
                ..
            })
        ));
        eprintln!("{n}: {d}");
        neighbours += 1;
    }
    for own in f.own_addresses() {
        let d = p.admit(*own).unwrap_err();
        if is_global(*own) {
            assert_eq!(d, Denied::OwnAddress(*own));
        }
        // An interface address (not the NAT address the reflectors report): the kernel says the
        // same on its own, delivered to this host.
        if is_global(*own) && !crate::public::public_addresses().contains(own) {
            assert!(matches!(
                f.kernel_verdict(*own, Some(443)),
                Err(Denied::OffDefaultRoute {
                    kind: RouteKind::Local,
                    ..
                })
            ));
        }
        if let IpAddr::V6(v6) = own {
            if is_global(*own) {
                // Another /64 of the same site.
                let other = IpAddr::V6(Ipv6Addr::from((u128::from(*v6) ^ (0x7f << 64)) | 1));
                assert!(
                    matches!(p.admit(other), Err(Denied::SitePrefix { .. })),
                    "{other}: {:?}",
                    p.admit(other)
                );
            }
        }
    }
    for r in crate::system_resolvers() {
        let d = p.admit(r).unwrap_err();
        assert!(
            matches!(
                d,
                Denied::DnsServer(_)
                    | Denied::NotGlobal(_)
                    | Denied::SitePrefix { .. }
                    | Denied::ConnectedPrefix { .. }
                    | Denied::OwnAddress(_)
            ),
            "{r}: {d}"
        );
        eprintln!("DNS server {r}: {d}");
    }
    let deny = NetPolicy::new(
        NetMode::Public,
        vec![pfx("1.0.0.0/24"), pfx("2606:4700::/32")],
    )
    .unwrap();
    for a in ["1.0.0.1", "2606:4700:4700::1001", "::ffff:1.0.0.1"] {
        assert!(
            matches!(deny.admit(ip(a)), Err(Denied::DenyCidr { .. })),
            "{a}: {:?}",
            deny.admit(ip(a))
        );
    }
    eprintln!("{neighbours} global neighbours refused");
    // Review round 1, cross-2: the neighbour checks must have run where they can.
    if global_prefixes > 0 {
        assert!(
            neighbours > 0,
            "{global_prefixes} global connected prefixes, no neighbour"
        );
    } else {
        crate::skipped("[ipv6] the global neighbours: no global connected prefix (IPv6) here");
    }
}

/// An ordinary public address is admitted, by the address checks and by the kernel (its route is
/// the default path, through an uplink), and the real near-hop probe finds it far: vetted.
#[test]
fn a_public_address_is_admitted_and_vetted() {
    let p = policy();
    assert!(
        p.facts().unknown_paths().is_empty(),
        "{:?}",
        p.facts().unknown_paths()
    );
    let addr = ["1.0.0.1:443", "8.8.4.4:443", "9.9.9.9:443", "1.1.1.1:443"]
        .iter()
        .map(|a| a.parse::<SocketAddr>().unwrap())
        .find(|a| p.admit(a.ip()).is_ok())
        .expect("a public anycast address the guard admits");
    assert_eq!(p.facts().kernel_verdict(addr.ip(), Some(443)), Ok(()));
    assert_eq!(p.vet_connection(addr), Ok(()), "{addr}");
    if p.facts().routes().routes_family(true) {
        let v6: SocketAddr = "[2606:4700:4700::1001]:443".parse().unwrap();
        if p.admit(v6.ip()).is_ok() {
            assert_eq!(p.vet_connection(v6), Ok(()), "{v6}");
        }
    }
}

/// A destination within the hop limit is refused before any connection carries data: a listener
/// on loopback stands in for a public address (the real probe and check connection are sent to
/// the listener in its place), as the Linux tests stage near destinations.
#[test]
fn a_destination_within_the_hop_limit_is_refused() {
    #[derive(Debug)]
    struct To(SocketAddr);
    impl NearProbe for To {
        fn probe(&self, _: SocketAddr, hops: u8, timeout: Duration) -> ProbeOutcome {
            TtlProbe.probe(self.0, hops, timeout)
        }
        fn confirm(&self, _: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
            TtlProbe.confirm(self.0, hops, timeout)
        }
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let near = l.local_addr().unwrap();
    let p = policy().with_near_probe(Arc::new(To(near)));
    let public = ["1.0.0.1:443", "8.8.4.4:443", "9.9.9.9:443"]
        .iter()
        .map(|a| a.parse::<SocketAddr>().unwrap())
        .find(|a| p.admit(a.ip()).is_ok())
        .expect("a public address the guard admits");
    let e = p.vet_connection(public).unwrap_err();
    assert!(
        matches!(e, Denied::NearHop { hops: 2, ref what, .. } if what.contains("accepted")),
        "{e}"
    );
    eprintln!("{e}");
    drop(l);
    // Nothing listening: a reset within the limit, refused too.
    let e = p.vet_connection(public).unwrap_err();
    assert!(
        matches!(e, Denied::NearHop { ref what, .. } if what.contains("refused")),
        "{e}"
    );
}

/// The facts this Mac's routing gives: a default route of each family it routes, through the
/// router on a physical interface (no `[egress] internal_ranges` needed); the system's scoped utun
/// defaults are neither default routes nor uplinks.
#[test]
fn this_macs_uplinks_are_its_unscoped_defaults() {
    let f = HostFacts::gather().unwrap();
    let t = f.routes();
    assert!(!t.uplinks().is_empty(), "{:?}", t.routes());
    for r in t.routes().iter().filter(|r| r.is_default_like()) {
        assert_eq!(r.table, crate::routes::RT_TABLE_MAIN, "{r:?}");
    }
    // On the raw dump, before the table drops anything (review round 1, cross-2): the scoped
    // defaults are there, in their interface's scoped table, and neither a route of the table nor
    // an uplink.
    let (raw, _) = crate::routes::read_routing(&[]).unwrap();
    let scoped: Vec<&Route> = raw
        .iter()
        .filter(|r| r.prefix.len == 0 && r.table != crate::routes::RT_TABLE_MAIN)
        .collect();
    for r in &scoped {
        assert!(r.table >= crate::routes::sys::SCOPED_TABLE, "{r:?}");
        assert_eq!(
            r.table,
            crate::routes::sys::SCOPED_TABLE + r.ifindex,
            "{r:?}"
        );
        assert!(
            !t.routes()
                .iter()
                .any(|x| x.prefix == r.prefix && x.ifindex == r.ifindex && x.table == r.table),
            "{r:?}"
        );
        if let Hop::Via(gw) = r.hop {
            assert!(!t.uplinks().contains(&(gw, r.ifindex)), "{r:?}");
        }
        assert!(!t.default_interfaces().contains(&r.ifindex), "{r:?}");
    }
    let links = crate::routes::read_links().unwrap();
    let utun_scoped = scoped
        .iter()
        .filter(|r| {
            links
                .iter()
                .any(|l| l.index == r.ifindex && l.name.starts_with("utun"))
        })
        .count();
    if utun_scoped == 0 {
        crate::skipped("the scoped utun defaults: this Mac has none");
    }
    eprintln!(
        "{} scoped defaults in the dump ({utun_scoped} on utun), none a default route",
        scoped.len()
    );
    let links = crate::routes::read_links().unwrap();
    for (_, i) in t.uplinks() {
        let l = links.iter().find(|l| l.index == *i).unwrap();
        eprintln!("uplink {l:?}");
    }
    assert_eq!(f.needs_internal_ranges(), Vec::<String>::new());
}

/// A macOS VPN that takes over the default route (`0/1` and `128.0/1`, or `default`, on a utun)
/// makes the host need `[egress] internal_ranges`, as a Linux tunnel uplink does; so does a `ppp`
/// uplink (macOS has no PPPoE session list). A VPN that only adds a scoped default (`UGScI`)
/// does not: it carries no unbound connection.
#[test]
fn a_utun_or_ppp_uplink_needs_internal_ranges() {
    let link = |index, name: &str, ift| Link {
        index,
        name: name.into(),
        kind: crate::routes::sys::link_kind(ift, name),
    };
    let links = vec![
        link(1, "lo0", 0x18),
        link(8, "en0", 0x6),
        link(30, "utun4", 0x1),
        link(31, "ppp0", 0x17),
    ];
    let raw = |routes: Vec<Route>| RawFacts {
        interface_prefixes: vec![pfx("192.168.1.0/24")],
        interface_addresses: vec![ip("192.168.1.213")],
        routes,
        rules: vec![
            crate::Rule::lookup(false, crate::routes::RT_TABLE_MAIN),
            crate::Rule::lookup(true, crate::routes::RT_TABLE_MAIN),
        ],
        links: links.clone(),
        ..RawFacts::default()
    };
    let lan_default = Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 8);
    let opts = FactsOptions::default();
    let plain = HostFacts::assemble(raw(vec![lan_default]), &opts);
    assert!(plain.needs_internal_ranges().is_empty());
    let split = HostFacts::assemble(
        raw(vec![
            lan_default,
            Route::on_link(pfx("0.0.0.0/1"), 30),
            Route::on_link(pfx("128.0.0.0/1"), 30),
        ]),
        &opts,
    );
    let why = split.needs_internal_ranges().join("; ");
    assert!(why.contains("utun4, a tun tunnel"), "{why}");
    let ppp = HostFacts::assemble(raw(vec![Route::on_link(pfx("0.0.0.0/0"), 31)]), &opts);
    assert!(ppp.needs_internal_ranges().join("; ").contains("ppp0"));
    let scoped = HostFacts::assemble(
        raw(vec![
            lan_default,
            Route {
                hop: Hop::Via(ip("10.8.0.1")),
                ..Route::on_link(pfx("0.0.0.0/0"), 30)
            }
            .in_table(crate::routes::sys::SCOPED_TABLE + 30),
        ]),
        &opts,
    );
    assert!(scoped.needs_internal_ranges().is_empty());
    assert_eq!(scoped.routes().uplinks(), &[(ip("192.168.1.1"), 8)]);
    // And the address checks still refuse what the facts name.
    assert!(matches!(
        admit(NetMode::Public, ip("192.168.1.213"), &scoped, &[]),
        Err(Denied::NotGlobal(_))
    ));
}
