//! Destinations that pass every address check and are still the operator's own network: the NAT
//! router when the host's public address is unknown, a NAT64 translator's own address, a campus
//! or VPC numbered from public space, a site delegated more than a /56, the home router's own
//! global address, a source rule's table. Each is refused now, and says why.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::{
    admit, is_global, Denied, EgressPath, FactsOptions, FixedProbe, HostFacts, KernelAnswer,
    NetMode, NetPolicy, Prefix, ProbeOutcome, RawFacts, Route, RouteKind, RouteOracle,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

/// The Direct Delegation AS112 service's IPv6 block is refused like its IPv4 twin.
#[test]
fn the_ipv6_as112_direct_delegation_block_is_refused() {
    let f = HostFacts::empty();
    for a in ["2620:4f:8000::1", "2620:4f:8000::42", "192.175.48.1"] {
        assert!(!is_global(ip(a)), "{a}");
        assert_eq!(
            admit(NetMode::Public, ip(a), &f, &[]),
            Err(Denied::NotGlobal(ip(a)))
        );
    }
}

/// A home host behind NAT. When public-address discovery fails (outbound DNS to the reflectors
/// filtered or intercepted, HTTPS blocked) the NAT address is unknown, and a URL at it would reach
/// the router: every IPv4 destination is refused until the address is known, and saying what to
/// set. Known (learned, or stated in `[egress] public_addresses`), it is refused as the host's own.
#[test]
fn an_unknown_public_address_refuses_its_family() {
    let nat_public = ip("81.2.69.160");
    let raw = |confirmed: Vec<IpAddr>| RawFacts {
        interface_prefixes: vec![pfx("127.0.0.0/8"), pfx("192.168.1.0/24")],
        interface_addresses: vec![ip("127.0.0.1"), ip("192.168.1.33")],
        routes: vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("192.168.1.0/24"), 2),
        ],
        resolvers: vec![ip("127.0.0.53")],
        public_addresses: confirmed.clone(),
        public_confirmed: confirmed,
        ..RawFacts::default()
    };
    let ok = HostFacts::assemble(raw(vec![nat_public]), &FactsOptions::default());
    assert_eq!(
        admit(NetMode::Public, nat_public, &ok, &[]),
        Err(Denied::OwnAddress(nat_public))
    );
    assert_eq!(admit(NetMode::Public, ip("8.8.8.8"), &ok, &[]), Ok(()));
    assert!(ok.unknown_paths().is_empty());

    let failed = HostFacts::assemble(raw(vec![]), &FactsOptions::default());
    assert_eq!(failed.unknown_paths(), vec![EgressPath::Ipv4]);
    for a in [nat_public, ip("8.8.8.8"), ip("::ffff:81.2.69.160")] {
        let e = admit(NetMode::Public, a, &failed, &[]).unwrap_err();
        assert_eq!(
            e,
            Denied::PublicAddressUnknown {
                ip: a,
                path: EgressPath::Ipv4
            }
        );
        assert!(e.to_string().contains("public_addresses"), "{e}");
        assert!(
            e.depends_on_facts(),
            "re-read: discovery may have succeeded since"
        );
    }
    // One DNS reflector's answer (an intercepting resolver's, say) is refused, but is not
    // confirmed: the family stays unknown.
    let lone = HostFacts::assemble(
        RawFacts {
            public_addresses: vec![ip("203.0.114.53")],
            public_confirmed: vec![],
            ..raw(vec![])
        },
        &FactsOptions::default(),
    );
    assert!(admit(NetMode::Public, ip("8.8.8.8"), &lone, &[]).is_err());
    assert!(admit(NetMode::Public, ip("203.0.114.53"), &lone, &[]).is_err());
    // Stated by the operator: known, and refused as the host's own.
    let stated = HostFacts::assemble(
        raw(vec![]),
        &FactsOptions {
            public_addresses: vec![nat_public],
            ..FactsOptions::default()
        },
    );
    assert!(stated.unknown_paths().is_empty());
    assert_eq!(
        admit(NetMode::Public, nat_public, &stated, &[]),
        Err(Denied::OwnAddress(nat_public))
    );
    assert_eq!(admit(NetMode::Public, ip("8.8.8.8"), &stated, &[]), Ok(()));
    // Developer mode is untouched.
    assert_eq!(admit(NetMode::DevPrivate, nat_public, &failed, &[]), Ok(()));
}

/// Discovery turned off without the address it would have learned is a configuration error on a
/// host that routes the family (this one routes IPv4).
#[test]
fn discovery_off_without_public_addresses_refuses_to_start() {
    let facts = HostFacts::gather_with(&FactsOptions {
        discover_public_addresses: false,
        ..FactsOptions::default()
    })
    .expect("read the host");
    let off = FactsOptions {
        discover_public_addresses: false,
        internal_ranges: Some(Vec::new()),
        ..FactsOptions::default()
    };
    let r = NetPolicy::with_options(NetMode::Public, Vec::new(), off.clone());
    if facts.routes().routes_family(false) || facts.routes().routes_family(true) {
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("discover_public_addresses = false") && e.contains("public_addresses = ["),
            "{e}"
        );
    }
    // Developer mode does not care.
    assert!(NetPolicy::with_options(NetMode::DevPrivate, Vec::new(), off).is_ok());
}

/// An IPv6-only host behind NAT64. Its IPv4 reflectors are unreachable natively; until the
/// translator's own IPv4 address (its pool address) is learned through the prefix (or stated),
/// every address under the prefix is refused, the pool address included. Learned, the pool address
/// is the host's own.
#[test]
fn a_nat64_translators_own_address_is_refused() {
    let raw = |pool: Vec<IpAddr>, via: Vec<Prefix>| RawFacts {
        interface_prefixes: vec![pfx("::1/128"), pfx("2a02:8070:1234:5600::/64")],
        interface_addresses: vec![ip("::1"), ip("2a02:8070:1234:5600::10")],
        routes: vec![
            Route::via(pfx("::/0"), ip("fe80::1"), 2),
            Route::on_link(pfx("2a02:8070:1234:5600::/64"), 2),
        ],
        resolvers: vec![ip("2a02:8070:1234:5600::1")],
        public_addresses: [vec![ip("2a02:8070:1234:5600::10")], pool.clone()].concat(),
        public_confirmed: [vec![ip("2a02:8070:1234:5600::10")], pool].concat(),
        public_via_nat64: via,
        ..RawFacts::default()
    };
    let to_pool = ip("64:ff9b::5102:45a0"); // 81.2.69.160 under the well-known prefix
    let unknown = HostFacts::assemble(raw(vec![], vec![]), &FactsOptions::default());
    assert_eq!(unknown.unknown_paths(), vec![EgressPath::Nat64]);
    for a in [to_pool, ip("64:ff9b::808:808")] {
        assert_eq!(
            admit(NetMode::Public, a, &unknown, &[]),
            Err(Denied::PublicAddressUnknown {
                ip: a,
                path: EgressPath::Nat64
            })
        );
    }
    // Native IPv6 is unaffected.
    assert_eq!(
        admit(NetMode::Public, ip("2606:4700:4700::1111"), &unknown, &[]),
        Ok(())
    );
    let learned = HostFacts::assemble(
        raw(vec![ip("81.2.69.160")], vec![pfx("64:ff9b::/96")]),
        &FactsOptions::default(),
    );
    assert!(learned.unknown_paths().is_empty());
    assert_eq!(
        admit(NetMode::Public, to_pool, &learned, &[]),
        Err(Denied::OwnAddress(to_pool))
    );
    assert_eq!(
        admit(NetMode::Public, ip("64:ff9b::808:808"), &learned, &[]),
        Ok(())
    );
}

/// A campus numbered from global IPv4 space: the host is 128.112.5.10/24 and the other subnets
/// are reached through the default gateway. The enclosing /16 is refused, and so is the site
/// around its IPv6 address at the default /48 (or wider, configured). The host may not start
/// without `[egress] internal_ranges`; what it lists is refused.
#[test]
fn a_campus_numbered_from_public_space_is_refused() {
    let raw = RawFacts {
        interface_prefixes: vec![pfx("128.112.5.0/24"), pfx("2620:c4:0:5::/64")],
        interface_addresses: vec![ip("128.112.5.10"), ip("2620:c4:0:5::10")],
        routes: vec![
            Route::via(pfx("0.0.0.0/0"), ip("128.112.5.1"), 2),
            Route::on_link(pfx("128.112.5.0/24"), 2),
            Route::via(pfx("::/0"), ip("fe80::1"), 2),
            Route::on_link(pfx("2620:c4:0:5::/64"), 2),
        ],
        resolvers: vec![ip("128.112.129.209")],
        public_addresses: vec![ip("128.112.5.10"), ip("2620:c4:0:5::10")],
        public_confirmed: vec![ip("128.112.5.10"), ip("2620:c4:0:5::10")],
        ..RawFacts::default()
    };
    // The operator has stated its ranges (none beyond the sites): the sites decide.
    let stated = FactsOptions {
        internal_ranges: Some(Vec::new()),
        ..FactsOptions::default()
    };
    let f = HostFacts::assemble(raw.clone(), &stated);
    assert_eq!(
        admit(NetMode::Public, ip("128.112.200.5"), &f, &[]),
        Err(Denied::SitePrefix {
            ip: ip("128.112.200.5"),
            prefix: pfx("128.112.0.0/16")
        })
    );
    assert!(matches!(
        admit(NetMode::Public, ip("2620:c4:0:9::5"), &f, &[]),
        Err(Denied::SitePrefix { .. })
    ));
    // The default IPv6 site is the /32 an organisation holds: its other /48s too.
    assert!(matches!(
        admit(NetMode::Public, ip("2620:c4:1::5"), &f, &[]),
        Err(Denied::SitePrefix { .. })
    ));
    assert_eq!(admit(NetMode::Public, ip("128.113.0.1"), &f, &[]), Ok(()));
    // Without the statement, nothing goes out (see also
    // `a_condition_that_appears_after_startup_refuses_every_connection`).
    let unstated = HostFacts::assemble(raw.clone(), &FactsOptions::default());
    assert!(matches!(
        admit(NetMode::Public, ip("128.113.0.1"), &unstated, &[]),
        Err(Denied::InternalRangesUnstated { .. })
    ));
    // A larger campus: the operator widens the sites.
    let wide = HostFacts::assemble(
        raw,
        &FactsOptions {
            ipv6_site_prefix_len: 24,
            ipv4_site_prefix_len: 8,
            ..stated
        },
    );
    assert!(matches!(
        admit(NetMode::Public, ip("2620:c4:1::5"), &wide, &[]),
        Err(Denied::SitePrefix { .. })
    ));
    assert!(matches!(
        admit(NetMode::Public, ip("128.200.0.1"), &wide, &[]),
        Err(Denied::SitePrefix { .. })
    ));
    // The broker's flattened view holds the IPv4 site too.
    assert!(f.refused_prefixes().contains(&pfx("128.112.0.0/16")));
    // A global IPv4 interface address needs `[egress] internal_ranges` to start.
    let why = f.needs_internal_ranges();
    assert_eq!(why.len(), 1, "{why:?}");
    assert!(why[0].contains("128.112.5.10"), "{why:?}");
}

/// A host whose default route goes out of a tunnel (a full-tunnel VPN: WireGuard here) needs
/// `[egress] internal_ranges`; a PPPoE uplink does not; a VPN reached only by specific routes
/// does not either (its ranges are refused as off the default path).
#[test]
fn a_default_route_through_a_tunnel_needs_internal_ranges() {
    use crate::Link;
    let link = |index, name: &str, kind: Option<&str>| Link {
        index,
        name: name.into(),
        kind: kind.map(Into::into),
    };
    let links = vec![
        link(1, "lo", None),
        link(2, "eth0", None),
        link(7, "wg0", Some("wireguard")),
        link(8, "ppp0", Some("ppp")),
        link(9, "tun0", Some("tun")),
    ];
    let facts = |routes: Vec<Route>, internet: Vec<u32>| {
        HostFacts::assemble(
            RawFacts {
                interface_prefixes: vec![pfx("192.168.1.0/24"), pfx("10.8.0.0/24")],
                interface_addresses: vec![ip("192.168.1.33"), ip("10.8.0.6")],
                routes,
                links: links.clone(),
                internet_interfaces: internet,
                public_confirmed: vec![ip("81.2.69.160")],
                ..RawFacts::default()
            },
            &FactsOptions::default(),
        )
    };
    let wg = facts(
        vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("0.0.0.0/1"), 7),
            Route::on_link(pfx("128.0.0.0/1"), 7),
        ],
        vec![],
    );
    let why = wg.needs_internal_ranges();
    assert_eq!(why.len(), 1, "{why:?}");
    assert!(
        why[0].contains("wg0") && why[0].contains("wireguard"),
        "{why:?}"
    );
    // The kernel's interface for internet traffic is judged too.
    let nh = facts(
        vec![Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2)],
        vec![9],
    );
    assert!(nh.needs_internal_ranges()[0].contains("tun0"));
    // A ppp uplink is PPPoE only with a PPPoE session for it; else a VPN (L2TP, PPTP, …).
    let ppp = facts(vec![Route::on_link(pfx("0.0.0.0/0"), 8)], vec![8]);
    assert!(ppp.needs_internal_ranges()[0].contains("not a PPPoE session"));
    let pppoe = HostFacts::assemble(
        RawFacts {
            routes: vec![Route::on_link(pfx("0.0.0.0/0"), 8)],
            links: links.clone(),
            internet_interfaces: vec![8],
            pppoe_sessions: 1,
            public_confirmed: vec![ip("81.2.69.160")],
            ..RawFacts::default()
        },
        &FactsOptions::default(),
    );
    assert!(pppoe.needs_internal_ranges().is_empty());
    let split = facts(
        vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::via(pfx("45.60.1.0/24"), ip("10.8.0.1"), 9),
        ],
        vec![2],
    );
    assert!(split.needs_internal_ranges().is_empty());
}

/// The uplink is judged against what is known to be physical, so a VPN of a kind the guard has
/// no name for is caught too: OpenVPN's data-channel offload (`ovpn`, `ovpn-dco`), `bareudp`,
/// `amt`, a kind nobody listed; a `ppp` link that is not a PPPoE session (L2TP, PPTP, SSTP,
/// openfortivpn); a policy-based IPsec full tunnel (strongSwan's table 220 routes through the
/// physical uplink's own gateway); and a default route through a nexthop object, judged by the
/// object's interface, or refused when it cannot be resolved.
#[test]
fn every_uplink_that_is_not_plainly_physical_needs_the_statement() {
    use crate::routes::Nexthop;
    use crate::{Hop, Link, Rule};
    let host = |kind: Option<&str>,
                routes: Vec<Route>,
                rules: Vec<Rule>,
                internet: Vec<u32>,
                nexthops: Vec<Nexthop>,
                pppoe: usize| {
        HostFacts::assemble(
            RawFacts {
                interface_prefixes: vec![pfx("192.168.1.0/24"), pfx("10.8.0.2/32")],
                interface_addresses: vec![ip("192.168.1.33"), ip("10.8.0.2")],
                routes,
                rules,
                links: vec![
                    Link {
                        index: 1,
                        name: "lo".into(),
                        kind: None,
                    },
                    Link {
                        index: 2,
                        name: "eth0".into(),
                        kind: None,
                    },
                    Link {
                        index: 7,
                        name: "vpn0".into(),
                        kind: kind.map(Into::into),
                    },
                ],
                internet_interfaces: internet,
                nexthops,
                pppoe_sessions: pppoe,
                public_confirmed: vec![ip("81.2.69.160")],
                ..RawFacts::default()
            },
            &FactsOptions::default(),
        )
    };
    let def1 = || {
        vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("192.168.1.0/24"), 2),
            Route::via(pfx("203.0.113.7/32"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("0.0.0.0/1"), 7),
            Route::on_link(pfx("128.0.0.0/1"), 7),
        ]
    };
    let corp = ip("130.59.31.80");
    for kind in [
        "wireguard",
        "tun",
        "ovpn",
        "ovpn-dco",
        "bareudp",
        "amt",
        "ppp",
        "some-new-vpn",
    ] {
        let f = host(Some(kind), def1(), vec![], vec![7], vec![], 0);
        let why = f.needs_internal_ranges();
        assert_eq!(why.len(), 1, "{kind}: {why:?}");
        assert!(why[0].contains("vpn0"), "{kind}: {why:?}");
        assert!(
            matches!(
                admit(NetMode::Public, corp, &f, &[]),
                Err(Denied::InternalRangesUnstated { .. })
            ),
            "{kind}"
        );
    }
    // Physical kinds and PPPoE need nothing.
    for kind in [
        None,
        Some("bridge"),
        Some("bond"),
        Some("vlan"),
        Some("veth"),
    ] {
        let f = host(kind, def1(), vec![], vec![7], vec![], 0);
        assert!(f.needs_internal_ranges().is_empty(), "{kind:?}");
    }
    let pppoe = host(Some("ppp"), def1(), vec![], vec![7], vec![], 1);
    assert!(pppoe.needs_internal_ranges().is_empty());
    // strongSwan's road warrior: table 220 (`from all lookup 220`) through the uplink's gateway.
    let mut rules = vec![
        Rule::lookup(false, 255),
        Rule {
            priority: 220,
            ..Rule::lookup(false, 220)
        },
        Rule::lookup(false, 254),
        Rule::lookup(false, 253),
    ];
    rules.extend(Rule::stock(true));
    let ipsec = host(
        None,
        vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("192.168.1.0/24"), 2),
            Route::via(pfx("0.0.0.0/1"), ip("192.168.1.1"), 2).in_table(220),
            Route::via(pfx("128.0.0.0/1"), ip("192.168.1.1"), 2).in_table(220),
        ],
        rules,
        vec![2],
        vec![],
        0,
    );
    let why = ipsec.needs_internal_ranges();
    assert!(why.iter().any(|w| w.contains("table 220")), "{why:?}");
    // A default route through a nexthop object into the tunnel, with the fixed probes routed
    // elsewhere: judged by the object's interface; an unresolvable object refuses.
    let mut nh_default = Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 0);
    nh_default.hop = Hop::Unknown;
    nh_default.nexthop = 10;
    let routes = vec![
        nh_default,
        Route::on_link(pfx("192.168.1.0/24"), 2),
        Route::via(pfx("1.1.1.1/32"), ip("192.168.1.1"), 2),
    ];
    let into_wg = host(
        Some("wireguard"),
        routes.clone(),
        vec![],
        vec![2],
        vec![Nexthop {
            id: 10,
            oif: 7,
            group: vec![],
            blackhole: false,
        }],
        0,
    );
    assert!(into_wg.needs_internal_ranges()[0].contains("vpn0"));
    let unknown = host(Some("wireguard"), routes, vec![], vec![2], vec![], 0);
    assert!(unknown.needs_internal_ranges()[0].contains("nexthop object 10"));
}

/// The conditions that need `[egress] internal_ranges` are judged on every facts snapshot, not
/// only at startup: a full-tunnel VPN that comes up after the miner started (wg-quick here: table
/// 51820 reached by `not fwmark`) refuses every connection until the operator states the ranges,
/// and it says so once per change; when the tunnel goes down, connections are admitted again.
#[test]
fn a_condition_that_appears_after_startup_refuses_every_connection() {
    use crate::{Link, Rule, RuleAction, RuleMatch};
    let raw = |vpn_up: bool| {
        let mut routes = vec![
            Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(pfx("192.168.1.0/24"), 2),
        ];
        let mut rules = vec![
            Rule::lookup(false, 255),
            Rule::lookup(false, 254),
            Rule::lookup(false, 253),
        ];
        let mut links = vec![Link {
            index: 2,
            name: "eth0".into(),
            kind: None,
        }];
        let mut internet = vec![2];
        if vpn_up {
            routes.push(Route::on_link(pfx("0.0.0.0/0"), 9).in_table(51820));
            rules.insert(
                1,
                Rule {
                    priority: 32764,
                    action: RuleAction::Lookup(51820),
                    to: None,
                    invert: true,
                    matches: RuleMatch::Never,
                    v6: false,
                },
            );
            links.push(Link {
                index: 9,
                name: "wg0".into(),
                kind: Some("wireguard".into()),
            });
            internet = vec![9];
        }
        rules.extend(Rule::stock(true));
        RawFacts {
            interface_prefixes: vec![pfx("192.168.1.0/24")],
            interface_addresses: vec![ip("192.168.1.33")],
            routes,
            rules,
            links,
            internet_interfaces: internet,
            public_addresses: vec![ip("81.2.69.160")],
            public_confirmed: vec![ip("81.2.69.160")],
            ..RawFacts::default()
        }
    };
    let corp: SocketAddr = "130.59.31.80:443".parse().unwrap();
    let before = HostFacts::assemble(raw(false), &FactsOptions::default());
    assert!(before.config_gaps().is_empty());
    assert_eq!(admit(NetMode::Public, corp.ip(), &before, &[]), Ok(()));
    let after = HostFacts::assemble(raw(true), &FactsOptions::default());
    let gaps = after.config_gaps();
    assert!(gaps.iter().any(|g| g.contains("wg0")), "{gaps:?}");
    let e = admit(NetMode::Public, corp.ip(), &after, &[]).unwrap_err();
    assert!(matches!(e, Denied::InternalRangesUnstated { .. }), "{e:?}");
    assert!(e.depends_on_facts(), "re-read: the tunnel may be gone");
    assert!(e.to_string().contains("internal_ranges = ["), "{e}");
    let p =
        NetPolicy::with_facts(NetMode::Public, after, vec![]).with_near_probe(FixedProbe::far());
    assert!(matches!(
        p.vet_connection(corp),
        Err(Denied::InternalRangesUnstated { .. })
    ));
    // Stated, the facts need nothing more.
    let stated = HostFacts::assemble(
        raw(true),
        &FactsOptions {
            internal_ranges: Some(vec![pfx("130.59.0.0/16")]),
            ..FactsOptions::default()
        },
    );
    assert!(stated.config_gaps().is_empty());
    assert_eq!(admit(NetMode::Public, ip("8.8.8.8"), &stated, &[]), Ok(()));
}

/// An organisation with private IPv4 (NAT) and a /32 of global IPv6: the default site is that
/// /32, so its other /48s are refused; a host that does not want that sets a longer site.
#[test]
fn an_ipv6_organisation_wider_than_a_48_is_refused_by_default() {
    let r = RawFacts {
        interface_prefixes: vec![pfx("10.20.5.0/24"), pfx("2001:620:0:5::/64")],
        interface_addresses: vec![ip("10.20.5.10"), ip("2001:620:0:5::10")],
        routes: vec![
            Route::via(pfx("0.0.0.0/0"), ip("10.20.5.1"), 2),
            Route::on_link(pfx("10.20.5.0/24"), 2),
            Route::via(pfx("::/0"), ip("fe80::1"), 2),
            Route::on_link(pfx("2001:620:0:5::/64"), 2),
        ],
        public_addresses: vec![ip("130.59.1.1"), ip("2001:620:0:5::10")],
        public_confirmed: vec![ip("130.59.1.1"), ip("2001:620:0:5::10")],
        ..RawFacts::default()
    };
    let f = HostFacts::assemble(r.clone(), &FactsOptions::default());
    assert_eq!(f.site_prefixes(), &[pfx("2001:620::/32")]);
    for a in ["2001:620:0:9::5", "2001:620:8:1::5", "2001:620:ff::5"] {
        assert!(
            matches!(
                admit(NetMode::Public, ip(a), &f, &[]),
                Err(Denied::SitePrefix { .. })
            ),
            "{a}"
        );
    }
    assert_eq!(admit(NetMode::Public, ip("2001:621::5"), &f, &[]), Ok(()));
    let narrow = HostFacts::assemble(
        r,
        &FactsOptions {
            ipv6_site_prefix_len: 48,
            ..FactsOptions::default()
        },
    );
    assert_eq!(
        admit(NetMode::Public, ip("2001:620:8:1::5"), &narrow, &[]),
        Ok(())
    );
}

/// On this host: a public-mode start needs `[egress] internal_ranges` exactly when the host has a
/// global IPv4 interface address or a tunnel uplink, and the listed ranges are refused like deny
/// CIDRs.
#[test]
fn internal_ranges_are_needed_where_the_host_says_so_and_refused() {
    let facts = HostFacts::gather().expect("read the host");
    let unset = NetPolicy::with_options(NetMode::Public, Vec::new(), FactsOptions::default());
    if facts.needs_internal_ranges().is_empty() {
        assert!(unset.is_ok(), "{:?}", unset.err());
    } else {
        let e = unset.unwrap_err().to_string();
        assert!(e.contains("internal_ranges = ["), "{e}");
    }
    let listed = NetPolicy::with_options(
        NetMode::Public,
        Vec::new(),
        FactsOptions {
            internal_ranges: Some(vec![pfx("8.8.4.0/24")]),
            ..FactsOptions::default()
        },
    )
    .expect("starts with internal_ranges listed");
    assert!(matches!(
        listed.admit(ip("8.8.4.4")),
        Err(Denied::DenyCidr { .. })
    ));
}

/// The home router's own global IPv6 address (its WAN side, outside the delegated prefix) is a
/// global stranger to every address check, and reached through the default route. The near-hop
/// probe refuses it: it answers within 2 hops. A far destination is connected to.
#[test]
fn a_destination_within_two_hops_is_refused_before_connecting() {
    let facts = HostFacts::new(vec![pfx("2a02:8070:1234:5600::/64")], vec![]);
    let cpe_wan: SocketAddr = "[2a02:8070:0:3a::2]:80".parse().unwrap();
    assert_eq!(admit(NetMode::Public, cpe_wan.ip(), &facts, &[]), Ok(()));
    for outcome in [
        ProbeOutcome::Connected,
        ProbeOutcome::Refused,
        ProbeOutcome::Reset,
        ProbeOutcome::Failed("Operation not permitted".into()),
    ] {
        let probe = FixedProbe::answering(outcome.clone());
        let p = NetPolicy::with_facts(NetMode::Public, facts.clone(), Vec::new())
            .with_near_probe(probe.clone());
        let e = p.vet_connection(cpe_wan).unwrap_err();
        assert!(
            matches!(e, Denied::NearHop { hops: 2, .. }),
            "{outcome:?}: {e:?}"
        );
        assert!(e.to_string().contains("within 2 hops"), "{e}");
        // The exact address and port were probed, at the hop limit.
        assert_eq!(*probe.asked.lock().unwrap(), vec![(cpe_wan, 2)]);
    }
    for far in [ProbeOutcome::Unreachable, ProbeOutcome::TimedOut] {
        let p = NetPolicy::with_facts(NetMode::Public, facts.clone(), Vec::new())
            .with_near_probe(FixedProbe::answering(far));
        assert_eq!(p.vet_connection(cpe_wan), Ok(()));
    }
    // An IPv4-mapped destination is probed as the IPv4 address a socket connects to.
    let probe = FixedProbe::far();
    let p = NetPolicy::with_facts(NetMode::Public, HostFacts::empty(), Vec::new())
        .with_near_probe(probe.clone());
    assert_eq!(
        p.vet_connection("[::ffff:8.8.8.8]:443".parse().unwrap()),
        Ok(())
    );
    assert_eq!(
        probe.asked.lock().unwrap()[0].0,
        "8.8.8.8:443".parse::<SocketAddr>().unwrap()
    );
    // Developer mode sends no probe.
    let probe = FixedProbe::answering(ProbeOutcome::Connected);
    let dev = NetPolicy::with_facts(NetMode::DevPrivate, HostFacts::empty(), Vec::new())
        .with_near_probe(probe.clone());
    assert_eq!(dev.vet_connection(cpe_wan), Ok(()));
    assert!(probe.asked.lock().unwrap().is_empty());
}

/// Kernel answers, staged per destination and port.
#[derive(Debug)]
struct Staged(Vec<((IpAddr, Option<u16>), KernelAnswer)>);

impl RouteOracle for Staged {
    fn route_to(&self, dst: IpAddr, dport: Option<u16>) -> io::Result<KernelAnswer> {
        self.0
            .iter()
            .find(|(k, _)| *k == (dst, dport))
            .map(|(_, a)| a.clone())
            .ok_or_else(|| io::Error::other("no staged answer"))
    }
}

/// A rule that selects by source (`from <the uplink's address> lookup 100`, table 100 holding a
/// default through a VPN) or by port (`dport 443 lookup 100`): the kernel, asked as the
/// connection is made — with the port, and (IPv4) again with the source it chose — answers with
/// table 100's default, or with lookups that land in different tables. Both are refused.
#[test]
fn source_and_port_rules_the_connection_follows_are_refused() {
    let main_default = Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2);
    let vpn_default = Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100);
    let mut rules = crate::Rule::stock(false);
    rules.insert(
        1,
        crate::Rule {
            v6: false,
            priority: 100,
            action: crate::RuleAction::Lookup(100),
            to: None,
            invert: false,
            matches: crate::RuleMatch::Sometimes,
        },
    );
    let staged = Staged(vec![
        // The prefix model and a portless query see the main default.
        (
            (ip("9.1.2.3"), None),
            KernelAnswer::Entry(vec![main_default]),
        ),
        // `dport 443 lookup 100`: with the port, table 100.
        (
            (ip("9.1.2.3"), Some(443)),
            KernelAnswer::Entry(vec![vpn_default]),
        ),
        // `from 192.168.1.33 lookup 100`: the first lookup in main, the second in table 100.
        (
            (ip("9.1.2.4"), Some(80)),
            KernelAnswer::Split {
                first_table: 254,
                entry: vec![vpn_default],
            },
        ),
        (
            (ip("9.1.2.5"), Some(443)),
            KernelAnswer::Entry(vec![main_default]),
        ),
    ]);
    let facts = HostFacts::assemble(
        RawFacts {
            interface_prefixes: vec![pfx("192.168.1.0/24"), pfx("10.8.0.0/24")],
            interface_addresses: vec![ip("192.168.1.33"), ip("10.8.0.6")],
            routes: vec![
                main_default,
                Route::on_link(pfx("192.168.1.0/24"), 2),
                Route::on_link(pfx("10.8.0.0/24"), 7),
                vpn_default,
            ],
            rules,
            public_confirmed: vec![ip("81.2.69.160")],
            ..RawFacts::default()
        },
        &FactsOptions::default(),
    )
    .with_route_oracle(Arc::new(staged));
    // Judged without a port, as a resolver must: admitted.
    assert_eq!(admit(NetMode::Public, ip("9.1.2.3"), &facts, &[]), Ok(()));
    let to = |s: &str| crate::admit_to(NetMode::Public, s.parse().unwrap(), &facts, &[]);
    assert!(matches!(
        to("9.1.2.3:443"),
        Err(Denied::OffDefaultRoute {
            kind: RouteKind::PolicyRule,
            ..
        })
    ));
    let e = to("9.1.2.4:80").unwrap_err();
    assert!(
        matches!(
            e,
            Denied::OffDefaultRoute {
                kind: RouteKind::PolicyRule,
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(to("9.1.2.5:443"), Ok(()));
}

/// URL and host spellings that must all be refused in public mode (they are).
#[test]
fn tricky_urls_are_refused() {
    let p = NetPolicy::with_facts(NetMode::Public, HostFacts::empty(), Vec::new());
    let refused = [
        "http://127.1/",
        "http://0x7f.1/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://127.0.0.1./",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::127.0.0.1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[64:ff9b:1::a00:1]/",
        "http://[::ffff:0:a9fe:a9fe]/",
        "http://[2002:7f00:1::]/",
        "http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/",
        "http://[fe80::1%25eth0]/",
        "http://[fe80::1]/",
        "http://[fd00:ec2::254]/",
        "http://example.com@127.0.0.1/",
        "http://127.0.0.1#@example.com/",
        "http://127.0.0.1\\@example.com/",
        "http://localhost/",
        "http://LOCALHOST./",
        "http://foo.localhost/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/",
        "http://%31%32%37.0.0.1/",
        "http://127.0.0.1:80:80/",
        "http:///127.0.0.1/",
        "http:\\\\127.0.0.1/",
        "http://\t127.0.0.1/",
        "http://example.com\n.127.0.0.1/",
        "http://１２７.0.0.1/",
        "http://xn--localhost-.com/",
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
        "http://[::]/",
        "http://0.0.0.0/",
        "http://0/",
        "http://192.0.0.170/",
        "http://100.100.100.200/",
        "http://wpad/",
        "http://a.svc/",
        "http://x.home.arpa/",
        "http://router.lan/",
        "http://[2620:4f:8000::1]/",
    ];
    let admitted: Vec<&str> = refused
        .iter()
        .copied()
        .filter(|u| p.check_url(u).is_ok())
        .collect();
    assert!(admitted.is_empty(), "{admitted:?}");
}
