//! Review r2 R2-NG-4 (PoC `embedded_ipv4_matrix`), inverted: behind NAT64 with a network-specific
//! prefix (RFC 6052), an address under that prefix carrying a private, metadata or own IPv4
//! address is refused, by the address predicate, by `admit` and by the broker's flattened view.
//!
//! The NAT64 prefix registry is process-wide, so this file is its own test process and holds a
//! single test.

use std::net::IpAddr;

use zkminer_netguard::nat64::{self, set_configured};
use zkminer_netguard::{
    admit, admit_prefix, canonical_ip, is_global, prefix_is_global, FactsOptions, HostFacts,
    NetMode, Prefix, RawFacts, Route,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

/// `v4` under `nsp` as RFC 6052 lays it out (u octet zero).
fn embed(nsp: &str, v4: [u8; 4]) -> IpAddr {
    let n = p(nsp);
    let IpAddr::V6(base) = n.addr else { panic!() };
    let mut b = base.octets();
    let mut bit = 0usize;
    let mut pos = n.len as usize;
    while bit < 32 {
        if n.len < 96 && (64..72).contains(&pos) {
            pos = 72;
        }
        let v = (v4[bit / 8] >> (7 - bit % 8)) & 1;
        b[pos / 8] |= v << (7 - pos % 8);
        bit += 1;
        pos += 1;
    }
    IpAddr::V6(b.into())
}

#[test]
fn private_and_own_ipv4_under_a_network_specific_nat64_prefix_are_refused() {
    let nsp96 = "2001:67c:2b0:db32::/96";
    let nsp64 = "2a00:1098:2c:1::/64";
    let nsp40 = "2a01:4f9:100::/40";
    // Before: nothing known, the PoC's addresses look global.
    assert!(is_global(ip("2001:67c:2b0:db32::a00:1")));
    set_configured(&[p(nsp96), p(nsp64), p(nsp40)]).unwrap();
    assert_eq!(nat64::prefixes().len(), 3);
    assert!(set_configured(&[p("2001:db8::/33")]).is_err());
    assert_eq!(nat64::configured().len(), 3, "a bad list changes nothing");

    let own_pub = [168, 93, 61, 57];
    let facts = HostFacts::assemble(
        RawFacts {
            interface_prefixes: vec![
                p("127.0.0.0/8"),
                p("192.168.1.0/24"),
                p("2606:a300:9024:184::/64"),
            ],
            interface_addresses: vec![
                ip("127.0.0.1"),
                ip("192.168.1.33"),
                ip("2606:a300:9024:184::33"),
            ],
            routes: vec![
                Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
                Route::on_link(p("192.168.1.0/24"), 2),
                Route::via(p("::/0"), ip("fe80::1"), 2),
                // A public range behind a VPN, as IPv4.
                Route::on_link(p("10.8.0.0/24"), 7),
                Route::via(p("45.60.1.0/24"), ip("10.8.0.1"), 7),
            ],
            resolvers: vec![ip("127.0.0.53"), ip("9.9.9.9")],
            public_addresses: vec![IpAddr::from(own_pub)],
            ..RawFacts::default()
        },
        &FactsOptions {
            discover_public_addresses: false,
            ..FactsOptions::default()
        },
    );
    let refused: [(&str, [u8; 4]); 8] = [
        ("RFC 1918", [10, 0, 0, 1]),
        ("loopback", [127, 0, 0, 1]),
        ("metadata", [169, 254, 169, 254]),
        ("CGNAT", [100, 64, 0, 1]),
        ("LAN", [192, 168, 1, 1]),
        ("own NAT address", own_pub),
        ("DNS server", [9, 9, 9, 9]),
        ("VPN-routed", [45, 60, 1, 20]),
    ];
    for nsp in [nsp96, nsp64, nsp40] {
        for (what, v4) in refused {
            let a = embed(nsp, v4);
            let r = admit(NetMode::Public, a, &facts, &[]);
            assert!(r.is_err(), "{what} under {nsp}: {a} admitted");
            assert_eq!(canonical_ip(a), IpAddr::from(v4), "{a}");
        }
        // A public IPv4 address under it is still reachable.
        let control = embed(nsp, [8, 8, 8, 8]);
        assert_eq!(
            admit(NetMode::Public, control, &facts, &[]),
            Ok(()),
            "{control}"
        );
        // The operator's deny CIDR written as IPv4 holds the NAT64 spelling.
        assert!(admit(NetMode::Public, control, &facts, &[p("8.8.8.0/24")]).is_err());
        // Whole prefixes.
        assert!(!prefix_is_global(p(nsp)), "{nsp}");
    }
    // The PoC's /64 spellings put the IPv4 address's first octet in the u octet: refused.
    for a in ["2a00:1098:2c:1:a00:0:100:0", "2a00:1098:2c:1:808:800:800:0"] {
        assert!(!is_global(ip(a)), "{a}");
    }
    // Role entries: an embedded public /24 is fine, an embedded private one is not.
    assert!(prefix_is_global(p("2001:67c:2b0:db32::808:800/120")));
    assert!(!prefix_is_global(p("2001:67c:2b0:db32::a00:0/104")));
    assert!(prefix_is_global(p("2a00:1098:2c:1:8:808::/96")));
    assert!(
        !prefix_is_global(p("2a00:1098:2c:1::/70")),
        "u octet not fixed"
    );
    assert!(admit_prefix(
        NetMode::Public,
        p("2001:67c:2b0:db32::808:800/120"),
        &facts,
        &[]
    )
    .is_ok());
    assert!(admit_prefix(
        NetMode::Public,
        p("2001:67c:2b0:db32::2d3c:100/120"),
        &facts,
        &[]
    )
    .is_err());

    // prefix_is_global agrees with is_global under the prefixes (sampled): a prefix judged global
    // holds no refused address; one judged not global has one, found by descending into it.
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let set = |a: u128, bit: u8| a | (1u128 << (127 - u32::from(bit)));
    for _ in 0..20_000 {
        let nsp = p([nsp96, nsp64, nsp40][(next() % 3) as usize]);
        let IpAddr::V6(base) = nsp.addr else { panic!() };
        let len = nsp.len + (next() % u64::from(129 - nsp.len)) as u8;
        // Bias the u octet to zero half the time, and the embedded address to public space.
        let mut x = u128::from(base)
            | ((u128::from(next()) << 64 | u128::from(next())) & (u128::MAX >> nsp.len));
        if next() % 2 == 0 {
            x &= !(0xffu128 << 56);
        }
        let pre = Prefix::new(IpAddr::V6(x.into()), len);
        let IpAddr::V6(pa) = pre.addr else { panic!() };
        let inside = |r: u128| {
            let host = if pre.len == 128 {
                0
            } else {
                r & (u128::MAX >> pre.len)
            };
            IpAddr::V6((u128::from(pa) | host).into())
        };
        if prefix_is_global(pre) {
            for r in [0, u128::MAX, u128::from(next()) << 64 | u128::from(next())] {
                assert!(
                    is_global(inside(r)),
                    "{pre} judged global, {} is not",
                    inside(r)
                );
            }
        } else {
            let mut q = pre;
            while q.len < 128 {
                let IpAddr::V6(qa) = q.addr else { panic!() };
                let lower = Prefix::new(q.addr, q.len + 1);
                let upper = Prefix::new(IpAddr::V6(set(u128::from(qa), q.len).into()), q.len + 1);
                q = if !prefix_is_global(lower) {
                    lower
                } else {
                    upper
                };
            }
            assert!(
                !is_global(q.addr),
                "{pre} judged not global, descended to global {}",
                q.addr
            );
        }
    }

    // The broker's view: it may not know the prefixes; the flattened list says it all.
    let flat = facts.refused_prefixes();
    assert!(
        flat.contains(&p("2001:67c:2b0:db32::a00:0/104")),
        "{flat:?}"
    );
    assert!(
        flat.contains(&p("2a00:1098:2c:1:8000::/65")),
        "u octet != 0"
    );
    assert!(
        flat.contains(&p(nsp40)),
        "a NAT64 prefix shorter than /64 is refused whole"
    );
    let broker = HostFacts::new(flat, facts.own_addresses().to_vec());
    set_configured(&[]).unwrap();
    assert!(nat64::prefixes().is_empty() || nat64::learned() == nat64::prefixes());
    for nsp in [nsp96, nsp64] {
        for (what, v4) in refused {
            let a = embed(nsp, v4);
            if nat64::prefixes().is_empty() {
                assert!(is_global(a), "{a}: the registry is empty here");
            }
            assert!(
                admit(NetMode::Public, a, &broker, &[]).is_err(),
                "broker view: {what} under {nsp}: {a} admitted"
            );
        }
        assert_eq!(
            admit(NetMode::Public, embed(nsp, [8, 8, 8, 8]), &broker, &[]),
            Ok(())
        );
    }

    // ISATAP (`::5efe:a.b.c.d`, the PoC's other rows) is not a translation this host does: the
    // address is routed to its /64's own network like any other (and a host with an ISATAP
    // tunnel has that /64 as a route on the tunnel, refused as off the default path).
    assert!(is_global(ip("2606:4700:1::5efe:a00:1")));
}
