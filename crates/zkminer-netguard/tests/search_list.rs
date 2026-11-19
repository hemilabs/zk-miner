//! Review r1 fetch F2 (PoC `search`), inverted: the system lookup never applies the resolver's
//! search list or `ndots` to a requester's name.
//!
//! glibc reads `LOCALDOMAIN` exactly like a `search` line in `/etc/resolv.conf`, and `RES_OPTIONS`
//! like its `options` line, so the test stages an operator search domain without touching the
//! host's files. The search domain is a public wildcard zone (`sslip.io`: `<anything>.1.1.1.1.sslip.io`
//! answers 1.1.1.1), standing in for an operator's private zone. Before the fix, `secrets.zzz`
//! (no public answer) resolved through it, and with `ndots:5` so did `example.com`.
//!
//! Needs a resolver that reaches public DNS through glibc's `dns` NSS module; without one (an
//! offline machine) the control lookup fails and the test says so and passes. This file holds
//! only this test: the environment it sets is process-wide.

use zkminer_netguard::{GuardedResolver, Lookup, NetMode, NetPolicy, SystemLookup};

#[tokio::test]
async fn requester_names_never_resolve_through_the_search_list() {
    // SAFETY: the only test in this binary, and no lookup has run yet in this process.
    std::env::set_var("LOCALDOMAIN", "corp-zone.1.1.1.1.sslip.io");
    std::env::set_var("RES_OPTIONS", "ndots:5");

    // Control: the search domain itself answers (the network and the wildcard zone are there).
    let control = SystemLookup
        .lookup("secrets.zzz.corp-zone.1.1.1.1.sslip.io")
        .await;
    let Ok(control) = control else {
        eprintln!("SKIPPED: no public DNS here ({control:?}); the search-list check needs it");
        return;
    };
    assert!(control.contains(&"1.1.1.1".parse().unwrap()), "{control:?}");

    // A name with no public answer is not answered from the search domain.
    let got = SystemLookup.lookup("secrets.zzz").await;
    assert!(
        got.is_err(),
        "secrets.zzz resolved through the search list: {got:?}"
    );
    let policy = NetPolicy::with_facts(
        NetMode::Public,
        zkminer_netguard::HostFacts::empty(),
        Vec::new(),
    );
    let r = GuardedResolver::new(policy, std::sync::Arc::new(SystemLookup));
    let got = r.resolve_admitted("secrets.zzz").await;
    assert!(got.is_err(), "the guarded resolver admitted {got:?}");

    // ndots:5 does not send a public name to the search domain first.
    if let Ok(ips) = SystemLookup.lookup("example.com").await {
        assert!(
            !ips.contains(&"1.1.1.1".parse().unwrap()),
            "example.com was answered from the search domain: {ips:?}"
        );
    }
}
