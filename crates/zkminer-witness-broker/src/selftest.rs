//! The broker's self-test (plan §10.3): the network floor refuses loopback, the metadata service, an
//! RFC 1918 address, the host's own addresses and its connected prefixes — on the requester path,
//! and for every operator role except an endpoint whose operator configured that very address (an
//! explicit `cidrs` host route or the URL's IP literal; never a DNS answer) — and the artifact and
//! `evm-rpc` endpoints answer with their configured chain ids.
//!
//! A role prefix that is not a host route and covers a probe address fails the check whoever
//! configured it (`0.0.0.0/0`, `10.0.0.0/8`, `::ffff:127.0.0.0/104`, which is `127.0.0.0/8`): local
//! nodes are configured as host routes. Only in developer mode can an operator have configured a
//! private address on purpose, so only there does a configured host route vouch for a probe.
//!
//! In public mode one more check, [`SelfTestCheck::RoleEntriesPublic`]: every prefix of every
//! configured role entry passes netguard's [`zkminer_netguard::admit_prefix`] against the host's
//! current facts and the deny CIDRs. With it failing, `ok` is false.
//!
//! These are checks of the broker's own, second-layer floor. Its first layer is that it has no
//! network (review r2 F5): [`SelfTestCheck::InetSocketDenied`] and [`SelfTestCheck::ConnectDenied`]
//! check, from inside the sandbox, that it can make no socket and call no `connect`, `bind`,
//! `listen` or `accept4`; [`SelfTestCheck::SocketOptionsDenied`] that it can set no socket option
//! but `TCP_NODELAY`, on fd -1 and on a socket the connector hands it for its first endpoint (so a
//! handed socket cannot be re-routed); [`SelfTestCheck::ConnectorRefusesBadIndex`] that the miner's connector
//! refuses an endpoint index past the configuration. The connector's own checks run in the miner
//! ([`crate::connector::Connector::self_test`]).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::AtomicU64;

use zkminer_witness::ipc::{ControlResponse, SelfTestCheck};
use zkminer_witness_sandbox::{set_socket_option, BROKER_SOCKET_OPTION, REFUSED_SOCKET_OPTIONS};

use crate::broker::Broker;
use crate::config::mask;
use crate::egress::{Admit, EgressPolicy, NetMode, Prefix};
use crate::jsonrpc::RpcClient;
use crate::lanes::WaitFlag;

const LOOPBACK: [&str; 2] = ["127.0.0.1", "::1"];
const METADATA: [&str; 2] = ["169.254.169.254", "fd00:ec2::254"];
const RFC1918: [&str; 3] = ["10.0.0.1", "172.16.0.1", "192.168.1.1"];

/// Whether `ip` is refused on the requester path (ports 443 and 80), covered by no role prefix
/// wider than a host route, and refused for every role entry — except, in developer mode, one whose
/// operator configured that very address (`configured`: alias → explicit cidrs or IP literal).
pub(crate) fn floor_denies(policy: &EgressPolicy, configured: &HashMap<String, Vec<Prefix>>, ip: IpAddr) -> bool {
    let denied = |a: Admit| matches!(a, Admit::Denied(_));
    if ![443, 80].into_iter().all(|port| denied(policy.admit(None, SocketAddr::new(ip, port)))) {
        return false;
    }
    policy.roles.iter().all(|e| {
        if e.prefixes.iter().any(|p| !p.is_host_route() && p.contains(ip)) {
            return false;
        }
        let vouched = policy.mode == NetMode::DevPrivate
            && configured.get(&e.alias).is_some_and(|c| c.iter().any(|p| p.is_host_route() && p.contains(ip)));
        vouched || denied(policy.admit(Some((e.role, &e.alias)), SocketAddr::new(ip, e.port)))
    })
}

/// Addresses to probe inside a connected prefix: the address given and the prefix's first host.
fn probes(p: &Prefix) -> Vec<IpAddr> {
    let net = mask(p.addr, p.len);
    let first = match net {
        IpAddr::V4(v) if p.len < 32 => IpAddr::V4((u32::from(v) + 1).into()),
        IpAddr::V6(v) if p.len < 128 => IpAddr::V6((u128::from(v) + 1).into()),
        other => other,
    };
    let mut v = vec![p.addr];
    if first != p.addr {
        v.push(first);
    }
    v
}

pub(crate) async fn run(b: &Broker) -> ControlResponse {
    let policy = b.policy.read().unwrap_or_else(|p| p.into_inner()).clone();
    let own = policy.own_addresses().to_vec();
    let configured = b.cfg.configured_prefixes();
    let denies = |ip: IpAddr| floor_denies(&policy, &configured, ip);
    let all = |ips: &[&str]| ips.iter().all(|s| denies(s.parse().expect("constant address")));
    let mut checks = vec![
        (SelfTestCheck::LoopbackDenied, all(&LOOPBACK)),
        (SelfTestCheck::MetadataDenied, all(&METADATA)),
        (SelfTestCheck::Rfc1918Denied, all(&RFC1918)),
        (SelfTestCheck::OwnAddressDenied, own.iter().all(|ip| denies(*ip))),
        (SelfTestCheck::ConnectedPrefixDenied, policy.connected().iter().flat_map(probes).all(denies)),
    ];
    if policy.mode == NetMode::Public {
        let bad = policy.first_non_public_role();
        if let Some((alias, why)) = &bad {
            tracing::error!(endpoint = %alias, "PAGE: self-test: a role entry is not public: {why}");
        }
        checks.push((SelfTestCheck::RoleEntriesPublic, bad.is_none()));
    }
    let ids = AtomicU64::new(1);
    let wait = WaitFlag::default();
    if let Some(ep) = b.artifacts.endpoint() {
        let got = RpcClient { ep, held: true, ids: &ids, wait: &wait }.chain_id().await;
        checks.push((SelfTestCheck::ArtifactEndpointChainId, got == Ok(b.artifacts.chain_id())));
    }
    if !b.evm.is_empty() {
        let answers = futures::future::join_all(b.evm.iter().map(|e| {
            let (ids, wait) = (&ids, &wait);
            async move { RpcClient { ep: &e.ep, held: true, ids, wait }.chain_id().await == Ok(e.info.chain_id) }
        }))
        .await;
        checks.push((SelfTestCheck::EndpointsReachable, answers.into_iter().all(|ok| ok)));
    }
    // The sandbox as this process sees it. Unreadable secrets are proven by the sandbox crate's
    // probe-based self-test for the broker profile, which the miner runs at startup and hourly.
    checks.extend(in_process_sandbox_checks());
    checks.extend(no_network_checks());
    // A socket handed for the first endpoint (closed unused), to try the options on.
    let handed = match b.cfg.endpoints().next() {
        Some(e) => match b.connector.connect(0, e.role, e.port).await {
            Ok((stream, _)) => Some(stream),
            Err(err) => {
                tracing::warn!(endpoint = %e.alias, error = %err, "self-test: no socket from the connector to try socket options on");
                None
            }
        },
        None => None,
    };
    checks.push((SelfTestCheck::SocketOptionsDenied, socket_options_denied(handed.as_ref().map(|s| s.as_raw_fd()))));
    drop(handed);
    let bad = b.connector.connect(u32::MAX, crate::egress::Role::EvmRpc, 443).await;
    checks.push((
        SelfTestCheck::ConnectorRefusesBadIndex,
        bad.as_ref().err() == Some(&crate::connector::ConnectError::Refused(crate::connector::Status::NoSuchEndpoint)),
    ));
    let ok = checks.iter().all(|(_, passed)| *passed);
    ControlResponse::SelfTest { ok, checks }
}

/// Checks of the sandbox from inside the broker: seccomp in filter mode, `NO_NEW_PRIVS`, Landlock
/// denying a directory it was not granted, and no GPU device node openable.
fn in_process_sandbox_checks() -> Vec<(SelfTestCheck, bool)> {
    // SAFETY: prctl reads of this process's own state.
    let seccomp = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } == 2;
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
    let denied = |path: &str, flags: libc::c_int| -> bool {
        let c = std::ffi::CString::new(path).expect("no NUL");
        // SAFETY: open/close of a path; the fd, if any, is closed at once.
        let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
    };
    let landlock = denied("/", libc::O_RDONLY | libc::O_DIRECTORY);
    let gpu = ["/dev/nvidiactl", "/dev/nvidia0", "/dev/dri/renderD128", "/dev/kfd"]
        .iter()
        .filter(|p| std::path::Path::new(p).exists())
        .all(|p| denied(p, libc::O_RDWR));
    vec![
        (SelfTestCheck::SeccompActive, seccomp),
        (SelfTestCheck::NoNewPrivs, nnp),
        (SelfTestCheck::LandlockActive, landlock),
        (SelfTestCheck::GpuNodeUnopenable, gpu),
    ]
}

/// The broker's first layer (review r2 F5): no socket of its own, and no `connect`, `bind`,
/// `listen` or `accept4` (each on fd -1, so the filter's `EPERM` is told from `EBADF`).
fn no_network_checks() -> Vec<(SelfTestCheck, bool)> {
    let eperm = || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let socket_denied = [libc::AF_INET, libc::AF_INET6].into_iter().all(|family| {
        // SAFETY: socket takes integers; a created socket is closed at once.
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        eperm()
    });
    // SAFETY: a valid sockaddr_in for 127.0.0.1:80 and fd -1: each call fails without a side
    // effect.
    let connect_denied = unsafe {
        let mut a: libc::sockaddr_in = std::mem::zeroed();
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_port = 80u16.to_be();
        a.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
        let p = (&a as *const libc::sockaddr_in).cast::<libc::sockaddr>();
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        (libc::connect(-1, p, len) < 0 && eperm())
            && (libc::bind(-1, p, len) < 0 && eperm())
            && (libc::listen(-1, 1) < 0 && eperm())
            && (libc::accept4(-1, std::ptr::null_mut(), std::ptr::null_mut(), 0) < 0 && eperm())
    };
    vec![(SelfTestCheck::InetSocketDenied, socket_denied), (SelfTestCheck::ConnectDenied, connect_denied)]
}

/// The broker's socket options: every [`REFUSED_SOCKET_OPTIONS`] entry fails with the filter's
/// `EPERM` on fd -1 (a missing filter says `EBADF`) and on `handed`, a socket the connector
/// handed over; `TCP_NODELAY` reaches the kernel on fd -1 (`EBADF`) and works on `handed`.
fn socket_options_denied(handed: Option<RawFd>) -> bool {
    let mut wrong = Vec::new();
    for o in REFUSED_SOCKET_OPTIONS {
        for fd in std::iter::once(-1).chain(handed) {
            let r = set_socket_option(fd, o);
            if r != Err(libc::EPERM) {
                wrong.push(format!("{} on fd {fd}: {r:?}", o.name));
            }
        }
    }
    let r = set_socket_option(-1, &BROKER_SOCKET_OPTION);
    if r != Err(libc::EBADF) {
        wrong.push(format!("TCP_NODELAY on fd -1: {r:?}"));
    }
    if let Some(fd) = handed {
        if let Err(e) = set_socket_option(fd, &BROKER_SOCKET_OPTION) {
            wrong.push(format!("TCP_NODELAY on fd {fd}: errno {e}"));
        }
    }
    if !wrong.is_empty() {
        tracing::error!("PAGE: self-test: socket options the broker may not set: {}", wrong.join("; "));
    }
    wrong.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_prefix_probes() {
        let p = Prefix { addr: "192.168.7.0".parse().unwrap(), len: 24 };
        assert_eq!(probes(&p), vec!["192.168.7.0".parse::<IpAddr>().unwrap(), "192.168.7.1".parse().unwrap()]);
        let p = Prefix { addr: "2001:db8::5".parse().unwrap(), len: 64 };
        assert_eq!(probes(&p), vec!["2001:db8::5".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]);
        let h = Prefix { addr: "10.1.1.1".parse().unwrap(), len: 32 };
        assert_eq!(probes(&h), vec!["10.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    /// Review F1(b)/F11: only explicit cidrs and IP literals count as configured, only as host
    /// routes; a wider role prefix covering a probe fails, `0.0.0.0/0` and its mapped spelling
    /// included.
    #[test]
    fn floor_denies_counts_only_configured_host_routes() {
        use crate::egress::{Role, RoleEntry};
        let p = |s: &str| crate::config::parse_cidr(s).unwrap();
        let in_mode = |mode: NetMode, prefixes: Vec<Prefix>| EgressPolicy {
            mode,
            roles: vec![RoleEntry { role: Role::EvmRpc, alias: "n".into(), prefixes, port: 8545 }],
            deny: vec![],
            facts: zkminer_netguard::HostFacts::new(vec![p("192.168.7.0/24")], vec![]),
        };
        let policy = |prefixes: Vec<Prefix>| in_mode(NetMode::DevPrivate, prefixes);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let configured = |c: Vec<Prefix>| HashMap::from([("n".to_string(), c)]);
        // An explicit host route at the probe: vouched for.
        let pol = policy(vec![p("127.0.0.1/32")]);
        assert!(floor_denies(&pol, &configured(vec![p("127.0.0.1/32")]), loopback));
        // The same entry from a DNS answer (nothing configured): fails.
        assert!(!floor_denies(&pol, &configured(vec![]), loopback));
        // Wider than a host route, whoever configured it.
        for wide in ["127.0.0.0/8", "0.0.0.0/0", "::ffff:0.0.0.0/96", "::ffff:127.0.0.0/104", "192.168.7.0/24"] {
            let pol = policy(vec![p(wide)]);
            let probe: IpAddr = if wide.starts_with("192") { "192.168.7.1".parse().unwrap() } else { loopback };
            assert!(!floor_denies(&pol, &configured(vec![p(wide)]), probe), "{wide}");
        }
        // A host route elsewhere does not cover the probe.
        let pol = policy(vec![p("10.9.9.9/32")]);
        assert!(floor_denies(&pol, &configured(vec![p("10.9.9.9/32")]), loopback));
        // A mapped host route is a host route.
        let pol = policy(vec![p("::ffff:127.0.0.1/128")]);
        assert!(floor_denies(&pol, &configured(vec![p("::ffff:127.0.0.1/128")]), loopback));
        // Public mode vouches for nothing: a configured loopback host route fails the check.
        let pol = in_mode(NetMode::Public, vec![p("127.0.0.1/32")]);
        assert!(floor_denies(&pol, &configured(vec![]), loopback), "the public floor refuses it at admission");
        let pol = in_mode(NetMode::Public, vec![p("127.0.0.0/8")]);
        assert!(!floor_denies(&pol, &configured(vec![p("127.0.0.0/8")]), loopback));
        assert!(pol.first_non_public_role().is_some());
    }

    #[test]
    fn no_network_checks_fail_outside_the_sandbox() {
        for (c, passed) in no_network_checks() {
            assert!(!passed, "{c:?} passed outside the sandbox");
        }
    }

    #[test]
    fn socket_options_check_fails_outside_the_sandbox() {
        assert!(!socket_options_denied(None));
    }

    #[test]
    fn in_process_checks_fail_outside_the_sandbox() {
        // The unit-test process is not sandboxed: every sandbox check must say so (no vacuous pass,
        // except the GPU check on a host without GPU nodes).
        let checks = in_process_sandbox_checks();
        for (c, passed) in &checks {
            match c {
                SelfTestCheck::GpuNodeUnopenable => {}
                _ => assert!(!passed, "{c:?} passed outside the sandbox"),
            }
        }
    }
}
