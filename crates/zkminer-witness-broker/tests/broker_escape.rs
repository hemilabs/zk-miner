//! Review r2 F5, as a regression test: a broker an attacker has **code execution** in cannot reach
//! anything but the configured endpoint.
//!
//! The "broker" here is this test binary re-executed as a probe (`ZKMINER_BROKER_ESCAPE_CHILD`),
//! spawned like the real broker (the sandbox launcher, a job cgroup, a cleared environment) with a
//! real connector session at fd 3, served by this process exactly as the miner serves the broker's.
//! The probe applies the real `Profile::Broker` sandbox and `seal_socket_creation`, then — as
//! arbitrary native code would — tries every way out it has:
//!
//! - directly: `socket(AF_INET/AF_INET6/AF_UNIX)`, `socketpair`, `connect`, `bind`, `listen`;
//! - through the sockets it was handed (IPv4 and IPv6): `connect(AF_UNSPEC)` to disconnect one and
//!   `connect` to aim it elsewhere, a TCP Fast Open `sendto` to another address, every socket
//!   option that re-routes a socket at the IP layer (`IPV6_RTHDR`, `IPV6_2292RTHDR`, `IP_OPTIONS`,
//!   `SO_BINDTODEVICE`, `SO_BINDTOIFINDEX`, `IP_UNICAST_IF`, `IPV6_UNICAST_IF`, `IPV6_NEXTHOP`,
//!   `IP_TRANSPARENT`, `SO_MARK`, the TTLs…: the filter's `EPERM` on each), and the same through
//!   ancillary data on `sendmsg` — routing headers, `PKTINFO` interfaces, next hops, IP options,
//!   each malformed or out of range so that a kernel that parsed it would refuse the send: TCP
//!   ignores them, and the bytes reach the configured peer, all of them and nothing else; a
//!   per-packet `SO_MARK` fails (no capability);
//! - through the connector: another port, another role, an index past the configuration, a
//!   malformed frame.
//!
//! Developer mode (the endpoints are 127.0.0.1:P and [::1]:P6 with their host routes as `cidrs`):
//! the only connections that exist afterwards are the one to P and the one to P6, carrying exactly
//! what the probe wrote; a second listener on 127.0.0.1 was never reached.
//! Public mode (the endpoint is a host name whose DNS answers loopback): no connection at all.
//!
//! Needs a delegated cgroup (`systemd-run --user --scope -p Delegate=yes`); skipped otherwise,
//! unless `ZKMINER_SANDBOX_TESTS_REQUIRED` is set.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use zkminer_witness_broker::connector::client::request_blocking;
use zkminer_witness_broker::connector::{Connector, Request, SessionEnd, Status};
use zkminer_witness_broker::egress::{NetMode, Role};
use zkminer_witness_broker::BrokerConfig;
use zkminer_witness_sandbox::{
    delegated_root, landlock_abi, prepare_command, restrict_self, seal_socket_creation, Cgroup, CgroupSpec, Profile,
    SandboxError, MIN_LANDLOCK_ABI,
};

const CHILD: &str = "ZKMINER_BROKER_ESCAPE_CHILD";
const CONNECTOR_FD: RawFd = 3;

fn main() {
    match std::env::var(CHILD).ok().as_deref() {
        Some(mode) => std::process::exit(child(mode)),
        None => parent(),
    }
}

// ------------------------------------------------------------------------------------------------
// The probe (the compromised broker).

struct Report(Vec<(String, bool, String)>);

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        let detail = detail.into();
        println!("RESULT {name} {} {detail}", if ok { "PASS" } else { "FAIL" });
        self.0.push((name.into(), ok, detail));
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn loopback(port: u16) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    a
}

/// `r < 0` with `EPERM` (the filter) or `EACCES` (Landlock).
fn denied(r: libc::c_long) -> (bool, String) {
    if r >= 0 {
        return (false, format!("returned {r}"));
    }
    let e = errno();
    ((e == libc::EPERM || e == libc::EACCES), format!("errno {e}"))
}

/// What the probe writes on its handed sockets, as the endpoints must receive it.
const V4_BYTES: &[&[u8]] = &[b"probe", b"|pktinfo", b"|retopts", b"|ttl0", b"|tos"];
const V6_BYTES: &[&[u8]] = &[b"probe6", b"|rthdr", b"|rthdr-bad", b"|2292", b"|pktinfo6", b"|nexthop", b"|hoplimit", b"|tclass"];

/// Every refused socket option on a handed socket: the filter's `EPERM`, and `TCP_NODELAY` works.
fn socket_options(r: &mut Report, name: &str, fd: RawFd) {
    let wrong: Vec<String> = zkminer_witness_sandbox::REFUSED_SOCKET_OPTIONS
        .iter()
        .filter_map(|o| match zkminer_witness_sandbox::set_socket_option(fd, o) {
            Err(libc::EPERM) => None,
            other => Some(format!("{}={other:?}", o.name)),
        })
        .collect();
    let n = zkminer_witness_sandbox::REFUSED_SOCKET_OPTIONS.len();
    r.check(&format!("{name}_options"), wrong.is_empty(), if wrong.is_empty() { format!("{n} options EPERM") } else { wrong.join(",") });
    let nd = zkminer_witness_sandbox::set_socket_option(fd, &zkminer_witness_sandbox::BROKER_SOCKET_OPTION);
    r.check(&format!("{name}_nodelay"), nd.is_ok(), format!("{nd:?}"));
}

/// `sendmsg(fd, payload)` with one control message `(level, type, data)`: the bytes sent, or the
/// errno.
fn send_with_cmsg(fd: RawFd, payload: &[u8], level: libc::c_int, ty: libc::c_int, data: &[u8]) -> Result<usize, i32> {
    let mut control = vec![0u8; 256];
    let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };
    // SAFETY: an all-zero msghdr is valid; the pointers below stay alive for the call.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_* only compute sizes and offsets inside `control`, which has room for one.
    unsafe {
        m.msg_controllen = libc::CMSG_SPACE(data.len() as u32) as usize;
        let c = libc::CMSG_FIRSTHDR(&m);
        (*c).cmsg_level = level;
        (*c).cmsg_type = ty;
        (*c).cmsg_len = libc::CMSG_LEN(data.len() as u32) as usize;
        std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(c), data.len());
    }
    // SAFETY: `m` describes valid buffers.
    let n = unsafe { libc::sendmsg(fd, &m, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(errno())
    } else {
        Ok(n as usize)
    }
}

/// IP-level ancillary data on a handed TCP socket. Each message is malformed or out of range, so
/// a kernel that parsed it would refuse the send (`EINVAL`/`ENODEV`, as for UDP): TCP ignores
/// them, every send goes through whole, and the endpoint gets the bytes (checked by the parent).
/// A per-packet `SO_MARK`, the one `SOL_SOCKET` message that steers routing, fails: the sandbox
/// holds no capability.
fn ancillary_data(r: &mut Report, name: &str, fd: RawFd, v6: bool) {
    let int = |v: i32| v.to_ne_bytes().to_vec();
    let mut rthdr2 = vec![0u8, 2, 2, 1, 0, 0, 0, 0];
    rthdr2.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    let mut rthdr_bad = rthdr2.clone();
    rthdr_bad[2] = 99;
    let mut pktinfo6 = vec![0u8; 16];
    pktinfo6.extend_from_slice(&int(0x7fff_fff0));
    // A sockaddr_in6 with family AF_INET.
    let mut nexthop = vec![0u8; 28];
    nexthop[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    let mut pktinfo4 = int(0x7fff_fff0);
    pktinfo4.extend_from_slice(&[0; 8]);
    let sends: Vec<(&[u8], libc::c_int, libc::c_int, Vec<u8>)> = if v6 {
        vec![
            (V6_BYTES[1], libc::IPPROTO_IPV6, libc::IPV6_RTHDR, rthdr2.clone()),
            (V6_BYTES[2], libc::IPPROTO_IPV6, libc::IPV6_RTHDR, rthdr_bad),
            (V6_BYTES[3], libc::IPPROTO_IPV6, libc::IPV6_2292RTHDR, rthdr2),
            (V6_BYTES[4], libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo6),
            (V6_BYTES[5], libc::IPPROTO_IPV6, libc::IPV6_NEXTHOP, nexthop),
            (V6_BYTES[6], libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, int(4096)),
            (V6_BYTES[7], libc::IPPROTO_IPV6, libc::IPV6_TCLASS, int(4096)),
        ]
    } else {
        vec![
            (V4_BYTES[1], libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo4),
            // An option of type 0x44 with a length past its end.
            (V4_BYTES[2], libc::IPPROTO_IP, libc::IP_RETOPTS, vec![0x44, 99, 0, 0]),
            (V4_BYTES[3], libc::IPPROTO_IP, libc::IP_TTL, int(0)),
            (V4_BYTES[4], libc::IPPROTO_IP, libc::IP_TOS, int(0x10)),
        ]
    };
    let mut wrong = Vec::new();
    for (payload, level, ty, data) in &sends {
        let got = send_with_cmsg(fd, payload, *level, *ty, data);
        if got != Ok(payload.len()) {
            wrong.push(format!("{}: {got:?}", String::from_utf8_lossy(payload)));
        }
    }
    r.check(&format!("{name}_ip_cmsg_ignored"), wrong.is_empty(), if wrong.is_empty() { format!("{} sends whole", sends.len()) } else { wrong.join(",") });
    let mark = send_with_cmsg(fd, b"|marked", libc::SOL_SOCKET, libc::SO_MARK, &int(1));
    r.check(&format!("{name}_so_mark_cmsg"), mark == Err(libc::EPERM), format!("{mark:?}"));
}

fn child(mode: &str) -> i32 {
    let port: u16 = std::env::var("ESCAPE_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(0);
    let port6: u16 = std::env::var("ESCAPE_PORT6").ok().and_then(|p| p.parse().ok()).unwrap_or(0);
    let other: u16 = std::env::var("ESCAPE_OTHER").ok().and_then(|p| p.parse().ok()).unwrap_or(0);
    // The configuration's endpoint count: the first index past the end.
    let past: u32 = if port6 != 0 { 2 } else { 1 };
    // SAFETY: the parent mapped the connector socket to fd 3; nothing else owns it.
    let connector = UnixStream::from(unsafe { OwnedFd::from_raw_fd(CONNECTOR_FD) });
    if let Err(e) = restrict_self(&Profile::Broker { readable: vec![], writable: vec![] }) {
        println!("RESULT restrict_self FAIL {e}");
        return 2;
    }
    if let Err(e) = seal_socket_creation() {
        println!("RESULT seal FAIL {e}");
        return 2;
    }
    let mut r = Report(Vec::new());
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let to_other = loopback(other);
    let p_other = (&to_other as *const libc::sockaddr_in).cast::<libc::sockaddr>();

    // Directly.
    for (name, family, ty) in [
        ("socket_inet", libc::AF_INET, libc::SOCK_STREAM),
        ("socket_inet6", libc::AF_INET6, libc::SOCK_STREAM),
        ("socket_udp", libc::AF_INET, libc::SOCK_DGRAM),
        ("socket_unix", libc::AF_UNIX, libc::SOCK_STREAM),
    ] {
        // SAFETY: integer arguments; a created socket would be closed below.
        let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, 0) };
        let (ok, d) = denied(fd as libc::c_long);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        r.check(name, ok, d);
    }
    let mut sv = [-1; 2];
    // SAFETY: socketpair writes two fds.
    let (ok, d) = denied(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } as libc::c_long);
    r.check("socketpair", ok, d);
    // SAFETY: fd -1 and a valid address: the filter answers EPERM, an unfiltered kernel EBADF.
    let (ok, d) = denied(unsafe { libc::connect(-1, p_other, len) } as libc::c_long);
    r.check("connect", ok, d);
    let (ok, d) = denied(unsafe { libc::bind(-1, p_other, len) } as libc::c_long);
    r.check("bind", ok, d);
    let (ok, d) = denied(unsafe { libc::listen(-1, 1) } as libc::c_long);
    r.check("listen", ok, d);

    // Through the connector: what it may not have.
    let ask = |id: u64, endpoint: u32, role: Role, port: u16| request_blocking(&connector, &Request { id, endpoint, role, port });
    for (name, id, endpoint, role, p, want) in [
        ("connector_other_port", 10, 0, Role::EvmRpc, other, Status::Mismatch),
        ("connector_other_role", 11, 0, Role::Artifact, port, Status::Mismatch),
        ("connector_index_past_the_end", 12, past, Role::EvmRpc, port, Status::NoSuchEndpoint),
        ("connector_index_max", 13, u32::MAX, Role::EvmRpc, port, Status::NoSuchEndpoint),
    ] {
        match ask(id, endpoint, role, p) {
            Ok((resp, fd)) => r.check(name, resp.status == want && fd.is_none(), format!("{:?}, fd {}", resp.status, fd.is_some())),
            Err(e) => r.check(name, false, e.to_string()),
        }
    }

    // Through the connector: the configured endpoint.
    match (mode, ask(1, 0, Role::EvmRpc, port)) {
        ("dev", Ok((resp, Some(fd)))) if resp.status == Status::Connected => {
            let mut s = std::net::TcpStream::from(fd);
            let peer = s.peer_addr().ok();
            r.check("connector_configured", peer == Some(SocketAddr::from(([127, 0, 0, 1], port))), format!("peer {peer:?}"));
            let _ = s.write_all(V4_BYTES[0]);
            let raw = s.as_raw_fd();
            socket_options(&mut r, "handed_socket", raw);
            ancillary_data(&mut r, "handed_socket", raw, false);
            match ask(2, 1, Role::EvmRpc, port6) {
                Ok((resp, Some(fd6))) if resp.status == Status::Connected => {
                    let mut s6 = std::net::TcpStream::from(fd6);
                    let peer = s6.peer_addr().ok();
                    r.check("connector_configured_v6", peer == Some(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port6))), format!("peer {peer:?}"));
                    let _ = s6.write_all(V6_BYTES[0]);
                    socket_options(&mut r, "handed_socket6", s6.as_raw_fd());
                    ancillary_data(&mut r, "handed_socket6", s6.as_raw_fd(), true);
                    // Kept open until the probe exits, like the first.
                    std::mem::forget(s6);
                }
                other => r.check("connector_configured_v6", false, format!("{other:?}")),
            }
            // Disconnect it and aim it elsewhere.
            // SAFETY: an AF_UNSPEC sockaddr, then the other listener's address.
            let mut unspec: libc::sockaddr = unsafe { std::mem::zeroed() };
            unspec.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
            let (ok, d) = denied(unsafe { libc::connect(raw, &unspec, std::mem::size_of::<libc::sockaddr>() as libc::socklen_t) } as libc::c_long);
            r.check("handed_socket_disconnect", ok, d);
            let (ok, d) = denied(unsafe { libc::connect(raw, p_other, len) } as libc::c_long);
            r.check("handed_socket_reconnect", ok, d);
            // SAFETY: a one-byte buffer and the other listener's address.
            let fo = unsafe { libc::sendto(raw, b"x".as_ptr().cast(), 1, libc::MSG_FASTOPEN | libc::MSG_NOSIGNAL, p_other, len) };
            r.check("handed_socket_fastopen", fo < 0, format!("errno {}", errno()));
        }
        ("public", Ok((resp, fd))) => {
            r.check("connector_dns_loopback", resp.status == Status::NotAdmitted && fd.is_none(), format!("{:?}", resp.status))
        }
        (_, other) => r.check("connector_configured", false, format!("{other:?}")),
    }

    // Last: a malformed frame ends the session; the connector closes the socket on us.
    let mut c = &connector;
    let _ = c.write_all(&[0x41; 32]);
    let mut b = [0u8; 1];
    let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
    let n = c.read(&mut b);
    r.check("connector_malformed_cut_off", matches!(n, Ok(0)), format!("{n:?}"));
    let after = ask(20, 0, Role::EvmRpc, port);
    r.check("connector_gone_after_cut_off", after.is_err(), format!("{after:?}"));

    println!("DONE {}", r.0.len());
    if r.0.iter().all(|(_, ok, _)| *ok) {
        0
    } else {
        1
    }
}

// ------------------------------------------------------------------------------------------------
// The miner's side.

fn skip(reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("broker_escape: sandbox unavailable: {reason}");
    }
    eprintln!("SKIPPED broker_escape: {reason}");
}

fn parent() {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        return skip(&format!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"));
    }
    let root = match delegated_root() {
        Ok(r) => r,
        Err(e @ SandboxError::NotDelegated { .. }) => return skip(&e.to_string()),
        Err(e) => panic!("delegated_root: {e}"),
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(developer_mode(&root));
    rt.block_on(public_mode(&root));
    println!("broker_escape: 2 scenarios passed");
}

/// Runs the probe with `connector` serving its fd 3; returns its stdout and the session's end.
async fn run_probe(root: &std::path::Path, connector: std::sync::Arc<Connector>, mode: &str, (port, port6): (u16, u16), other: u16) -> (String, SessionEnd) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let session = tokio::spawn(connector.serve(ours));
    let cg = Cgroup::create(
        root,
        &CgroupSpec { name: format!("broker-escape-{mode}-{}", std::process::id()), memory_max: 256 << 20, pids_max: 16, cpu_max: None, cpu_weight: 50 },
    )
    .unwrap();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.env(CHILD, mode).env("ESCAPE_PORT", port.to_string()).env("ESCAPE_PORT6", port6.to_string()).env("ESCAPE_OTHER", other.to_string());
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    prepare_command(&mut cmd, &cg, &[(theirs.as_fd(), CONNECTOR_FD)]).unwrap();
    let child = cmd.spawn().unwrap();
    drop(theirs);
    drop(cmd);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await.unwrap().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let end = tokio::time::timeout(Duration::from_secs(10), session).await.expect("session ended").unwrap();
    cg.remove().unwrap();
    assert!(
        out.status.success(),
        "probe {mode} {:?}:\n{stdout}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    print!("{stdout}");
    (stdout, end)
}

fn accepted(l: &TcpListener) -> Vec<std::net::TcpStream> {
    l.set_nonblocking(true).unwrap();
    std::iter::from_fn(|| l.accept().ok().map(|(s, _)| s)).collect()
}

fn config(dir: &std::path::Path, text: &str, mode: NetMode) -> BrokerConfig {
    let path = dir.join("broker.toml");
    std::fs::write(&path, zkminer_witness_broker::testkit::config_text(dir, text)).unwrap();
    BrokerConfig::load_for_connector(&path, mode).expect("the miner loads the config")
}

/// Developer mode: the configured endpoint is reachable, nothing else is.
async fn developer_mode(root: &std::path::Path) {
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let node6 = TcpListener::bind("[::1]:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let (port, other_port) = (node.local_addr().unwrap().port(), other.local_addr().unwrap().port());
    let port6 = node6.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &format!(
            "[[evm_rpc]]\nalias = \"n\"\nurl = \"http://127.0.0.1:{port}\"\nchain_id = 31337\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n\
             [[evm_rpc]]\nalias = \"n6\"\nurl = \"http://[::1]:{port6}\"\nchain_id = 31337\nmethod_sets = [\"state-read\"]\ncidrs = [\"::1/128\"]\n"
        ),
        NetMode::DevPrivate,
    );
    let facts = zkminer_netguard::FactsOptions { discover_public_addresses: false, ..Default::default() };
    let connector = Connector::for_miner(&cfg, &[], facts).unwrap();
    let (stdout, end) = run_probe(root, connector.clone(), "dev", (port, port6), other_port).await;
    for want in [
        "socket_inet", "socket_inet6", "socket_udp", "socket_unix", "socketpair", "connect", "bind", "listen",
        "connector_other_port", "connector_other_role", "connector_index_past_the_end", "connector_index_max",
        "connector_configured", "handed_socket_options", "handed_socket_nodelay", "handed_socket_ip_cmsg_ignored",
        "handed_socket_so_mark_cmsg", "connector_configured_v6", "handed_socket6_options", "handed_socket6_nodelay",
        "handed_socket6_ip_cmsg_ignored", "handed_socket6_so_mark_cmsg", "handed_socket_disconnect",
        "handed_socket_reconnect", "handed_socket_fastopen", "connector_malformed_cut_off", "connector_gone_after_cut_off",
    ] {
        assert!(stdout.contains(&format!("RESULT {want} PASS")), "{want}:\n{stdout}");
    }
    assert!(matches!(end, SessionEnd::CutOff(_)), "{end:?}");
    // Each endpoint has exactly the connection the connector made, and it carried exactly what the
    // probe wrote on it: no option or control message sent a byte anywhere else.
    for (l, want) in [(&node, V4_BYTES), (&node6, V6_BYTES)] {
        let mut served = accepted(l);
        assert_eq!(served.len(), 1, "exactly the one connection the connector made");
        let mut got = Vec::new();
        served[0].set_nonblocking(false).unwrap();
        served[0].set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        served[0].read_to_end(&mut got).unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&want.concat()));
    }
    assert!(accepted(&other).is_empty(), "the unconfigured listener on 127.0.0.1 was reached");
    assert_eq!(connector.stats.attempts.load(std::sync::atomic::Ordering::Relaxed), 2);
    println!("broker_escape developer mode: {} checks passed, 2 connections, to the configured endpoints", stdout.matches(" PASS ").count());
}

/// Public mode: a configured host name that answers loopback gets the compromised broker nothing.
async fn public_mode(root: &std::path::Path) {
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let (port, other_port) = (node.local_addr().unwrap().port(), other.local_addr().unwrap().port());
    let dns = zkminer_witness_broker::testkit::TestDns::start(&[("rpc.example.com", &["127.0.0.1", "::1"])]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &format!(
            "{}[egress]\ndiscover_public_addresses = false\n[[evm_rpc]]\nalias = \"p\"\nurl = \"http://rpc.example.com:{port}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\n",
            dns.config()
        ),
        NetMode::Public,
    );
    // Without discovery, the host's public addresses as an operator states them (documentation-
    // like stand-ins: no connection goes anywhere in this test).
    let facts = zkminer_netguard::FactsOptions {
        discover_public_addresses: false,
        public_addresses: vec!["198.51.99.7".parse().unwrap(), "2a02:db8:99::7".parse().unwrap()],
        ..Default::default()
    };
    let connector = Connector::for_miner(&cfg, &[], facts).unwrap();
    let (stdout, end) = run_probe(root, connector.clone(), "public", (port, 0), other_port).await;
    for want in [
        "socket_inet", "socket_unix", "connect", "connector_other_port", "connector_index_past_the_end",
        "connector_dns_loopback", "connector_malformed_cut_off",
    ] {
        assert!(stdout.contains(&format!("RESULT {want} PASS")), "{want}:\n{stdout}");
    }
    assert!(matches!(end, SessionEnd::CutOff(_)), "{end:?}");
    assert!(dns.queries() >= 1, "the connector resolved the name");
    assert!(accepted(&node).is_empty() && accepted(&other).is_empty(), "loopback was reached in public mode");
    assert_eq!(connector.stats.attempts.load(std::sync::atomic::Ordering::Relaxed), 0, "no connection was even tried");
    println!("broker_escape public mode: {} checks passed, no connection", stdout.matches(" PASS ").count());
}
