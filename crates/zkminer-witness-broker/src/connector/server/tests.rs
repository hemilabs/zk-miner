//! The connector against a hostile broker: what it connects to, what it refuses, when it cuts the
//! broker off, and a fuzz of its reader.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;

use super::*;
use crate::connector::client::request_blocking;
use crate::testkit::config_text;

fn facts() -> zkminer_netguard::HostFacts {
    zkminer_netguard::HostFacts::new(
        vec!["127.0.0.0/8".parse().unwrap(), "192.168.7.0/24".parse().unwrap()],
        vec!["127.0.0.1".parse().unwrap(), "192.168.7.10".parse().unwrap()],
    )
}

fn connector_for(text: &str, mode: NetMode, dns: Vec<SocketAddr>) -> (Arc<Connector>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = BrokerConfig::from_toml_for_connector(&config_text(dir.path(), text), dir.path(), mode).expect("config");
    let deny = Connector::deny_for(&cfg, &["203.0.113.0/24".parse().unwrap()], &dns);
    let floor = NetPolicy::with_facts(NetMode::Public, facts(), deny);
    (Connector::with_floor(&cfg, dns, floor).unwrap(), dir)
}

fn evm(alias: &str, url: &str, extra: &str) -> String {
    format!("[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\n{extra}\n")
}

/// A session on a fresh socketpair: the broker's (blocking) end and the session's result.
fn session(c: &Arc<Connector>) -> (UnixStream, tokio::task::JoinHandle<SessionEnd>) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    (theirs, tokio::spawn(c.clone().serve(ours)))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// A test that cannot check what it is for here says so; under `ZKMINER_CI_STRICT=1` (CI's
/// callers job) it fails instead (review round 5, cross-4), as netguard's own tests do.
fn skipped(why: &str) {
    // A reason that starts with a token ZKMINER_CI_ALLOW_SKIP names exactly ("[ipv6] ...": a CI
    // host without IPv6) is allowed, as in netguard's own tests.
    let token = why.strip_prefix('[').and_then(|r| r.split_once(']')).map(|(t, _)| t.trim().to_string());
    let allowed = std::env::var("ZKMINER_CI_ALLOW_SKIP")
        .unwrap_or_default()
        .split(',')
        .any(|a| token.as_deref().is_some_and(|t| !t.is_empty() && a.trim() == t));
    assert!(
        allowed || std::env::var("ZKMINER_CI_STRICT").as_deref() != Ok("1"),
        "SKIPPED under ZKMINER_CI_STRICT=1: {why}"
    );
    eprintln!("SKIPPED: {why}");
}

fn req(id: u64, endpoint: u32, port: u16) -> Request {
    Request { id, endpoint, role: Role::EvmRpc, port }
}

/// Developer mode: endpoint 0 (a loopback literal with its host route) is connected, and the
/// socket is connected exactly there; a second listener nobody configured is never reached.
#[tokio::test(flavor = "multi_thread")]
async fn connects_only_to_the_configured_endpoint() {
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    other.set_nonblocking(true).unwrap();
    let port = node.local_addr().unwrap().port();
    let (c, _d) = connector_for(&evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
    let (b, s) = session(&c);
    let (resp, fd, other_port) = blocking(move || {
        let other_port = other.local_addr().unwrap().port();
        let (resp, fd) = request_blocking(&b, &req(1, 0, port)).unwrap();
        // The broker cannot name the other port: a mismatch, never a connection.
        let (m, none) = request_blocking(&b, &req(2, 0, other_port)).unwrap();
        assert_eq!((m.status, none.is_none()), (Status::Mismatch, true));
        assert!(other.accept().is_err(), "the unconfigured listener was reached");
        drop(b);
        (resp, fd, other_port)
    })
    .await;
    assert_eq!(resp.status, Status::Connected);
    let mut stream = std::net::TcpStream::from(fd.expect("a socket"));
    assert_eq!(stream.peer_addr().unwrap(), SocketAddr::from(([127, 0, 0, 1], port)));
    assert_eq!(resp.peer, Some(stream.peer_addr().unwrap()));
    let (mut served, _) = node.accept().unwrap();
    stream.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    served.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    assert_ne!(other_port, port);
    assert_eq!(s.await.unwrap(), SessionEnd::Closed);
}

/// Public mode: a host name answering loopback, a private address, the host's own address, a
/// connected neighbour or a deny CIDR is never connected to; an IP literal cannot even load.
#[tokio::test(flavor = "multi_thread")]
async fn public_mode_refuses_every_private_answer() {
    use crate::testkit::TestDns;
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    node.set_nonblocking(true).unwrap();
    let port = node.local_addr().unwrap().port();
    for answer in ["127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "192.168.7.20", "192.168.7.10", "203.0.113.5", "::ffff:127.0.0.1", "64:ff9b::7f00:1"] {
        let dns = TestDns::start(&[("rpc.example.com", &[answer])]).await;
        let (c, _d) = connector_for(&evm("p", &format!("http://rpc.example.com:{port}"), ""), NetMode::Public, vec![dns.addr]);
        let (b, s) = session(&c);
        let (resp, fd) = blocking(move || request_blocking(&b, &req(7, 0, port)).unwrap()).await;
        assert_eq!((resp.status, fd.is_none()), (Status::NotAdmitted, true), "{answer}");
        assert!(dns.queries() >= 1, "{answer}: resolved by the connector");
        assert!(s.await.is_ok());
        // Every probe refused at admission too.
        let me = c.clone();
        assert!(blocking(move || me.admit(0, answer.parse().unwrap()).is_err()).await, "{answer}");
    }
    assert!(node.accept().is_err(), "a private answer was connected to");
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(dir.path(), &evm("p", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]"));
    assert!(BrokerConfig::from_toml_for_connector(&text, dir.path(), NetMode::Public).is_err());
}

/// Developer mode does not make a DNS answer the operator's word: loopback without `cidrs` is
/// still refused; with explicit `cidrs` it is admitted.
#[tokio::test(flavor = "multi_thread")]
async fn dns_answers_need_cidrs_to_be_private_even_in_developer_mode() {
    use crate::testkit::TestDns;
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = node.local_addr().unwrap().port();
    let dns = TestDns::start(&[("rpc.test", &["127.0.0.1"])]).await;
    let url = format!("http://rpc.test:{port}");
    let (c, _d) = connector_for(&evm("p", &url, ""), NetMode::DevPrivate, vec![dns.addr]);
    let (b, _s) = session(&c);
    let (resp, _) = blocking(move || request_blocking(&b, &req(1, 0, port)).unwrap()).await;
    assert_eq!(resp.status, Status::NotAdmitted);
    let (c, _d) = connector_for(&evm("p", &url, "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![dns.addr]);
    let (b, _s) = session(&c);
    let (resp, fd) = blocking(move || request_blocking(&b, &req(1, 0, port)).unwrap()).await;
    assert_eq!(resp.status, Status::Connected);
    assert!(fd.is_some());
}

/// A bad index or role/port is refused; past `MAX_MISUSE` within the window the broker is cut off.
#[tokio::test(flavor = "multi_thread")]
async fn misuse_is_refused_then_cut_off() {
    let (c, _d) = connector_for(&evm("n", "http://127.0.0.1:9", "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
    let (b, s) = session(&c);
    let statuses = blocking(move || {
        let mut v = Vec::new();
        for (i, r) in [req(1, 1, 9), req(2, u32::MAX, 9), req(3, 0, 10), Request { id: 4, endpoint: 0, role: Role::Artifact, port: 9 }]
            .into_iter()
            .enumerate()
        {
            v.push((i, request_blocking(&b, &r).unwrap().0.status));
        }
        for id in 10..10 + MAX_MISUSE as u64 {
            let _ = request_blocking(&b, &req(id, 99, 9));
        }
        let mut buf = [0u8; 1];
        v.push((99, if (&b).read(&mut buf).unwrap_or(0) == 0 { Status::Internal } else { Status::Connected }));
        v
    })
    .await;
    assert_eq!(statuses[0].1, Status::NoSuchEndpoint);
    assert_eq!(statuses[1].1, Status::NoSuchEndpoint);
    assert_eq!(statuses[2].1, Status::Mismatch);
    assert_eq!(statuses[3].1, Status::Mismatch);
    assert_eq!(statuses[4].1, Status::Internal, "the socket was closed on the broker");
    assert_eq!(s.await.unwrap(), SessionEnd::CutOff(CutOff::Misuse));
}

/// Strict decoding: one bad byte cuts the broker off, and so does an fd sent to the connector.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_frame_or_a_passed_fd_cuts_the_broker_off() {
    let (c, _d) = connector_for(&evm("n", "http://127.0.0.1:9", "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
    let mut frame = req(1, 0, 9).encode();
    frame[31] = 1;
    let (mut b, s) = session(&c);
    b.write_all(&frame).unwrap();
    assert!(matches!(s.await.unwrap(), SessionEnd::CutOff(CutOff::Malformed(Malformed("reserved bytes")))));
    let mut buf = [0u8; 8];
    assert_eq!(b.read(&mut buf).unwrap(), 0);

    let (b, s) = session(&c);
    let (pair, _keep) = UnixStream::pair().unwrap();
    let sent = crate::fdpass::sendmsg_once(b.as_raw_fd(), &req(2, 0, 9).encode(), Some(pair.as_raw_fd())).unwrap();
    assert_eq!(sent, REQUEST_LEN);
    assert_eq!(s.await.unwrap(), SessionEnd::CutOff(CutOff::FdAttached));
}

/// A listener that accepts DNS connections and never answers: resolution hangs until its timeout.
fn silent_dns() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let mut held = Vec::new();
        l.set_nonblocking(true).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < until {
            if let Ok((s, _)) = l.accept() {
                held.push(s);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    (addr, t)
}

/// An id still in flight, and more than `MAX_INFLIGHT` requests in flight, cut the broker off.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_ids_and_floods_cut_the_broker_off() {
    let (dns, _t) = silent_dns();
    let text = evm("n", "http://rpc.test:9", "cidrs = [\"127.0.0.1/32\"]");
    let (c, _d) = connector_for(&text, NetMode::DevPrivate, vec![dns]);
    let (mut b, s) = session(&c);
    // The first is in flight while its name resolves (the server never answers).
    b.write_all(&req(5, 0, 9).encode()).unwrap();
    b.write_all(&req(5, 0, 9).encode()).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(20), s).await.expect("cut off in time");
    assert_eq!(end.unwrap(), SessionEnd::CutOff(CutOff::DuplicateId));

    // A burst drains the bucket; what follows waits for tokens (in flight), and one past
    // MAX_INFLIGHT of those is a flood.
    let lit = evm("n", "http://127.0.0.1:9", "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024");
    let (c, _d) = connector_for(&lit, NetMode::DevPrivate, vec![]);
    let (mut b, s) = session(&c);
    let mut frames = Vec::new();
    for id in 0..(RATE_BURST as u64 + MAX_INFLIGHT as u64 + 4) {
        frames.extend_from_slice(&req(100 + id, 0, 9).encode());
    }
    b.write_all(&frames).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(20), s).await.expect("cut off in time");
    assert_eq!(end.unwrap(), SessionEnd::CutOff(CutOff::Flood));
}

/// The bucket bounds connection attempts: past the burst, attempts come at the refill rate.
#[tokio::test(flavor = "multi_thread")]
async fn connection_attempts_are_paced() {
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = node.local_addr().unwrap().port();
    let (c, _d) = connector_for(
        &evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024"),
        NetMode::DevPrivate,
        vec![],
    );
    let (b, _s) = session(&c);
    let n = RATE_BURST as u64 + 2 * u64::from(RATE_PER_SEC);
    let started = std::time::Instant::now();
    let connected = blocking(move || {
        let mut ok = 0;
        for id in 0..n {
            let (r, fd) = request_blocking(&b, &req(id, 0, port)).unwrap();
            ok += u64::from(r.status == Status::Connected && fd.is_some());
        }
        ok
    })
    .await;
    assert_eq!(connected, n);
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1_800), "{n} attempts in {took:?}: not paced");
    assert_eq!(c.stats.attempts.load(Ordering::Relaxed), n);
}

/// The connector's self-test passes, in both modes, with literal, cidrs and host-name endpoints.
#[tokio::test(flavor = "multi_thread")]
async fn the_self_test_passes() {
    use crate::testkit::TestDns;
    let dns = TestDns::start(&[("rpc.example.com", &["45.60.1.1"])]).await;
    let text = format!(
        "{}{}",
        evm("lit", "https://1.1.1.1/", ""),
        evm("named", "https://rpc.example.com/", "")
    );
    let (c, _d) = connector_for(&text, NetMode::Public, vec![dns.addr]);
    c.warm_up();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = c.self_test().await;
    assert_eq!(r.len(), 4, "{r:?}");
    assert!(r.iter().all(|(_, ok)| *ok), "{r:?}");
    let dev = format!("{}{}", evm("local", "http://127.0.0.1:8545", "cidrs = [\"127.0.0.1/32\"]"), evm("named", "https://rpc.example.com/", ""));
    let (c, _d) = connector_for(&dev, NetMode::DevPrivate, vec![dns.addr]);
    let r = c.self_test().await;
    assert_eq!(r.len(), 3, "no private check in developer mode: {r:?}");
    assert!(r.iter().all(|(_, ok)| *ok), "{r:?}");
}

/// Random byte streams into a session: the connector never panics, every answer it writes decodes,
/// and the session ends closed or cut off.
#[tokio::test(flavor = "multi_thread")]
async fn fuzz_the_reader() {
    let (c, _d) = connector_for(&evm("n", "http://127.0.0.1:9", "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..400 {
        let len = (next() % 200) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        // Often a valid prefix, so decoding gets past the magic.
        if round % 2 == 0 && bytes.len() >= 8 {
            bytes[..6].copy_from_slice(&req(1, 0, 9).encode()[..6]);
        }
        if round % 5 == 0 {
            bytes.extend_from_slice(&req(round, (next() % 3) as u32, 9).encode());
        }
        let (mut b, s) = session(&c);
        b.write_all(&bytes).unwrap();
        b.shutdown(std::net::Shutdown::Write).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(20), s).await.expect("session ended").expect("no panic");
        assert!(matches!(end, SessionEnd::Closed | SessionEnd::CutOff(_)));
        let mut out = Vec::new();
        b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let _ = b.read_to_end(&mut out);
        assert_eq!(out.len() % RESPONSE_LEN, 0, "round {round}: a partial answer");
        for chunk in out.chunks(RESPONSE_LEN) {
            Response::decode(chunk.try_into().unwrap()).expect("answers decode");
        }
    }
}

/// Public mode: right before connecting, the connector asks the near-hop probe about the exact
/// address and port; a destination that answers within the hop limit (here a staged probe, so
/// nothing leaves the host) is refused and never connected to.
#[tokio::test(flavor = "multi_thread")]
async fn a_near_destination_is_refused_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let text = evm("p", "https://93.184.216.34:8545", "");
    let cfg = BrokerConfig::from_toml_for_connector(&config_text(dir.path(), &text), dir.path(), NetMode::Public).expect("config");
    let deny = Connector::deny_for(&cfg, &[], &[]);
    for (outcome, refused) in [
        (zkminer_netguard::ProbeOutcome::Refused, true),
        (zkminer_netguard::ProbeOutcome::Connected, true),
        (zkminer_netguard::ProbeOutcome::Failed("Operation not permitted".into()), true),
    ] {
        let probe = zkminer_netguard::FixedProbe::answering(outcome.clone());
        let floor = NetPolicy::with_facts(NetMode::Public, facts(), deny.clone()).with_near_probe(probe.clone());
        let c = Connector::with_floor(&cfg, vec![], floor).unwrap();
        let (b, s) = session(&c);
        let (resp, fd) = blocking(move || {
            let r = request_blocking(&b, &req(1, 0, 8545)).unwrap();
            drop(b);
            r
        })
        .await;
        assert_eq!(resp.status == Status::Connected, !refused, "{outcome:?}: {resp:?}");
        assert!(fd.is_none());
        let addr: SocketAddr = "93.184.216.34:8545".parse().unwrap();
        assert_eq!(*probe.asked.lock().unwrap(), vec![(addr, 2)], "{outcome:?}");
        assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 0, "{outcome:?}: no connection was attempted");
        assert_eq!(s.await.unwrap(), SessionEnd::Closed);
    }
}

/// Review round 4, cross-6: the connection, once made, is checked again before the broker gets
/// it (`recheck_connected`): a route that is the default path when the address is vetted and
/// gone once connected closes it (no socket handed over); one that stays hands it over. A real
/// public peer (1.1.1.1:443; skipped where unreachable), a staged route oracle and probe.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_is_checked_again_once_made() {
    use zkminer_netguard::routes::{KernelAnswer, Route, RouteOracle};
    #[derive(Debug)]
    struct Flip {
        admitted: usize,
        asked: std::sync::atomic::AtomicUsize,
    }
    impl RouteOracle for Flip {
        fn route_to(&self, _: IpAddr, dport: Option<u16>) -> io::Result<KernelAnswer> {
            let default = Route::via("0.0.0.0/0".parse().unwrap(), "192.168.1.1".parse().unwrap(), 2);
            if dport.is_none() {
                return Ok(KernelAnswer::Entry(vec![default]));
            }
            let n = self.asked.fetch_add(1, Ordering::SeqCst);
            Ok(if n < self.admitted { KernelAnswer::Entry(vec![default]) } else { KernelAnswer::NoRoute })
        }
    }
    let peer: SocketAddr = "1.1.1.1:443".parse().unwrap();
    if std::net::TcpStream::connect_timeout(&peer, Duration::from_secs(5)).is_err() {
        skipped(&format!("{peer} unreachable here"));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let text = evm("p", "https://1.1.1.1:443", "");
    let cfg = BrokerConfig::from_toml_for_connector(&config_text(dir.path(), &text), dir.path(), NetMode::Public).expect("config");
    let deny = Connector::deny_for(&cfg, &[], &[]);
    for (admitted, connected) in [(1, false), (2, true)] {
        let facts = zkminer_netguard::HostFacts::assemble(
            zkminer_netguard::RawFacts {
                interface_prefixes: vec!["192.168.1.0/24".parse().unwrap()],
                interface_addresses: vec!["192.168.1.33".parse().unwrap()],
                routes: vec![Route::via("0.0.0.0/0".parse().unwrap(), "192.168.1.1".parse().unwrap(), 2)],
                ..Default::default()
            },
            &zkminer_netguard::FactsOptions {
                discover_public_addresses: false,
                public_addresses: vec!["198.51.99.7".parse().unwrap()],
                ..Default::default()
            },
        )
        .with_route_oracle(Arc::new(Flip { admitted, asked: Default::default() }));
        let floor = NetPolicy::with_facts(NetMode::Public, facts, deny.clone()).with_near_probe(zkminer_netguard::FixedProbe::far());
        let c = Connector::with_floor(&cfg, vec![], floor).unwrap();
        let (b, s) = session(&c);
        let (resp, fd) = blocking(move || {
            let r = request_blocking(&b, &req(1, 0, 443)).unwrap();
            drop(b);
            r
        })
        .await;
        assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 1, "connected once");
        assert_eq!(resp.status == Status::Connected, connected, "{admitted}: {resp:?}");
        assert_eq!(fd.is_some(), connected, "{admitted}");
        assert_eq!(s.await.unwrap(), SessionEnd::Closed);
    }
}

/// A listener that accepts every connection on a thread and keeps the accepted streams, so the
/// connector's connects complete.
struct Endpoint {
    port: u16,
    accepted: Arc<Mutex<Vec<std::net::TcpStream>>>,
}

impl Endpoint {
    fn start() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let accepted: Arc<Mutex<Vec<std::net::TcpStream>>> = Arc::default();
        let a = accepted.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                match s {
                    Ok(s) => lock(&a).push(s),
                    Err(_) => return,
                }
            }
        });
        Endpoint { port, accepted }
    }

    fn count(&self) -> usize {
        lock(&self.accepted).len()
    }

    /// Accepted connections whose other end (the connector's socket, wherever it is) is still
    /// open: no end-of-file within `wait`.
    fn still_open(&self, wait: Duration) -> usize {
        let until = std::time::Instant::now() + wait;
        let mut v = lock(&self.accepted);
        let mut open = 0;
        for s in v.iter_mut() {
            let left = until.saturating_duration_since(std::time::Instant::now()).max(Duration::from_millis(1));
            s.set_read_timeout(Some(left)).unwrap();
            let mut b = [0u8; 64];
            if let Err(e) = s.read(&mut b) {
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
                    open += 1;
                }
            }
        }
        open
    }
}

/// How many answers (each with its socket) the kernel queues for a broker that does not read
/// them, at the connector's send buffer (the kernel's minimum holds about six 40-byte frames).
const KERNEL_QUEUE_SLACK: u64 = 12;

/// A broker that sends requests and never reads an answer: an id stays in flight until its answer
/// is handed to the socket, so the broker reaches the in-flight bound and is cut off, having made
/// the connector connect no more than the bound, the answer being written and the few the kernel
/// queues. Every one of those sockets is closed once the broker's end is.
#[tokio::test(flavor = "multi_thread")]
async fn a_broker_that_never_reads_is_held_to_the_in_flight_bound() {
    let ep = Endpoint::start();
    let port = ep.port;
    let (c, _d) = connector_for(
        &evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024"),
        NetMode::DevPrivate,
        vec![],
    );
    let (b, s) = session(&c);
    // 20 a second, well under the bucket: only the in-flight bound can stop it.
    let writer = std::thread::spawn(move || {
        let mut sent = 0u64;
        for id in 0..400u64 {
            if (&b).write_all(&req(id, 0, port).encode()).is_err() {
                break;
            }
            sent += 1;
            std::thread::sleep(Duration::from_millis(50));
        }
        (sent, b)
    });
    let end = tokio::time::timeout(Duration::from_secs(15), s).await.expect("cut off in time").unwrap();
    assert_eq!(end, SessionEnd::CutOff(CutOff::Flood));
    let (sent, b) = blocking(move || writer.join().unwrap()).await;
    let connected = c.stats.connected.load(Ordering::Relaxed);
    println!("requests sent {sent}, connections made {connected}, endpoint accepts {}", ep.count());
    assert!(connected <= MAX_INFLIGHT as u64 + 1 + KERNEL_QUEUE_SLACK, "{connected} connections for a broker that reads nothing");
    assert!(sent <= MAX_INFLIGHT as u64 + 1 + KERNEL_QUEUE_SLACK + 2, "{sent} requests taken before the cut-off");
    // The broker's end goes (the miner kills a broker it cut off): every socket made for it closes.
    drop(b);
    assert_eq!(ep.still_open(Duration::from_secs(2)), 0);
}

/// A broker that keeps fewer requests than the bound in flight but never reads: the writer stalls,
/// and past the request budget the broker is cut off.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_answer_cuts_the_broker_off_after_the_request_budget() {
    let ep = Endpoint::start();
    let port = ep.port;
    let text = format!(
        "[timeouts]\nconnect_secs = 1\n{}",
        evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024")
    );
    let (c, _d) = connector_for(&text, NetMode::DevPrivate, vec![]);
    let (mut b, s) = session(&c);
    let n = 30u64;
    let mut frames = Vec::new();
    for id in 0..n {
        frames.extend_from_slice(&req(id, 0, port).encode());
    }
    b.write_all(&frames).unwrap();
    let started = std::time::Instant::now();
    let end = tokio::time::timeout(Duration::from_secs(40), s).await.expect("cut off in time").unwrap();
    let took = started.elapsed();
    assert_eq!(end, SessionEnd::CutOff(CutOff::AnswersStalled));
    let budget = request_budget(Duration::from_secs(1));
    assert!(took >= budget && took < budget + Duration::from_secs(5), "cut off after {took:?}, budget {budget:?}");
    assert!(c.stats.connected.load(Ordering::Relaxed) <= n);
    drop(b);
    assert_eq!(ep.still_open(Duration::from_secs(2)), 0);
}

/// A broker that shuts only the reading side of its socket: the first answer fails to write, and
/// the session ends in a cut-off, never quietly closed. Requests it sends afterwards are still
/// judged (misuse past the bound is a misuse cut-off) but never connected; if it just keeps its
/// end open, it is cut off for refusing answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_broker_that_shuts_its_reading_side_is_cut_off() {
    let ep = Endpoint::start();
    let port = ep.port;
    for misuse_after in [true, false] {
        let (c, _d) = connector_for(&evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
        let (b, s) = session(&c);
        let b = blocking(move || {
            b.shutdown(std::net::Shutdown::Read).unwrap();
            let mut w = &b;
            w.write_all(&req(1, 0, port).encode()).unwrap();
            // Time for the first answer's write to fail (the connector then serves nothing more).
            // Review round 6: 300 ms was too little under Rosetta with the whole suite running
            // (the first request answered after 290 ms: fix-r6/vm-gate-x86-broker-run*.log).
            std::thread::sleep(Duration::from_millis(1000));
            if misuse_after {
                // More requests for the endpoint, then misuse past the bound.
                for id in 2..7 {
                    let _ = w.write_all(&req(id, 0, port).encode());
                }
                for id in 100..100 + MAX_MISUSE as u64 + 3 {
                    let _ = w.write_all(&req(id, 999, port).encode());
                }
            }
            b
        })
        .await;
        let end = tokio::time::timeout(Duration::from_secs(10), s).await.expect("ended in time").unwrap();
        let want = if misuse_after { CutOff::Misuse } else { CutOff::AnswersRefused };
        assert_eq!(end, SessionEnd::CutOff(want), "misuse after the shut: {misuse_after}");
        assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 1, "only the first request was connected");
        drop(b);
    }
    assert_eq!(ep.still_open(Duration::from_secs(2)), 0);
}

/// A broker that exits with requests in flight (its whole end closes) ends the session closed,
/// not cut off, whether its answers were being written or not.
#[tokio::test(flavor = "multi_thread")]
async fn a_broker_that_exits_mid_request_ends_closed() {
    let ep = Endpoint::start();
    let port = ep.port;
    let (c, _d) = connector_for(
        &evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024"),
        NetMode::DevPrivate,
        vec![],
    );
    for n in [1u64, 10, 40] {
        let (mut b, s) = session(&c);
        let mut frames = Vec::new();
        for id in 0..n {
            frames.extend_from_slice(&req(id, 0, port).encode());
        }
        b.write_all(&frames).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        drop(b);
        let end = tokio::time::timeout(Duration::from_secs(10), s).await.expect("ended in time").unwrap();
        assert_eq!(end, SessionEnd::Closed, "{n} requests");
    }
    assert_eq!(ep.still_open(Duration::from_secs(2)), 0);
}

/// At a cut-off the broker's socket is shut, and the answer writer stopped, before anything else:
/// answers still queued for a broker that was not reading (each with a socket connected for it)
/// never reach it. Reading after the cut-off, it finds at most what the kernel already held, then
/// the end of the stream; every socket made for it is closed once its end is.
#[tokio::test(flavor = "multi_thread")]
async fn a_cut_off_delivers_no_queued_answer() {
    let ep = Endpoint::start();
    let port = ep.port;
    let (c, _d) = connector_for(
        &evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]\nmax_concurrency = 1024"),
        NetMode::DevPrivate,
        vec![],
    );
    let (b, s) = session(&c);
    let n = 40u64;
    let mut frames = Vec::new();
    for id in 0..n {
        frames.extend_from_slice(&req(id, 0, port).encode());
    }
    (&b).write_all(&frames).unwrap();
    // Every request connected: their answers are written or queued, none read.
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while c.stats.connected.load(Ordering::Relaxed) < n && std::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(c.stats.connected.load(Ordering::Relaxed), n);
    (&b).write_all(&[0x41; REQUEST_LEN]).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(10), s).await.expect("cut off in time").unwrap();
    assert!(matches!(end, SessionEnd::CutOff(CutOff::Malformed(_))), "{end:?}");
    let (bytes, fds) = blocking(move || {
        use std::os::fd::AsRawFd;
        let mut bytes = 0usize;
        let mut fds = 0usize;
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let mut got = Vec::new();
            match crate::fdpass::recvmsg_once(b.as_raw_fd(), &mut buf, &mut got) {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    bytes += k;
                    fds += got.len();
                }
            }
        }
        (bytes, fds)
    })
    .await;
    let answers = (bytes / RESPONSE_LEN) as u64;
    println!("answers read after the cut-off: {answers} ({fds} sockets), of {n}");
    assert!(answers <= KERNEL_QUEUE_SLACK, "{answers} answers reached a broker after its cut-off");
    assert_eq!(ep.still_open(Duration::from_secs(2)), 0);
}

/// Requests still being served when the broker is cut off are aborted: one waiting for a token of
/// the bucket is never connected (and, without the cut-off, the same request is).
#[tokio::test(flavor = "multi_thread")]
async fn requests_in_flight_at_a_cut_off_are_aborted() {
    let ep = Endpoint::start();
    let port = ep.port;
    let (c, _d) = connector_for(&evm("n", &format!("http://127.0.0.1:{port}"), "cidrs = [\"127.0.0.1/32\"]"), NetMode::DevPrivate, vec![]);
    let empty_the_bucket = |c: &Connector| {
        let mut b = lock(&c.bucket);
        // About 0.7 s until the next token.
        b.tokens = -10.0;
        b.at = Instant::now();
    };
    // Control: the request waits for its token, then connects.
    empty_the_bucket(&c);
    let (b, s) = session(&c);
    let (r, fd) = blocking(move || request_blocking(&b, &req(1, 0, port)).unwrap()).await;
    assert_eq!((r.status, fd.is_some()), (Status::Connected, true));
    assert!(s.await.is_ok());
    assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 1);
    // The same request with a malformed frame right behind it: cut off while it waits.
    empty_the_bucket(&c);
    let (mut b, s) = session(&c);
    let mut frames = req(2, 0, port).encode().to_vec();
    frames.extend_from_slice(&[0x41; REQUEST_LEN]);
    b.write_all(&frames).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(10), s).await.expect("cut off in time").unwrap();
    assert!(matches!(end, SessionEnd::CutOff(CutOff::Malformed(_))), "{end:?}");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 1, "the request in flight at the cut-off was connected");
    assert_eq!(ep.count(), 1);
}

/// The session races its frame reader against the answer writer and a deadline: a read cancelled
/// in the middle of a frame keeps the bytes it had, so the next read completes the same frame
/// (losing them would put every later frame out of step).
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_read_keeps_the_partial_frame() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    ours.set_nonblocking(true).unwrap();
    let ours = tokio::net::UnixStream::from_std(ours).unwrap();
    let mut frames = FrameReader::default();
    let first = req(7, 0, 9).encode();
    let second = req(8, 0, 9).encode();
    theirs.write_all(&first[..13]).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(100), frames.read(&ours)).await.is_err(), "half a frame is not a frame");
    theirs.write_all(&first[13..20]).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(100), frames.read(&ours)).await.is_err());
    theirs.write_all(&first[20..]).unwrap();
    theirs.write_all(&second).unwrap();
    for want in [first, second] {
        let got = tokio::time::timeout(Duration::from_secs(1), frames.read(&ours)).await.unwrap();
        assert!(matches!(got, Ok(Some(f)) if f == want));
    }
    drop(theirs);
    assert!(matches!(frames.read(&ours).await, Ok(None)));
}

/// A probe that takes `delay` and then finds the destination far (a slow path, review round 5,
/// probe-1).
#[derive(Debug)]
struct SlowFar {
    delay: Duration,
    asked: Mutex<Vec<SocketAddr>>,
}

impl zkminer_netguard::NearProbe for SlowFar {
    #[allow(clippy::too_many_arguments)]
    fn round(
        &self,
        round: u32,
        addr: SocketAddr,
        hops: u8,
        extra: u8,
        pin: &zkminer_netguard::nearhop::Pin,
        wait: Duration,
        deadline: std::time::Instant,
    ) -> Result<Vec<zkminer_netguard::nearhop::Obs>, String> {
        lock(&self.asked).push(addr);
        std::thread::sleep(self.delay);
        zkminer_netguard::FixedProbe::far().round(round, addr, hops, extra, pin, wait, deadline)
    }
}

/// Review round 5, probe-1: a near-hop check that takes 3.6 s (a silent hop at the limit) no
/// longer outlives the per-address share of the connect time (5 s / 2 addresses): the check runs
/// within the request's time, the share bounds only the TCP connect, so the first of two far
/// addresses is connected to. Real public peers (1.1.1.1 and 1.0.0.1 on 443; skipped where
/// unreachable), resolved by a test DNS server.
#[tokio::test(flavor = "multi_thread")]
async fn r5_a_slow_near_hop_check_does_not_lose_its_address() {
    use crate::testkit::TestDns;
    let peers: [SocketAddr; 2] = ["1.1.1.1:443".parse().unwrap(), "1.0.0.1:443".parse().unwrap()];
    if peers.iter().any(|p| std::net::TcpStream::connect_timeout(p, Duration::from_secs(5)).is_err()) {
        skipped(&format!("{peers:?} unreachable here"));
        return;
    }
    let dns = TestDns::start(&[("rpc.example.com", &["1.1.1.1", "1.0.0.1"])]).await;
    let dir = tempfile::tempdir().unwrap();
    let text = evm("p", "https://rpc.example.com:443", "");
    let cfg = BrokerConfig::from_toml_for_connector(&config_text(dir.path(), &text), dir.path(), NetMode::Public).expect("config");
    assert_eq!(cfg.timeouts.connect(), Duration::from_secs(5));
    let deny = Connector::deny_for(&cfg, &[], &[dns.addr]);
    let probe = Arc::new(SlowFar { delay: Duration::from_millis(3600), asked: Mutex::new(Vec::new()) });
    let floor = NetPolicy::with_facts(NetMode::Public, facts(), deny).with_near_probe(probe.clone());
    let c = Connector::with_floor(&cfg, vec![dns.addr], floor).unwrap();
    let (b, s) = session(&c);
    let t = std::time::Instant::now();
    let (resp, fd) = blocking(move || {
        let r = request_blocking(&b, &req(1, 0, 443)).unwrap();
        drop(b);
        r
    })
    .await;
    eprintln!("{resp:?} after {:?}; probed {:?}", t.elapsed(), lock(&probe.asked));
    assert_eq!(resp.status, Status::Connected, "{resp:?}");
    assert!(fd.is_some());
    assert_eq!(c.stats.attempts.load(Ordering::Relaxed), 1);
    assert_eq!(s.await.unwrap(), SessionEnd::Closed);
}

/// Review round 5, bypass-5: an IPv4-mapped address is connected to on an IPv4 socket, from the
/// IPv4 source the check vetted (an IPv6 socket bound to it failed with EINVAL).
#[tokio::test(flavor = "multi_thread")]
async fn r5_an_ipv4_mapped_address_is_connected_as_ipv4() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{port}").parse().unwrap();
    let vetted = zkminer_netguard::Vetted::staged(mapped, mapped, Some("127.0.0.1".parse().unwrap()), None);
    let fd = connect_tcp(mapped, Some(&vetted)).await.expect("connected");
    let stream = std::net::TcpStream::from(fd);
    assert_eq!(stream.peer_addr().unwrap(), format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap());
    assert!(stream.local_addr().unwrap().is_ipv4());
    let fd = connect_tcp(mapped, None).await.expect("connected without a source too");
    assert!(std::net::TcpStream::from(fd).local_addr().unwrap().is_ipv4());
}

/// A probe on a host one of whose families is blackholed: every round of probes of an address of
/// that family takes `delay` (within the deadline) and finds no evidence; the other family is far.
#[derive(Debug)]
struct Blackholed {
    v6: bool,
    delay: Duration,
    asked: Mutex<Vec<SocketAddr>>,
}

impl zkminer_netguard::NearProbe for Blackholed {
    #[allow(clippy::too_many_arguments)]
    fn round(
        &self,
        round: u32,
        addr: SocketAddr,
        hops: u8,
        extra: u8,
        pin: &zkminer_netguard::nearhop::Pin,
        wait: Duration,
        deadline: std::time::Instant,
    ) -> Result<Vec<zkminer_netguard::nearhop::Obs>, String> {
        if round == 0 {
            lock(&self.asked).push(addr);
        }
        if addr.is_ipv6() == self.v6 {
            std::thread::sleep(self.delay.min(deadline.saturating_duration_since(std::time::Instant::now())));
            return zkminer_netguard::FixedProbe::answering(zkminer_netguard::ProbeOutcome::TimedOut)
                .round(round, addr, hops, extra, pin, wait, deadline);
        }
        zkminer_netguard::FixedProbe::far().round(round, addr, hops, extra, pin, wait, deadline)
    }
}

/// Review round 6, cross-6 (a regression against pr/37): the connector vetted an endpoint's
/// addresses one after another, each check given the whole 17 s budget, so a blackholed family
/// whose addresses came first (~13.5 s a check) left the other no time. The resolver answers A
/// first, so the staged case is a blackholed IPv4 path with IPv6 working (the reviewer's IPv6
/// case is the same with the families swapped). The families are vetted at once now (the other
/// FAMILY_DELAY later), and a family stops after MAX_UNANSWERED checks that could not tell.
/// Real public peers (skipped where unreachable: `[ipv6]` where this host has no IPv6).
#[tokio::test(flavor = "multi_thread")]
async fn r6_a_blackholed_family_does_not_starve_the_other() {
    use crate::testkit::TestDns;
    let v6: [SocketAddr; 2] = ["[2606:4700:4700::1111]:443".parse().unwrap(), "[2606:4700:4700::1001]:443".parse().unwrap()];
    if v6.iter().any(|p| std::net::TcpStream::connect_timeout(p, Duration::from_secs(5)).is_err()) {
        skipped(&format!("[ipv6] {v6:?} unreachable here"));
        return;
    }
    let dns = TestDns::start(&[(
        "rpc.example.com",
        &["1.1.1.1", "1.0.0.1", "1.1.1.2", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    )])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let text = evm("p", "https://rpc.example.com:443", "");
    let cfg = BrokerConfig::from_toml_for_connector(&config_text(dir.path(), &text), dir.path(), NetMode::Public).expect("config");
    let deny = Connector::deny_for(&cfg, &[], &[dns.addr]);
    let probe = Arc::new(Blackholed { v6: false, delay: Duration::from_millis(13_500), asked: Mutex::new(Vec::new()) });
    let floor = NetPolicy::with_facts(NetMode::Public, facts(), deny).with_near_probe(probe.clone());
    let c = Connector::with_floor(&cfg, vec![dns.addr], floor).unwrap();
    let (b, s) = session(&c);
    let t = std::time::Instant::now();
    let (resp, fd) = blocking(move || {
        let r = request_blocking(&b, &req(1, 0, 443)).unwrap();
        drop(b);
        r
    })
    .await;
    let took = t.elapsed();
    eprintln!("{resp:?} after {took:?}; probed {:?}", lock(&probe.asked));
    assert_eq!(resp.status, Status::Connected, "{resp:?}");
    assert!(resp.peer.is_some_and(|p| p.is_ipv6()), "{resp:?}");
    assert!(fd.is_some());
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert_eq!(s.await.unwrap(), SessionEnd::Closed);
}
