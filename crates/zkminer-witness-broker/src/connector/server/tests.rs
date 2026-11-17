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
