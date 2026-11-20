//! One hop of a guarded request on a connection of its own (review round 4, bypass-2): the TCP
//! connection to a vetted address, checked once made ([`NetPolicy::recheck_connected`]), then,
//! for `https`, the TLS handshake, then one HTTP/1.1 exchange. Before review round 4 reqwest made
//! the connection and the TLS handshake inside its connector and the check ran on what it
//! returned, so a ClientHello (naming the requester's host) had already gone out on a connection
//! the check then refused, and that refusal surfaced as an HTTP error. Now nothing is written on
//! a connection before it is checked, and a refusal is [`Denied::PathChanged`]. The response is
//! handed back as a [`reqwest::Response`] (its body read through [`Bounded`]: every read within
//! the read timeout, the whole within the deadline).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{ClientOptions, FetchError, RecheckLayer, USER_AGENT};
use crate::policy::Denied;

/// The TLS configuration of every hop: rustls (ring) with the compiled-in web roots, HTTP/1.1
/// offered by ALPN.
pub(super) fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}

/// A hop's connection: plain TCP, or TLS over it.
enum Stream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn failed(what: &str, e: impl std::fmt::Display) -> FetchError {
    FetchError::Connection(format!("{what}: {}", crate::printable(&e.to_string(), 300)))
}

/// [`failed`] for an error with a chain of sources, each named.
fn failed_with(what: &str, e: &(dyn std::error::Error + 'static)) -> FetchError {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    failed(what, text)
}

/// How long after one address's attempt the next one starts while the first has neither
/// connected nor failed (RFC 8305's connection attempt delay, 250 ms).
pub(super) const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// When one attempt's connect must have finished: its connect timeout from `now`, within the
/// request's `deadline`.
pub(super) fn attempt_limit(
    now: tokio::time::Instant,
    connect_timeout: Duration,
    deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    (now + connect_timeout).min(deadline)
}

/// A TCP connection to one of `pinned` (at most one per family: [`super::GuardedClient`]'s pin),
/// raced as RFC 8305 says (review round 5, cross-2): IPv6 first, the next address
/// [`ATTEMPT_DELAY`] later or as soon as the one before failed, each within its own connect
/// timeout and `deadline`, from the source address it was vetted with (review round 4, cross-3:
/// the source the kernel chose for the vetted path, so a rule that picks a path by protocol
/// cannot make the check's source and the connection's differ), and checked once made
/// ([`RecheckLayer::check`]) before anything is written on it. The first that connects and
/// passes the check is used; every other attempt is dropped then (closed before a byte is
/// written). A check that refuses a connection refuses the hop (a path that changed is not
/// retried elsewhere). When none connects, the error names every address's failure. Before
/// round 5 the addresses were tried one after another with the whole connect timeout each, so a
/// blackholed IPv6 path added 15 s to every hop.
pub(super) async fn connect_checked(
    pinned: &[SocketAddr],
    recheck: &RecheckLayer,
    options: &ClientOptions,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, FetchError> {
    let recheck = recheck.clone();
    let options = *options;
    race(pinned, ATTEMPT_DELAY, move |addr| {
        let recheck = recheck.clone();
        async move { attempt(addr, &recheck, &options, deadline).await }
    })
    .await
}

/// The race of [`connect_checked`] over `pinned` (IPv6 first), each address's `attempt` started
/// `delay` after the one before, or at once when that one failed.
pub(super) async fn race<T, F, Fut>(
    pinned: &[SocketAddr],
    delay: Duration,
    attempt: F,
) -> Result<T, FetchError>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, FetchError>> + Send + 'static,
{
    let mut order: Vec<SocketAddr> = pinned.to_vec();
    order.sort_by_key(|a| !super::unmapped(*a).is_ipv6());
    let mut running = tokio::task::JoinSet::new();
    let mut failures: Vec<String> = Vec::new();
    let mut next = 0;
    let mut start_next = tokio::time::Instant::now();
    loop {
        if next < order.len() && (running.is_empty() || tokio::time::Instant::now() >= start_next)
        {
            running.spawn(attempt(order[next]));
            next += 1;
            start_next = tokio::time::Instant::now() + delay;
        }
        if running.is_empty() {
            break;
        }
        tokio::select! {
            done = running.join_next() => match done {
                Some(Ok(Ok(won))) => return Ok(won),
                Some(Ok(Err(FetchError::Connection(why)))) => {
                    failures.push(why);
                    // The next address at once.
                    start_next = tokio::time::Instant::now();
                }
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => failures.push(format!("a connection attempt did not finish: {e}")),
                None => {}
            },
            _ = tokio::time::sleep_until(start_next), if next < order.len() => {}
        }
    }
    Err(if failures.is_empty() {
        FetchError::BadRedirect("no address to connect to")
    } else {
        FetchError::Connection(crate::printable(&failures.join("; "), 600))
    })
}

/// One address's attempt of [`connect_checked`]: the connection, then its check.
async fn attempt(
    addr: SocketAddr,
    recheck: &RecheckLayer,
    options: &ClientOptions,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, FetchError> {
    let source = recheck.source_of(addr);
    let connect = async {
        let sock = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        if let Some(src) = source {
            sock.bind(SocketAddr::new(src, 0))?;
        }
        sock.connect(addr).await
    };
    let limit = attempt_limit(tokio::time::Instant::now(), options.connect_timeout, deadline);
    let tcp = match tokio::time::timeout_at(limit, connect).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => return Err(failed(&format!("connecting to {addr}"), e)),
        Err(_) => return Err(failed(&format!("connecting to {addr}"), "timed out")),
    };
    let (local, peer) = match (tcp.local_addr(), tcp.peer_addr()) {
        (Ok(l), Ok(p)) => (l, p),
        _ => {
            return Err(FetchError::Denied(Denied::PathChanged {
                addr,
                why: "the connection's own addresses could not be read".into(),
            }))
        }
    };
    recheck
        .check(local, peer)
        .await
        .map_err(FetchError::Denied)?;
    Ok(tcp)
}

/// One request on a connection of its own (see the module doc): `method` to `url` (whose host
/// is `name`, or its IP literal), connected to the first of `pinned` that connects, with `body`
/// (a POST's, with its content type) when given; the response head within `deadline` and the
/// read timeout, its body bounded by both ([`Bounded`]).
#[allow(clippy::too_many_arguments)]
pub(super) async fn send(
    tls: &Arc<rustls::ClientConfig>,
    options: &ClientOptions,
    method: http::Method,
    url: &url::Url,
    pinned: &[SocketAddr],
    recheck: &RecheckLayer,
    body: Option<(Vec<u8>, &'static str)>,
    deadline: Instant,
) -> Result<reqwest::Response, FetchError> {
    let deadline = tokio::time::Instant::from_std(deadline);
    let host = url.host_str().ok_or(FetchError::BadRedirect("a URL without a host"))?;
    let stream = async {
        let tcp = connect_checked(pinned, recheck, options, deadline).await?;
        if url.scheme() != "https" {
            return Ok::<Stream, FetchError>(Stream::Plain(tcp));
        }
        let name = match url.host() {
            Some(url::Host::Ipv4(a)) => rustls::pki_types::ServerName::from(std::net::IpAddr::V4(a)),
            Some(url::Host::Ipv6(a)) => rustls::pki_types::ServerName::from(std::net::IpAddr::V6(a)),
            _ => rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| failed("the host name for TLS", e))?,
        };
        // Review round 5, parse-1: the handshake within the connect timeout (as reqwest's
        // connector bounded it before round 4), not only the request's whole time.
        let by = (tokio::time::Instant::now() + options.connect_timeout).min(deadline);
        let tls = tokio::time::timeout_at(by, tokio_rustls::TlsConnector::from(tls.clone()).connect(name, tcp))
            .await
            .map_err(|_| failed("the TLS handshake", "timed out"))?
            .map_err(|e| failed_with("the TLS handshake", &e))?;
        Ok(Stream::Tls(Box::new(tls)))
    };
    let stream = tokio::time::timeout_at(deadline, stream)
        .await
        .map_err(|_| FetchError::TimedOut)??;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| failed_with("HTTP/1.1", &e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut target = url.path().to_string();
    if let Some(q) = url.query() {
        target.push('?');
        target.push_str(q);
    }
    let authority = match url.port() {
        Some(p) => format!("{}:{p}", host),
        None => host.to_string(),
    };
    let mut req = http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, authority)
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_ENCODING, "identity");
    let body = match body {
        Some((bytes, content_type)) => {
            req = req
                .header(http::header::CONTENT_TYPE, content_type)
                .header(http::header::CONTENT_LENGTH, bytes.len());
            reqwest::Body::from(bytes)
        }
        None => reqwest::Body::from(Vec::new()),
    };
    let req = req.body(body).map_err(|e| failed("the request", e))?;
    let head_by = (tokio::time::Instant::now() + options.read_timeout).min(deadline);
    let response = tokio::time::timeout_at(head_by, sender.send_request(req))
        .await
        .map_err(|_| FetchError::TimedOut)?
        .map_err(|e| failed_with("the response", &e))?;
    let (parts, incoming) = response.into_parts();
    let mut b = http::Response::builder()
        .status(parts.status)
        .version(parts.version);
    if let Some(h) = b.headers_mut() {
        *h = parts.headers;
    }
    use reqwest::ResponseBuilderExt;
    let r = b
        .url(url.clone())
        .body(reqwest::Body::wrap(Bounded::new(
            incoming,
            options.read_timeout,
            deadline,
        )))
        .map_err(|e| failed("the response", e))?;
    Ok(reqwest::Response::from(r))
}

/// A response body read within `read_timeout` per read and `deadline` in all (what reqwest's
/// read and request timeouts did).
pub(super) struct Bounded<B> {
    inner: B,
    read_timeout: Duration,
    idle: Pin<Box<tokio::time::Sleep>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<B> Bounded<B> {
    pub(super) fn new(inner: B, read_timeout: Duration, deadline: tokio::time::Instant) -> Self {
        Bounded {
            inner,
            read_timeout,
            idle: Box::pin(tokio::time::sleep(read_timeout)),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }
}

impl<B> http_body::Body for Bounded<B>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = bytes::Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "the request's time ran out while its body was read",
            )))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let next = tokio::time::Instant::now() + this.read_timeout;
                this.idle.as_mut().reset(next);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if this.idle.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(Box::new(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "a read of the response body timed out",
                    )))));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A body whose frames come from a channel.
    struct Chan(tokio::sync::mpsc::Receiver<bytes::Bytes>);

    impl http_body::Body for Chan {
        type Data = bytes::Bytes;
        type Error = io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<bytes::Bytes>, io::Error>>> {
            self.0
                .poll_recv(cx)
                .map(|b| b.map(|b| Ok(http_body::Frame::data(b))))
        }
    }

    async fn read_all(b: &mut Bounded<Chan>) -> Result<usize, String> {
        use http_body::Body;
        let mut n = 0;
        loop {
            match std::future::poll_fn(|cx| Pin::new(&mut *b).poll_frame(cx)).await {
                Some(Ok(f)) => n += f.into_data().map_or(0, |d| d.len()),
                Some(Err(e)) => return Err(e.to_string()),
                None => return Ok(n),
            }
        }
    }

    /// Review round 5, cross-2: the hop's addresses race (RFC 8305): IPv6 first, IPv4
    /// [`ATTEMPT_DELAY`] later (or at once when IPv6 failed); the first to connect and pass its
    /// check wins and the other attempt is dropped; a refusal by the check refuses the hop; when
    /// every address fails, every failure is named.
    #[tokio::test]
    async fn r5_the_addresses_race_ipv6_first() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;
        let v6: SocketAddr = "[2606:2800:220:1::1]:443".parse().unwrap();
        let v4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        // A blackholed IPv6 path: the IPv4 attempt starts 250 ms later and wins; the IPv6 one is
        // dropped.
        let dropped = Arc::new(AtomicBool::new(false));
        let started: Arc<Mutex<Vec<(SocketAddr, Duration)>>> = Arc::default();
        let t0 = tokio::time::Instant::now();
        let (d, st) = (dropped.clone(), started.clone());
        let won = race(&[v4, v6], ATTEMPT_DELAY, move |a| {
            let (d, st) = (d.clone(), st.clone());
            async move {
                st.lock().unwrap().push((a, t0.elapsed()));
                if a.is_ipv6() {
                    let _f = Flag(d);
                    std::future::pending::<()>().await;
                }
                Ok(a)
            }
        })
        .await
        .unwrap();
        assert_eq!(won, v4);
        let started = started.lock().unwrap().clone();
        assert_eq!(started[0].0, v6, "IPv6 first");
        assert!(started[1].1 >= ATTEMPT_DELAY && started[1].1 < Duration::from_secs(2), "{started:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(dropped.load(Ordering::SeqCst), "the losing attempt was dropped");
        // IPv6 fails at once: IPv4 starts at once.
        let t0 = tokio::time::Instant::now();
        let won = race(&[v6, v4], Duration::from_secs(5), |a| async move {
            if a.is_ipv6() {
                Err(FetchError::Connection(format!("connecting to {a}: refused")))
            } else {
                Ok(a)
            }
        })
        .await
        .unwrap();
        assert_eq!(won, v4);
        assert!(t0.elapsed() < Duration::from_secs(1));
        // Both fail: both named.
        let e = race(&[v6, v4], ATTEMPT_DELAY, |a| async move {
            Err::<SocketAddr, _>(FetchError::Connection(format!("connecting to {a}: timed out")))
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains(&v6.to_string()) && e.contains(&v4.to_string()), "{e}");
        // The check refuses the first connection: the hop is refused, the other never used.
        let e = race(&[v6, v4], ATTEMPT_DELAY, |a| async move {
            if a.is_ipv6() {
                Err(FetchError::Denied(Denied::PathChanged {
                    addr: a,
                    why: "test".into(),
                }))
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(a)
            }
        })
        .await
        .unwrap_err();
        assert!(e.is_denied(), "{e}");
        // One address: just it.
        assert_eq!(race(&[v4], ATTEMPT_DELAY, |a| async move { Ok(a) }).await.unwrap(), v4);
    }

    /// cross-3 (`hop.rs:126`): an attempt's connect is bounded by its connect timeout and by
    /// the request's deadline, whichever comes first.
    #[test]
    fn r5_an_attempt_is_bounded_by_the_deadline_too() {
        let now = tokio::time::Instant::now();
        let soon = now + Duration::from_secs(2);
        assert_eq!(attempt_limit(now, Duration::from_secs(15), soon), soon);
        assert_eq!(
            attempt_limit(now, Duration::from_secs(1), soon),
            now + Duration::from_secs(1)
        );
    }

    /// The body's read timeout counts from the last read (a body that keeps coming, a chunk
    /// every 300 ms, outlives a 500 ms read timeout); one silent for longer fails; the
    /// request's deadline bounds the whole.
    #[tokio::test]
    async fn the_body_is_bounded_per_read_and_in_all() {
        let feed = |gap: u64, n: usize| {
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                for _ in 0..n {
                    tokio::time::sleep(Duration::from_millis(gap)).await;
                    if tx.send(bytes::Bytes::from_static(b"abc")).await.is_err() {
                        return;
                    }
                }
            });
            Chan(rx)
        };
        let far = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut b = Bounded::new(feed(300, 4), Duration::from_millis(500), far);
        assert_eq!(read_all(&mut b).await, Ok(12));
        let mut b = Bounded::new(feed(800, 2), Duration::from_millis(500), far);
        assert!(read_all(&mut b).await.unwrap_err().contains("timed out"));
        let soon = tokio::time::Instant::now() + Duration::from_millis(700);
        let mut b = Bounded::new(feed(300, 4), Duration::from_millis(500), soon);
        assert!(read_all(&mut b).await.unwrap_err().contains("time ran out"));
    }
}
