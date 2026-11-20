//! The guarded HTTP client for requester-controlled URLs.
//!
//! [`guarded_client`] builds a client that:
//!
//! - refuses every URL that fails [`crate::check_url`] before anything else happens;
//! - resolves every name itself, once per hop, through the [`GuardedResolver`] (in public mode
//!   over DNS-over-HTTPS to fixed public resolvers, [`crate::doh`]; the system resolver in
//!   developer mode), keeping only the admitted addresses;
//! - **vets each address right before connecting** ([`NetPolicy::vet_connection`]): its route
//!   asked of the kernel with the destination port, then the near-hop probe
//!   ([`crate::nearhop`]), and connects only to the addresses that pass: each hop gets an HTTP
//!   client pinned to exactly those addresses (reqwest resolves nothing itself, and an IP-literal
//!   host is vetted the same way);
//! - **checks each connection once made**, before any request byte is written on it
//!   ([`NetPolicy::recheck_connected`], a connector layer: the connection's own peer and source
//!   addresses must be the vetted ones, and the destination is admitted again with the kernel
//!   asked afresh), and drops it otherwise: a route or VPN that changed between the check and the
//!   connection is seen (the Linux application of review round 2, bypass-3, every platform). For
//!   `https` the TLS handshake (its ClientHello names the host) runs inside reqwest's connector,
//!   before this check; no HTTP request does;
//! - ignores proxies, from the environment or the system (a proxy resolves the name itself and
//!   would reach whatever it can);
//! - follows no redirect itself: [`GuardedClient::get_following_redirects`] follows them by hand,
//!   each hop checked like the first, within a hop limit and one time budget for the whole chain;
//! - uses rustls with compiled-in web roots, HTTP/1.1 only, and no connection reuse (a pooled
//!   connection would outlive the decision that made it);
//! - asks for and decodes no compression (`Accept-Encoding: identity`; a server that compresses
//!   anyway hands back the compressed bytes, which the caller's size cap and hash check bound);
//! - sends a constant `User-Agent: zkminer`, no version, and no `Referer`;
//! - bounds connecting and every read ([`ClientOptions`]); callers bound the whole request.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT_ENCODING, LOCATION};
use reqwest::StatusCode;

use crate::policy::{Denied, NetMode, NetPolicy, UrlDenied, Vetted};
use crate::resolve::{GuardedResolver, Lookup, ResolveError, SystemLookup};

/// The `User-Agent` of every guarded request. Constant and versionless, so it says nothing about
/// the build; some stores (Arweave's gateways) refuse a request without one.
pub const USER_AGENT: &str = "zkminer";

/// Timeouts of a guarded client.
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// For connecting.
    pub connect_timeout: Duration,
    /// For each read of the response.
    pub read_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(30),
        }
    }
}

/// An HTTP client for requester-controlled URLs: see the module doc.
#[derive(Clone)]
pub struct GuardedClient {
    resolver: GuardedResolver,
    options: ClientOptions,
}

impl fmt::Debug for GuardedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedClient")
            .field("mode", &self.resolver.policy().mode())
            .finish_non_exhaustive()
    }
}

/// The guarded client for `policy`: in public mode it resolves names over DNS-over-HTTPS
/// ([`crate::doh::DohLookup`]), in developer mode through the system resolver.
pub fn guarded_client(policy: &NetPolicy) -> Result<GuardedClient, reqwest::Error> {
    let lookup: Arc<dyn Lookup> = match policy.mode() {
        NetMode::Public => Arc::new(crate::doh::DohLookup::new(policy)?),
        NetMode::DevPrivate => Arc::new(SystemLookup),
    };
    guarded_client_with(policy, lookup, ClientOptions::default())
}

/// [`guarded_client`] with a lookup of the caller's (a fake, in tests) and its own timeouts.
pub fn guarded_client_with(
    policy: &NetPolicy,
    lookup: Arc<dyn Lookup>,
    options: ClientOptions,
) -> Result<GuardedClient, reqwest::Error> {
    build(GuardedResolver::new(policy.clone(), lookup), options)
}

/// [`guarded_client_with`] whose resolver connects to `map(ip)` for each admitted `ip`, so a server
/// on loopback can stand in for a public address in a public-mode test (the policy's near-hop
/// probe should then be a fake one too: [`NetPolicy::with_near_probe`]). Test builds only (the
/// `test-util` feature, which only `[dev-dependencies]` enable).
#[cfg(any(test, feature = "test-util"))]
pub fn guarded_client_for_test(
    policy: &NetPolicy,
    lookup: Arc<dyn Lookup>,
    map: crate::resolve::ConnectMap,
    options: ClientOptions,
) -> Result<GuardedClient, reqwest::Error> {
    build(
        GuardedResolver::new(policy.clone(), lookup).with_connect_map(map),
        options,
    )
}

fn build(
    resolver: GuardedResolver,
    options: ClientOptions,
) -> Result<GuardedClient, reqwest::Error> {
    // Built once here so a configuration error shows now rather than at the first fetch.
    hop_client(None, &[], options, None)?;
    Ok(GuardedClient { resolver, options })
}

/// reqwest's resolver for a hop's client: the hop's name is pinned to its vetted addresses, so
/// any name that reaches this is refused.
struct NoNames;

impl reqwest::dns::Resolve for NoNames {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Err::<reqwest::dns::Addrs, _>("a guarded hop resolves no other name".into())
        })
    }
}

/// The check of each connection once made ([`NetPolicy::recheck_connected`]), as a reqwest
/// connector layer: its service connects as reqwest's does (TCP, and TLS for `https`), then reads
/// the connection's own addresses (hyper-util's `HttpInfo`: `getsockname`, `getpeername`) and
/// hands the connection on only if the check admits it, before anything is written on it.
#[derive(Clone)]
struct RecheckLayer {
    policy: NetPolicy,
    vetted: Arc<[Vetted]>,
}

impl RecheckLayer {
    /// The check for a connection whose own addresses are `local` and `peer` (on the blocking
    /// pool: it asks the kernel).
    async fn check(&self, local: SocketAddr, peer: SocketAddr) -> Result<(), Denied> {
        let Some(vetted) = self
            .vetted
            .iter()
            .find(|v| v.connect == unmapped(peer))
            .cloned()
        else {
            return Err(Denied::PathChanged {
                addr: peer,
                why: "it reached an address that was not vetted".into(),
            });
        };
        let policy = self.policy.clone();
        let addr = vetted.addr;
        tokio::task::spawn_blocking(move || policy.recheck_connected(&vetted, local, peer))
            .await
            .unwrap_or_else(|e| {
                Err(Denied::PathChanged {
                    addr,
                    why: format!("the check did not finish: {e}"),
                })
            })
    }
}

fn unmapped(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(a, |v4| SocketAddr::new(IpAddr::V4(v4), a.port())),
        IpAddr::V4(_) => a,
    }
}

impl<S> tower_layer::Layer<S> for RecheckLayer {
    type Service = Recheck<S>;

    fn layer(&self, inner: S) -> Recheck<S> {
        Recheck {
            inner,
            check: self.clone(),
        }
    }
}

/// [`RecheckLayer`]'s service.
#[derive(Clone)]
struct Recheck<S> {
    inner: S,
    check: RecheckLayer,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<S, Req> tower_service::Service<Req> for Recheck<S>
where
    S: tower_service::Service<Req>,
    S::Response: hyper_util::client::legacy::connect::Connection + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<S::Response, BoxError>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let connecting = self.inner.call(req);
        let check = self.check.clone();
        Box::pin(async move {
            let conn = connecting.await.map_err(Into::into)?;
            let mut extras = http::Extensions::new();
            use hyper_util::client::legacy::connect::Connection;
            conn.connected().get_extras(&mut extras);
            let denied = |d: Denied| -> BoxError { Box::new(ResolveError::Denied(d)) };
            let Some(info) = extras.get::<hyper_util::client::legacy::connect::HttpInfo>() else {
                // No addresses to check: not connected as vetted, as far as anyone can tell.
                return Err(denied(Denied::PathChanged {
                    addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                    why: "the connection's own addresses could not be read".into(),
                }));
            };
            let (local, peer) = (info.local_addr(), info.remote_addr());
            check.check(local, peer).await.map_err(denied)?;
            Ok(conn)
        })
    }
}

/// The client of one hop: `name` (when the hop's host is a name) pinned to `pinned`, every other
/// name refused; each connection checked once made when `recheck` is given (every hop does, but
/// the configuration check in [`build`]).
fn hop_client(
    name: Option<&str>,
    pinned: &[SocketAddr],
    options: ClientOptions,
    recheck: Option<RecheckLayer>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let mut b = reqwest::Client::builder()
        .dns_resolver(Arc::new(NoNames))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .http1_only()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .default_headers(headers)
        .user_agent(USER_AGENT)
        .referer(false)
        .pool_max_idle_per_host(0)
        .connect_timeout(options.connect_timeout)
        .read_timeout(options.read_timeout);
    if let Some(name) = name {
        b = b.resolve_to_addrs(name, pinned);
    }
    if let Some(layer) = recheck {
        b = b.connector_layer(layer);
    }
    b.build()
}

impl GuardedClient {
    pub fn policy(&self) -> &NetPolicy {
        self.resolver.policy()
    }

    /// The addresses one hop to `url` connects to: its host resolved through the guarded
    /// resolver (an IP literal as it is), each address vetted for the URL's port right before
    /// the connection ([`NetPolicy::vet_connection`]; concurrently), the ones that pass in answer
    /// order. Also the name to pin them to (`None` for an IP literal), and the check each
    /// connection gets once made ([`NetPolicy::recheck_connected`]).
    async fn pin(
        &self,
        url: &url::Url,
    ) -> Result<(Option<String>, Vec<SocketAddr>, RecheckLayer), FetchError> {
        let port = url
            .port_or_known_default()
            .ok_or(FetchError::Denied(Denied::Url(UrlDenied::BadPort)))?;
        let (name, ips) = match url.host() {
            Some(url::Host::Domain(d)) => (
                Some(d.to_string()),
                self.resolver
                    .resolve_admitted(d)
                    .await
                    .map_err(FetchError::from_resolve)?,
            ),
            Some(url::Host::Ipv4(a)) => (None, vec![IpAddr::V4(a)]),
            Some(url::Host::Ipv6(a)) => (None, vec![IpAddr::V6(a)]),
            None => return Err(FetchError::Denied(Denied::Url(UrlDenied::BadAuthority))),
        };
        let mut checks = tokio::task::JoinSet::new();
        for (i, ip) in ips.iter().enumerate() {
            let policy = self.policy().clone();
            let addr = SocketAddr::new(*ip, port);
            let connect = SocketAddr::new(self.resolver.connect_ip(*ip), port);
            checks.spawn_blocking(move || (i, policy.vet_path(addr, connect)));
        }
        let mut verdicts: Vec<(usize, Result<Vetted, Denied>)> = Vec::new();
        while let Some(r) = checks.join_next().await {
            match r {
                Ok(v) => verdicts.push(v),
                Err(_) => return Err(FetchError::BadRedirect("a connection check failed")),
            }
        }
        verdicts.sort_by_key(|(i, _)| *i);
        let mut pinned = Vec::new();
        let mut vetted = Vec::new();
        let mut refused = Vec::new();
        for (_, v) in verdicts {
            match v {
                Ok(v) => {
                    pinned.push(v.connect);
                    vetted.push(v);
                }
                Err(d) => refused.push(d),
            }
        }
        if pinned.is_empty() {
            return Err(FetchError::Denied(match (name.as_deref(), refused.len()) {
                (None, 1) => refused.remove(0),
                (host, _) => Denied::NoAdmittedAddress {
                    host: crate::printable(host.unwrap_or(url.host_str().unwrap_or("")), 128),
                    refused,
                },
            }));
        }
        if !refused.is_empty() {
            tracing::debug!(
                "network guard: {} of {}'s addresses refused right before connecting",
                refused.len(),
                crate::printable(url.host_str().unwrap_or(""), 128)
            );
        }
        let recheck = RecheckLayer {
            policy: self.policy().clone(),
            vetted: vetted.into(),
        };
        Ok((name, pinned, recheck))
    }

    /// [`NetPolicy::check_url`] on the blocking pool: an IP literal is judged by `admit`, which
    /// blocks (a facts re-read, a route query), so it never runs on a runtime worker (review round
    /// 2, cross-3; the Linux application).
    async fn check_url(&self, raw: &str) -> Result<url::Url, FetchError> {
        let policy = self.policy().clone();
        let raw = raw.to_owned();
        tokio::task::spawn_blocking(move || policy.check_url(&raw))
            .await
            .map_err(|_| FetchError::BadRedirect("a URL check failed"))?
            .map_err(FetchError::Denied)
    }

    /// GETs `raw`, following up to `max_redirects` redirects (301, 302, 303, 307, 308) by hand: each
    /// target is joined to the hop it came from and checked like the first URL before anything
    /// connects to it. `budget` bounds the whole chain and the read of the final body, which the
    /// caller does after this returns. A response that is not a redirect is returned whatever its
    /// status.
    pub async fn get_following_redirects(
        &self,
        raw: &str,
        max_redirects: usize,
        budget: Duration,
    ) -> Result<reqwest::Response, FetchError> {
        // Bounded: `Instant + Duration` panics past what an Instant holds.
        let deadline = Instant::now() + budget.min(Duration::from_secs(7 * 24 * 3600));
        let mut url = self.check_url(raw).await?;
        for hop in 0..=max_redirects {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(FetchError::TimedOut);
            }
            let (name, pinned, recheck) = tokio::time::timeout(remaining, self.pin(&url))
                .await
                .map_err(|_| FetchError::TimedOut)??;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(FetchError::TimedOut);
            }
            let response = hop_client(name.as_deref(), &pinned, self.options, Some(recheck))
                .map_err(|e| FetchError::Http(e.without_url()))?
                .get(url.clone())
                .timeout(remaining)
                .send()
                .await
                .map_err(FetchError::from_reqwest)?;
            if !matches!(
                response.status(),
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) {
                return Ok(response);
            }
            if hop == max_redirects {
                break;
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(FetchError::BadRedirect(
                    "a redirect without a usable Location",
                ))?;
            // The joined URL is re-serialized, so check the raw target's bytes here: what the URL
            // standard would strip or reinterpret (tabs, newlines, backslashes) is refused, not
            // quietly normalized.
            if !location
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b'\\')
            {
                return Err(FetchError::Denied(Denied::Url(UrlDenied::BadCharacter)));
            }
            // A target that names its own host (`scheme://host…`, or `//host…` on this hop's
            // scheme) is checked as written, so the strict reading sees the host the server sent,
            // not the standard parser's rewrite of it (`0x7f.1` would otherwise arrive as
            // `127.0.0.1`). A path-relative one keeps this hop's host and is checked once joined.
            let raw_target = if location.starts_with("//") {
                Some(format!("{}:{location}", url.scheme()))
            } else if let Some(rest) = after_scheme(location) {
                if !rest.starts_with("//") {
                    // `https:host/x` and friends: the standard reads a host into some of them.
                    return Err(FetchError::BadRedirect(
                        "a redirect to a target with a scheme but no '//'",
                    ));
                }
                Some(location.to_string())
            } else {
                None
            };
            url = match raw_target {
                Some(raw) => self.check_url(&raw).await?,
                None => {
                    let next = url.join(location).map_err(|_| {
                        FetchError::BadRedirect("a redirect to an invalid Location")
                    })?;
                    self.check_url(next.as_str()).await?
                }
            };
            tracing::debug!(
                "guarded fetch redirected to {:?}",
                crate::printable(url.as_str(), 256)
            );
        }
        Err(FetchError::TooManyRedirects)
    }

    /// POSTs a JSON `body` to `raw` (a JSON-RPC endpoint an operator or a requester names, such as
    /// `zkminer artifact publish --rpc-url`), with the URL checked and each address vetted and
    /// pinned exactly as for [`Self::get_following_redirects`]'s first hop. No redirect is followed:
    /// the response is returned whatever its status (a redirect is a non-2xx the caller refuses), so
    /// a POST body never travels to a second host. `budget` bounds the whole exchange up to the
    /// response head; the caller bounds its read of the body.
    pub async fn post_json(&self, raw: &str, body: Vec<u8>, budget: Duration) -> Result<reqwest::Response, FetchError> {
        let deadline = Instant::now() + budget.min(Duration::from_secs(7 * 24 * 3600));
        let url = self.check_url(raw).await?;
        let (name, pinned, recheck) = tokio::time::timeout(budget, self.pin(&url))
            .await
            .map_err(|_| FetchError::TimedOut)??;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::TimedOut);
        }
        hop_client(name.as_deref(), &pinned, self.options, Some(recheck))
            .map_err(|e| FetchError::Http(e.without_url()))?
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(remaining)
            .send()
            .await
            .map_err(FetchError::from_reqwest)
    }
}

/// What follows the scheme of an absolute URL reference (`scheme:`, the scheme a letter then
/// letters, digits, `+`, `-` or `.`, before any `/`, `?` or `#`), or `None` for a relative one.
fn after_scheme(reference: &str) -> Option<&str> {
    let end = reference.find([':', '/', '?', '#'])?;
    let (scheme, rest) = reference.split_at(end);
    let is_scheme = rest.starts_with(':')
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    is_scheme.then(|| &rest[1..])
}

/// Why a guarded fetch failed.
#[derive(Debug)]
pub enum FetchError {
    /// The network guard refused a URL, a name or every address (no connection was made to it).
    Denied(Denied),
    /// The name did not resolve (no such name, no resolver answered).
    Lookup(String),
    /// The request failed (connection, TLS, protocol, timeout). Carries no URL.
    Http(reqwest::Error),
    TooManyRedirects,
    BadRedirect(&'static str),
    /// The budget ran out between hops.
    TimedOut,
}

impl FetchError {
    /// A reqwest error, as a [`FetchError::Denied`] when the guarded resolver refused the
    /// connection (its error sits in the source chain), else [`FetchError::Http`] without the URL.
    pub fn from_reqwest(e: reqwest::Error) -> Self {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(s) = source {
            if let Some(ResolveError::Denied(d)) = s.downcast_ref::<ResolveError>() {
                return FetchError::Denied(d.clone());
            }
            source = s.source();
        }
        FetchError::Http(e.without_url())
    }

    /// A resolution failure as a [`FetchError`]: [`FetchError::Denied`] when the guard refused the
    /// name or every address, else [`FetchError::Lookup`].
    pub fn from_resolve(e: ResolveError) -> Self {
        match e {
            ResolveError::Denied(d) => FetchError::Denied(d),
            ResolveError::Lookup(e) => FetchError::Lookup(e.to_string()),
        }
    }

    /// Whether the network guard refused it.
    pub fn is_denied(&self) -> bool {
        matches!(self, FetchError::Denied(_))
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Denied(d) => fmt::Display::fmt(d, f),
            FetchError::Lookup(e) => write!(f, "DNS lookup failed: {e}"),
            FetchError::Http(e) => {
                write!(f, "{e}")?;
                let mut source = std::error::Error::source(e);
                while let Some(s) = source {
                    write!(f, ": {s}")?;
                    source = s.source();
                }
                Ok(())
            }
            FetchError::TooManyRedirects => f.write_str("too many redirects"),
            FetchError::BadRedirect(why) => f.write_str(why),
            FetchError::TimedOut => f.write_str("timed out"),
        }
    }
}

impl std::error::Error for FetchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::HostFacts;
    use crate::policy::NetMode;
    use crate::resolve::tests::{public_policy, FakeLookup};
    use std::net::IpAddr;
    use std::sync::Mutex;

    /// A server on loopback that answers each connection with the next canned reply (`{port}` in
    /// one becomes its port) and records each request's head. `STALL` reads the request and then
    /// says nothing, with the connection held open; see [`SLOW`] and [`BODY_STALLS`] for the other
    /// ways it misbehaves.
    struct CannedServer {
        port: u16,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl CannedServer {
        fn hosts(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter_map(|r| {
                    r.lines()
                        .find_map(|l| l.strip_prefix("host: "))
                        .map(|h| h.split(':').next().unwrap().to_string())
                })
                .collect()
        }
    }

    fn canned_server(replies: &[&str]) -> CannedServer {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies: Vec<String> = replies
            .iter()
            .map(|r| r.replace("{port}", &port.to_string()))
            .collect();
        let seen = requests.clone();
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).to_ascii_lowercase());
                if reply == STALL {
                    std::thread::sleep(Duration::from_secs(60));
                    return;
                }
                let reply = match reply.strip_prefix(SLOW) {
                    Some(rest) => {
                        std::thread::sleep(SLOW_BY);
                        rest.to_string()
                    }
                    None => reply,
                };
                let _ = stream.write_all(reply.as_bytes());
                if reply.ends_with(BODY_STALLS) {
                    std::thread::sleep(Duration::from_secs(60));
                    return;
                }
            }
        });
        CannedServer { port, requests }
    }

    fn redirect_to(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    const STALL: &str = "stall";
    /// A reply starting with this comes after [`SLOW_BY`].
    const SLOW: &str = "slow:";
    const SLOW_BY: Duration = Duration::from_millis(1500);
    /// A reply ending with this is left open: its headers promise more than it sends.
    const BODY_STALLS: &str = "part of";
    const OK_ELF: &str = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nelf";
    const BUDGET: Duration = Duration::from_secs(20);

    /// Public mode with names faked to public addresses, every one of which connects to loopback.
    fn public_client(lookup: FakeLookup) -> GuardedClient {
        let to_loopback: crate::resolve::ConnectMap = Arc::new(|_| IpAddr::from([127, 0, 0, 1]));
        guarded_client_for_test(
            &public_policy().with_near_probe(crate::nearhop::FixedProbe::far()),
            Arc::new(lookup),
            to_loopback,
            ClientOptions::default(),
        )
        .unwrap()
    }

    fn public_names() -> FakeLookup {
        FakeLookup::with(&[
            ("elfs.example.com", &["93.184.216.34"]),
            ("cdn.example.net", &["2606:2800:220:1::1"]),
            ("private.example.com", &["10.0.0.1"]),
            ("rebind.example.com", &["127.0.0.1"]),
        ])
    }

    /// Dev mode: every name in the table answers loopback, and is admitted.
    fn dev_client() -> (GuardedClient, FakeLookup) {
        let lookup = FakeLookup::with(&[
            ("store.invalid", &["127.0.0.1"]),
            ("cdn.invalid", &["127.0.0.1"]),
        ]);
        let dev = NetPolicy::with_facts(NetMode::DevPrivate, HostFacts::empty(), Vec::new());
        let c =
            guarded_client_with(&dev, Arc::new(lookup.clone()), ClientOptions::default()).unwrap();
        (c, lookup)
    }

    fn start(server: &CannedServer, host: &str) -> String {
        format!("http://{host}:{}/elf", server.port)
    }

    #[tokio::test]
    async fn a_public_name_is_served_and_the_request_is_plain() {
        let server = canned_server(&[OK_ELF]);
        let c = public_client(public_names());
        let response = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "elf");
        let head = server.requests.lock().unwrap()[0].clone();
        assert!(head.contains("\r\nuser-agent: zkminer\r\n"), "{head}");
        assert!(head.contains("\r\naccept-encoding: identity\r\n"), "{head}");
        assert!(!head.contains("referer"), "{head}");
        assert!(head.starts_with("get /elf http/1.1\r\n"), "{head}");
    }

    /// The point of the whole guard: nothing connects to a hop the guard refuses, whether the
    /// check that refuses it is the URL's (a local name, an IP literal, a scheme) or the resolver's
    /// (a public-looking name that answers a private address).
    #[tokio::test]
    async fn a_refused_redirect_target_is_never_connected_to() {
        for target in [
            "http://localhost:{port}/",
            "http://127.0.0.1:{port}/",
            "http://[::1]:{port}/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:0:a9fe:a9fe]/",
            "http://private.example.com:{port}/",
            "http://rebind.example.com:{port}/",
            "http://metadata.google.internal/",
            "http://2130706433:{port}/",
            "ftp://elfs.example.com/elf",
            "file:///etc/passwd",
            "http://elfs.example.com\\@127.0.0.1/",
            "//localhost:{port}/x",
        ] {
            let server = canned_server(&[&redirect_to(target), OK_ELF]);
            let c = public_client(public_names());
            let e = c
                .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
                .await
                .err()
                .unwrap_or_else(|| panic!("{target} was followed"));
            assert!(
                e.to_string().starts_with("refused by the network guard: "),
                "{target}: {e}"
            );
            assert!(e.is_denied(), "{target}: {e:?}");
            assert_eq!(
                server.hosts(),
                ["elfs.example.com"],
                "{target} was connected to"
            );
        }
    }

    #[tokio::test]
    async fn a_json_post_is_guarded_like_a_get_and_never_redirected() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        let server = canned_server(&[ok]);
        let c = public_client(public_names());
        let r = c
            .post_json(&start(&server, "elfs.example.com"), b"{\"id\":1}".to_vec(), BUDGET)
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let head = server.requests.lock().unwrap()[0].clone();
        assert!(head.starts_with("post /elf http/1.1\r\n"), "{head}");
        assert!(head.contains("\r\ncontent-type: application/json\r\n"), "{head}");
        // A redirect is handed back, not followed: the body never reaches a second host.
        let server = canned_server(&[&redirect_to("http://cdn.example.net:{port}/x"), ok]);
        let r = c.post_json(&start(&server, "elfs.example.com"), b"{}".to_vec(), BUDGET).await.unwrap();
        assert_eq!(r.status(), 302);
        assert_eq!(server.hosts(), ["elfs.example.com"]);
        // Local and private targets are refused before any connection, as for a GET.
        for target in ["http://localhost:{port}/", "http://127.0.0.1:{port}/", "http://private.example.com:{port}/"] {
            let server = canned_server(&[ok]);
            let url = target.replace("{port}", &server.port.to_string());
            let e = c.post_json(&url, b"{}".to_vec(), BUDGET).await.expect_err("refused");
            assert!(e.is_denied(), "{target}: {e:?}");
            assert!(server.hosts().is_empty(), "{target} was connected to");
        }
    }

    #[tokio::test]
    async fn a_redirect_to_another_public_host_is_checked_and_followed() {
        let server = canned_server(&[&redirect_to("http://cdn.example.net:{port}/real"), OK_ELF]);
        let lookup = public_names();
        let c = public_client(lookup.clone());
        let response = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "elf");
        assert_eq!(
            *lookup.asked.lock().unwrap(),
            ["elfs.example.com", "cdn.example.net"]
        );
        assert_eq!(server.hosts(), ["elfs.example.com", "cdn.example.net"]);
    }

    #[tokio::test]
    async fn local_urls_are_refused_in_public_mode_before_any_connection() {
        let server = canned_server(&[OK_ELF]);
        let c = public_client(public_names());
        for raw in [
            format!("http://127.0.0.1:{}/elf", server.port),
            format!("http://localhost:{}/elf", server.port),
            format!("http://rebind.example.com:{}/elf", server.port),
        ] {
            let e = c
                .get_following_redirects(&raw, 5, BUDGET)
                .await
                .unwrap_err();
            assert!(e.is_denied(), "{raw}: {e}");
            assert!(
                c.policy().check_url(&raw).is_err() || raw.contains("rebind"),
                "{raw}"
            );
        }
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dev_mode_follows_local_redirects() {
        let server = canned_server(&[
            &redirect_to("http://cdn.invalid:{port}/real"),
            &redirect_to("http://127.0.0.1:{port}/again"),
            OK_ELF,
        ]);
        let (c, _) = dev_client();
        let response = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "elf");
        assert_eq!(
            server.hosts(),
            ["store.invalid", "cdn.invalid", "127.0.0.1"]
        );
    }

    #[tokio::test]
    async fn dev_mode_still_refuses_other_schemes() {
        let server = canned_server(&[&redirect_to("file:///etc/passwd"), OK_ELF]);
        let (c, _) = dev_client();
        let e = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
            .await
            .unwrap_err();
        assert!(e.is_denied(), "{e}");
        assert_eq!(server.hosts(), ["store.invalid"]);
    }

    #[tokio::test]
    async fn a_relative_location_stays_on_the_host_and_is_checked_again() {
        let server = canned_server(&[&redirect_to("/moved/elf"), OK_ELF]);
        let lookup = public_names();
        let c = public_client(lookup.clone());
        let response = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            *lookup.asked.lock().unwrap(),
            ["elfs.example.com", "elfs.example.com"]
        );
        assert!(server.requests.lock().unwrap()[1].starts_with("get /moved/elf "));
    }

    /// A URL in a relative target's query is no target: the redirect stays on the host.
    #[tokio::test]
    async fn a_relative_location_with_a_url_in_its_query_is_followed() {
        let server = canned_server(&[
            &redirect_to("/moved?to=http://127.0.0.1/&next=https://x.example/"),
            OK_ELF,
        ]);
        let lookup = public_names();
        let c = public_client(lookup.clone());
        let response = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(server.hosts(), ["elfs.example.com", "elfs.example.com"]);
    }

    /// An absolute or scheme-relative target is read as the server wrote it, so the strict rules
    /// hold for it in developer mode too (where only the destination checks are off).
    #[tokio::test]
    async fn a_redirect_target_is_checked_as_written() {
        for (target, denied) in [
            ("http://0x7f.0.0.1:{port}/", true),
            ("//0x7f.0.0.1:{port}/", true),
            ("http://127.1:{port}/", true),
            ("https:store.invalid/x", false),
            ("javascript:alert(1)", false),
        ] {
            let server = canned_server(&[&redirect_to(target), OK_ELF]);
            let (c, _) = dev_client();
            let e = c
                .get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
                .await
                .unwrap_err();
            assert_eq!(e.is_denied(), denied, "{target}: {e:?}");
            assert_eq!(
                server.hosts(),
                ["store.invalid"],
                "{target} was connected to"
            );
        }
        assert_eq!(after_scheme("https://a/b"), Some("//a/b"));
        assert_eq!(after_scheme("HTTP://a"), Some("//a"));
        assert_eq!(after_scheme("javascript:x"), Some("x"));
        assert_eq!(after_scheme("/a?u=http://b"), None);
        assert_eq!(after_scheme("a/b:c"), None);
        assert_eq!(after_scheme("?x:y"), None);
        assert_eq!(after_scheme("1http://a"), None);
        assert_eq!(after_scheme("moved"), None);
    }

    #[tokio::test]
    async fn a_redirect_chain_is_bounded() {
        let hop = redirect_to("http://store.invalid:{port}/again");
        let replies = vec![hop.as_str(); 8];
        let server = canned_server(&replies);
        let (c, lookup) = dev_client();
        let e = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
            .await
            .unwrap_err();
        assert!(matches!(e, FetchError::TooManyRedirects), "{e}");
        assert_eq!(e.to_string(), "too many redirects");
        assert_eq!(lookup.asked.lock().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn a_redirect_without_a_location_fails_and_other_statuses_are_returned() {
        let server = canned_server(&[
            "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let (c, _) = dev_client();
        assert!(matches!(
            c.get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
                .await,
            Err(FetchError::BadRedirect(_))
        ));
        let server = canned_server(&[
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let response = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    /// The budget covers the whole chain: a host that stalls gets no fresh allowance per hop. The
    /// first hop spends most of it, so a fresh one for the second would take over 3.5 s rather than
    /// the 2 s of the budget.
    #[tokio::test]
    async fn the_budget_covers_the_whole_chain() {
        let hop = format!("{SLOW}{}", redirect_to("http://store.invalid:{port}/stall"));
        let server = canned_server(&[&hop, STALL]);
        let (c, _) = dev_client();
        let started = Instant::now();
        let e = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(server.hosts().len(), 2, "the stalled hop was reached: {e}");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(1900) && took < Duration::from_secs(3),
            "{took:?}"
        );
    }

    /// And the body, which the caller reads after this returns.
    #[tokio::test]
    async fn the_budget_covers_the_body_read() {
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{BODY_STALLS}");
        let server = canned_server(&[&reply]);
        let (c, _) = dev_client();
        let started = Instant::now();
        let response = c
            .get_following_redirects(&start(&server, "store.invalid"), 5, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(response.text().await.is_err(), "the body never finishes");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_secs(4),
            "{took:?}"
        );
    }

    /// A failure that is not the guard's is told apart from one that is, and carries no URL.
    #[tokio::test]
    async fn a_connection_failure_is_not_a_denial() {
        // A server that drops every connection unanswered (not a freed port, which another test's
        // server can take in between).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        let (c, _) = dev_client();
        let e = c
            .get_following_redirects(
                &format!("http://store.invalid:{port}/secret-path"),
                5,
                BUDGET,
            )
            .await
            .unwrap_err();
        assert!(matches!(e, FetchError::Http(_)), "{e:?}");
        assert!(!e.to_string().contains("secret-path"), "{e}");
    }

    /// A route oracle whose answer for a connection (asked with its port) is the default route
    /// via 192.168.1.1 for the first `admitted` such questions and no route after: a route that
    /// changes between the check and the connection.
    #[derive(Debug)]
    struct Flip {
        admitted: usize,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl crate::routes::RouteOracle for Flip {
        fn route_to(
            &self,
            _: IpAddr,
            dport: Option<u16>,
        ) -> std::io::Result<crate::routes::KernelAnswer> {
            use crate::routes::{KernelAnswer, Route};
            let default = Route::via(
                "0.0.0.0/0".parse().unwrap(),
                "192.168.1.1".parse().unwrap(),
                2,
            );
            if dport.is_none() {
                return Ok(KernelAnswer::Entry(vec![default]));
            }
            let n = self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(if n < self.admitted {
                KernelAnswer::Entry(vec![default])
            } else {
                KernelAnswer::NoRoute
            })
        }
    }

    fn flipping_client(admitted: usize) -> GuardedClient {
        use crate::facts::{FactsOptions, RawFacts};
        use crate::routes::Route;
        let facts = HostFacts::assemble(
            RawFacts {
                interface_prefixes: vec!["192.168.1.0/24".parse().unwrap()],
                interface_addresses: vec!["192.168.1.33".parse().unwrap()],
                routes: vec![Route::via(
                    "0.0.0.0/0".parse().unwrap(),
                    "192.168.1.1".parse().unwrap(),
                    2,
                )],
                ..RawFacts::default()
            },
            &FactsOptions {
                discover_public_addresses: false,
                public_addresses: vec!["198.51.99.7".parse().unwrap()],
                ..FactsOptions::default()
            },
        )
        .with_route_oracle(Arc::new(Flip {
            admitted,
            asked: Default::default(),
        }));
        let policy = NetPolicy::with_facts(NetMode::Public, facts, Vec::new())
            .with_near_probe(crate::nearhop::FixedProbe::far());
        let to_loopback: crate::resolve::ConnectMap = Arc::new(|_| IpAddr::from([127, 0, 0, 1]));
        guarded_client_for_test(
            &policy,
            Arc::new(public_names()),
            to_loopback,
            ClientOptions::default(),
        )
        .unwrap()
    }

    /// The Linux application of review round 2, bypass-3 (every platform): the route is judged
    /// again once the connection is made, with the kernel asked afresh. A route that is the
    /// default path when the address is checked and gone once the connection exists refuses the
    /// connection before any request is written on it; one that stays admits it.
    #[tokio::test]
    async fn a_route_that_changes_between_the_check_and_the_connection_drops_it() {
        let server = canned_server(&[OK_ELF, OK_ELF]);
        // Admitted at the check (one question with the port), gone when connected.
        let c = flipping_client(1);
        let e = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &e,
                FetchError::Denied(Denied::OffDefaultRoute {
                    kind: crate::RouteKind::NoRoute,
                    ..
                })
            ),
            "{e:?}"
        );
        // The connection was made (and dropped): no request was written on it.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            server.requests.lock().unwrap().iter().all(|r| r.is_empty()),
            "{:?}",
            server.requests.lock().unwrap()
        );
        // Admitted at the check and once connected: served.
        let server = canned_server(&[OK_ELF]);
        let c = flipping_client(2);
        let r = c
            .get_following_redirects(&start(&server, "elfs.example.com"), 5, BUDGET)
            .await
            .unwrap();
        assert_eq!(r.text().await.unwrap(), "elf");
    }

    /// The same, for the source address: a connection whose own source is not the one the
    /// kernel chose for it when it was checked (a VPN came up, the route moved it to another
    /// interface) is refused, and so is one whose peer is not the vetted address; the vetted
    /// connection, read from a real socket, is admitted. Mapped addresses read as IPv4.
    #[test]
    fn a_connection_that_left_by_another_path_is_refused() {
        use crate::policy::connected_as_vetted;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = l.local_addr().unwrap();
        let policy = NetPolicy::with_facts(NetMode::Public, HostFacts::empty(), Vec::new())
            .with_near_probe(crate::nearhop::FixedProbe::far());
        let vetted = policy.vet_path(peer, peer);
        // Loopback is not public: the check itself refuses it in public mode.
        assert!(vetted.is_err());
        let v = Vetted {
            addr: "93.184.216.34:443".parse().unwrap(),
            connect: peer,
            source: Some("127.0.0.1".parse().unwrap()),
        };
        let c = std::net::TcpStream::connect(peer).unwrap();
        let (local, remote) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        assert_eq!(connected_as_vetted(&v, local, remote), Ok(()));
        let moved = Vetted {
            source: Some("192.168.1.33".parse().unwrap()),
            ..v.clone()
        };
        let why = connected_as_vetted(&moved, local, remote).unwrap_err();
        assert!(why.contains("left from 127.0.0.1") && why.contains("192.168.1.33"), "{why}");
        let d = policy.recheck_connected(&moved, local, remote).unwrap_err();
        assert!(matches!(d, Denied::PathChanged { .. }), "{d:?}");
        assert!(d.to_string().contains("dropped once made"), "{d}");
        let elsewhere: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(connected_as_vetted(&v, local, elsewhere)
            .unwrap_err()
            .contains("reached 127.0.0.1:1"));
        // An IPv4-mapped peer or source is its IPv4 address.
        let mapped_peer: SocketAddr = format!("[::ffff:127.0.0.1]:{}", peer.port()).parse().unwrap();
        let mapped_local: SocketAddr = format!("[::ffff:127.0.0.1]:{}", local.port()).parse().unwrap();
        assert_eq!(connected_as_vetted(&v, mapped_local, mapped_peer), Ok(()));
        // Developer mode checks nothing.
        let dev = NetPolicy::with_facts(NetMode::DevPrivate, HostFacts::empty(), Vec::new());
        assert_eq!(dev.recheck_connected(&moved, local, elsewhere), Ok(()));
        let dv = dev.vet_path(peer, peer).unwrap();
        assert_eq!(dv.source, None);
        drop(l);
    }

    /// `vet_path` reads the source the kernel chooses for the connection, right after the
    /// checks: for a loopback stand-in, loopback.
    #[tokio::test]
    async fn the_vetted_source_is_the_kernels() {
        let c = public_client(public_names());
        let url = c.policy().check_url("http://elfs.example.com:8080/").unwrap();
        let (_, pinned, recheck) = c.pin(&url).await.unwrap();
        assert_eq!(pinned, vec!["127.0.0.1:8080".parse::<SocketAddr>().unwrap()]);
        assert_eq!(recheck.vetted.len(), 1);
        let v = &recheck.vetted[0];
        assert_eq!(v.addr, "93.184.216.34:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(v.source, Some("127.0.0.1".parse().unwrap()));
    }
}
