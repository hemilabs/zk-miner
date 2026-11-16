//! The guarded HTTP client for requester-controlled URLs.
//!
//! [`guarded_client`] builds a reqwest client that:
//!
//! - resolves every name through the [`GuardedResolver`] (one lookup per connection, only admitted
//!   addresses handed to the connector), and refuses every URL that fails [`crate::check_url`]
//!   before a request is built: the raw reqwest client is never handed out, so no request skips the
//!   check (an IP-literal host never reaches a resolver);
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
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT_ENCODING, LOCATION};
use reqwest::StatusCode;

use crate::policy::{Denied, NetPolicy, UrlDenied};
use crate::resolve::{GuardedResolver, Lookup, ResolveError, SystemLookup};

/// The `User-Agent` of every guarded request. Constant and versionless, so it says nothing about
/// the build; some stores (Arweave's gateways) refuse a request without one.
pub const USER_AGENT: &str = "zkminer";

/// Timeouts of a guarded client.
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// For connecting, the lookup included.
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
    inner: reqwest::Client,
    policy: NetPolicy,
}

impl fmt::Debug for GuardedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedClient")
            .field("mode", &self.policy.mode())
            .finish_non_exhaustive()
    }
}

/// The guarded client for `policy`, resolving through the system resolver.
pub fn guarded_client(policy: &NetPolicy) -> Result<GuardedClient, reqwest::Error> {
    guarded_client_with(policy, Arc::new(SystemLookup), ClientOptions::default())
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
/// on loopback can stand in for a public address in a public-mode test. Test builds only (the
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
    let policy = resolver.policy().clone();
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let inner = reqwest::Client::builder()
        .dns_resolver(Arc::new(resolver))
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
        .read_timeout(options.read_timeout)
        .build()?;
    Ok(GuardedClient { inner, policy })
}

impl GuardedClient {
    pub fn policy(&self) -> &NetPolicy {
        &self.policy
    }

    /// A GET of a requester URL: [`crate::check_url`] first, then a request whose URL is fixed (the
    /// caller may add headers and a timeout). Its connection is still judged by the resolver.
    pub fn get(&self, raw: &str) -> Result<reqwest::RequestBuilder, Denied> {
        let url = self.policy.check_url(raw)?;
        Ok(self.inner.get(url))
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
        let mut url = self.policy.check_url(raw).map_err(FetchError::Denied)?;
        for hop in 0..=max_redirects {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(FetchError::TimedOut);
            }
            let response = self
                .inner
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
                Some(raw) => self.policy.check_url(&raw).map_err(FetchError::Denied)?,
                None => {
                    let next = url.join(location).map_err(|_| {
                        FetchError::BadRedirect("a redirect to an invalid Location")
                    })?;
                    self.policy
                        .check_url(next.as_str())
                        .map_err(FetchError::Denied)?
                }
            };
            tracing::debug!(
                "guarded fetch redirected to {:?}",
                crate::printable(url.as_str(), 256)
            );
        }
        Err(FetchError::TooManyRedirects)
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

    /// Whether the network guard refused it.
    pub fn is_denied(&self) -> bool {
        matches!(self, FetchError::Denied(_))
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Denied(d) => fmt::Display::fmt(d, f),
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
            &public_policy(),
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
            assert!(c.get(&raw).is_err() || raw.contains("rebind"), "{raw}");
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
}
