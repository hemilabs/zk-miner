//! The egress wiring (plan §14.2): one HTTP/1.1 client per operator endpoint, whose every TCP
//! connection comes from the **miner's connector** ([`crate::connector`]) — the broker has no
//! `socket` or `connect` of its own (review r2 F5). No proxy, no redirects, no `Referer`, no
//! decompression (hyper has none of them), a constant User-Agent; endpoints are logged by alias and
//! errors pass through `redact_urls(sanitize_log(…))`.
//!
//! For each new connection the client asks the connector for endpoint `index` (its position in
//! [`crate::config::BrokerConfig::endpoints`]) with the role and port the broker expects; the
//! connector, in the miner, resolves the endpoint's host name, admits the address (its role entry
//! and netguard's floor, with the miner's facts and deny CIDRs) and connects. The broker never
//! resolves a name and never names an address.
//!
//! **The second layer.** The broker keeps its own floor and checks every socket it is handed
//! before using it ([`Endpoint`]'s connector service): the socket's peer must be on the
//! endpoint's port and in its role entry — explicit `cidrs` or the IP literal, plus netguard's
//! public floor in public mode ([`EgressPolicy::admit`]) — or, for a host name without `cidrs`
//! (whose role entry is a DNS answer the broker no longer sees), pass the public floor in either
//! mode ([`EgressPolicy::dns_admissible`]). A socket that fails is closed unused.
//!
//! TLS is rustls (ring) with the compiled-in webpki roots, over the received socket, verifying the
//! certificate against the URL's host name (or IP literal) as before.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT as USER_AGENT_HEADER};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::time::Instant;

use crate::config::{host_prefix, EndpointSpec, TimeoutConfig};
use crate::connector::{ConnectError, ConnectorClient, Status};
use crate::egress::{Admit, DenyReason, EgressPolicy, NetMode, Prefix, Role, RoleEntry};
use crate::hooks::EgressHooks;
use crate::lanes::{LanePermit, Lanes, Pacer, TokenBucket, WaitFlag};

/// The shared, refreshable policy (with the host's connected prefixes and own addresses).
pub type PolicyHandle = Arc<RwLock<EgressPolicy>>;

const USER_AGENT: &str = "zkminer-witness-broker";
/// How long an idle connection stays pooled.
pub const POOL_IDLE: Duration = Duration::from_secs(30);

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}

/// Builds the broker's own policy in `mode`: one role entry per endpoint — its explicit CIDRs, else
/// its IP literal; a host name without `cidrs` has an empty one (its sockets are judged by the
/// public floor, see the module doc) — the deny CIDRs (the operator's and the DNS servers', see
/// [`crate::config::BrokerConfig::effective_deny`]), the connected prefixes and own addresses.
pub fn build_policy<'a>(
    mode: NetMode,
    endpoints: impl Iterator<Item = &'a EndpointSpec>,
    deny: Vec<Prefix>,
    connected: Vec<Prefix>,
    own: &[IpAddr],
) -> EgressPolicy {
    let roles = endpoints
        .map(|e| RoleEntry {
            role: e.role,
            alias: e.alias.clone(),
            prefixes: if !e.cidrs.is_empty() { e.cidrs.clone() } else { e.literal.map(host_prefix).into_iter().collect() },
            port: e.port,
        })
        .collect();
    EgressPolicy { mode, roles, deny, facts: zkminer_netguard::HostFacts::new(connected, own.to_vec()) }
}

/// Why a request to an endpoint failed. Messages are already redacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("no address the egress floor admits")]
    Egress,
    /// Connecting failed (refused, reset, unreachable, a connect timeout, TLS) or the connection
    /// broke: the operator's side.
    #[error("transport: {0}")]
    Transport(String),
    /// The endpoint took longer than `request_secs` to answer the request once it was sent, or to
    /// stream its body: the request's own cost, as far as the broker can tell.
    #[error("timed out")]
    Timeout,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("response larger than its cap")]
    TooLarge,
    #[error("local: {0}")]
    Local(String),
}

impl EndpointError {
    /// Whether the failure is the operator's (plan §11.2, §16): transport, a non-2xx other than
    /// 404, no admitted address, a local resource. A timeout after the request was sent, a 404 and a
    /// body above the job's cap are not: a builder can cause each of them on demand.
    pub fn operator_side(&self) -> bool {
        match self {
            EndpointError::Egress | EndpointError::Transport(_) | EndpointError::Local(_) => true,
            EndpointError::Status(s) => *s != 404,
            EndpointError::Timeout | EndpointError::TooLarge => false,
        }
    }
}

/// Why the connector service produced no connection (inside hyper's connect error).
#[derive(Debug, thiserror::Error)]
enum ConnectFailed {
    #[error("connector: {0}")]
    Connector(ConnectError),
    /// The broker's own floor refused the socket it was handed.
    #[error("the broker's floor refused the connector's socket: {0:?}")]
    Floor(DenyReason),
    #[error("the request URL is not the endpoint's host and port")]
    WrongDestination,
    #[error("the socket: {0}")]
    Io(#[from] std::io::Error),
}

/// What the connector service needs about its endpoint.
struct Target {
    index: u32,
    role: Role,
    alias: String,
    host: String,
    literal: Option<IpAddr>,
    explicit_cidrs: bool,
    port: u16,
    connector: Arc<ConnectorClient>,
    policy: PolicyHandle,
    /// How long one connection may take to come back from the connector.
    connect_phase: Duration,
}

impl Target {
    /// The second layer (see the module doc).
    fn check_peer(&self, peer: SocketAddr) -> Result<(), DenyReason> {
        if peer.port() != self.port {
            return Err(DenyReason::WrongPort);
        }
        let policy = read(&self.policy);
        if self.literal.is_none() && !self.explicit_cidrs {
            return policy.public_floor(peer.ip());
        }
        match policy.admit(Some((self.role, &self.alias)), peer) {
            Admit::Role => Ok(()),
            Admit::Denied(r) => Err(r),
            Admit::Global => Err(DenyReason::NoRoleEntry),
        }
    }

    /// Whether `uri` is this endpoint's host and port (the broker builds every URL from the
    /// endpoint's own; anything else is a bug, refused).
    fn is_ours(&self, uri: &http::Uri) -> bool {
        let Some(h) = uri.host() else { return false };
        let h = h.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
        let host_ok = match self.literal {
            Some(lit) => h.parse::<IpAddr>().is_ok_and(|ip| ip == lit),
            None => h == self.host,
        };
        let default = if uri.scheme_str() == Some("https") { 443 } else { 80 };
        host_ok && uri.port_u16().unwrap_or(default) == self.port
    }

    async fn connect(&self, uri: http::Uri) -> Result<TokioIo<tokio::net::TcpStream>, ConnectFailed> {
        if !self.is_ours(&uri) {
            return Err(ConnectFailed::WrongDestination);
        }
        let (stream, reported) = match tokio::time::timeout(self.connect_phase, self.connector.connect(self.index, self.role, self.port)).await
        {
            Ok(r) => r.map_err(ConnectFailed::Connector)?,
            Err(_) => return Err(ConnectFailed::Connector(ConnectError::Timeout)),
        };
        // The socket's own peer, not the connector's word for it (they must agree).
        let peer = stream.peer_addr()?;
        if peer != reported {
            tracing::warn!(endpoint = %self.alias, "the connector's socket is not connected where it said");
            return Err(ConnectFailed::Floor(DenyReason::NoRoleEntry));
        }
        if let Err(r) = self.check_peer(peer) {
            tracing::error!(endpoint = %self.alias, reason = ?r, "PAGE: the broker's floor refused a socket from the miner's connector");
            return Err(ConnectFailed::Floor(r));
        }
        stream.set_nodelay(true)?;
        stream.set_nonblocking(true)?;
        Ok(TokioIo::new(tokio::net::TcpStream::from_std(stream)?))
    }
}

/// hyper's connector: every connection from the miner's connector, checked by [`Target`].
#[derive(Clone)]
struct ViaConnector(Arc<Target>);

impl tower_service::Service<http::Uri> for ViaConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let t = self.0.clone();
        Box::pin(async move { t.connect(uri).await.map_err(Into::into) })
    }
}

type HttpClient = Client<hyper_rustls::HttpsConnector<ViaConnector>, Full<Bytes>>;

/// The TLS settings every endpoint uses: rustls with ring, TLS 1.2 and 1.3, the compiled-in webpki
/// roots, SNI, ALPN `http/1.1` only.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(c)
        })
        .clone()
}

/// What an [`Endpoint`] is built from besides its spec.
pub struct EndpointEnv {
    pub policy: PolicyHandle,
    pub egress: Arc<dyn EgressHooks>,
    pub connector: Arc<ConnectorClient>,
    /// The share of the operator budget only held-lock work may spend.
    pub held_lock_share: f64,
}

/// One operator endpoint: its client, floor check, concurrency lanes, pacing and operator budget.
pub struct Endpoint {
    pub spec: EndpointSpec,
    client: HttpClient,
    egress: Arc<dyn EgressHooks>,
    request_timeout: Duration,
    pub concurrency: Lanes,
    pacer: Option<Pacer>,
    budget: Option<TokenBucket>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").field("alias", &self.spec.alias).finish_non_exhaustive()
    }
}

/// A 2xx response body being read under its cap, holding the endpoint's concurrency slot.
pub struct BodyReader<'a> {
    ep: &'a Endpoint,
    body: hyper::body::Incoming,
    deadline: Instant,
    cap: u64,
    total: u64,
    _slot: LanePermit,
}

impl BodyReader<'_> {
    /// Appends the next chunk to `buf`; `false` at the end of the body.
    pub async fn next_into(&mut self, buf: &mut Vec<u8>) -> Result<bool, EndpointError> {
        loop {
            let frame = match tokio::time::timeout_at(self.deadline, self.body.frame()).await {
                Err(_) => return Err(EndpointError::Timeout),
                Ok(None) => return Ok(false),
                Ok(Some(Err(e))) => return Err(self.ep.transport(&e)),
                Ok(Some(Ok(f))) => f,
            };
            // Trailers carry no data.
            let Ok(chunk) = frame.into_data() else { continue };
            self.total += chunk.len() as u64;
            if self.total > self.cap {
                return Err(EndpointError::TooLarge);
            }
            buf.extend_from_slice(&chunk);
            return Ok(true);
        }
    }

    /// Bytes read so far.
    pub fn total(&self) -> u64 {
        self.total
    }
}

impl Endpoint {
    /// Needs a tokio runtime (the pacer's dispatcher, hyper's pool). `index` is the endpoint's
    /// position in [`crate::config::BrokerConfig::endpoints`]: what the connector knows it by.
    pub fn new(spec: EndpointSpec, index: u32, env: &EndpointEnv, t: &TimeoutConfig) -> Arc<Self> {
        let wait = crate::connector::request_budget(t.connect()) + Duration::from_secs(2);
        let target = Target {
            index,
            role: spec.role,
            alias: spec.alias.clone(),
            host: spec.host.clone(),
            literal: spec.literal,
            explicit_cidrs: !spec.cidrs.is_empty(),
            port: spec.port,
            connector: env.connector.clone(),
            policy: env.policy.clone(),
            // A connection that cannot be had fails as the operator's before the request's own
            // deadline would call it the request's.
            connect_phase: wait.min(t.request().saturating_sub(Duration::from_millis(250)).max(Duration::from_millis(250))),
        };
        let https = hyper_rustls::HttpsConnector::from((ViaConnector(Arc::new(target)), tls_config()));
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(POOL_IDLE)
            .pool_max_idle_per_host(spec.max_concurrency as usize)
            .pool_timer(TokioTimer::new())
            .build(https);
        Arc::new(Self {
            concurrency: Lanes::concurrency(spec.max_concurrency),
            pacer: spec.max_requests_per_sec.map(Pacer::new),
            budget: spec.max_units_per_minute.map(|u| TokenBucket::per_minute(u, env.held_lock_share)),
            egress: env.egress.clone(),
            request_timeout: t.request(),
            spec,
            client,
        })
    }

    pub fn alias(&self) -> &str {
        &self.spec.alias
    }

    /// Spends `units` of the operator budget (always true without one). Work that holds no lock
    /// may not take the held-lock share of it.
    pub fn try_spend(&self, units: u64, held: bool) -> bool {
        self.budget.as_ref().is_none_or(|b| b.try_take(units, held))
    }

    async fn gate(&self, held: bool, wait: &WaitFlag) -> Result<LanePermit, EndpointError> {
        wait.during(async {
            if let Some(p) = &self.pacer {
                p.acquire(held).await;
            }
            Ok(self.concurrency.acquire(held, 1).await)
        })
        .await
    }

    /// `url` as the URL standard normalizes it (the host lowercased, IDNA, IP literals in canonical
    /// form, percent-encoding), as a request URI.
    fn uri(&self, url: &str) -> Result<http::Uri, EndpointError> {
        let u = url::Url::parse(url).map_err(|_| EndpointError::Local("the endpoint URL does not parse".into()))?;
        http::Uri::try_from(u.as_str()).map_err(|_| EndpointError::Local("the endpoint URL is not a request URI".into()))
    }

    fn request(&self, method: http::Method, uri: http::Uri, body: Vec<u8>, json: bool) -> Result<http::Request<Full<Bytes>>, EndpointError> {
        let mut req = http::Request::builder()
            .method(method)
            .uri(uri)
            .header(USER_AGENT_HEADER, HeaderValue::from_static(USER_AGENT))
            .header(ACCEPT, HeaderValue::from_static("*/*"));
        if json {
            req = req.header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        if let Some((name, value)) = &self.spec.key_header {
            req = req.header(name.clone(), value.clone());
        }
        req.body(Full::new(Bytes::from(body))).map_err(|_| EndpointError::Local("building the request".into()))
    }

    async fn send(&self, req: http::Request<Full<Bytes>>, deadline: Instant) -> Result<hyper::Response<hyper::body::Incoming>, EndpointError> {
        match tokio::time::timeout_at(deadline, self.client.request(req)).await {
            Err(_) => Err(EndpointError::Timeout),
            Ok(Err(e)) => Err(self.transport(&e)),
            Ok(Ok(r)) => Ok(r),
        }
    }

    /// POSTs a JSON body to the endpoint URL; the 2xx response body, at most `cap` bytes. `wait` is
    /// marked while the request waits for the pacer or a concurrency slot.
    pub async fn post_json(&self, held: bool, body: Vec<u8>, cap: u64, wait: &WaitFlag) -> Result<Vec<u8>, EndpointError> {
        let slot = self.gate(held, wait).await?;
        let deadline = Instant::now() + self.request_timeout;
        let req = self.request(http::Method::POST, self.uri(self.spec.url())?, body, true)?;
        let resp = self.send(req, deadline).await?;
        let mut r = self.reader(resp, cap, slot, deadline)?;
        let mut out = Vec::new();
        while r.next_into(&mut out).await? {}
        Ok(out)
    }

    /// GETs `url` (built by the broker from this endpoint's template); the 2xx body is read from
    /// the returned reader, at most `cap` bytes.
    pub async fn get(&self, url: &str, held: bool, cap: u64, wait: &WaitFlag) -> Result<BodyReader<'_>, EndpointError> {
        let slot = self.gate(held, wait).await?;
        let deadline = Instant::now() + self.request_timeout;
        let req = self.request(http::Method::GET, self.uri(url)?, Vec::new(), false)?;
        let resp = self.send(req, deadline).await?;
        self.reader(resp, cap, slot, deadline)
    }

    fn reader(&self, resp: hyper::Response<hyper::body::Incoming>, cap: u64, slot: LanePermit, deadline: Instant) -> Result<BodyReader<'_>, EndpointError> {
        let status = resp.status();
        if !status.is_success() {
            return Err(EndpointError::Status(status.as_u16()));
        }
        let body = resp.into_body();
        if http_body::Body::size_hint(&body).exact().is_some_and(|l| l > cap) {
            return Err(EndpointError::TooLarge);
        }
        Ok(BodyReader { ep: self, body, deadline, cap, total: 0, _slot: slot })
    }

    fn transport(&self, e: &(dyn std::error::Error + 'static)) -> EndpointError {
        let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
        while let Some(x) = src {
            if let Some(f) = x.downcast_ref::<ConnectFailed>() {
                match f {
                    ConnectFailed::Connector(ConnectError::Refused(Status::NotAdmitted)) | ConnectFailed::Floor(_) => {
                        return EndpointError::Egress;
                    }
                    _ => {}
                }
            }
            src = x.source();
        }
        let mut s = e.to_string();
        let mut src = e.source();
        while let Some(x) = src {
            s.push_str(": ");
            s.push_str(&x.to_string());
            src = x.source();
        }
        EndpointError::Transport(self.redact(&s))
    }

    /// Logs a failure by alias, with the redacted error.
    pub fn log_failure(&self, what: &str, e: &EndpointError) {
        tracing::warn!(endpoint = %self.spec.alias, error = %self.redact(&e.to_string()), "{what}");
    }

    pub fn redact(&self, s: &str) -> String {
        self.egress.redact(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_side_errors() {
        for (e, op) in [
            (EndpointError::Egress, true),
            (EndpointError::Transport("x".into()), true),
            (EndpointError::Local("x".into()), true),
            (EndpointError::Status(429), true),
            (EndpointError::Status(500), true),
            (EndpointError::Status(307), true),
            (EndpointError::Status(404), false),
            (EndpointError::Timeout, false),
            (EndpointError::TooLarge, false),
        ] {
            assert_eq!(e.operator_side(), op, "{e:?}");
        }
    }

    #[test]
    fn tls_offers_http1_only_with_webpki_roots() {
        let c = tls_config();
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(c.enable_sni);
    }
}
