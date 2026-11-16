//! Test support, not for production: a minimal HTTP/1.1 server, a test network floor, a mock
//! `evm-rpc` codec, a fake builder, and a broker started in-process (no sandbox).
//!
//! [`TestEgress`] stands in for [`crate::egress`] until its implementation merges: role entries
//! match by prefix and port, the requester path admits only global addresses on 443, and
//! redaction replaces URLs. [`MockCodec`] stands in for [`crate::evm_rpc`] with a toy request
//! format (below), so the broker's failover, caching and budget logic can be tested now.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zkminer_witness::envelope::MethodSet;
use zkminer_witness::ipc::{
    decode_fetch_result, encode_fetch, fetch_result_frame_max, FetchStatus, FRAME_HEADER_BYTES, KIND_FETCH,
    KIND_FETCH_RESULT,
};

use crate::client::BrokerClient;
use crate::config::{mask, BrokerConfig};
use crate::egress::{Admit, DenyReason, EgressPolicy, Prefix, Role};
use crate::evm_rpc::{BlockPin, BlockTag, CallAnswer, Denied, ResponseError};
use crate::hooks::{EgressHooks, Hooks, RpcCodec, RpcReq};

// ---------------------------------------------------------------------------------------------
// HTTP server.

#[derive(Debug, Clone)]
pub struct TestRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl TestRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct TestResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub delay: Option<Duration>,
    /// Send `Content-Length` (else the body is delimited by closing the connection).
    pub content_length: bool,
    pub headers: Vec<(String, String)>,
}

impl TestResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self { status: 200, body: body.into(), delay: None, content_length: true, headers: vec![] }
    }
    pub fn status(status: u16) -> Self {
        Self { status, ..Self::ok(Vec::new()) }
    }
    pub fn delayed(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }
    pub fn without_length(mut self) -> Self {
        self.content_length = false;
        self
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

type Handler = Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync>;

/// A one-request-per-connection HTTP/1.1 server on 127.0.0.1.
pub struct TestServer {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub requests: Arc<std::sync::Mutex<Vec<TestRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub async fn start(handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static) -> Self {
        Self::start_at("127.0.0.1:0".parse().expect("addr"), handler).await.expect("bind")
    }

    /// On a given address (another loopback address, or a port another server already has on
    /// another address).
    pub async fn start_at(
        at: SocketAddr,
        handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(at).await?;
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let (h, r, hd) = (hits.clone(), requests.clone(), handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = listener.accept().await else { return };
                let (h, r, hd) = (h.clone(), r.clone(), hd.clone());
                tokio::spawn(async move {
                    let _ = serve_conn(conn, h, r, hd).await;
                });
            }
        });
        Ok(Self { addr, hits, requests, task })
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn serve_conn(
    mut conn: tokio::net::TcpStream,
    hits: Arc<AtomicUsize>,
    requests: Arc<std::sync::Mutex<Vec<TestRequest>>>,
    handler: Handler,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = conn.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = conn.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let req = TestRequest { method, path, headers, body };
    hits.fetch_add(1, Ordering::SeqCst);
    requests.lock().unwrap().push(req.clone());
    let resp = handler(req);
    if let Some(d) = resp.delay {
        tokio::time::sleep(d).await;
    }
    let mut out = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", resp.status);
    if resp.content_length {
        out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    conn.write_all(out.as_bytes()).await?;
    conn.write_all(&resp.body).await?;
    conn.shutdown().await
}

// ---------------------------------------------------------------------------------------------
// The test network floor.

/// A stand-in for [`crate::egress`]: role entries by prefix and port; the requester path admits
/// global addresses on 443 outside `deny` and `connected`.
#[derive(Debug, Default, Clone)]
pub struct TestEgress {
    pub connected: Vec<Prefix>,
}

fn contains(p: &Prefix, ip: IpAddr) -> bool {
    crate::config::prefix_contains(p, ip)
}

fn roughly_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return roughly_global(IpAddr::V4(v4));
            }
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

impl EgressHooks for TestEgress {
    fn admit(&self, policy: &EgressPolicy, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit {
        let ip = addr.ip();
        match role {
            Some((role, alias)) => {
                let Some(e) = policy.roles.iter().find(|e| e.role == role && e.alias == alias) else {
                    return Admit::Denied(DenyReason::NoRoleEntry);
                };
                if e.port != addr.port() {
                    return Admit::Denied(DenyReason::WrongPort);
                }
                if e.prefixes.iter().any(|p| contains(p, ip)) {
                    Admit::Role
                } else {
                    Admit::Denied(DenyReason::NoRoleEntry)
                }
            }
            None => {
                if !roughly_global(ip) {
                    Admit::Denied(DenyReason::NotGlobal)
                } else if policy.deny.iter().any(|p| contains(p, ip)) {
                    Admit::Denied(DenyReason::DenyCidr)
                } else if policy.connected.iter().any(|p| contains(p, ip)) {
                    Admit::Denied(DenyReason::ConnectedPrefix)
                } else if addr.port() != 443 {
                    Admit::Denied(DenyReason::WrongPort)
                } else {
                    Admit::Global
                }
            }
        }
    }

    fn connected_prefixes(&self) -> std::io::Result<Vec<Prefix>> {
        Ok(self.connected.clone())
    }

    fn redact(&self, s: &str) -> String {
        s.split(' ')
            .map(|w| if w.contains("://") { "<url>".to_string() } else { w.escape_default().to_string() })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A prefix from its text (tests).
pub fn prefix(s: &str) -> Prefix {
    crate::config::parse_cidr(s).unwrap_or_else(|_| {
        let (a, l) = s.split_once('/').expect("addr/len");
        let len: u8 = l.parse().expect("len");
        Prefix { addr: mask(a.parse().expect("addr"), len), len }
    })
}

// ---------------------------------------------------------------------------------------------
// The mock codec.
//
// A request is a JSON string (one call) or an array of strings (a batch). A name starting with
// "deny" is refused; "latest", "safe" and "finalized" need that tag; names starting with "h:" are
// pinned (cacheable); "n:<decimal>" names an explicit block number. The outgoing body is
// `{"first_id":N,"calls":[…],"tags":{"latest":n,…}}`; an answer body is `{"lagging":true}` or
// `{"answers":[{"id":N,"result":"…"}|{"id":N,"error":"…"},…]}`, whose canonical form per call is the
// JSON string of the result (or `{"error":"…"}`). A tag query is `{"tag_query":"latest","id":N}`,
// answered `{"id":N,"number":n}`.

#[derive(Debug, Default, Clone, Copy)]
pub struct MockCodec;

#[derive(Debug, Clone)]
pub struct MockReq {
    pub calls: Vec<String>,
    pub batch: bool,
}

fn tag_name(t: BlockTag) -> &'static str {
    match t {
        BlockTag::Latest => "latest",
        BlockTag::Safe => "safe",
        BlockTag::Finalized => "finalized",
    }
}

impl RpcCodec for MockCodec {
    fn parse(&self, bytes: &[u8], _set: MethodSet) -> Result<Box<dyn RpcReq>, Denied> {
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Denied::Malformed)?;
        let (calls, batch) = match v {
            serde_json::Value::String(s) => (vec![s], false),
            serde_json::Value::Array(a) => {
                let calls: Option<Vec<String>> = a.into_iter().map(|x| x.as_str().map(str::to_string)).collect();
                (calls.ok_or(Denied::Malformed)?, true)
            }
            _ => return Err(Denied::Malformed),
        };
        if calls.is_empty() || calls.len() > crate::evm_rpc::MAX_BATCH {
            return Err(Denied::BatchSize);
        }
        if calls.iter().any(|c| c.starts_with("deny")) {
            return Err(Denied::MethodNotAllowed);
        }
        Ok(Box::new(MockReq { calls, batch }))
    }

    fn tag_query(&self, tag: BlockTag, id: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"tag_query": tag_name(tag), "id": id})).unwrap()
    }

    fn parse_tag_answer(&self, body: &[u8], id: u64) -> Result<u64, ResponseError> {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| ResponseError::Malformed)?;
        if v.get("lagging").is_some() {
            return Err(ResponseError::Lagging);
        }
        if v.get("id").and_then(|x| x.as_u64()) != Some(id) {
            return Err(ResponseError::Mismatch);
        }
        v.get("number").and_then(|x| x.as_u64()).ok_or(ResponseError::Malformed)
    }
}

impl RpcReq for MockReq {
    fn len(&self) -> usize {
        self.calls.len()
    }
    fn tags(&self) -> Vec<BlockTag> {
        let mut t = Vec::new();
        for c in &self.calls {
            let tag = match c.as_str() {
                "latest" => BlockTag::Latest,
                "safe" => BlockTag::Safe,
                "finalized" => BlockTag::Finalized,
                _ => continue,
            };
            if !t.contains(&tag) {
                t.push(tag);
            }
        }
        t
    }
    /// Calls named `n:<decimal>` name that explicit block number.
    fn max_block_number(&self) -> Option<u64> {
        self.calls.iter().filter_map(|c| c.strip_prefix("n:")?.parse().ok()).max()
    }
    fn pin(&self, i: usize, _resolve: &dyn Fn(BlockTag) -> u64) -> Option<BlockPin> {
        self.calls.get(i)?.strip_prefix("n:")?.parse().ok().map(BlockPin::Number)
    }
    fn check_after_resolution(&self, _resolve: &dyn Fn(BlockTag) -> u64) -> Result<(), Denied> {
        Ok(())
    }
    fn outgoing(&self, resolve: &dyn Fn(BlockTag) -> u64, first_id: u64) -> Vec<u8> {
        let tags: serde_json::Map<String, serde_json::Value> =
            self.tags().into_iter().map(|t| (tag_name(t).to_string(), resolve(t).into())).collect();
        serde_json::to_vec(&serde_json::json!({"first_id": first_id, "calls": self.calls, "tags": tags})).unwrap()
    }
    fn subset(&self, indices: &[usize]) -> Box<dyn RpcReq> {
        Box::new(MockReq { calls: indices.iter().map(|&i| self.calls[i].clone()).collect(), batch: self.batch })
    }
    fn cache_key(&self, i: usize) -> Option<Vec<u8>> {
        self.calls[i].starts_with("h:").then(|| self.calls[i].as_bytes().to_vec())
    }
    fn parse_answers(&self, body: &[u8], first_id: u64, max_bytes: usize) -> Result<Vec<CallAnswer>, ResponseError> {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| ResponseError::Malformed)?;
        if v.get("lagging").is_some() {
            return Err(ResponseError::Lagging);
        }
        let answers = v.get("answers").and_then(|a| a.as_array()).ok_or(ResponseError::Malformed)?;
        if answers.len() != self.calls.len() {
            return Err(ResponseError::Mismatch);
        }
        let mut out = Vec::new();
        let mut total = 0;
        for (i, a) in answers.iter().enumerate() {
            if a.get("id").and_then(|x| x.as_u64()) != Some(first_id + i as u64) {
                return Err(ResponseError::Mismatch);
            }
            let (canonical, is_error) = if let Some(r) = a.get("result") {
                (serde_json::to_vec(r).unwrap(), false)
            } else if let Some(e) = a.get("error") {
                (serde_json::to_vec(&serde_json::json!({"error": e})).unwrap(), true)
            } else {
                return Err(ResponseError::Malformed);
            };
            total += canonical.len();
            if total > max_bytes {
                return Err(ResponseError::TooLarge);
            }
            out.push(CallAnswer { canonical, is_error, suspect: false });
        }
        Ok(out)
    }
    fn render(&self, answers: &[CallAnswer]) -> Vec<u8> {
        if !self.batch {
            return answers[0].canonical.clone();
        }
        let mut out = b"[".to_vec();
        for (i, a) in answers.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(&a.canonical);
        }
        out.push(b']');
        out
    }
}

/// A mock node: answers each call `"<name>@<tags>"`, tag queries with `number`.
pub fn mock_node(number: u64) -> impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static {
    move |req| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        if let Some(id) = v.get("tag_query").and(v.get("id")) {
            return TestResponse::ok(serde_json::to_vec(&serde_json::json!({"id": id, "number": number})).unwrap());
        }
        let first = v.get("first_id").and_then(|x| x.as_u64()).unwrap_or(0);
        let tags = v.get("tags").cloned().unwrap_or_default();
        let answers: Vec<serde_json::Value> = v
            .get("calls")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let name = c.as_str().unwrap_or_default();
                if name.contains("revert") {
                    serde_json::json!({"id": first + i as u64, "error": "reverted"})
                } else {
                    serde_json::json!({"id": first + i as u64, "result": format!("{name}@{tags}")})
                }
            })
            .collect();
        TestResponse::ok(serde_json::to_vec(&serde_json::json!({"answers": answers})).unwrap())
    }
}

// ---------------------------------------------------------------------------------------------
// Harness.

/// Test hooks: [`TestEgress`] and [`MockCodec`].
pub fn test_hooks() -> Hooks {
    Hooks { egress: Arc::new(TestEgress::default()), codec: Arc::new(MockCodec) }
}

/// Test hooks with the real codec (merge-dependent: `evm_rpc` is a stub until then).
pub fn test_egress_real_codec() -> Hooks {
    Hooks { egress: Arc::new(TestEgress::default()), codec: Arc::new(crate::hooks::RealCodec) }
}

/// Starts a broker in-process on a socketpair and returns the miner's client.
pub async fn spawn_broker(config: BrokerConfig, hooks: Hooks) -> (BrokerClient, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let (miner, broker) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn(crate::serve_with(config, std::os::fd::OwnedFd::from(broker), hooks));
    (BrokerClient::new(miner).expect("client"), task)
}

/// The builder's side of a job socket.
pub struct FakeBuilder {
    pub sock: tokio::net::UnixStream,
    pub max_response_bytes: u32,
}

impl FakeBuilder {
    pub fn new(sock: std::os::unix::net::UnixStream, max_response_bytes: u32) -> Self {
        sock.set_nonblocking(true).expect("nonblocking");
        Self { sock: tokio::net::UnixStream::from_std(sock).expect("tokio socket"), max_response_bytes }
    }

    /// Sends one fetch frame.
    pub async fn send(&mut self, cap: u32, request: &[u8]) {
        let payload = encode_fetch(cap, request);
        let mut frame = vec![KIND_FETCH];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        self.sock.write_all(&frame).await.expect("write fetch");
    }

    /// Reads one result frame; `None` if the broker closed the socket.
    pub async fn recv(&mut self) -> Option<(FetchStatus, Vec<u8>)> {
        let mut h = [0u8; FRAME_HEADER_BYTES];
        self.sock.read_exact(&mut h).await.ok()?;
        assert_eq!(h[0], KIND_FETCH_RESULT);
        let len = u32::from_be_bytes(h[1..].try_into().unwrap());
        assert!(len <= fetch_result_frame_max(self.max_response_bytes), "result frame within the job's cap");
        let mut p = vec![0u8; len as usize];
        self.sock.read_exact(&mut p).await.ok()?;
        let (s, body) = decode_fetch_result(&p).expect("result decodes");
        Some((s, body.to_vec()))
    }

    pub async fn fetch(&mut self, cap: u32, request: &[u8]) -> (FetchStatus, Vec<u8>) {
        self.send(cap, request).await;
        self.recv().await.expect("a result")
    }
}

/// A config text with the common top-level keys (spool in `dir`), plus `extra`.
pub fn config_text(dir: &std::path::Path, extra: &str) -> String {
    format!(
        "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n{extra}",
        dir.join("spool").display()
    )
}

// ---------------------------------------------------------------------------------------------
// DNS.

/// A UDP DNS server on 127.0.0.1 answering `A`/`AAAA` queries from a fixed table (lowercase names,
/// no trailing dot); `NXDOMAIN` for other names. Counts the queries it answered.
pub struct TestDns {
    pub addr: SocketAddr,
    pub queries: Arc<AtomicUsize>,
    records: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<IpAddr>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestDns {
    pub async fn start(records: &[(&str, &[&str])]) -> Self {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        let queries = Arc::new(AtomicUsize::new(0));
        let table = Arc::new(std::sync::Mutex::new(
            records.iter().map(|(n, ips)| (n.to_string(), ips.iter().map(|s| s.parse().expect("ip")).collect())).collect(),
        ));
        let (q, t) = (queries.clone(), table.clone());
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                let answer = dns_answer(&buf[..n], &t.lock().unwrap());
                if let Some(answer) = answer {
                    q.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.send_to(&answer, peer).await;
                }
            }
        });
        Self { addr, queries, records: table, task }
    }

    /// `[dns]` for a broker config.
    pub fn config(&self) -> String {
        format!("[dns]\nservers = [\"{}\"]\n", self.addr)
    }

    /// Changes what `name` resolves to.
    pub fn set(&self, name: &str, ips: &[&str]) {
        self.records.lock().unwrap().insert(name.to_string(), ips.iter().map(|s| s.parse().expect("ip")).collect());
    }

    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

fn dns_answer(q: &[u8], table: &std::collections::HashMap<String, Vec<IpAddr>>) -> Option<Vec<u8>> {
    if q.len() < 12 {
        return None;
    }
    let mut labels = Vec::new();
    let mut i = 12;
    loop {
        let l = usize::from(*q.get(i)?);
        if l == 0 {
            i += 1;
            break;
        }
        labels.push(String::from_utf8_lossy(q.get(i + 1..i + 1 + l)?).to_ascii_lowercase());
        i += 1 + l;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let question = q.get(12..i + 4)?;
    let name = labels.join(".");
    let ips: Vec<IpAddr> = table
        .get(&name)
        .map(|v| v.iter().copied().filter(|ip| (qtype == 1 && ip.is_ipv4()) || (qtype == 28 && ip.is_ipv6())).collect())
        .unwrap_or_default();
    let rcode = if table.contains_key(&name) { 0 } else { 3 };
    let mut a = Vec::new();
    a.extend_from_slice(&q[..2]);
    a.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    a.extend_from_slice(&1u16.to_be_bytes());
    a.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    a.extend_from_slice(&[0, 0, 0, 0]);
    a.extend_from_slice(question);
    for ip in ips {
        a.extend_from_slice(&[0xc0, 12]);
        a.extend_from_slice(&qtype.to_be_bytes());
        a.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
        match ip {
            IpAddr::V4(v) => {
                a.extend_from_slice(&4u16.to_be_bytes());
                a.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                a.extend_from_slice(&16u16.to_be_bytes());
                a.extend_from_slice(&v.octets());
            }
        }
    }
    Some(a)
}
