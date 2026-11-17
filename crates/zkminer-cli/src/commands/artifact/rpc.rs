//! The publisher's JSON-RPC client: every request through the network guard
//! (`zkminer_netguard::GuardedClient::post_json`: the URL checked, each address vetted and pinned,
//! no proxy, no redirect), paced by a limiter of its own (§13.5 "uses its own limiter"), each
//! response read under a cap. The URL (which may carry a provider key) is never logged or put in an
//! error: errors name the host only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zkminer_netguard::{GuardedClient, NetPolicy};

/// Bound on one request, response head and body.
pub const REQUEST_BUDGET: Duration = Duration::from_secs(30);
/// The largest response body read (a batch of 256 full chunks is about 12.6 MB of hex).
pub const MAX_RESPONSE_BYTES: usize = 32 << 20;

/// A JSON-RPC error the node answered (not a transport failure).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the node answered error {code}: {message}")]
pub struct NodeError {
    pub code: i64,
    pub message: String,
}

pub struct Rpc {
    client: GuardedClient,
    url: String,
    host: String,
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
    ids: AtomicU64,
}

impl std::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rpc").field("host", &self.host).finish_non_exhaustive()
    }
}

impl Rpc {
    /// A client for `url` under `policy`, at most `max_requests_per_sec` requests a second. The URL
    /// is checked by the guard now, so a refused one fails before anything else.
    pub fn new(policy: &NetPolicy, url: &str, max_requests_per_sec: u32) -> Result<Self> {
        let parsed = policy.check_url(url).map_err(|d| anyhow::anyhow!("--rpc-url is refused by the network guard: {d}"))?;
        let host = parsed.host_str().unwrap_or("").to_string();
        let client = zkminer_netguard::guarded_client(policy).context("building the guarded HTTP client")?;
        Ok(Rpc {
            client,
            url: url.to_string(),
            host,
            interval: Duration::from_secs(1) / max_requests_per_sec.max(1),
            next: tokio::sync::Mutex::new(Instant::now()),
            ids: AtomicU64::new(1),
        })
    }

    /// The endpoint's host, for messages.
    pub fn host(&self) -> &str {
        &self.host
    }

    async fn pace(&self) {
        let mut next = self.next.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = Instant::now() + self.interval;
    }

    async fn post(&self, body: &Value) -> Result<Value> {
        self.pace().await;
        let bytes = serde_json::to_vec(body)?;
        let deadline = Instant::now() + REQUEST_BUDGET;
        let mut resp = self
            .client
            .post_json(&self.url, bytes, REQUEST_BUDGET)
            .await
            .map_err(|e| anyhow::anyhow!("the RPC at {}: {e}", self.host))?;
        if !resp.status().is_success() {
            bail!("the RPC at {} answered HTTP {}", self.host, resp.status().as_u16());
        }
        let mut buf = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let chunk = tokio::time::timeout(left, resp.chunk())
                .await
                .map_err(|_| anyhow::anyhow!("the RPC at {} timed out", self.host))?
                .map_err(|e| anyhow::anyhow!("the RPC at {}: {}", self.host, e.without_url()))?;
            match chunk {
                Some(c) => {
                    if buf.len() + c.len() > MAX_RESPONSE_BYTES {
                        bail!("the RPC at {} answered more than {MAX_RESPONSE_BYTES} bytes", self.host);
                    }
                    buf.extend_from_slice(&c);
                }
                None => break,
            }
        }
        serde_json::from_slice(&buf).with_context(|| format!("the RPC at {} answered something that is not JSON", self.host))
    }

    fn node_error(v: &Value) -> Option<NodeError> {
        let e = v.get("error")?;
        Some(NodeError {
            code: e.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: zkminer_chain::programs::sanitize_log(e.get("message").and_then(Value::as_str).unwrap_or(""))
                .chars()
                .take(300)
                .collect(),
        })
    }

    /// One call; a node error is returned as a [`NodeError`] in the chain.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let v = self.post(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).await?;
        if let Some(e) = Self::node_error(&v) {
            return Err(anyhow::Error::new(e).context(method.to_string()));
        }
        v.get("result").cloned().with_context(|| format!("{method}: no result"))
    }

    /// Several calls in one batch, answered in request order (each a result or a node error).
    pub async fn batch(&self, calls: &[(&str, Value)]) -> Result<Vec<Result<Value, NodeError>>> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        let first = self.ids.fetch_add(calls.len() as u64, Ordering::Relaxed);
        let body: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, (m, p))| json!({"jsonrpc": "2.0", "id": first + i as u64, "method": m, "params": p}))
            .collect();
        let v = self.post(&Value::Array(body)).await?;
        let arr = v.as_array().with_context(|| format!("the RPC at {} answered a batch with no array", self.host))?;
        let mut out: Vec<Option<Result<Value, NodeError>>> = vec![None; calls.len()];
        for item in arr {
            let Some(id) = item.get("id").and_then(Value::as_u64) else { continue };
            let Some(i) = id.checked_sub(first).map(|i| i as usize).filter(|i| *i < calls.len()) else { continue };
            out[i] = Some(match Self::node_error(item) {
                Some(e) => Err(e),
                None => Ok(item.get("result").cloned().unwrap_or(Value::Null)),
            });
        }
        out.into_iter()
            .enumerate()
            .map(|(i, r)| r.with_context(|| format!("the batch's answer lacks request {i}")))
            .collect()
    }
}

/// A JSON-RPC quantity (`"0x…"`).
pub fn qty(v: &Value) -> Result<u128> {
    let s = v.as_str().context("expected a hex quantity")?;
    let h = s.strip_prefix("0x").context("expected 0x")?;
    u128::from_str_radix(if h.is_empty() { "0" } else { h }, 16).context("not a hex quantity")
}

/// `0x` hex data.
pub fn data(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().context("expected hex data")?;
    alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("not hex data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_and_data_parse_strictly() {
        assert_eq!(qty(&json!("0x0")).unwrap(), 0);
        assert_eq!(qty(&json!("0x")).unwrap(), 0);
        assert_eq!(qty(&json!("0x3b9aca00")).unwrap(), 1_000_000_000);
        assert!(qty(&json!("12")).is_err());
        assert!(qty(&json!(12)).is_err());
        assert_eq!(data(&json!("0x00ff")).unwrap(), vec![0, 0xff]);
        assert!(data(&json!("0xzz")).is_err());
    }

    #[test]
    fn a_refused_url_fails_before_anything_connects() {
        let public = NetPolicy::with_facts(zkminer_netguard::NetMode::Public, zkminer_netguard::HostFacts::empty(), Vec::new());
        for url in ["http://127.0.0.1:8545", "http://localhost:8545", "http://10.0.0.5:8545", "file:///etc/passwd"] {
            let e = Rpc::new(&public, url, 4).unwrap_err().to_string();
            assert!(e.contains("refused by the network guard"), "{url}: {e}");
        }
        let dev = NetPolicy::with_facts(zkminer_netguard::NetMode::DevPrivate, zkminer_netguard::HostFacts::empty(), Vec::new());
        assert_eq!(Rpc::new(&dev, "http://127.0.0.1:8545", 4).unwrap().host(), "127.0.0.1");
    }
}
