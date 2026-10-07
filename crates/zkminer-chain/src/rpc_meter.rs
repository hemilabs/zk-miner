//! RPC request meter — a tower layer over the alloy RPC transport that counts
//! every JSON-RPC request actually sent to the endpoint (including alloy-internal
//! calls: receipt polling, gas estimation, nonce fills). A bundled multicall is a
//! single `eth_call`, so it counts as one request — which is the whole point of the
//! batching work.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use alloy::transports::{TransportError, TransportErrorKind, TransportFut};
use alloy_json_rpc::{ErrorPayload, RequestPacket, Response, ResponsePacket, RpcError};
use tower::{Layer, Service};

const WINDOW: Duration = Duration::from_secs(60);

/// Shared counter of RPC requests: a monotonic total plus a rolling 1-minute window.
#[derive(Debug)]
pub struct RpcMeter {
    total: AtomicU64,
    /// Timestamps of recent requests, pruned to the last [`WINDOW`].
    recent: Mutex<VecDeque<Instant>>,
    /// Monotonic count of responses that came back rate-limited (HTTP 429 or a
    /// JSON-RPC rate-limit error).
    rate_limit_total: AtomicU64,
    /// The most recent instant a rate-limit response was observed, if any.
    last_rate_limit: Mutex<Option<Instant>>,
}

impl RpcMeter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
            recent: Mutex::new(VecDeque::new()),
            rate_limit_total: AtomicU64::new(0),
            last_rate_limit: Mutex::new(None),
        })
    }

    fn record(&self, count: usize, now: Instant) {
        if count == 0 {
            return;
        }
        self.total.fetch_add(count as u64, Ordering::Relaxed);
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..count {
            recent.push_back(now);
        }
        Self::prune(&mut recent, now);
    }

    fn prune(recent: &mut VecDeque<Instant>, now: Instant) {
        let cutoff = now.checked_sub(WINDOW);
        while let Some(&front) = recent.front() {
            match cutoff {
                Some(c) if front < c => {
                    recent.pop_front();
                }
                _ => break,
            }
        }
    }

    /// Total requests since startup.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Requests in the last rolling minute.
    pub fn last_minute(&self) -> u64 {
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune(&mut recent, now);
        recent.len() as u64
    }

    /// Note that a response came back rate-limited.
    fn record_rate_limit(&self, now: Instant) {
        self.rate_limit_total.fetch_add(1, Ordering::Relaxed);
        let mut last = self
            .last_rate_limit
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *last = Some(now);
    }

    /// Total rate-limited responses since startup.
    pub fn rate_limit_total(&self) -> u64 {
        self.rate_limit_total.load(Ordering::Relaxed)
    }

    /// True if a rate-limit response was seen within the last `window`.
    ///
    /// This is the health signal the brain consults before claiming a *new* job:
    /// when the endpoint is actively 429-ing, taking on more work only deepens the
    /// backlog (each job's descriptor reconstruction is a heavy `getLogs` burst),
    /// so claiming pauses until the window clears while in-flight jobs keep draining.
    pub fn rate_limited_within(&self, window: Duration) -> bool {
        let last = *self
            .last_rate_limit
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match last {
            Some(t) => Instant::now().saturating_duration_since(t) < window,
            None => false,
        }
    }
}

/// True if a transport result represents a rate-limited / overloaded endpoint.
///
/// This is the signal that pauses NEW claims, so it is deliberately NARROWER than
/// alloy's "should I retry this request" predicate (`is_retry_err`). We build on
/// alloy's canonical codes/messages — which stay current with Infura/Alchemy/
/// QuickNode/Cloudflare quirks — but subtract two branches that are NOT overload
/// signals and would spuriously (or persistently) stall claiming on a healthy
/// chain:
///   * `"header not found"` — an Infura load-balancer consistency race where a
///     request lands on a replica behind the requested block. The miner's
///     descriptor `getLogs` bursts provoke it routinely on healthy endpoints.
///   * `MissingBatchResponse` — a batch-shape/transient issue; if a provider
///     structurally mishandles batches it recurs every tick and would wedge
///     claiming forever, even though the chain is fine.
///
/// A 429 can surface two ways depending on the provider: as a transport-level
/// `Err(HttpError { status: 429 })`, or as an HTTP-200 body carrying a JSON-RPC
/// error (`Ok(ResponsePacket::…Failure)`, e.g. Alchemy's code-429-in-body). Both
/// are handled.
fn is_rate_limited(result: &Result<ResponsePacket, TransportError>) -> bool {
    match result {
        Err(RpcError::ErrorResp(payload)) => payload_is_overloaded(payload),
        Err(RpcError::Transport(kind)) => transport_is_overloaded(kind),
        Err(_) => false,
        Ok(ResponsePacket::Single(resp)) => resp_is_rate_limit(resp),
        Ok(ResponsePacket::Batch(resps)) => resps.iter().any(resp_is_rate_limit),
    }
}

/// True if a single JSON-RPC response carries a rate-limit/overload error payload.
fn resp_is_rate_limit(resp: &Response) -> bool {
    resp.payload.as_error().is_some_and(payload_is_overloaded)
}

/// alloy's canonical rate-limit/retry classification for a JSON-RPC error, minus
/// `"header not found"` (a per-request consistency race, not an overload signal).
fn payload_is_overloaded(payload: &ErrorPayload) -> bool {
    payload.is_retry_err() && payload.message != "header not found"
}

/// True only for genuine transport-level overload: HTTP 429 (rate limit) / 503
/// (temporarily unavailable), or a provider that surfaces 429 as a custom error
/// string. Excludes `MissingBatchResponse` and other merely-retryable variants.
fn transport_is_overloaded(kind: &TransportErrorKind) -> bool {
    match kind.as_http_error() {
        Some(http) => http.is_rate_limit_err() || http.is_temporarily_unavailable(),
        // QuickNode & co. surface 429 as a Custom error; match alloy's own phrase.
        None => kind.to_string().contains("429 Too Many Requests"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::HttpError;
    use alloy_json_rpc::{ErrorPayload, Id, ResponsePayload};

    fn http_err(status: u16) -> Result<ResponsePacket, TransportError> {
        Err(RpcError::Transport(TransportErrorKind::HttpError(
            HttpError {
                status,
                body: String::new(),
            },
        )))
    }

    fn failure_resp(code: i64, message: &'static str) -> Response {
        Response {
            id: Id::Number(1),
            payload: ResponsePayload::Failure(ErrorPayload {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    #[test]
    fn detects_rate_limit_responses() {
        // Alchemy surfaces 429 as a JSON-RPC error code in a 200 body.
        assert!(resp_is_rate_limit(&failure_resp(429, "Too Many Requests")));
        // Infura: "exceeded project rate limit".
        assert!(resp_is_rate_limit(&failure_resp(
            -32005,
            "exceeded project rate limit"
        )));
        // Message-based match on a generic code.
        assert!(resp_is_rate_limit(&failure_resp(
            -32000,
            "rate limit exceeded"
        )));
        // A plain contract revert must NOT trip backoff.
        assert!(!resp_is_rate_limit(&failure_resp(3, "execution reverted")));
        assert!(!resp_is_rate_limit(&failure_resp(
            -32000,
            "insufficient funds for gas"
        )));
        // "header not found" is a per-request consistency race, NOT overload — the
        // narrowed classifier must exclude it so getLogs bursts don't stall claims.
        assert!(!resp_is_rate_limit(&failure_resp(
            -32000,
            "header not found"
        )));
        // is_rate_limited must route an Ok(Failure) packet the same way.
        assert!(is_rate_limited(&Ok(ResponsePacket::Single(failure_resp(
            429,
            "Too Many Requests"
        )))));
        assert!(!is_rate_limited(&Ok(ResponsePacket::Single(failure_resp(
            3,
            "execution reverted"
        )))));
    }

    #[test]
    fn detects_transport_rate_limits() {
        // HTTP 429 / 503 are overload; other 5xx / 4xx are not.
        assert!(is_rate_limited(&http_err(429)));
        assert!(is_rate_limited(&http_err(503)));
        assert!(!is_rate_limited(&http_err(500)));
        assert!(!is_rate_limited(&http_err(400)));
    }

    #[test]
    fn rate_limited_within_tracks_recency() {
        let meter = RpcMeter::new();
        assert!(!meter.rate_limited_within(Duration::from_secs(30)));
        assert_eq!(meter.rate_limit_total(), 0);

        let now = Instant::now();
        meter.record_rate_limit(now);
        assert_eq!(meter.rate_limit_total(), 1);
        // Just recorded ⇒ within any positive window.
        assert!(meter.rate_limited_within(Duration::from_secs(30)));

        // A stale hit (recorded 60s ago) is outside a 30s window.
        let stale = now.checked_sub(Duration::from_secs(60)).unwrap();
        meter.record_rate_limit(stale);
        // last_rate_limit is now `stale` (older than the first) — outside 30s.
        assert!(!meter.rate_limited_within(Duration::from_secs(30)));
        // ...but inside a 90s window.
        assert!(meter.rate_limited_within(Duration::from_secs(90)));
        assert_eq!(meter.rate_limit_total(), 2);
    }
}

/// tower [`Layer`] that installs an [`RpcMeter`] over a transport.
#[derive(Clone)]
pub struct MeterLayer {
    meter: Arc<RpcMeter>,
}

impl MeterLayer {
    pub fn new(meter: Arc<RpcMeter>) -> Self {
        Self { meter }
    }
}

impl<S> Layer<S> for MeterLayer {
    type Service = MeterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        MeterService {
            inner,
            meter: self.meter.clone(),
        }
    }
}

/// Transport wrapper that counts each request packet before forwarding it.
#[derive(Clone)]
pub struct MeterService<S> {
    inner: S,
    meter: Arc<RpcMeter>,
}

impl<S> Service<RequestPacket> for MeterService<S>
where
    S: Service<
        RequestPacket,
        Response = ResponsePacket,
        Error = TransportError,
        Future = TransportFut<'static>,
    >,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let count = match &req {
            RequestPacket::Single(_) => 1,
            RequestPacket::Batch(reqs) => reqs.len(),
        };
        self.meter.record(count, Instant::now());
        let meter = self.meter.clone();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let result = fut.await;
            if is_rate_limited(&result) {
                meter.record_rate_limit(Instant::now());
            }
            result
        })
    }
}

/// tower [`Layer`] that paces outgoing requests to at most one every `min_interval`,
/// smoothing instantaneous bursts so a rate-limited endpoint's per-second cap is never
/// tripped no matter how many lifecycles (monitor + refresh + brain + N concurrent
/// claim/fulfill/release) fire in the same instant.
///
/// This is PURE pacing: it only *delays* — it never retries, swallows, or inspects
/// errors — so genuine 429s still flow through to the [`MeterService`] beneath it (the
/// meter's `rate_limited_within` gate and the brain's claim-pause keep working). It is
/// installed OUTERMOST (delays before the meter records the actual dispatch). Steady
/// state (~1-2 req/s) is unaffected; only concurrent spikes queue into the window.
#[derive(Clone)]
pub struct ThrottleLayer {
    /// Next instant at which a request may be dispatched. Advanced by `min_interval`
    /// per reserved slot so concurrent callers get distinct, monotonically-spaced slots.
    next_slot: Arc<Mutex<Instant>>,
    min_interval: Duration,
}

impl ThrottleLayer {
    /// `max_per_sec`: sustained requests/second ceiling. Excess concurrent requests
    /// queue (each waits for its reserved slot) rather than firing in the same second.
    /// Keep this safely BELOW the endpoint's observed per-second cap (~5/s here).
    pub fn new(max_per_sec: u32) -> Self {
        let mps = max_per_sec.max(1) as u64;
        Self {
            next_slot: Arc::new(Mutex::new(Instant::now())),
            min_interval: Duration::from_micros(1_000_000 / mps),
        }
    }
}

impl<S> Layer<S> for ThrottleLayer {
    type Service = ThrottleService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ThrottleService {
            inner,
            next_slot: self.next_slot.clone(),
            min_interval: self.min_interval,
        }
    }
}

/// Transport wrapper that delays each request until its reserved pacing slot.
#[derive(Clone)]
pub struct ThrottleService<S> {
    inner: S,
    next_slot: Arc<Mutex<Instant>>,
    min_interval: Duration,
}

impl<S> Service<RequestPacket> for ThrottleService<S>
where
    S: Service<
        RequestPacket,
        Response = ResponsePacket,
        Error = TransportError,
        Future = TransportFut<'static>,
    >,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        // Reserve this request's slot synchronously (brief lock, no await held) so
        // concurrent calls each claim a distinct, spaced slot; the future then sleeps
        // until that slot before the request reaches the transport. inner.call() is
        // lazy (the HTTP request is not issued until the returned future is polled),
        // so constructing it before the sleep does not send anything early.
        let now = Instant::now();
        let slot = {
            let mut next = self.next_slot.lock().unwrap_or_else(|e| e.into_inner());
            let slot = if *next <= now { now } else { *next };
            *next = slot + self.min_interval;
            slot
        };
        let delay = slot.saturating_duration_since(now);
        let fut = self.inner.call(req);
        Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            fut.await
        })
    }
}
