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

/// A priority lane of the chain client's pacer (design §17.6), highest priority first.
///
/// Every request takes the lane of the task-local scope it is issued from ([`with_lane`]); a request
/// issued outside any scope is [`Lane::Default`]. With every request in one lane the pacer is exactly
/// the single FIFO limiter it was before lanes existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Lane {
    /// Reads and sends for a lock this miner already holds: its fulfil, release, recovery and
    /// deadline reads. Never waits behind anything but another held-lock request.
    HeldLock = 0,
    /// Lock transactions (the claim send, and the reads inside it).
    Lock = 1,
    /// Pre-claim reads for candidate jobs (descriptor fetches, static gates, simulation's chain
    /// reads). Capped at a share of the endpoint's rate ([`LaneConfig::pre_claim_share`]), even when
    /// the endpoint is otherwise idle.
    PreClaim = 2,
    /// Everything else, and every request no scope names a lane for.
    Default = 3,
}

const LANES: usize = 4;

impl Lane {
    /// Every lane, highest priority first.
    pub const ALL: [Lane; LANES] = [Lane::HeldLock, Lane::Lock, Lane::PreClaim, Lane::Default];

    fn idx(self) -> usize {
        self as usize
    }

    pub fn label(self) -> &'static str {
        match self {
            Lane::HeldLock => "held-lock",
            Lane::Lock => "lock",
            Lane::PreClaim => "pre-claim",
            Lane::Default => "default",
        }
    }
}

tokio::task_local! {
    static CURRENT_LANE: Lane;
}

/// Run `fut` with every RPC request it issues (through any [`ChainClient`](crate::client::ChainClient)
/// clone, including the provider's own fillers: nonce, gas, chain id) charged to `lane`. Scopes nest;
/// the innermost wins. Tasks spawned from inside do NOT inherit the lane.
pub fn with_lane<F: std::future::Future>(
    lane: Lane,
    fut: F,
) -> tokio::task::futures::TaskLocalFuture<Lane, F> {
    CURRENT_LANE.scope(lane, fut)
}

/// [`with_lane`] for synchronous code: requests created (not only awaited) inside `f` take `lane`.
pub fn with_lane_sync<R>(lane: Lane, f: impl FnOnce() -> R) -> R {
    CURRENT_LANE.sync_scope(lane, f)
}

/// The lane a request issued here would take.
pub fn current_lane() -> Lane {
    CURRENT_LANE.try_with(|l| *l).unwrap_or(Lane::Default)
}

/// Lane policy for [`ThrottleLayer::with_lanes`].
#[derive(Debug, Clone, Copy)]
pub struct LaneConfig {
    /// The share of `max_requests_per_sec` pre-claim reads may use, in `(0, 1]` (default 0.25). The
    /// budget is per one-second tick: at most `max(1, share x rate)` in a burst, refilled at
    /// `share x rate` per second (a GCRA), so over any window of `T` seconds pre-claim reads take
    /// at most `max(1, share x rate) + share x rate x T` slots.
    pub pre_claim_share: f64,
}

impl Default for LaneConfig {
    fn default() -> Self {
        Self {
            pre_claim_share: 0.25,
        }
    }
}

/// Requests dispatched and waiting, per lane (index = `Lane as usize`, see [`Lane::ALL`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaneStats {
    pub dispatched: [u64; LANES],
    pub waiting: [usize; LANES],
}

impl LaneStats {
    pub fn dispatched(&self, lane: Lane) -> u64 {
        self.dispatched[lane.idx()]
    }

    pub fn waiting(&self, lane: Lane) -> usize {
        self.waiting[lane.idx()]
    }
}

/// The pre-claim budget: a GCRA (a token bucket kept as a "theoretical arrival time"), exact in
/// integer time.
#[derive(Debug)]
struct Gcra {
    /// Theoretical arrival time of the next conforming request.
    tat: tokio::time::Instant,
    /// One token's worth of time: `1 / (share x rate)`.
    emission: Duration,
    /// How far ahead of `tat` a request may still conform: `(burst - 1) x emission`.
    tolerance: Duration,
}

impl Gcra {
    fn new(now: tokio::time::Instant, per_sec: f64) -> Self {
        let per_sec = per_sec.max(1e-3);
        let burst = per_sec.floor().max(1.0);
        let emission = Duration::from_secs_f64(1.0 / per_sec);
        Self {
            tat: now,
            emission,
            tolerance: emission.mul_f64(burst - 1.0),
        }
    }

    /// The earliest instant a request conforms.
    fn ready_at(&self) -> tokio::time::Instant {
        self.tat.checked_sub(self.tolerance).unwrap_or(self.tat)
    }

    fn take(&mut self, now: tokio::time::Instant) {
        self.tat = self.tat.max(now) + self.emission;
    }
}

struct SchedState {
    /// The earliest instant the next request may be dispatched (the pacing slot).
    next_slot: tokio::time::Instant,
    /// Waiting tickets, FIFO per lane.
    queues: [std::collections::VecDeque<u64>; LANES],
    next_ticket: u64,
    pre_claim: Gcra,
    dispatched: [u64; LANES],
}

impl SchedState {
    /// The ticket to dispatch next, pacing aside: the head of the highest-priority lane allowed to go
    /// now. The pre-claim lane is passed over while its budget is spent (lower lanes may then go).
    fn select(&self, now: tokio::time::Instant) -> Option<(usize, u64)> {
        self.queues.iter().enumerate().find_map(|(lane, q)| {
            let head = *q.front()?;
            if lane == Lane::PreClaim.idx() && now < self.pre_claim.ready_at() {
                return None;
            }
            Some((lane, head))
        })
    }
}

/// The shared pacer behind every clone of one [`ThrottleLayer`].
///
/// Waiters drive it themselves (no background task): the selected waiter sleeps until the pacing
/// slot and dispatches; every dispatch or abandoned wait wakes the rest to re-select. A pre-claim
/// head held back by its budget sleeps until the budget allows it.
struct LaneScheduler {
    state: Mutex<SchedState>,
    wake: tokio::sync::Notify,
    min_interval: Duration,
}

impl LaneScheduler {
    fn lock(&self) -> std::sync::MutexGuard<'_, SchedState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take a place in `lane`'s queue now (so FIFO order is call order, as before lanes).
    fn enqueue(self: &Arc<Self>, lane: Lane) -> Ticket {
        let mut st = self.lock();
        let id = st.next_ticket;
        st.next_ticket += 1;
        st.queues[lane.idx()].push_back(id);
        Ticket {
            sched: self.clone(),
            lane,
            id,
            dispatched: false,
        }
    }

    fn stats(&self) -> LaneStats {
        let st = self.lock();
        LaneStats {
            dispatched: st.dispatched,
            waiting: std::array::from_fn(|i| st.queues[i].len()),
        }
    }
}

/// A request's place in the pacer. Dropping it before it is dispatched (the request's future was
/// cancelled) gives the place up, so a cancelled request no longer burns a slot.
struct Ticket {
    sched: Arc<LaneScheduler>,
    lane: Lane,
    id: u64,
    dispatched: bool,
}

impl Ticket {
    /// Wait for this ticket's turn: it must be the selected head, and the pacing slot reached.
    async fn wait(mut self) {
        let sched = self.sched.clone();
        loop {
            let notified = sched.wake.notified();
            tokio::pin!(notified);
            // Register before reading the state, so a dispatch between the read and the await still
            // wakes this waiter.
            notified.as_mut().enable();
            let wake_at = {
                let mut st = sched.lock();
                let now = tokio::time::Instant::now();
                match st.select(now) {
                    Some((lane, id)) if id == self.id => {
                        if now >= st.next_slot {
                            st.queues[lane].pop_front();
                            st.next_slot = now + sched.min_interval;
                            if lane == Lane::PreClaim.idx() {
                                st.pre_claim.take(now);
                            }
                            st.dispatched[lane] += 1;
                            self.dispatched = true;
                            drop(st);
                            sched.wake.notify_waiters();
                            return;
                        }
                        Some(st.next_slot)
                    }
                    // A pre-claim head passed over for its budget: nobody else will wake it when the
                    // budget refills, so it sets its own timer.
                    _ if self.lane == Lane::PreClaim
                        && st.queues[self.lane.idx()].front() == Some(&self.id) =>
                    {
                        Some(st.pre_claim.ready_at().max(st.next_slot).max(now))
                    }
                    _ => None,
                }
            };
            match wake_at {
                Some(at) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(at) => {}
                        _ = &mut notified => {}
                    }
                }
                None => notified.await,
            }
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.dispatched {
            return;
        }
        let removed = {
            let mut st = self.sched.lock();
            let q = &mut st.queues[self.lane.idx()];
            let before = q.len();
            q.retain(|&t| t != self.id);
            q.len() != before
        };
        if removed {
            self.sched.wake.notify_waiters();
        }
    }
}

/// tower [`Layer`] that paces outgoing requests to at most one every `min_interval`,
/// smoothing instantaneous bursts so a rate-limited endpoint's per-second cap is never
/// tripped no matter how many lifecycles (monitor + refresh + brain + N concurrent
/// claim/fulfill/release) fire in the same instant.
///
/// Waiting requests are served by [`Lane`], highest first, FIFO within a lane; pre-claim reads are
/// also held to their budget ([`LaneConfig`]). A request is charged to the lane of the scope it was
/// issued from ([`with_lane`]), [`Lane::Default`] outside any scope — so a client that names no lanes
/// paces exactly as the single FIFO limiter did. Lanes reorder the queue; they never raise the rate:
/// a held-lock request still waits for the next slot.
///
/// This is PURE pacing: it only *delays* — it never retries, swallows, or inspects
/// errors — so genuine 429s still flow through to the [`MeterService`] beneath it (the
/// meter's `rate_limited_within` gate and the brain's claim-pause keep working). It is
/// installed OUTERMOST (delays before the meter records the actual dispatch). Steady
/// state (~1-2 req/s) is unaffected; only concurrent spikes queue into the window.
#[derive(Clone)]
pub struct ThrottleLayer {
    sched: Arc<LaneScheduler>,
}

impl ThrottleLayer {
    /// `max_per_sec`: sustained requests/second ceiling. Excess concurrent requests
    /// queue (each waits for its slot) rather than firing in the same second.
    /// Keep this safely BELOW the endpoint's observed per-second cap (~5/s here).
    /// Lanes take the default policy ([`LaneConfig::default`]).
    pub fn new(max_per_sec: u32) -> Self {
        Self::with_lanes(max_per_sec, LaneConfig::default())
    }

    /// [`Self::new`] with an explicit lane policy.
    pub fn with_lanes(max_per_sec: u32, lanes: LaneConfig) -> Self {
        let mps = max_per_sec.max(1);
        let now = tokio::time::Instant::now();
        let share = if lanes.pre_claim_share.is_finite() {
            lanes.pre_claim_share.clamp(0.01, 1.0)
        } else {
            LaneConfig::default().pre_claim_share
        };
        Self {
            sched: Arc::new(LaneScheduler {
                state: Mutex::new(SchedState {
                    next_slot: now,
                    queues: Default::default(),
                    next_ticket: 0,
                    pre_claim: Gcra::new(now, share * mps as f64),
                    dispatched: [0; LANES],
                }),
                wake: tokio::sync::Notify::new(),
                min_interval: Duration::from_micros(1_000_000 / mps as u64),
            }),
        }
    }

    /// Requests dispatched and waiting per lane, across every service this layer built.
    pub fn lane_stats(&self) -> LaneStats {
        self.sched.stats()
    }
}

impl<S> Layer<S> for ThrottleLayer {
    type Service = ThrottleService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ThrottleService {
            inner,
            sched: self.sched.clone(),
        }
    }
}

/// Transport wrapper that delays each request until its lane's turn and its pacing slot.
#[derive(Clone)]
pub struct ThrottleService<S> {
    inner: S,
    sched: Arc<LaneScheduler>,
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
        // Take this request's place synchronously (brief lock, no await held), in the lane of the
        // scope it is issued from, so FIFO order within a lane is call order; the future then waits
        // for its turn and its pacing slot before the request reaches the transport. inner.call() is
        // lazy (the HTTP request is not issued until the returned future is polled), so constructing
        // it before the wait does not send anything early.
        let ticket = self.sched.enqueue(current_lane());
        let fut = self.inner.call(req);
        Box::pin(async move {
            ticket.wait().await;
            fut.await
        })
    }
}

/// The lanes, against a mock transport that records when each request reaches it. Time is tokio's
/// paused clock, so every dispatch instant is exact.
#[cfg(test)]
mod lane_tests {
    use super::*;
    use alloy_json_rpc::{Id, Request, ResponsePayload};
    use serde_json::value::RawValue;

    const MS: Duration = Duration::from_millis(1);

    /// (dispatch time since start, request id, lane it was issued in)
    type Dispatches = Arc<Mutex<Vec<(Duration, u64)>>>;

    #[derive(Clone)]
    struct MockTransport {
        log: Dispatches,
        start: tokio::time::Instant,
    }

    impl Service<RequestPacket> for MockTransport {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: RequestPacket) -> Self::Future {
            let RequestPacket::Single(r) = req else {
                unreachable!("the tests send single requests")
            };
            let id = r.id().as_number().expect("numeric id");
            let (log, start) = (self.log.clone(), self.start);
            // Recorded when POLLED: that is when the request would reach the endpoint.
            Box::pin(async move {
                log.lock().unwrap().push((start.elapsed(), id));
                Ok(ResponsePacket::Single(alloy_json_rpc::Response {
                    id: Id::Number(id),
                    payload: ResponsePayload::Success(
                        RawValue::from_string("\"0x1\"".into()).unwrap(),
                    ),
                }))
            })
        }
    }

    fn req(id: u64) -> RequestPacket {
        RequestPacket::Single(
            Request::new("eth_blockNumber", Id::Number(id), ())
                .serialize()
                .unwrap(),
        )
    }

    fn setup(mps: u32) -> (ThrottleLayer, ThrottleService<MockTransport>, Dispatches) {
        let log: Dispatches = Default::default();
        let layer = ThrottleLayer::new(mps);
        let svc = layer.layer(MockTransport {
            log: log.clone(),
            start: tokio::time::Instant::now(),
        });
        (layer, svc, log)
    }

    /// Issue request `id` in `lane` now (its place is taken here) and run it on its own task.
    fn issue(
        svc: &mut ThrottleService<MockTransport>,
        lane: Lane,
        id: u64,
    ) -> tokio::task::JoinHandle<()> {
        let fut = with_lane_sync(lane, || svc.call(req(id)));
        tokio::spawn(async move {
            fut.await.unwrap();
        })
    }

    /// Wait for every task; a stranded request fails the test (a minute of paused time) instead of
    /// hanging it.
    async fn join(hs: Vec<tokio::task::JoinHandle<()>>) {
        tokio::time::timeout(Duration::from_secs(60), async {
            for h in hs {
                h.await.unwrap();
            }
        })
        .await
        .expect("a request was never dispatched");
    }

    fn snapshot(log: &Dispatches) -> Vec<(Duration, u64)> {
        log.lock().unwrap().clone()
    }

    fn spacing_ok(d: &[(Duration, u64)], interval: Duration) {
        for w in d.windows(2) {
            assert!(
                w[1].0 >= w[0].0 + interval,
                "two dispatches closer than the pacing interval: {w:?}"
            );
        }
    }

    #[test]
    fn requests_outside_a_scope_are_default_lane_and_scopes_nest() {
        assert_eq!(current_lane(), Lane::Default);
        with_lane_sync(Lane::PreClaim, || {
            assert_eq!(current_lane(), Lane::PreClaim);
            with_lane_sync(Lane::HeldLock, || {
                assert_eq!(current_lane(), Lane::HeldLock)
            });
            assert_eq!(current_lane(), Lane::PreClaim);
        });
        assert_eq!(current_lane(), Lane::Default);
    }

    /// No lane named anywhere: exactly the single FIFO limiter (call order, one slot per interval,
    /// an idle limiter dispatching at once).
    #[tokio::test(start_paused = true)]
    async fn unannotated_requests_keep_the_fifo_pacing() {
        let (layer, mut svc, log) = setup(4);
        // Plain calls, no lane scope anywhere.
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let f = svc.call(req(i));
                tokio::spawn(async move {
                    f.await.unwrap();
                })
            })
            .collect();
        join(hs).await;
        let d = snapshot(&log);
        let want: Vec<_> = (0..8).map(|i| (250 * MS * i as u32, i)).collect();
        assert_eq!(d, want);
        // Idle again: the next request goes at once.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let at = log.lock().unwrap().last().unwrap().0 + Duration::from_secs(5);
        svc.call(req(99)).await.unwrap();
        assert_eq!(snapshot(&log).last(), Some(&(at, 99)));
        assert_eq!(layer.lane_stats().dispatched(Lane::Default), 9);
        assert_eq!(layer.lane_stats().waiting, [0; LANES]);
    }

    /// Under saturation a held-lock request takes the next slot, ahead of every queued request of a
    /// lower lane, and a lock transaction the slot after it.
    #[tokio::test(start_paused = true)]
    async fn held_lock_requests_are_served_first_under_saturation() {
        let (layer, mut svc, log) = setup(4);
        let mut hs: Vec<_> = (0..12).map(|i| issue(&mut svc, Lane::Default, i)).collect();
        hs.extend((20..22).map(|i| issue(&mut svc, Lane::PreClaim, i)));
        // Mid-backlog (dispatches at 0, 250, ..., 1000 have happened).
        tokio::time::sleep(1100 * MS).await;
        assert!(layer.lane_stats().waiting(Lane::Default) > 0, "saturated");
        hs.push(issue(&mut svc, Lane::Lock, 200));
        hs.push(issue(&mut svc, Lane::HeldLock, 100));
        hs.push(issue(&mut svc, Lane::HeldLock, 101));
        join(hs).await;
        let d = snapshot(&log);
        spacing_ok(&d, 250 * MS);
        let at = |id| d.iter().find(|(_, i)| *i == id).unwrap().0;
        assert_eq!(at(100), 1250 * MS, "the first slot after it arrived");
        assert_eq!(at(101), 1500 * MS);
        assert_eq!(
            at(200),
            1750 * MS,
            "lock transactions right after held-lock requests"
        );
        // Nothing queued before them jumped them.
        assert!(
            d.iter()
                .filter(|(t, _)| *t > 1100 * MS && *t < 1250 * MS)
                .count()
                == 0
        );
        // Every request was served, and FIFO within its lane.
        assert_eq!(d.len(), 17);
        let order = |lo: u64, hi: u64| -> Vec<u64> {
            d.iter()
                .map(|&(_, i)| i)
                .filter(|i| (lo..hi).contains(i))
                .collect()
        };
        assert_eq!(order(0, 12), (0..12).collect::<Vec<_>>());
        assert_eq!(order(20, 22), vec![20, 21]);
        let s = layer.lane_stats();
        assert_eq!(s.dispatched, [2, 1, 2, 12]);
    }

    /// Pre-claim reads never take more than their share (25% of 4/s = one per second, burst one):
    /// not when competing with the default lane, and not when the pacer is otherwise idle.
    #[tokio::test(start_paused = true)]
    async fn pre_claim_reads_never_exceed_their_share() {
        let (layer, mut svc, log) = setup(4);
        let mut hs = Vec::new();
        for i in 0..20 {
            hs.push(issue(&mut svc, Lane::PreClaim, 1000 + i));
            hs.push(issue(&mut svc, Lane::Default, i));
        }
        join(hs).await;
        let d = snapshot(&log);
        spacing_ok(&d, 250 * MS);
        let pre: Vec<Duration> = d
            .iter()
            .filter(|(_, i)| *i >= 1000)
            .map(|&(t, _)| t)
            .collect();
        assert_eq!(pre.len(), 20);
        // At most max(1, 0.25 x 4) + 1/s x T in any window of T: with burst 1, one per second.
        for w in pre.windows(2) {
            assert!(
                w[1] - w[0] >= Duration::from_secs(1),
                "pre-claim over budget: {w:?}"
            );
        }
        // ...and, ahead of the default lane, it gets that share while both are backlogged.
        let first_10s = pre.iter().filter(|t| **t < Duration::from_secs(10)).count();
        assert!(first_10s >= 9, "pre-claim starved: {first_10s} in 10 s");
        // The default lane filled the remaining slots: 20 default requests in the first ~6.7 s.
        let def_last = d
            .iter()
            .filter(|(_, i)| *i < 1000)
            .map(|&(t, _)| t)
            .max()
            .unwrap();
        assert!(
            def_last < Duration::from_secs(7),
            "default lane under-served: {def_last:?}"
        );

        // Alone on an idle pacer, still one per second.
        log.lock().unwrap().clear();
        let t0 = tokio::time::Instant::now();
        let hs: Vec<_> = (0..4)
            .map(|i| issue(&mut svc, Lane::PreClaim, 2000 + i))
            .collect();
        join(hs).await;
        let d = snapshot(&log);
        let base = t0.duration_since(log_start(&svc));
        assert_eq!(d.len(), 4);
        assert!(d[0].0 >= base);
        for w in d.windows(2) {
            assert!(
                w[1].0 - w[0].0 >= Duration::from_secs(1),
                "idle pre-claim over budget: {w:?}"
            );
        }
        assert_eq!(layer.lane_stats().dispatched(Lane::PreClaim), 24);
    }

    fn log_start(svc: &ThrottleService<MockTransport>) -> tokio::time::Instant {
        svc.inner.start
    }

    /// A higher pre-claim share scales the budget (and its burst).
    #[tokio::test(start_paused = true)]
    async fn pre_claim_budget_scales_with_the_rate() {
        let log: Dispatches = Default::default();
        let layer = ThrottleLayer::with_lanes(
            20,
            LaneConfig {
                pre_claim_share: 0.25,
            },
        );
        let mut svc = layer.layer(MockTransport {
            log: log.clone(),
            start: tokio::time::Instant::now(),
        });
        let hs: Vec<_> = (0..30)
            .map(|i| issue(&mut svc, Lane::PreClaim, i))
            .collect();
        join(hs).await;
        let d = snapshot(&log);
        // 5/s with a burst of 5: in any window of T seconds at most 5 + 5T.
        for (k, &(t, _)) in d.iter().enumerate() {
            let allowed = 5.0 + 5.0 * t.as_secs_f64();
            assert!(
                (k + 1) as f64 <= allowed + 1e-9,
                "request {k} at {t:?} over budget"
            );
        }
        spacing_ok(&d, 50 * MS);
    }

    /// The fairness check over a mock transport, with lanes set by async scopes on concurrent tasks
    /// (as the miner sets them): strict priority between the lanes, FIFO within each, every request
    /// served, pacing never exceeded, and the per-lane counters charge each request to its lane.
    #[tokio::test(start_paused = true)]
    async fn mixed_lanes_from_concurrent_tasks_are_served_fairly() {
        let (layer, svc, log) = setup(4);
        let plan: Vec<(Lane, u64)> = (0..24)
            .map(|i| {
                let lane = match i % 8 {
                    0 => Lane::HeldLock,
                    1 | 2 => Lane::PreClaim,
                    3 => Lane::Lock,
                    _ => Lane::Default,
                };
                (lane, i)
            })
            .collect();
        // A request already in flight, so every planned one queues behind it.
        let mut first = svc.clone();
        first.call(req(999)).await.unwrap();
        let hs: Vec<_> = plan
            .iter()
            .map(|&(lane, i)| {
                let mut svc = svc.clone();
                tokio::spawn(with_lane(lane, async move {
                    svc.call(req(i)).await.unwrap();
                }))
            })
            .collect();
        join(hs).await;
        let d: Vec<_> = snapshot(&log)
            .into_iter()
            .filter(|(_, i)| *i != 999)
            .collect();
        assert_eq!(d.len(), plan.len(), "every request served");
        spacing_ok(&snapshot(&log), 250 * MS);
        let lane_of = |id: u64| plan.iter().find(|(_, i)| *i == id).unwrap().0;
        let pos = |lane: Lane| -> Vec<usize> {
            d.iter()
                .enumerate()
                .filter(|(_, (_, i))| lane_of(*i) == lane)
                .map(|(k, _)| k)
                .collect()
        };
        // Strict priority: all held-lock, then all lock, before any pre-claim or default.
        let (hl, lk, pc, df) = (
            pos(Lane::HeldLock),
            pos(Lane::Lock),
            pos(Lane::PreClaim),
            pos(Lane::Default),
        );
        assert_eq!(hl, vec![0, 1, 2]);
        assert_eq!(lk, vec![3, 4, 5]);
        assert!(pc.iter().chain(&df).all(|&k| k >= 6));
        // FIFO within every lane.
        for lane in Lane::ALL {
            let ids: Vec<u64> = d
                .iter()
                .map(|&(_, i)| i)
                .filter(|&i| lane_of(i) == lane)
                .collect();
            let mut sorted = ids.clone();
            sorted.sort();
            assert_eq!(ids, sorted, "{lane:?} served out of order");
        }
        // Pre-claim within its budget.
        let pre_t: Vec<Duration> = d
            .iter()
            .filter(|(_, i)| lane_of(*i) == Lane::PreClaim)
            .map(|&(t, _)| t)
            .collect();
        for w in pre_t.windows(2) {
            assert!(w[1] - w[0] >= Duration::from_secs(1));
        }
        let s = layer.lane_stats();
        assert_eq!(s.dispatched, [3, 3, 6, 12 + 1]);
        assert_eq!(s.waiting, [0; LANES]);
    }

    /// A request whose future is dropped while it waits gives its place up: the next one takes the
    /// slot instead of waiting behind a request that will never be sent.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_request_frees_its_place() {
        let (layer, mut svc, log) = setup(4);
        let a = issue(&mut svc, Lane::Default, 0); // dispatched at 0
        let b = issue(&mut svc, Lane::Default, 1); // would be at 250
        let c = issue(&mut svc, Lane::Default, 2);
        // Never polled at all: dropping it releases its place too.
        let unpolled = svc.call(req(3));
        tokio::time::sleep(10 * MS).await;
        b.abort();
        drop(unpolled);
        let _ = b.await;
        join(vec![a, c]).await;
        assert_eq!(snapshot(&log), vec![(Duration::ZERO, 0), (250 * MS, 2)]);
        assert_eq!(layer.lane_stats().waiting, [0; LANES]);
        assert_eq!(layer.lane_stats().dispatched(Lane::Default), 2);
    }

    /// A cancelled head of the pre-claim lane does not strand the one behind it.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_pre_claim_head_does_not_strand_the_lane() {
        let (_layer, mut svc, log) = setup(4);
        let a = issue(&mut svc, Lane::PreClaim, 0); // at 0, spends the budget
        let b = issue(&mut svc, Lane::PreClaim, 1); // waits for the budget
        let c = issue(&mut svc, Lane::PreClaim, 2);
        tokio::time::sleep(100 * MS).await;
        b.abort();
        let _ = b.await;
        join(vec![a, c]).await;
        assert_eq!(
            snapshot(&log),
            vec![(Duration::ZERO, 0), (Duration::from_secs(1), 2)]
        );
    }
}
