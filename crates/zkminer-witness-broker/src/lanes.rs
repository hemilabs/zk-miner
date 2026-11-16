//! Lanes and budgets (plan §11.4, §14.6, §17.3).
//!
//! - [`Lanes`]: a capacity split into a shared lane and a lane only held-lock work may draw on, so no
//!   flood of simulation jobs can delay a lock this host holds. Used for the global in-flight byte
//!   budget ([`ByteLanes`]) and each endpoint's concurrency cap.
//! - [`Pacer`]: a requests-per-second limiter that serves held-lock waiters first (the artifact
//!   endpoint's `max_requests_per_sec`, and any endpoint's optional pacing).
//! - [`TokenBucket`]: an operator/provider budget in cost units, with the same held-lock share kept
//!   back for held-lock work; spending it is status 2, never the job's status 3 (§11.2).
//! - [`WaitFlag`]: marks the spans in which a fetch waits on operator-side capacity (a lane, the
//!   pacer, a concurrency slot), so a deadline that hits it there is not the builder's (§16).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

/// Set while a fetch waits on operator-side capacity. A wait abandoned midway (its future
/// dropped, e.g. by `EndJob`) leaves it set: the fetch ended in that wait.
#[derive(Debug, Default)]
pub struct WaitFlag(AtomicBool);

impl WaitFlag {
    /// Runs `f` with the flag set.
    pub async fn during<F: Future>(&self, f: F) -> F::Output {
        self.0.store(true, Ordering::SeqCst);
        let r = f.await;
        self.0.store(false, Ordering::SeqCst);
        r
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub fn clear(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// A capacity of `total` units, `reserved` of which only held-lock work may take. Held-lock work
/// takes whichever lane frees first; other work waits on the shared lane only. A request for more
/// units than a lane holds is clamped to the lane's size, so it always completes eventually.
#[derive(Debug)]
pub struct Lanes {
    shared: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
    shared_cap: u32,
    reserved_cap: u32,
}

/// Units held in one lane until dropped.
#[derive(Debug)]
pub struct LanePermit {
    _permit: OwnedSemaphorePermit,
    /// Whether the units came from the held-lock lane.
    pub reserved: bool,
    /// The units actually held (a request is clamped to its lane's size).
    pub units: u32,
}

impl Lanes {
    /// `total` ≥ 1 units; the shared lane keeps at least one.
    pub fn new(total: u32, reserved: u32) -> Self {
        let total = total.max(1);
        let reserved_cap = reserved.min(total - 1);
        let shared_cap = total - reserved_cap;
        Self {
            shared: Arc::new(Semaphore::new(shared_cap as usize)),
            reserved: Arc::new(Semaphore::new(reserved_cap as usize)),
            shared_cap,
            reserved_cap,
        }
    }

    /// Concurrency lanes: one slot of `max` reserved for held-lock work when `max` ≥ 2.
    pub fn concurrency(max: u32) -> Self {
        Self::new(max, u32::from(max >= 2))
    }

    pub async fn acquire(&self, held: bool, units: u32) -> LanePermit {
        let units = units.max(1);
        let ns = units.min(self.shared_cap);
        if !held || self.reserved_cap == 0 {
            let p = self.shared.clone().acquire_many_owned(ns).await.expect("lane semaphores are never closed");
            return LanePermit { _permit: p, reserved: false, units: ns };
        }
        let nr = units.min(self.reserved_cap);
        tokio::select! {
            biased;
            p = self.reserved.clone().acquire_many_owned(nr) => {
                LanePermit { _permit: p.expect("lane semaphores are never closed"), reserved: true, units: nr }
            }
            p = self.shared.clone().acquire_many_owned(ns) => {
                LanePermit { _permit: p.expect("lane semaphores are never closed"), reserved: false, units: ns }
            }
        }
    }

    /// `(shared, reserved)` units free now.
    pub fn available(&self) -> (usize, usize) {
        (self.shared.available_permits(), self.reserved.available_permits())
    }

    /// The most units a request of this kind (`held` or not) can be granted at once.
    pub fn largest(&self, held: bool) -> u32 {
        if held {
            self.shared_cap.max(self.reserved_cap)
        } else {
            self.shared_cap
        }
    }
}

/// The global in-flight byte budget, in KiB units (so budgets past 4 GiB fit `u32` permits).
#[derive(Debug)]
pub struct ByteLanes(Lanes);

impl ByteLanes {
    pub fn new(total_bytes: u64, reserved_bytes: u64) -> Self {
        Self(Lanes::new(kib(total_bytes), kib(reserved_bytes)))
    }

    /// Reserves `bytes` (clamped to the lane) for the life of the permit; see [`permit_bytes`] for
    /// what was granted.
    pub async fn acquire(&self, held: bool, bytes: u64) -> LanePermit {
        self.0.acquire(held, kib(bytes)).await
    }

    pub fn available_kib(&self) -> (usize, usize) {
        self.0.available()
    }

    /// The most bytes one permit of this kind can hold.
    pub fn largest(&self, held: bool) -> u64 {
        u64::from(self.0.largest(held)) * 1024
    }
}

/// The bytes a [`ByteLanes`] permit holds.
pub fn permit_bytes(p: &LanePermit) -> u64 {
    u64::from(p.units) * 1024
}

fn kib(bytes: u64) -> u32 {
    u32::try_from(bytes.div_ceil(1024)).unwrap_or(u32::MAX)
}

/// At most `per_sec` grants per second, one at a time, held-lock waiters first. Waiters that give
/// up (their future dropped) cost no slot.
#[derive(Debug)]
pub struct Pacer {
    held: mpsc::UnboundedSender<oneshot::Sender<()>>,
    normal: mpsc::UnboundedSender<oneshot::Sender<()>>,
}

impl Pacer {
    /// Spawns the dispatcher on the current tokio runtime.
    pub fn new(per_sec: u32) -> Self {
        let period = Duration::from_secs_f64(1.0 / f64::from(per_sec.max(1)));
        let (held, held_rx) = mpsc::unbounded_channel();
        let (normal, normal_rx) = mpsc::unbounded_channel();
        tokio::spawn(dispatch(held_rx, normal_rx, period));
        Self { held, normal }
    }

    pub async fn acquire(&self, held: bool) {
        let (tx, rx) = oneshot::channel();
        let queue = if held { &self.held } else { &self.normal };
        if queue.send(tx).is_ok() {
            let _ = rx.await;
        }
    }
}

async fn dispatch(
    mut held: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
    mut normal: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
    period: Duration,
) {
    loop {
        let waiter = tokio::select! {
            biased;
            Some(w) = held.recv() => w,
            Some(w) = normal.recv() => w,
            else => return,
        };
        if waiter.send(()).is_ok() {
            tokio::time::sleep(period).await;
        }
    }
}

/// An operator/provider budget: `capacity` cost units, refilled continuously over a minute, of
/// which `reserve_share × capacity` only held-lock work may spend: other work takes `n` only while
/// `tokens − n ≥ reserve`, held-lock work may drain the bucket to zero.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    reserve: f64,
    per_sec: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub fn per_minute(units: u64, reserve_share: f64) -> Self {
        let capacity = units as f64;
        Self {
            capacity,
            reserve: capacity * reserve_share.clamp(0.0, 1.0),
            per_sec: capacity / 60.0,
            state: Mutex::new((capacity, Instant::now())),
        }
    }

    /// Takes `n` units if they are there (for work that holds no lock, above the reserve).
    pub fn try_take(&self, n: u64, held: bool) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(s.1).as_secs_f64();
        s.0 = (s.0 + elapsed * self.per_sec).min(self.capacity);
        s.1 = now;
        let floor = if held { 0.0 } else { self.reserve };
        if s.0 - n as f64 >= floor {
            s.0 -= n as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn held_lock_work_passes_a_flood() {
        let lanes = Arc::new(Lanes::new(4, 1));
        // Simulation work takes the whole shared lane.
        let mut flood = Vec::new();
        for _ in 0..3 {
            flood.push(lanes.acquire(false, 1).await);
        }
        assert_eq!(lanes.available(), (0, 1));
        // More simulation work waits...
        let l = lanes.clone();
        let waiting = tokio::spawn(async move { l.acquire(false, 1).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        // ...but a held lock gets through at once, on the reserved lane.
        let held = tokio::time::timeout(Duration::from_secs(1), lanes.acquire(true, 1)).await.unwrap();
        assert!(held.reserved);
        drop(flood.pop());
        let p = tokio::time::timeout(Duration::from_secs(1), waiting).await.unwrap().unwrap();
        assert!(!p.reserved, "simulation work never draws on the reserved lane");
    }

    #[tokio::test]
    async fn held_work_also_uses_the_shared_lane_and_big_requests_clamp() {
        let lanes = Lanes::new(4, 1);
        let r = lanes.acquire(true, 1).await;
        assert!(r.reserved);
        let s = tokio::time::timeout(Duration::from_secs(1), lanes.acquire(true, 1)).await.unwrap();
        assert!(!s.reserved, "with the reserved lane busy, held work takes a shared slot");
        drop((r, s));
        // A request above every lane's size still completes (clamped).
        let big = tokio::time::timeout(Duration::from_secs(1), lanes.acquire(false, 100)).await.unwrap();
        assert_eq!(lanes.available(), (0, 1));
        drop(big);
        assert_eq!(Lanes::concurrency(1).available(), (1, 0));
        assert_eq!(Lanes::concurrency(8).available(), (7, 1));
        let bytes = ByteLanes::new(256 << 20, 64 << 20);
        assert_eq!(bytes.available_kib(), (192 * 1024, 64 * 1024));
        let p = bytes.acquire(false, 1).await;
        assert_eq!(bytes.available_kib().0, 192 * 1024 - 1, "partial KiB rounds up");
        drop(p);
    }

    #[tokio::test(start_paused = true)]
    async fn pacer_serves_held_first_at_its_rate() {
        let pacer = Arc::new(Pacer::new(10));
        let order = Arc::new(Mutex::new(Vec::new()));
        let start = tokio::time::Instant::now();
        pacer.acquire(false).await; // the dispatcher now sleeps 100 ms
        let mut tasks = Vec::new();
        for name in ["n1", "n2"] {
            let (p, o) = (pacer.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                p.acquire(false).await;
                o.lock().unwrap().push(name);
            }));
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
        }
        let (p, o) = (pacer.clone(), order.clone());
        tasks.push(tokio::spawn(async move {
            p.acquire(true).await;
            o.lock().unwrap().push("held");
        }));
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec!["held", "n1", "n2"]);
        assert!(start.elapsed() >= Duration::from_millis(300), "four grants at 10/s");
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_waiter_costs_no_slot() {
        let pacer = Pacer::new(1);
        pacer.acquire(false).await;
        let gave_up = tokio::time::timeout(Duration::from_millis(10), pacer.acquire(false)).await;
        assert!(gave_up.is_err());
        let served = Arc::new(AtomicUsize::new(0));
        let start = tokio::time::Instant::now();
        pacer.acquire(false).await;
        served.fetch_add(1, Ordering::SeqCst);
        assert!(start.elapsed() <= Duration::from_millis(1_000));
    }

    #[test]
    fn token_bucket_spends_and_refuses() {
        let b = TokenBucket::per_minute(60, 0.0);
        assert!(b.try_take(59, false));
        assert!(b.try_take(1, false));
        assert!(!b.try_take(1, false));
        assert!(!b.try_take(1, true));
    }

    /// Review F3: simulation work cannot spend the held-lock share; held-lock work can drain it.
    #[test]
    fn token_bucket_keeps_a_held_lock_reserve() {
        let b = TokenBucket::per_minute(100, 0.25);
        assert!(!b.try_take(76, false), "would leave 24 < 25");
        assert!(b.try_take(75, false), "leaves exactly the reserve");
        assert!(!b.try_take(1, false), "the reserve is held-lock work's");
        assert!(b.try_take(25, true), "held-lock work drains it to zero");
        assert!(!b.try_take(1, true));
    }

    #[tokio::test]
    async fn permits_report_what_they_hold() {
        let bytes = ByteLanes::new(4 << 20, 1 << 20);
        assert_eq!((bytes.largest(false), bytes.largest(true)), (3 << 20, 3 << 20));
        let p = bytes.acquire(false, 10 << 20).await;
        assert_eq!(permit_bytes(&p), 3 << 20, "clamped to the shared lane");
        let h = bytes.acquire(true, 10 << 20).await;
        assert!(h.reserved);
        assert_eq!(permit_bytes(&h), 1 << 20, "clamped to the reserved lane");
    }

    #[tokio::test]
    async fn a_wait_flag_marks_its_span() {
        let f = WaitFlag::default();
        let inside = f.during(async { f.is_set() }).await;
        assert!(inside && !f.is_set());
        // Abandoned midway: left set.
        let _ = tokio::time::timeout(Duration::from_millis(10), f.during(std::future::pending::<()>())).await;
        assert!(f.is_set());
        f.clear();
        assert!(!f.is_set());
    }
}
