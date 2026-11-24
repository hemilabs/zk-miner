//! The miner's side of the control channel (plan §10.1).
//!
//! ```text
//! let (miner_end, broker_end) = UnixStream::pair()?;   // broker_end → fd 3 of the broker process
//! let broker = BrokerClient::new(miner_end)?;
//! let (builder_end, broker_job_end) = job_socketpair()?; // builder_end → the builder runner
//! broker.register_job(registration, broker_job_end).await?;
//! … run the builder …
//! let stats = broker.end_job(job_key).await?;
//! ```
//!
//! Requests may be issued concurrently from many tasks; each gets its own id and its own answer.
//!
//! # A broker that breaks the protocol (review r3 W1)
//!
//! The broker is sandboxed but not trusted, so nothing it sends may grow the miner without bound.
//! Each request queues at most [`ANSWER_QUEUE`] answers; an fd is taken only on an `Artifact`
//! answer; a fetch takes at most one `ArtifactCharge`; sends, calls and fetches are bounded in time
//! ([`SEND_TIMEOUT`], [`CALL_TIMEOUT`], [`BrokerClient::with_artifact_fetch_timeout`]). A broker
//! that floods a request, attaches an fd anywhere else, sends a second charge, sends more than
//! [`MAX_UNDECODABLE`] frames that do not decode, or stops taking requests has broken the
//! protocol: the client stops reading, every waiter gets [`ClientError::Violation`], and
//! [`BrokerClient::violated`] resolves. The broker process cuts the broker off on it, as it does
//! when the connector cuts it off.

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use alloy_primitives::{Address, B256};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Notify};
use zkminer_witness::ipc::{
    decode_control, encode_control, ArtifactFailure, ArtifactSource, ControlErrorCode,
    ControlMessage, ControlRequest, ControlResponse, FrameError, IpPrefix, JobBudget,
    SelfTestCheck, KIND_CONTROL, MAX_CONTROL_BYTES,
};

use crate::fdpass::{check_sealed, recv_with_fd_async, send_with_fd_async};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("control channel: {0}")]
    Io(#[from] io::Error),
    #[error("the broker closed the control channel")]
    Closed,
    #[error("the broker refused the request: {0:?}")]
    Refused(ControlErrorCode),
    #[error("unexpected answer from the broker")]
    Protocol,
    #[error("the artifact memfd failed its checks: {0}")]
    BadMemfd(io::Error),
    #[error("the broker did not answer in time")]
    Timeout,
    #[error("the broker broke the control protocol")]
    Violation,
}

type Answer = (ControlResponse, Option<OwnedFd>);
type Pending = Arc<Mutex<HashMap<u64, mpsc::Sender<Answer>>>>;

/// Answers queued for one request before the broker counts as flooding it. A fetch gets two at
/// most (its charge and its answer), every other request one.
pub const ANSWER_QUEUE: usize = 4;
/// Frames that do not decode (or are not control frames) tolerated over the channel's life. An
/// honest broker sends none.
pub const MAX_UNDECODABLE: u32 = 8;
/// Writing one request frame, the wait for the write lock included. A frame not written in time
/// may be half written, which desyncs the stream: a violation.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// The answer to `RegisterJob`, `EndJob` (the broker waits ≤ 5 s for the job's task),
/// `CheckProvisioned` and `RefreshPrefixes`, none of which waits on the network.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The answer to `SelfTest` (the miner bounds its whole self-test at 120 s too).
pub const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(120);
/// A fetch's limit beyond the broker's own `artifact_fetch_secs`, which bounds everything the
/// broker does for it (its reads through the connector, whose stall timers are shorter, included):
/// an honest broker has answered by then.
pub const FETCH_SLACK: Duration = Duration::from_secs(30);
/// The longest a fetch may take, whatever the broker's `artifact_fetch_secs`.
pub const FETCH_MAX: Duration = Duration::from_secs(15 * 60);

fn fetch_limit(broker: Duration) -> Duration {
    broker.saturating_add(FETCH_SLACK).min(FETCH_MAX)
}

/// Set once the broker broke the control protocol; [`BrokerClient::violated`] waits for it.
#[derive(Debug, Default)]
struct Violation {
    why: OnceLock<String>,
    notify: Notify,
}

impl Violation {
    /// The first reason is kept.
    fn raise(&self, why: String) {
        let _ = self.why.set(why);
        self.notify.notify_waiters();
    }

    fn get(&self) -> Option<&str> {
        self.why.get().map(String::as_str)
    }

    async fn wait(&self) -> String {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Registered before the check, so a `raise` in between is not missed.
            notified.as_mut().enable();
            if let Some(why) = self.why.get() {
                return why.clone();
            }
            notified.await;
        }
    }
}

/// A request's entry in `pending`, removed when this is dropped: on every way out of the request,
/// a dropped future included.
struct InFlight<'a> {
    pending: &'a Pending,
    id: u64,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

/// A registration: the job's capabilities exactly as in the envelope (fetch `cap` indexes them).
#[derive(Debug, Clone)]
pub struct JobRegistration {
    pub job_key: B256,
    pub caller: Address,
    pub sources: Vec<(B256, Vec<u8>)>,
    pub budget: JobBudget,
    pub held_lock: bool,
}

/// The broker's account of a finished job (`JobStats`; see `ControlResponse::JobStats` for the
/// exact meaning of each flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobStats {
    pub fetches: u32,
    pub fetch_bytes: u64,
    /// Some fetch failed (status 2) for an operator-side reason.
    pub operator_failure: bool,
    /// Some fetch failed (status 2) because every endpoint tried lacked what it asked for, as at
    /// least two independent endpoints (or the source's pruning horizon) confirm.
    pub unanswerable: bool,
    /// Some fetch failed (status 2) because the endpoints tried lacked the block or state, but
    /// fewer than two independent ones said so and it is within the pruning horizon (a lagging
    /// node looks the same).
    pub lagging_unconfirmed: bool,
    /// A fetch was being served when the job ended or its socket closed.
    pub fetch_in_flight_at_end: bool,
    /// ...and it was waiting on operator-side capacity or had met an operator-side failure.
    pub in_flight_operator_wait: bool,
    pub denied: u32,
    /// Fetch frames received after a builder-visible budget was spent.
    pub frames_after_exhaustion: u32,
}

#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub job_key: B256,
    pub caller: Address,
    pub source: ArtifactSource,
    pub builder_type: u8,
    pub expected_sha256: Option<B256>,
    pub max_bytes: u64,
    pub held_lock: bool,
}

/// The cost of a `hemi-code` read, reported before any chunk is read: `length` bytes and `chunks`
/// chunk reads (`chunks + 1` with the manifest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactCharge {
    pub length: u64,
    pub chunks: u32,
}

/// A verified artifact: a sealed memfd of exactly `len` bytes. Read it with `pread`/`mmap` only:
/// a cache hit is a duplicate of the broker's cached descriptor, so its file offset is shared with
/// the broker and with every other job served the same artifact, and is never meaningful.
#[derive(Debug)]
pub struct FetchedArtifact {
    pub memfd: File,
    pub len: u64,
    pub sha256: B256,
    pub cached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestResult {
    pub ok: bool,
    pub checks: Vec<(SelfTestCheck, bool)>,
}

/// A connected socketpair for one job: `(builder end, broker end)`. Pass the broker end to
/// [`BrokerClient::register_job`] and the builder end to the builder runner.
pub fn job_socketpair() -> io::Result<(UnixStream, OwnedFd)> {
    let (a, b) = UnixStream::pair()?;
    Ok((a, OwnedFd::from(b)))
}

/// The cgroups of the builder runners that hold a job socket to this broker.
///
/// The broker can pass any descriptor it holds over a job socket (`SCM_RIGHTS`), a TCP socket the
/// connector handed it included, and a passed socket lives on in the runner after the broker is
/// killed. So when the broker's connector session ends — a cut-off above all — the miner kills
/// every runner registered here with it, and closes the set: a runner registered afterwards (one
/// spawned with a socket already queued on its job socket) is killed at once.
#[derive(Debug, Default)]
pub struct RunnerCgroups {
    inner: Mutex<RunnerSet>,
}

#[derive(Debug, Default)]
struct RunnerSet {
    closed: bool,
    next: u64,
    cgroups: HashMap<u64, std::path::PathBuf>,
}

fn kill_cgroup(path: &std::path::Path) -> io::Result<()> {
    std::fs::write(path.join("cgroup.kill"), "1")
}

impl RunnerCgroups {
    /// Registers the cgroup at `path`, which a runner holding a job socket of this broker is
    /// already in. `None` if the set is closed: the cgroup was killed instead.
    pub fn add(&self, path: &std::path::Path) -> Option<u64> {
        let mut set = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if set.closed {
            drop(set);
            if let Err(e) = kill_cgroup(path) {
                tracing::error!(cgroup = %path.display(), error = %e, "killing a builder runner registered after its broker's end");
            }
            return None;
        }
        set.next += 1;
        let id = set.next;
        set.cgroups.insert(id, path.to_path_buf());
        Some(id)
    }

    /// Forgets a runner that is done.
    pub fn remove(&self, id: u64) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).cgroups.remove(&id);
    }

    /// Whether the set is closed (the broker's session ended).
    pub fn closed(&self) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).closed
    }

    /// Closes the set and kills every registered cgroup; returns how many were registered.
    pub fn close_and_kill(&self) -> usize {
        let mut set = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        set.closed = true;
        let cgroups: Vec<_> = set.cgroups.drain().map(|(_, p)| p).collect();
        // Killed under the lock: a registration waits, then finds the set closed.
        for path in &cgroups {
            if let Err(e) = kill_cgroup(path) {
                // A runner that finished and removed its cgroup in the meantime.
                tracing::debug!(cgroup = %path.display(), error = %e, "killing a builder runner with its broker");
            }
        }
        cgroups.len()
    }
}

pub struct BrokerClient {
    sock: Arc<tokio::net::UnixStream>,
    write: tokio::sync::Mutex<()>,
    /// Every id below it was issued (the reader tells a request that ended from one never made).
    next_id: Arc<AtomicU64>,
    pending: Pending,
    reader: tokio::task::JoinHandle<()>,
    runners: Arc<RunnerCgroups>,
    violation: Arc<Violation>,
    fetch_limit: Duration,
}

impl Drop for BrokerClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl BrokerClient {
    /// Wraps the miner's end of the control socketpair. Needs a tokio runtime.
    pub fn new(sock: UnixStream) -> io::Result<Self> {
        sock.set_nonblocking(true)?;
        let sock = Arc::new(tokio::net::UnixStream::from_std(sock)?);
        let pending: Pending = Arc::default();
        let next_id = Arc::new(AtomicU64::new(1));
        let violation = Arc::new(Violation::default());
        let reader = tokio::spawn(read_loop(sock.clone(), pending.clone(), next_id.clone(), violation.clone()));
        Ok(Self {
            sock,
            write: tokio::sync::Mutex::new(()),
            next_id,
            pending,
            reader,
            runners: Arc::default(),
            violation,
            fetch_limit: fetch_limit(crate::config::TimeoutConfig::default().artifact_fetch()),
        })
    }

    /// Bounds each `FetchArtifact` by the broker's own `artifact_fetch_secs` (`broker`, from the
    /// broker's config as the miner reads it) plus [`FETCH_SLACK`], at most [`FETCH_MAX`]. Without
    /// it the default `artifact_fetch_secs` is assumed.
    pub fn with_artifact_fetch_timeout(mut self, broker: Duration) -> Self {
        self.fetch_limit = fetch_limit(broker);
        self
    }

    /// Resolves, with the reason, once the broker has broken the control protocol (see the module
    /// doc). Holds no reference to the client.
    pub fn violated(&self) -> impl Future<Output = String> + Send + 'static {
        let v = self.violation.clone();
        async move { v.wait().await }
    }

    /// Why the broker broke the control protocol, if it did.
    pub fn violation(&self) -> Option<String> {
        self.violation.get().map(str::to_string)
    }

    /// The error for a request whose answer channel closed: the reader stopped.
    fn ended(&self) -> ClientError {
        if self.violation.get().is_some() {
            ClientError::Violation
        } else {
            ClientError::Closed
        }
    }

    /// The builder runners holding a job socket of this broker ([`RunnerCgroups`]).
    pub fn runners(&self) -> &Arc<RunnerCgroups> {
        &self.runners
    }

    /// Writes one request frame within [`SEND_TIMEOUT`]; a broker that does not take it in time
    /// has broken the protocol.
    async fn send(&self, id: u64, body: ControlRequest, fd: Option<std::os::fd::BorrowedFd<'_>>) -> Result<(), ClientError> {
        let payload = encode_control(&ControlMessage { id, body });
        let sent = tokio::time::timeout(SEND_TIMEOUT, async {
            let _g = self.write.lock().await;
            send_with_fd_async(&self.sock, KIND_CONTROL, &payload, fd).await
        })
        .await;
        match sent {
            Ok(r) => Ok(r?),
            Err(_) => {
                self.violation
                    .raise(format!("it took no request for {SEND_TIMEOUT:?}"));
                Err(ClientError::Violation)
            }
        }
    }

    /// Sends a request and returns its entry in `pending` and the channel its answers arrive on.
    async fn start(
        &self,
        body: ControlRequest,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<(InFlight<'_>, mpsc::Receiver<Answer>), ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(ANSWER_QUEUE);
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).insert(id, tx);
        let req = InFlight { pending: &self.pending, id };
        // Nothing would read the answer (checked after the insert: the reader clears `pending`
        // before it finishes).
        if self.reader.is_finished() {
            return Err(self.ended());
        }
        self.send(id, body, fd).await?;
        Ok((req, rx))
    }

    /// One request and its one answer, within `limit` (then [`ClientError::Timeout`]).
    async fn call(
        &self,
        body: ControlRequest,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
        limit: Duration,
    ) -> Result<Answer, ClientError> {
        let (_req, mut rx) = self.start(body, fd).await?;
        match tokio::time::timeout(limit, rx.recv()).await {
            Err(_) => Err(ClientError::Timeout),
            Ok(None) => Err(self.ended()),
            Ok(Some((ControlResponse::Error { code }, _))) => Err(ClientError::Refused(code)),
            Ok(Some(a)) => Ok(a),
        }
    }

    /// `RegisterJob`, handing the broker its end of the job's socketpair.
    pub async fn register_job(&self, reg: JobRegistration, broker_end: OwnedFd) -> Result<(), ClientError> {
        let body = ControlRequest::RegisterJob {
            job_key: reg.job_key,
            caller: reg.caller,
            sources: reg.sources,
            budget: reg.budget,
            held_lock: reg.held_lock,
        };
        match self
            .call(body, Some(broker_end.as_fd()), CALL_TIMEOUT)
            .await?
        {
            (ControlResponse::Registered { job_key }, None) if job_key == reg.job_key => Ok(()),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `EndJob`: stops the broker serving the job and returns its account.
    pub async fn end_job(&self, job_key: B256) -> Result<JobStats, ClientError> {
        match self
            .call(ControlRequest::EndJob { job_key }, None, CALL_TIMEOUT)
            .await?
        {
            (
                ControlResponse::JobStats {
                    job_key: k,
                    fetches,
                    fetch_bytes,
                    operator_failure,
                    unanswerable,
                    lagging_unconfirmed,
                    fetch_in_flight_at_end,
                    in_flight_operator_wait,
                    denied,
                    frames_after_exhaustion,
                },
                None,
            ) if k == job_key => Ok(JobStats {
                fetches,
                fetch_bytes,
                operator_failure,
                unanswerable,
                lagging_unconfirmed,
                fetch_in_flight_at_end,
                in_flight_operator_wait,
                denied,
                frames_after_exhaustion,
            }),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `FetchArtifact`. For a `hemi-code` read that is not cached, `charge` is called with its cost
    /// before any chunk is read, once at most (a second charge is a violation); `false` ends the
    /// fetch with `ArtifactFailure::Budget`. The memfd's seals and size are checked before it is
    /// returned. The broker must answer within the fetch limit
    /// ([`Self::with_artifact_fetch_timeout`], not counting the time `charge` takes), else
    /// [`ClientError::Timeout`].
    pub async fn fetch_artifact<F, Fut>(
        &self,
        req: ArtifactRequest,
        mut charge: F,
    ) -> Result<Result<FetchedArtifact, ArtifactFailure>, ClientError>
    where
        F: FnMut(ArtifactCharge) -> Fut,
        Fut: Future<Output = bool>,
    {
        let body = ControlRequest::FetchArtifact {
            job_key: req.job_key,
            caller: req.caller,
            source: req.source,
            builder_type: req.builder_type,
            expected_sha256: req.expected_sha256,
            max_bytes: req.max_bytes,
            held_lock: req.held_lock,
        };
        let (req, mut rx) = self.start(body, None).await?;
        // One bound for every wait on the broker (an honest one sends nothing between its charge
        // and its answer while it reads every chunk, so an idle bound is the fetch's bound).
        let mut deadline = tokio::time::Instant::now() + self.fetch_limit;
        let mut charged = false;
        loop {
            let answer = match tokio::time::timeout_at(deadline, rx.recv()).await {
                Err(_) => return Err(ClientError::Timeout),
                Ok(None) => return Err(self.ended()),
                Ok(Some(a)) => a,
            };
            match answer {
                (ControlResponse::ArtifactCharge { length, chunks }, None) if !charged => {
                    charged = true;
                    let asked = tokio::time::Instant::now();
                    let proceed = charge(ArtifactCharge { length, chunks }).await;
                    deadline += asked.elapsed();
                    self.send(req.id, ControlRequest::ChargeDecision { proceed }, None)
                        .await?;
                }
                // The broker charges a fetch once, before its first chunk read (and reads nothing
                // after a refusal): another charge would be admitted twice, or answered forever.
                (ControlResponse::ArtifactCharge { .. }, None) => {
                    self.violation
                        .raise("a second ArtifactCharge for one fetch".into());
                    return Err(ClientError::Protocol);
                }
                (ControlResponse::Artifact { len, sha256, cached }, Some(fd)) => {
                    if let Err(e) = check_sealed(fd.as_fd(), len) {
                        return Err(ClientError::BadMemfd(e));
                    }
                    return Ok(Ok(FetchedArtifact { memfd: File::from(fd), len, sha256, cached }));
                }
                (ControlResponse::ArtifactFailed { failure }, None) => return Ok(Err(failure)),
                (ControlResponse::Error { code }, _) => return Err(ClientError::Refused(code)),
                _ => return Err(ClientError::Protocol),
            }
        }
    }

    /// `CheckProvisioned`: one answer per `(class, config)`, in order.
    pub async fn check_provisioned(&self, sources: Vec<(B256, Vec<u8>)>) -> Result<Vec<bool>, ClientError> {
        let n = sources.len();
        match self.call(ControlRequest::CheckProvisioned { sources }, None, CALL_TIMEOUT).await? {
            (ControlResponse::Provisioned { ok }, None) if ok.len() == n => Ok(ok),
            _ => Err(ClientError::Protocol),
        }
    }

    pub async fn self_test(&self) -> Result<SelfTestResult, ClientError> {
        match self
            .call(ControlRequest::SelfTest, None, SELF_TEST_TIMEOUT)
            .await?
        {
            (ControlResponse::SelfTest { ok, checks }, None) => Ok(SelfTestResult { ok, checks }),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `RefreshPrefixes` (see [`crate::hostinfo::refresh_message`]): returns the prefix count.
    pub async fn refresh_prefixes(&self, prefixes: Vec<IpPrefix>, own_addresses: Vec<IpAddr>) -> Result<u32, ClientError> {
        match self.call(ControlRequest::RefreshPrefixes { prefixes, own_addresses }, None, CALL_TIMEOUT).await? {
            (ControlResponse::PrefixesRefreshed { count }, None) => Ok(count),
            _ => Err(ClientError::Protocol),
        }
    }
}

/// Hands each answer to its request. Stops at end-of-file or at a violation (found here or by a
/// request); every waiter then sees its channel close.
async fn read_loop(sock: Arc<tokio::net::UnixStream>, pending: Pending, next_id: Arc<AtomicU64>, violation: Arc<Violation>) {
    let mut undecodable = 0u32;
    let why = loop {
        let read = tokio::select! {
            r = recv_with_fd_async(&sock, MAX_CONTROL_BYTES) => r,
            // Found by a request (a second charge, a request not taken).
            _ = violation.wait() => break None,
        };
        // A received fd is owned by the frame: closed with it unless handed on.
        let frame = match read {
            Ok(Some(f)) => f,
            Ok(None) | Err(FrameError::Io(_)) => break None,
            Err(e) => break Some(format!("a malformed frame ({e})")),
        };
        let msg = match frame.kind {
            KIND_CONTROL => decode_control::<ControlMessage<ControlResponse>>(&frame.payload).ok(),
            _ => None,
        };
        let Some(msg) = msg else {
            if frame.fd.is_some() {
                break Some("a file descriptor on a frame that does not decode".into());
            }
            undecodable += 1;
            if undecodable > MAX_UNDECODABLE {
                break Some(format!(
                    "more than {MAX_UNDECODABLE} frames that do not decode"
                ));
            }
            continue;
        };
        // Only an artifact comes with a descriptor.
        if frame.fd.is_some() && !matches!(msg.body, ControlResponse::Artifact { .. }) {
            break Some("a file descriptor on an answer other than Artifact".into());
        }
        let tx = pending.lock().unwrap_or_else(|p| p.into_inner()).get(&msg.id).cloned();
        let Some(tx) = tx else {
            // A request that ended (answered, timed out or dropped) may still get an honest
            // broker's answer, its memfd included (closed here at once). An id never issued is the
            // broker's invention.
            if frame.fd.is_some() && (msg.id == 0 || msg.id >= next_id.load(Ordering::Relaxed)) {
                break Some("a file descriptor for a request never made".into());
            }
            continue;
        };
        match tx.try_send((msg.body, frame.fd)) {
            Ok(()) => {}
            // The waiter is gone: the answer, and its fd, are dropped.
            Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(_)) => break Some(format!("more than {ANSWER_QUEUE} answers queued for one request")),
        }
    };
    if let Some(why) = why {
        violation.raise(why);
    }
    // Closed or cut off: every waiter sees its channel close.
    pending.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::atomic::AtomicU32;

    use super::*;

    /// A client and the broker's end of its control socket (a fake broker drives it).
    fn pair() -> (BrokerClient, Arc<tokio::net::UnixStream>) {
        let (miner, broker) = UnixStream::pair().unwrap();
        broker.set_nonblocking(true).unwrap();
        (BrokerClient::new(miner).unwrap(), Arc::new(tokio::net::UnixStream::from_std(broker).unwrap()))
    }

    async fn request(broker: &tokio::net::UnixStream) -> (ControlMessage<ControlRequest>, Option<OwnedFd>) {
        let f = recv_with_fd_async(broker, MAX_CONTROL_BYTES).await.unwrap().unwrap();
        (decode_control(&f.payload).unwrap(), f.fd)
    }

    async fn answer(
        broker: &tokio::net::UnixStream,
        id: u64,
        body: ControlResponse,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> io::Result<()> {
        send_with_fd_async(broker, KIND_CONTROL, &encode_control(&ControlMessage { id, body }), fd).await
    }

    fn fetch_request() -> ArtifactRequest {
        ArtifactRequest {
            job_key: B256::ZERO,
            caller: Address::ZERO,
            source: ArtifactSource::Mirror { builder_type: 1, builder_id: B256::ZERO },
            builder_type: 1,
            expected_sha256: None,
            max_bytes: 1 << 20,
            held_lock: false,
        }
    }

    fn pending_len(c: &BrokerClient) -> usize {
        c.pending.lock().unwrap().len()
    }

    /// A descriptor to pass, and a probe that reads end-of-file once every copy of it is closed.
    fn passed_fd() -> (UnixStream, OwnedFd) {
        let (probe, passed) = UnixStream::pair().unwrap();
        probe.set_nonblocking(true).unwrap();
        (probe, OwnedFd::from(passed))
    }

    /// Whether every copy of the probe's peer is closed (the miner kept none).
    async fn all_copies_closed(mut probe: &UnixStream) -> bool {
        for _ in 0..500 {
            match probe.read(&mut [0u8; 1]) {
                Ok(0) => return true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => tokio::time::sleep(Duration::from_millis(10)).await,
                _ => return false,
            }
        }
        false
    }

    async fn violated_soon(c: &BrokerClient) -> String {
        tokio::time::timeout(Duration::from_secs(5), c.violated())
            .await
            .expect("a violation")
    }

    #[tokio::test]
    async fn a_flood_of_charges_is_a_violation() {
        let (client, broker) = pair();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                let (msg, _) = request(&broker).await;
                for _ in 0..1000 {
                    let charge = ControlResponse::ArtifactCharge { length: 1, chunks: 1 };
                    if answer(&broker, msg.id, charge, None).await.is_err() {
                        break;
                    }
                }
            }
        });
        let charges = AtomicU32::new(0);
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            client.fetch_artifact(fetch_request(), |_| {
                charges.fetch_add(1, Ordering::SeqCst);
                async { true }
            }),
        )
        .await
        .expect("the fetch ends");
        assert!(
            matches!(r, Err(ClientError::Protocol | ClientError::Violation)),
            "{r:?}"
        );
        assert!(charges.load(Ordering::SeqCst) <= 1);
        violated_soon(&client).await;
        assert_eq!(pending_len(&client), 0);
        fake.abort();
    }

    #[tokio::test]
    async fn a_second_charge_is_a_protocol_error_and_a_violation() {
        let (client, broker) = pair();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                let (msg, _) = request(&broker).await;
                answer(&broker, msg.id, ControlResponse::ArtifactCharge { length: 1, chunks: 1 }, None).await.unwrap();
                let (decision, _) = request(&broker).await;
                assert_eq!(
                    (decision.id, decision.body),
                    (msg.id, ControlRequest::ChargeDecision { proceed: false })
                );
                // After a refusal, and a second one at that.
                answer(&broker, msg.id, ControlResponse::ArtifactCharge { length: 2, chunks: 1 }, None).await.unwrap();
            }
        });
        let charges = AtomicU32::new(0);
        let r = client
            .fetch_artifact(fetch_request(), |_| {
                charges.fetch_add(1, Ordering::SeqCst);
                async { false }
            })
            .await;
        assert!(matches!(r, Err(ClientError::Protocol)), "{r:?}");
        assert_eq!(charges.load(Ordering::SeqCst), 1);
        assert!(violated_soon(&client)
            .await
            .contains("second ArtifactCharge"));
        fake.await.unwrap();
        // The reader stopped: a new request fails at once.
        assert!(matches!(
            client.check_provisioned(Vec::new()).await,
            Err(ClientError::Violation)
        ));
    }

    #[tokio::test]
    async fn descriptors_on_other_answers_are_a_violation_and_none_is_kept() {
        let (client, broker) = pair();
        let (probe, passed) = passed_fd();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                let (msg, _job_socket) = request(&broker).await;
                for _ in 0..1000 {
                    let registered = ControlResponse::Registered { job_key: B256::ZERO };
                    if answer(&broker, msg.id, registered, Some(passed.as_fd())).await.is_err() {
                        break;
                    }
                }
            }
        });
        let reg = JobRegistration {
            job_key: B256::ZERO,
            caller: Address::ZERO,
            sources: Vec::new(),
            budget: JobBudget { max_fetches: 1, max_fetch_bytes: 1, max_request_bytes: 1, max_response_bytes: 1 },
            held_lock: false,
        };
        let (_builder_end, broker_end) = job_socketpair().unwrap();
        let r = client.register_job(reg, broker_end).await;
        assert!(matches!(r, Err(ClientError::Violation)), "{r:?}");
        assert!(violated_soon(&client).await.contains("other than Artifact"));
        // The fake's copy and the frames still queued (closed with the socket) go too.
        fake.abort();
        let _ = fake.await;
        drop(client);
        drop(broker);
        assert!(
            all_copies_closed(&probe).await,
            "the miner kept a passed descriptor"
        );
    }

    #[tokio::test]
    async fn a_descriptor_for_a_request_never_made_is_a_violation() {
        let (client, broker) = pair();
        let (probe, passed) = passed_fd();
        let artifact = ControlResponse::Artifact { len: 0, sha256: B256::ZERO, cached: false };
        answer(&broker, 999, artifact, Some(passed.as_fd())).await.unwrap();
        drop(passed);
        assert!(violated_soon(&client).await.contains("never made"));
        assert!(all_copies_closed(&probe).await);
    }

    #[tokio::test]
    async fn frames_that_do_not_decode_are_tolerated_up_to_a_bound() {
        let (client, broker) = pair();
        for _ in 0..MAX_UNDECODABLE {
            send_with_fd_async(&broker, KIND_CONTROL, b"not json", None)
                .await
                .unwrap();
        }
        // Still serving: an answer after them arrives. The one frame past the bound is sent only
        // once the test has looked (it raced the check before).
        let (checked, wait_checked) = tokio::sync::oneshot::channel::<()>();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                let (msg, _) = request(&broker).await;
                answer(&broker, msg.id, ControlResponse::Provisioned { ok: Vec::new() }, None).await.unwrap();
                wait_checked.await.unwrap();
                send_with_fd_async(&broker, KIND_CONTROL, b"not json", None).await.unwrap();
            }
        });
        assert_eq!(
            client.check_provisioned(Vec::new()).await.unwrap(),
            Vec::<bool>::new()
        );
        assert!(client.violation().is_none());
        checked.send(()).unwrap();
        fake.await.unwrap();
        assert!(violated_soon(&client).await.contains("do not decode"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_broker_that_takes_no_request_is_a_violation() {
        let (miner, broker) = UnixStream::pair().unwrap();
        // The broker reads nothing: fill the miner's direction of the socket.
        miner.set_nonblocking(true).unwrap();
        let junk = [0u8; 4096];
        loop {
            match (&miner).write(&junk) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        let client = BrokerClient::new(miner).unwrap();
        let t0 = tokio::time::Instant::now();
        let r = client
            .fetch_artifact(fetch_request(), |_| async { true })
            .await;
        assert!(matches!(r, Err(ClientError::Violation)), "{r:?}");
        assert!(
            t0.elapsed() >= SEND_TIMEOUT && t0.elapsed() < SEND_TIMEOUT + Duration::from_secs(1),
            "{:?}",
            t0.elapsed()
        );
        assert!(client.violation().unwrap().contains("took no request"));
        assert_eq!(pending_len(&client), 0);
        drop(broker);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_call_times_out_and_leaves_nothing_pending() {
        let (client, broker) = pair();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                loop {
                    request(&broker).await;
                }
            }
        });
        let t0 = tokio::time::Instant::now();
        let r = client.check_provisioned(Vec::new()).await;
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(
            t0.elapsed() >= CALL_TIMEOUT && t0.elapsed() < CALL_TIMEOUT + Duration::from_secs(1),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(pending_len(&client), 0);
        assert!(
            client.violation().is_none(),
            "a slow answer is not a violation"
        );
        // A dropped request leaves nothing pending either.
        let _ = tokio::time::timeout(Duration::from_secs(1), client.check_provisioned(Vec::new()))
            .await;
        assert_eq!(pending_len(&client), 0);
        fake.abort();
    }

    #[tokio::test]
    async fn a_late_artifact_for_an_ended_request_is_closed_without_a_violation() {
        let (client, broker) = pair();
        let (probe, passed) = passed_fd();
        let fake = tokio::spawn({
            let broker = broker.clone();
            async move {
                let (first, _) = request(&broker).await;
                let (second, _) = request(&broker).await;
                // The first request's waiter is gone by now: its answer comes late.
                let artifact = ControlResponse::Artifact { len: 0, sha256: B256::ZERO, cached: false };
                answer(&broker, first.id, artifact, Some(passed.as_fd())).await.unwrap();
                drop(passed);
                answer(&broker, second.id, ControlResponse::Provisioned { ok: Vec::new() }, None).await.unwrap();
            }
        });
        let dropped = client.fetch_artifact(fetch_request(), |_| async { true });
        assert!(tokio::time::timeout(Duration::from_millis(50), dropped)
            .await
            .is_err());
        assert_eq!(pending_len(&client), 0);
        // Answered after the late artifact: the reader has handled (and closed) it.
        assert_eq!(
            client.check_provisioned(Vec::new()).await.unwrap(),
            Vec::<bool>::new()
        );
        fake.await.unwrap();
        assert!(client.violation().is_none());
        assert!(all_copies_closed(&probe).await);
    }
}
