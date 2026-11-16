//! Per-job fetch serving (plan §10.1, §11.2–§11.4).
//!
//! A job is the socket it was registered with (`RegisterJob`'s `SCM_RIGHTS` fd), never a peer
//! credential. Its builder sends `KIND_FETCH` frames (`cap ‖ request`), one at a time; each gets a
//! `KIND_FETCH_RESULT` (`status ‖ body`). Frames are read with the job's cap
//! (`fetch_frame_max(maxRequestBytes)`), refused before allocating; once a frame's first byte has
//! arrived the rest must follow within `partial_frame_secs`, and so must the reader take the
//! result: a builder that stops reading loses its socket, and with it the result's byte permit
//! and spool file (both live until the result is written).
//!
//! Builder-visible budgets: one unit per request element (a batch of `k` calls is `k`; a refused
//! request is 1) and the response bytes delivered, both charged as if every request missed the
//! cache. A budget hit is status 3. Once `maxFetches` or `maxFetchBytes` is spent, every further
//! frame is status 3 at once, without a charge or an endpoint contact; after
//! [`MAX_FRAMES_AFTER_EXHAUSTION`] of them the job's socket is closed. Retries and failover are
//! charged only to operator budgets, so operator exhaustion is status 2.
//!
//! A status-2 fetch is classified ([`Failure`]) into `JobStats.operator_failure`,
//! `JobStats.unanswerable` or neither (the request's own cost); see `zkminer_witness::ipc`.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zkminer_witness::envelope::MethodSet;
use zkminer_witness::ipc::{
    decode_fetch, fetch_frame_max, ControlErrorCode, ControlResponse, FetchStatus, FrameError, JobBudget,
    FRAME_HEADER_BYTES, KIND_FETCH, KIND_FETCH_RESULT, MAX_FRAMES_AFTER_EXHAUSTION,
};

use crate::broker::Broker;
use crate::lanes::{LanePermit, WaitFlag};
use crate::net::Endpoint;
use crate::spool::SpoolFile;

/// Spool bytes read back per blocking-pool trip when a result is written.
const SPOOL_READ_CHUNK: usize = 256 << 10;

/// Where one of a job's capabilities is served from.
pub(crate) enum JobSource {
    EvmRpc { chain_id: u64, method_set: MethodSet, endpoints: Vec<Arc<Endpoint>> },
    Blob { max_bytes: u64 },
}

/// Why a fetch ended with status 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The operator's side: transport, connect timeouts, non-2xx (404 only for RPC endpoints), a
    /// malformed answer, an operator budget or the spool quota, a lane or pacer wait at the deadline.
    Operator,
    /// Every endpoint tried lacked the block or state, or every mirror lacked the blob.
    Unanswerable,
    /// The request's own cost: a timeout once sent, the deadline while an endpoint worked on it.
    Own,
}

#[derive(Debug, Default, Clone, Copy)]
struct Account {
    fetches: u32,
    fetch_bytes: u64,
    operator_failure: bool,
    unanswerable: bool,
    denied: u32,
    in_flight_at_close: bool,
    operator_wait_at_close: bool,
    frames_after_exhaustion: u32,
}

pub(crate) struct Job {
    pub key: B256,
    pub caller: Address,
    pub held_lock: bool,
    pub budget: JobBudget,
    pub sources: Vec<JobSource>,
    /// Set while the current fetch waits on operator-side capacity (lanes, pacer, slots).
    pub wait: WaitFlag,
    /// The current fetch met an operator-side failure (it may still succeed elsewhere).
    operator_fault: AtomicBool,
    acct: Mutex<Account>,
    in_flight: AtomicBool,
    cancel: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// A fetch result body.
pub(crate) enum Body {
    Empty,
    Bytes(Vec<u8>),
    Spool(SpoolFile),
}

pub(crate) struct Outcome {
    pub status: FetchStatus,
    pub body: Body,
    /// For status 2.
    pub failure: Option<Failure>,
    /// The in-flight byte permit that covers `body`, held until the result is written (or its
    /// write times out).
    pub _permit: Option<LanePermit>,
}

impl Outcome {
    pub fn status(status: FetchStatus) -> Self {
        debug_assert!(status != FetchStatus::Failed, "status 2 needs a Failure");
        Self { status, body: Body::Empty, failure: None, _permit: None }
    }
    pub fn failed(f: Failure) -> Self {
        Self { status: FetchStatus::Failed, body: Body::Empty, failure: Some(f), _permit: None }
    }
    pub fn bytes(b: Vec<u8>, permit: LanePermit) -> Self {
        Self { status: FetchStatus::Ok, body: Body::Bytes(b), failure: None, _permit: Some(permit) }
    }
    pub fn spool(f: SpoolFile, permit: LanePermit) -> Self {
        Self { status: FetchStatus::Ok, body: Body::Spool(f), failure: None, _permit: Some(permit) }
    }
}

impl Job {
    fn acct(&self) -> std::sync::MutexGuard<'_, Account> {
        self.acct.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Charges `n` request units if they fit the job's `maxFetches`.
    pub fn try_charge_units(&self, n: u32) -> bool {
        let mut a = self.acct();
        match a.fetches.checked_add(n) {
            Some(t) if t <= self.budget.max_fetches => {
                a.fetches = t;
                true
            }
            _ => false,
        }
    }

    /// Gives back `n` units charged with [`Job::try_charge_units`].
    pub fn refund_units(&self, n: u32) {
        let mut a = self.acct();
        a.fetches = a.fetches.saturating_sub(n);
    }

    /// Charges one unit for a refused request, up to the budget.
    pub fn charge_refused(&self) {
        let mut a = self.acct();
        a.fetches = a.fetches.saturating_add(1).min(self.budget.max_fetches);
    }

    pub fn units_left(&self) -> u32 {
        self.budget.max_fetches.saturating_sub(self.acct().fetches)
    }

    pub fn bytes_left(&self) -> u64 {
        self.budget.max_fetch_bytes.saturating_sub(self.acct().fetch_bytes)
    }

    /// Whether a builder-visible budget is spent (every further fetch is status 3).
    fn spent(&self) -> bool {
        self.units_left() == 0 || self.bytes_left() == 0
    }

    /// Charges `n` delivered bytes if they fit the job's `maxFetchBytes`.
    pub fn try_charge_bytes(&self, n: u64) -> bool {
        let mut a = self.acct();
        match a.fetch_bytes.checked_add(n) {
            Some(t) if t <= self.budget.max_fetch_bytes => {
                a.fetch_bytes = t;
                true
            }
            _ => false,
        }
    }

    /// The current fetch met an operator-side failure.
    pub fn note_operator_fault(&self) {
        self.operator_fault.store(true, Ordering::SeqCst);
    }

    /// The current fetch is in an operator-side wait or met an operator-side failure.
    fn operator_side_now(&self) -> bool {
        self.wait.is_set() || self.operator_fault.load(Ordering::SeqCst)
    }

    /// A short job id for logs.
    pub fn tag(&self) -> String {
        hex::encode(&self.key[..6])
    }
}

/// `RegisterJob`: provisions every source, then serves `sock` until `EndJob`.
pub(crate) fn register(
    b: &Arc<Broker>,
    job_key: B256,
    caller: Address,
    sources: &[(B256, Vec<u8>)],
    budget: JobBudget,
    held_lock: bool,
    sock: std::os::fd::OwnedFd,
) -> ControlResponse {
    use std::os::fd::AsFd;
    if !crate::fdpass::is_unix_stream(sock.as_fd()) || crate::fdpass::set_nonblocking(&sock).is_err() {
        return ControlResponse::Error { code: ControlErrorCode::Malformed };
    }
    let mut provisioned = Vec::with_capacity(sources.len());
    for (class, config) in sources {
        match b.provision(*class, config) {
            Some(s) => provisioned.push(s),
            None => return ControlResponse::Error { code: ControlErrorCode::NotProvisioned },
        }
    }
    let stream = match tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(sock)) {
        Ok(s) => s,
        Err(_) => return ControlResponse::Error { code: ControlErrorCode::Internal },
    };
    let (cancel, cancel_rx) = watch::channel(false);
    let job = Arc::new(Job {
        key: job_key,
        caller,
        held_lock,
        budget,
        sources: provisioned,
        wait: WaitFlag::default(),
        operator_fault: AtomicBool::new(false),
        acct: Mutex::new(Account::default()),
        in_flight: AtomicBool::new(false),
        cancel,
        task: Mutex::new(None),
    });
    {
        let mut jobs = b.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if jobs.contains_key(&job_key) {
            return ControlResponse::Error { code: ControlErrorCode::DuplicateJob };
        }
        jobs.insert(job_key, job.clone());
    }
    let handle = tokio::spawn(run(b.clone(), job.clone(), stream, cancel_rx));
    *job.task.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
    tracing::info!(job = %job.tag(), caller = %caller, held_lock, sources = sources.len(), "job registered");
    ControlResponse::Registered { job_key }
}

/// `EndJob`: stops serving and reports the job's account. `fetch_in_flight_at_end` is whether a
/// fetch was being served when `EndJob` arrived or when the builder's socket closed;
/// `in_flight_operator_wait` whether that fetch was then in an operator-side wait or had met an
/// operator-side failure.
pub(crate) async fn end(b: &Arc<Broker>, job_key: B256) -> ControlResponse {
    let Some(job) = b.jobs.lock().unwrap_or_else(|p| p.into_inner()).remove(&job_key) else {
        return ControlResponse::Error { code: ControlErrorCode::UnknownJob };
    };
    let in_flight = job.in_flight.load(Ordering::SeqCst);
    let operator_wait = in_flight && job.operator_side_now();
    job.cancel.send_replace(true);
    let handle = job.task.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(h) = handle {
        let abort = h.abort_handle();
        if tokio::time::timeout(std::time::Duration::from_secs(5), h).await.is_err() {
            abort.abort();
        }
    }
    let a = *job.acct();
    tracing::info!(
        job = %job.tag(),
        caller = %job.caller,
        fetches = a.fetches,
        bytes = a.fetch_bytes,
        operator_failure = a.operator_failure,
        unanswerable = a.unanswerable,
        denied = a.denied,
        frames_after_exhaustion = a.frames_after_exhaustion,
        "job ended"
    );
    ControlResponse::JobStats {
        job_key,
        fetches: a.fetches,
        fetch_bytes: a.fetch_bytes,
        operator_failure: a.operator_failure,
        unanswerable: a.unanswerable,
        fetch_in_flight_at_end: in_flight || a.in_flight_at_close,
        in_flight_operator_wait: operator_wait || a.operator_wait_at_close,
        denied: a.denied,
        frames_after_exhaustion: a.frames_after_exhaustion,
    }
}

/// Cancels every job (the control channel closed).
pub(crate) fn cancel_all(b: &Broker) {
    let jobs: Vec<_> = b.jobs.lock().unwrap_or_else(|p| p.into_inner()).drain().map(|(_, j)| j).collect();
    for j in jobs {
        j.cancel.send_replace(true);
    }
}

async fn cancelled(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Reads one `KIND_FETCH` frame. Waits indefinitely for its first byte (`Ok(None)` on a clean
/// close); the rest must arrive within `partial`.
async fn read_fetch_frame(
    rd: &mut OwnedReadHalf,
    max: u32,
    partial: std::time::Duration,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    if rd.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    let rest = async {
        rd.read_exact(&mut header[1..]).await?;
        if header[0] != KIND_FETCH {
            return Err(FrameError::UnexpectedKind(header[0]));
        }
        let len = u32::from_be_bytes(header[1..].try_into().expect("4 bytes"));
        if len > max {
            return Err(FrameError::TooLarge { len, max });
        }
        let mut payload = vec![0u8; len as usize];
        rd.read_exact(&mut payload).await?;
        Ok(payload)
    };
    match tokio::time::timeout(partial, rest).await {
        Ok(r) => r.map(Some),
        Err(_) => Err(FrameError::Io(io::ErrorKind::TimedOut.into())),
    }
}

/// Resolves when the builder closes its socket (`true`) or sends bytes while a fetch is being
/// served (`false`: it pipelined, a protocol violation).
async fn closed_or_pipelined(rd: &OwnedReadHalf) -> bool {
    let mut byte = [0u8; 1];
    loop {
        if rd.readable().await.is_err() {
            return true;
        }
        match rd.try_read(&mut byte) {
            Ok(0) => return true,
            Ok(_) => return false,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return true,
        }
    }
}

/// Writes one result frame. A spooled body is read back on the blocking pool, a chunk at a time.
async fn write_result(wr: &mut OwnedWriteHalf, o: &Outcome) -> io::Result<()> {
    let body_len = match &o.body {
        Body::Empty => 0,
        Body::Bytes(b) => b.len() as u64,
        Body::Spool(f) => f.len(),
    };
    let len = u32::try_from(body_len + 1).map_err(|_| io::Error::other("result too large"))?;
    let mut head = [0u8; FRAME_HEADER_BYTES + 1];
    head[0] = KIND_FETCH_RESULT;
    head[1..5].copy_from_slice(&len.to_be_bytes());
    head[5] = o.status as u8;
    wr.write_all(&head).await?;
    match &o.body {
        Body::Empty => {}
        Body::Bytes(b) => wr.write_all(b).await?,
        Body::Spool(f) => {
            let mut off = 0u64;
            while off < body_len {
                let chunk = f.read_at(off, SPOOL_READ_CHUNK).await?;
                if chunk.is_empty() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                wr.write_all(&chunk).await?;
                off += chunk.len() as u64;
            }
        }
    }
    wr.flush().await
}

async fn run(b: Arc<Broker>, job: Arc<Job>, sock: tokio::net::UnixStream, mut cancel: watch::Receiver<bool>) {
    let (mut rd, mut wr) = sock.into_split();
    let max = fetch_frame_max(job.budget.max_request_bytes);
    let partial = b.cfg.timeouts.partial_frame();
    loop {
        let frame = tokio::select! {
            f = read_fetch_frame(&mut rd, max, partial) => f,
            _ = cancelled(&mut cancel) => return,
        };
        let payload = match frame {
            Ok(Some(p)) => p,
            Ok(None) => return,
            Err(FrameError::TooLarge { .. }) => {
                // Refused before allocating; the stream cannot be resynchronized.
                job.acct().denied += 1;
                job.charge_refused();
                let _ = tokio::time::timeout(partial, write_result(&mut wr, &Outcome::status(FetchStatus::Denied))).await;
                return;
            }
            Err(e) => {
                tracing::debug!(job = %job.tag(), error = %e, "job socket closed on a bad frame");
                return;
            }
        };
        if job.spent() {
            // Status 3 at once, no charge, no endpoint; a builder spinning on it loses its socket.
            let n = {
                let mut a = job.acct();
                a.frames_after_exhaustion = a.frames_after_exhaustion.saturating_add(1);
                a.frames_after_exhaustion
            };
            if n > MAX_FRAMES_AFTER_EXHAUSTION {
                tracing::info!(job = %job.tag(), "builder keeps fetching past its spent budget; closing its socket");
                return;
            }
            match tokio::time::timeout(partial, write_result(&mut wr, &Outcome::status(FetchStatus::Exhausted))).await {
                Ok(Ok(())) => continue,
                _ => return,
            }
        }
        job.wait.clear();
        job.operator_fault.store(false, Ordering::SeqCst);
        job.in_flight.store(true, Ordering::SeqCst);
        let outcome = tokio::select! {
            o = serve_fetch(&b, &job, &payload) => Some(o),
            _ = cancelled(&mut cancel) => None,
            closed = closed_or_pipelined(&rd) => {
                if closed {
                    let mut a = job.acct();
                    a.in_flight_at_close = true;
                    a.operator_wait_at_close = job.operator_side_now();
                } else {
                    job.acct().denied += 1;
                    tracing::debug!(job = %job.tag(), "builder pipelined a fetch; closing its socket");
                }
                None
            }
        };
        job.in_flight.store(false, Ordering::SeqCst);
        let Some(o) = outcome else { return };
        match (o.status, o.failure) {
            (FetchStatus::Failed, Some(Failure::Operator)) => job.acct().operator_failure = true,
            (FetchStatus::Failed, Some(Failure::Unanswerable)) => job.acct().unanswerable = true,
            (FetchStatus::Denied, _) => job.acct().denied += 1,
            _ => {}
        }
        // `o` (its permit and spool file) lives until the write is done or abandoned.
        match tokio::time::timeout(partial, write_result(&mut wr, &o)).await {
            Ok(Ok(())) => {}
            _ => {
                tracing::debug!(job = %job.tag(), "result not taken in time; closing the job's socket");
                return;
            }
        }
    }
}

/// Serves one fetch: the cap index, then the class's handler, within the fetch wall time (status 2
/// past it: the operator's when the fetch was in an operator-side wait or had met an operator-side
/// failure, else the request's own).
async fn serve_fetch(b: &Arc<Broker>, job: &Arc<Job>, payload: &[u8]) -> Outcome {
    let Ok((cap, request)) = decode_fetch(payload) else {
        job.charge_refused();
        return Outcome::status(FetchStatus::Denied);
    };
    if job.spent() {
        return Outcome::status(FetchStatus::Exhausted);
    }
    let Some(source) = job.sources.get(cap as usize) else {
        job.charge_refused();
        return Outcome::status(FetchStatus::Denied);
    };
    let fut = async {
        match source {
            JobSource::EvmRpc { chain_id, method_set, endpoints } => {
                crate::rpc_serve::serve(b, job, *chain_id, *method_set, endpoints, request).await
            }
            JobSource::Blob { max_bytes } => crate::blob::serve(b, job, *max_bytes, request).await,
        }
    };
    tokio::time::timeout(b.cfg.timeouts.fetch(), fut).await.unwrap_or_else(|_| {
        let operator = job.operator_side_now();
        tracing::warn!(job = %job.tag(), cap, operator, "fetch timed out");
        Outcome::failed(if operator { Failure::Operator } else { Failure::Own })
    })
}
