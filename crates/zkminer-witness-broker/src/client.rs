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

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use tokio::sync::mpsc;
use zkminer_witness::ipc::{
    decode_control, encode_control, ArtifactFailure, ArtifactSource, ControlErrorCode, ControlMessage, ControlRequest,
    ControlResponse, IpPrefix, JobBudget, SelfTestCheck, KIND_CONTROL, MAX_CONTROL_BYTES,
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
}

type Answer = (ControlResponse, Option<OwnedFd>);
type Pending = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Answer>>>>;

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
    /// Some fetch failed (status 2) because every endpoint tried lacked what it asked for.
    pub unanswerable: bool,
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
    next_id: AtomicU64,
    pending: Pending,
    reader: tokio::task::JoinHandle<()>,
    runners: Arc<RunnerCgroups>,
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
        let reader = tokio::spawn(read_loop(sock.clone(), pending.clone()));
        Ok(Self {
            sock,
            write: tokio::sync::Mutex::new(()),
            next_id: AtomicU64::new(1),
            pending,
            reader,
            runners: Arc::default(),
        })
    }

    /// The builder runners holding a job socket of this broker ([`RunnerCgroups`]).
    pub fn runners(&self) -> &Arc<RunnerCgroups> {
        &self.runners
    }

    async fn send(&self, id: u64, body: ControlRequest, fd: Option<std::os::fd::BorrowedFd<'_>>) -> Result<(), ClientError> {
        let payload = encode_control(&ControlMessage { id, body });
        let _g = self.write.lock().await;
        send_with_fd_async(&self.sock, KIND_CONTROL, &payload, fd).await?;
        Ok(())
    }

    /// Sends a request and returns the channel its answers arrive on.
    async fn start(
        &self,
        body: ControlRequest,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<(u64, mpsc::UnboundedReceiver<Answer>), ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).insert(id, tx);
        if let Err(e) = self.send(id, body, fd).await {
            self.finish(id);
            return Err(e);
        }
        Ok((id, rx))
    }

    fn finish(&self, id: u64) {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    }

    async fn call(&self, body: ControlRequest, fd: Option<std::os::fd::BorrowedFd<'_>>) -> Result<Answer, ClientError> {
        let (id, mut rx) = self.start(body, fd).await?;
        let r = rx.recv().await.ok_or(ClientError::Closed);
        self.finish(id);
        match r? {
            (ControlResponse::Error { code }, _) => Err(ClientError::Refused(code)),
            a => Ok(a),
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
        match self.call(body, Some(broker_end.as_fd())).await? {
            (ControlResponse::Registered { job_key }, None) if job_key == reg.job_key => Ok(()),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `EndJob`: stops the broker serving the job and returns its account.
    pub async fn end_job(&self, job_key: B256) -> Result<JobStats, ClientError> {
        match self.call(ControlRequest::EndJob { job_key }, None).await? {
            (
                ControlResponse::JobStats {
                    job_key: k,
                    fetches,
                    fetch_bytes,
                    operator_failure,
                    unanswerable,
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
                fetch_in_flight_at_end,
                in_flight_operator_wait,
                denied,
                frames_after_exhaustion,
            }),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `FetchArtifact`. For a `hemi-code` read that is not cached, `charge` is called with its cost
    /// before any chunk is read; `false` ends the fetch with `ArtifactFailure::Budget`. The memfd's
    /// seals and size are checked before it is returned.
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
        let (id, mut rx) = self.start(body, None).await?;
        let r = loop {
            let Some(answer) = rx.recv().await else { break Err(ClientError::Closed) };
            match answer {
                (ControlResponse::ArtifactCharge { length, chunks }, None) => {
                    let proceed = charge(ArtifactCharge { length, chunks }).await;
                    if let Err(e) = self.send(id, ControlRequest::ChargeDecision { proceed }, None).await {
                        break Err(e);
                    }
                }
                (ControlResponse::Artifact { len, sha256, cached }, Some(fd)) => {
                    if let Err(e) = check_sealed(fd.as_fd(), len) {
                        break Err(ClientError::BadMemfd(e));
                    }
                    break Ok(Ok(FetchedArtifact { memfd: File::from(fd), len, sha256, cached }));
                }
                (ControlResponse::ArtifactFailed { failure }, None) => break Ok(Err(failure)),
                (ControlResponse::Error { code }, _) => break Err(ClientError::Refused(code)),
                _ => break Err(ClientError::Protocol),
            }
        };
        self.finish(id);
        r
    }

    /// `CheckProvisioned`: one answer per `(class, config)`, in order.
    pub async fn check_provisioned(&self, sources: Vec<(B256, Vec<u8>)>) -> Result<Vec<bool>, ClientError> {
        let n = sources.len();
        match self.call(ControlRequest::CheckProvisioned { sources }, None).await? {
            (ControlResponse::Provisioned { ok }, None) if ok.len() == n => Ok(ok),
            _ => Err(ClientError::Protocol),
        }
    }

    pub async fn self_test(&self) -> Result<SelfTestResult, ClientError> {
        match self.call(ControlRequest::SelfTest, None).await? {
            (ControlResponse::SelfTest { ok, checks }, None) => Ok(SelfTestResult { ok, checks }),
            _ => Err(ClientError::Protocol),
        }
    }

    /// `RefreshPrefixes` (see [`crate::hostinfo::refresh_message`]): returns the prefix count.
    pub async fn refresh_prefixes(&self, prefixes: Vec<IpPrefix>, own_addresses: Vec<IpAddr>) -> Result<u32, ClientError> {
        match self.call(ControlRequest::RefreshPrefixes { prefixes, own_addresses }, None).await? {
            (ControlResponse::PrefixesRefreshed { count }, None) => Ok(count),
            _ => Err(ClientError::Protocol),
        }
    }
}

async fn read_loop(sock: Arc<tokio::net::UnixStream>, pending: Pending) {
    loop {
        let frame = match recv_with_fd_async(&sock, MAX_CONTROL_BYTES).await {
            Ok(Some(f)) if f.kind == KIND_CONTROL => f,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        };
        let Ok(msg) = decode_control::<ControlMessage<ControlResponse>>(&frame.payload) else { continue };
        let tx = pending.lock().unwrap_or_else(|p| p.into_inner()).get(&msg.id).cloned();
        if let Some(tx) = tx {
            let _ = tx.send((msg.body, frame.fd));
        }
    }
    // Closed: every waiter sees `Closed`.
    pending.lock().unwrap_or_else(|p| p.into_inner()).clear();
}
