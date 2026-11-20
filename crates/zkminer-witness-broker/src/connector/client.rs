//! The broker's side of the connector (see the module doc of [`crate::connector`]): asks for a
//! connection to an endpoint by index and receives the connected socket.
//!
//! The client keeps the connector's in-flight bound itself: at most [`MAX_INFLIGHT`] requests are
//! outstanding, and a request's slot is released only when its answer arrives (also when the
//! caller stopped waiting), so the connector never sees more and never cuts an honest broker off.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::Interest;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

use super::{Malformed, Request, Response, Status, MAX_INFLIGHT, REQUEST_LEN, RESPONSE_LEN};
use crate::egress::Role;
use crate::fdpass::{recvmsg_once, retry_eintr, sendmsg_once};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Why no connection came back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// The connector answered with a refusal.
    #[error("the connector refused: {0:?}")]
    Refused(Status),
    /// The connector's socket is closed (the miner stopped, or cut this broker off).
    #[error("the connector is gone")]
    Closed,
    /// No answer in time.
    #[error("no answer from the connector in time")]
    Timeout,
    /// The connector broke the protocol (a malformed answer, a missing or extra fd).
    #[error("connector protocol: {0}")]
    Protocol(String),
}

struct Pending {
    tx: oneshot::Sender<(Response, Option<OwnedFd>)>,
    /// Released when the answer arrives (or the socket closes), never earlier.
    _slot: OwnedSemaphorePermit,
}

type PendingMap = Arc<Mutex<HashMap<u64, Pending>>>;

/// The broker's connector client. Needs a tokio runtime.
pub struct ConnectorClient {
    sock: Arc<tokio::net::UnixStream>,
    write: tokio::sync::Mutex<()>,
    pending: PendingMap,
    slots: Arc<Semaphore>,
    next_id: AtomicU64,
    closed: Arc<AtomicBool>,
    reader: tokio::task::JoinHandle<()>,
    /// How long a caller waits for an answer.
    wait: Duration,
}

impl std::fmt::Debug for ConnectorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorClient").field("closed", &self.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

impl Drop for ConnectorClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl ConnectorClient {
    /// A client on the broker's end of the connector socketpair (fd 4 in the broker). `wait` is
    /// how long a caller waits for one answer (at least the connector's
    /// [`super::request_budget`]).
    pub fn new(fd: OwnedFd, wait: Duration) -> io::Result<Self> {
        if !crate::fdpass::is_unix_stream(std::os::fd::AsFd::as_fd(&fd)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the connector fd is not a Unix stream socket"));
        }
        crate::fdpass::set_nonblocking(&fd)?;
        let sock = Arc::new(tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))?);
        let pending: PendingMap = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let reader = tokio::spawn(read_loop(sock.clone(), pending.clone(), closed.clone()));
        Ok(Self {
            sock,
            write: tokio::sync::Mutex::new(()),
            pending,
            slots: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            next_id: AtomicU64::new(1),
            closed,
            reader,
            wait,
        })
    }

    /// Whether the connector's socket closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// A connection to endpoint `endpoint` (its index in the configuration), which this broker
    /// knows as a `role` on `port`: the connected socket and its peer, as the connector reported
    /// it. The caller checks the peer itself.
    pub async fn connect(&self, endpoint: u32, role: Role, port: u16) -> Result<(std::net::TcpStream, SocketAddr), ConnectError> {
        if self.is_closed() {
            return Err(ConnectError::Closed);
        }
        let slot = tokio::time::timeout(self.wait, self.slots.clone().acquire_owned())
            .await
            .map_err(|_| ConnectError::Timeout)?
            .map_err(|_| ConnectError::Closed)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, Pending { tx, _slot: slot });
        let frame = Request { id, endpoint, role, port }.encode();
        let wrote = {
            let _w = self.write.lock().await;
            // A whole frame or nothing usable: a failed write closes the client for everyone.
            write_all(&self.sock, &frame).await
        };
        if wrote.is_err() {
            lock(&self.pending).remove(&id);
            self.closed.store(true, Ordering::SeqCst);
            return Err(ConnectError::Closed);
        }
        let (resp, fd) = match tokio::time::timeout(self.wait, rx).await {
            Err(_) => return Err(ConnectError::Timeout),
            Ok(Err(_)) => return Err(ConnectError::Closed),
            Ok(Ok(answer)) => answer,
        };
        match (resp.status, fd, resp.peer) {
            (Status::Connected, Some(fd), Some(peer)) => {
                if !is_tcp_stream(&fd) {
                    return Err(ConnectError::Protocol("the attached fd is not a TCP stream socket".into()));
                }
                Ok((std::net::TcpStream::from(fd), peer))
            }
            (Status::Connected, _, _) => Err(ConnectError::Protocol("connected without a socket".into())),
            (status, None, _) => Err(ConnectError::Refused(status)),
            (_, Some(_), _) => Err(ConnectError::Protocol("a refusal with a socket".into())),
        }
    }
}

async fn write_all(sock: &tokio::net::UnixStream, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = sock.async_io(Interest::WRITABLE, || retry_eintr(|| sendmsg_once(sock.as_raw_fd(), buf, None))).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
    }
    Ok(())
}

/// Whether `fd` is a stream socket of family `AF_INET`/`AF_INET6`.
fn is_tcp_stream(fd: &OwnedFd) -> bool {
    let get = |opt: libc::c_int| -> Option<libc::c_int> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into a c_int of the stated length.
        let r = unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, opt, (&mut v as *mut libc::c_int).cast(), &mut len) };
        (r == 0).then_some(v)
    };
    get(libc::SO_TYPE) == Some(libc::SOCK_STREAM) && matches!(get(libc::SO_DOMAIN), Some(libc::AF_INET) | Some(libc::AF_INET6))
}

/// Reads answers until the socket closes: each frame's fd may only be attached to its first byte,
/// and at most one. An answer for an id nobody waits for (the caller timed out) is dropped, its fd
/// closed. A protocol violation closes the client.
async fn read_loop(sock: Arc<tokio::net::UnixStream>, pending: PendingMap, closed: Arc<AtomicBool>) {
    loop {
        match read_response(&sock).await {
            Ok(Some((resp, fd))) => {
                let p = lock(&pending).remove(&resp.id);
                match p {
                    Some(p) => {
                        let _ = p.tx.send((resp, fd));
                    }
                    None => tracing::warn!(id = resp.id, "connector answer for no pending request"),
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!(error = %e, "connector: closing after a protocol error");
                break;
            }
        }
    }
    closed.store(true, Ordering::SeqCst);
    // Every waiter learns the socket is gone; every slot is released.
    lock(&pending).clear();
}

async fn read_response(sock: &tokio::net::UnixStream) -> io::Result<Option<(Response, Option<OwnedFd>)>> {
    let mut buf = [0u8; RESPONSE_LEN];
    let mut off = 0;
    let mut fd = None;
    while off < RESPONSE_LEN {
        let mut fds = Vec::new();
        let n = sock
            .async_io(Interest::READABLE, || retry_eintr(|| recvmsg_once(sock.as_raw_fd(), &mut buf[off..], &mut fds)))
            .await?;
        if !fds.is_empty() {
            if off != 0 || fds.len() > 1 || fd.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "an fd past a frame's first byte, or several"));
            }
            fd = fds.pop();
        }
        match n {
            0 if off == 0 && fd.is_none() => return Ok(None),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => off += n,
        }
    }
    let resp = Response::decode(&buf).map_err(|Malformed(m)| io::Error::new(io::ErrorKind::InvalidData, m))?;
    Ok(Some((resp, fd)))
}

/// One request on a blocking socket (tests and probes): writes `req`, reads one answer and the fd
/// attached to it.
pub fn request_blocking(sock: &std::os::unix::net::UnixStream, req: &Request) -> io::Result<(Response, Option<OwnedFd>)> {
    use std::io::Write;
    let mut s = sock;
    s.write_all(&req.encode())?;
    let mut buf = [0u8; RESPONSE_LEN];
    let mut off = 0;
    let mut fd = None;
    while off < RESPONSE_LEN {
        let mut fds = Vec::new();
        let n = retry_eintr(|| recvmsg_once(sock.as_raw_fd(), &mut buf[off..], &mut fds))?;
        if !fds.is_empty() {
            if off != 0 || fds.len() > 1 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "an fd past a frame's first byte, or several"));
            }
            fd = fds.pop();
        }
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        off += n;
    }
    let resp = Response::decode(&buf).map_err(|Malformed(m)| io::Error::new(io::ErrorKind::InvalidData, m))?;
    Ok((resp, fd))
}

const _: () = assert!(REQUEST_LEN == 32 && RESPONSE_LEN == 40);
