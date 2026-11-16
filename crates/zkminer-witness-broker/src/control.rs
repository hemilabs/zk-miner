//! The control channel (plan §10.1): the miner's end of a socketpair at fd 3, `KIND_CONTROL` frames
//! with [`ControlMessage`] JSON (at most `MAX_CONTROL_BYTES`), fds by `SCM_RIGHTS` (see
//! [`crate::fdpass`]). Requests are served concurrently; one writer task sends every response, so a
//! frame and its fd are never interleaved with another. A frame the broker cannot read in full (too
//! large, cut short) ends the channel; a malformed one is answered `Error{Malformed}` with id 0 (or
//! its own id when that much parsed). When the channel closes, every job is cancelled and
//! [`run`] returns.

use std::collections::HashMap;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use zkminer_witness::ipc::{
    decode_control, encode_control, ControlErrorCode, ControlMessage, ControlRequest, ControlResponse, FrameError,
    KIND_CONTROL, MAX_CONTROL_BYTES,
};

use crate::artifact::{ArtifactRequest, ChargeFn};
use crate::broker::Broker;
use crate::config::parse_cidr;
use crate::egress::Prefix;
use crate::fdpass::{recv_with_fd_async, send_with_fd_async};

type Reply = (u64, ControlResponse, Option<OwnedFd>);
type Decisions = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<bool>>>>;

pub(crate) async fn run(b: Arc<Broker>, sock: tokio::net::UnixStream) -> anyhow::Result<()> {
    let sock = Arc::new(sock);
    let (tx, mut rx) = mpsc::channel::<Reply>(256);
    let writer = {
        let sock = sock.clone();
        tokio::spawn(async move {
            while let Some((id, body, fd)) = rx.recv().await {
                let payload = encode_control(&ControlMessage { id, body });
                if let Err(e) = send_with_fd_async(&sock, KIND_CONTROL, &payload, fd.as_ref().map(|f| f.as_fd())).await {
                    tracing::warn!(error = %e, "control channel write failed");
                    return;
                }
            }
        })
    };
    let decisions: Decisions = Arc::default();
    let result = loop {
        let frame = match recv_with_fd_async(&sock, MAX_CONTROL_BYTES).await {
            Ok(Some(f)) => f,
            Ok(None) => break Ok(()),
            Err(FrameError::Malformed) => {
                let _ = tx.send((0, error(ControlErrorCode::Malformed), None)).await;
                continue;
            }
            Err(e) => break Err(anyhow::anyhow!("control channel: {e}")),
        };
        if frame.kind != KIND_CONTROL {
            let _ = tx.send((0, error(ControlErrorCode::Malformed), None)).await;
            continue;
        }
        let msg = match decode_control::<ControlMessage<ControlRequest>>(&frame.payload) {
            Ok(m) => m,
            Err(_) => {
                let _ = tx.send((0, error(ControlErrorCode::Malformed), None)).await;
                continue;
            }
        };
        dispatch(&b, &tx, &decisions, msg, frame.fd).await;
    };
    crate::job::cancel_all(&b);
    drop(tx);
    let _ = writer.await;
    result
}

fn error(code: ControlErrorCode) -> ControlResponse {
    ControlResponse::Error { code }
}

async fn dispatch(
    b: &Arc<Broker>,
    tx: &mpsc::Sender<Reply>,
    decisions: &Decisions,
    msg: ControlMessage<ControlRequest>,
    fd: Option<OwnedFd>,
) {
    let id = msg.id;
    let takes_fd = matches!(msg.body, ControlRequest::RegisterJob { .. });
    if fd.is_some() != takes_fd {
        let _ = tx.send((id, error(ControlErrorCode::Malformed), None)).await;
        return;
    }
    match msg.body {
        ControlRequest::RegisterJob { job_key, caller, sources, budget, held_lock } => {
            let fd = fd.expect("checked above");
            let r = crate::job::register(b, job_key, caller, &sources, budget, held_lock, fd);
            let _ = tx.send((id, r, None)).await;
        }
        ControlRequest::EndJob { job_key } => {
            let (b, tx) = (b.clone(), tx.clone());
            tokio::spawn(async move {
                let r = crate::job::end(&b, job_key).await;
                let _ = tx.send((id, r, None)).await;
            });
        }
        ControlRequest::FetchArtifact { job_key, caller, source, builder_type, expected_sha256, max_bytes, held_lock } => {
            let req = ArtifactRequest { source, builder_type, expected_sha256, max_bytes, held_lock };
            let charge = charge_hook(id, tx.clone(), decisions.clone(), b.cfg.timeouts.charge_decision());
            let (b, tx) = (b.clone(), tx.clone());
            tokio::spawn(async move {
                let job = hex::encode(&job_key[..6]);
                let reply = match b.artifacts.fetch(&req, charge).await {
                    Ok(a) => {
                        tracing::info!(job = %job, caller = %caller, len = a.len, cached = a.cached, "artifact served");
                        (id, ControlResponse::Artifact { len: a.len, sha256: a.sha256, cached: a.cached }, Some(OwnedFd::from(a.file)))
                    }
                    Err(failure) => {
                        tracing::info!(job = %job, caller = %caller, ?failure, "artifact fetch failed");
                        (id, ControlResponse::ArtifactFailed { failure }, None)
                    }
                };
                let _ = tx.send(reply).await;
            });
        }
        ControlRequest::ChargeDecision { proceed } => {
            let waiter = decisions.lock().unwrap_or_else(|p| p.into_inner()).get(&id).cloned();
            match waiter {
                Some(w) => {
                    let _ = w.send(proceed);
                }
                None => tracing::warn!(id, "charge decision for no pending artifact charge"),
            }
        }
        ControlRequest::CheckProvisioned { sources } => {
            let ok = sources.iter().map(|(class, config)| b.provision(*class, config).is_some()).collect();
            let _ = tx.send((id, ControlResponse::Provisioned { ok }, None)).await;
        }
        ControlRequest::SelfTest => {
            let (b, tx) = (b.clone(), tx.clone());
            tokio::spawn(async move {
                let r = crate::selftest::run(&b).await;
                let _ = tx.send((id, r, None)).await;
            });
        }
        ControlRequest::RefreshPrefixes { prefixes, own_addresses } => {
            let r = refresh(b, &prefixes, own_addresses);
            let _ = tx.send((id, r, None)).await;
        }
    }
}

/// Replaces the connected prefixes and own addresses. Every prefix must be valid with no host
/// bits set beyond its length; otherwise nothing changes.
fn refresh(b: &Broker, prefixes: &[zkminer_witness::ipc::IpPrefix], own: Vec<std::net::IpAddr>) -> ControlResponse {
    let mut parsed: Vec<Prefix> = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        if !p.is_valid() {
            return error(ControlErrorCode::Malformed);
        }
        // Normalize through the config parser (host bits are cleared, not refused, here: an
        // interface prefix names its address).
        let net = crate::config::mask(p.addr, p.len);
        match parse_cidr(&format!("{net}/{}", p.len)) {
            Ok(prefix) => parsed.push(prefix),
            Err(_) => return error(ControlErrorCode::Malformed),
        }
    }
    let count = u32::try_from(parsed.len()).unwrap_or(u32::MAX);
    b.policy.write().unwrap_or_else(|p| p.into_inner()).connected = parsed;
    *b.own_addresses.write().unwrap_or_else(|p| p.into_inner()) = own;
    tracing::info!(count, "connected prefixes refreshed");
    ControlResponse::PrefixesRefreshed { count }
}

/// The charge hook of one `FetchArtifact`: sends `ArtifactCharge` (same id) and waits for the
/// miner's `ChargeDecision` (refused on timeout or a closed channel).
fn charge_hook(id: u64, tx: mpsc::Sender<Reply>, decisions: Decisions, wait: std::time::Duration) -> ChargeFn {
    Box::new(move |length, chunks| {
        let (tx, decisions) = (tx.clone(), decisions.clone());
        Box::pin(async move {
            let (dtx, mut drx) = mpsc::unbounded_channel();
            decisions.lock().unwrap_or_else(|p| p.into_inner()).insert(id, dtx);
            let proceed = if tx.send((id, ControlResponse::ArtifactCharge { length, chunks }, None)).await.is_ok() {
                matches!(tokio::time::timeout(wait, drx.recv()).await, Ok(Some(true)))
            } else {
                false
            };
            decisions.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
            proceed
        })
    })
}
