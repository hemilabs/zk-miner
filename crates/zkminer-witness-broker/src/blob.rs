//! `blob/v1` serving (plan §11.3): the request is exactly the 32-byte sha256 of the content. The
//! broker builds each mirror's URL from its template (builders never supply paths), spools the body
//! to a quota'd file while hashing it (the writes run on the blocking pool), and returns the bytes
//! only when the hash matches.
//!
//! The cap is `min(config maxBytes, maxResponseBytes, the job's remaining maxFetchBytes)`, then
//! clamped to the in-flight byte permit granted, which is held until the result is written. A
//! mismatched, failed or missing body counts against that mirror and the next is tried. When no
//! mirror delivers:
//! - status 3 if some mirror's body exceeded the job's cap (the content is larger than the job
//!   allows); status 2 [`Failure::Operator`] if it exceeded only a permit narrower than that cap;
//! - status 2 [`Failure::Operator`] if a mirror failed on the operator's side (transport, a
//!   non-2xx other than 404/410, a body that does not hash to the id, the spool quota);
//! - status 2 [`Failure::Unanswerable`] if every mirror answered 404 or 410 (a builder can name a
//!   hash nobody has on demand);
//! - status 2 [`Failure::Own`] otherwise (a timeout once the request was sent).

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zkminer_witness::ipc::FetchStatus;

use crate::broker::Broker;
use crate::job::{Failure, Job, Outcome};
use crate::lanes::permit_bytes;
use crate::net::EndpointError;
use crate::spool::SpoolFile;

/// Body bytes gathered before one spool write.
const SPOOL_WRITE_CHUNK: usize = 256 << 10;

enum MirrorFail {
    Missing,
    TooLarge,
    Operator,
    Own,
}

pub(crate) async fn serve(b: &Arc<Broker>, job: &Arc<Job>, max_bytes: u64, request: &[u8]) -> Outcome {
    let Ok(want) = <[u8; 32]>::try_from(request) else {
        job.charge_refused();
        return Outcome::status(FetchStatus::Denied);
    };
    if !job.try_charge_units(1) {
        return Outcome::status(FetchStatus::Exhausted);
    }
    let job_cap = max_bytes.min(u64::from(job.budget.max_response_bytes)).min(job.bytes_left());
    let permit = job.wait.during(b.bytes.acquire(job.held_lock, job_cap)).await;
    let cap = job_cap.min(permit_bytes(&permit));
    let id = hex::encode(want);
    let (mut missing, mut oversize, mut operator, mut own) = (0usize, false, false, false);
    for mirror in &b.blob_mirrors {
        let url = mirror.spec.url_with(&[("sha256", &id)]);
        let mut spool = match b.spool.create_async(job.held_lock).await {
            Ok(s) => s,
            Err(e) => {
                operator = true;
                job.note_operator_fault();
                tracing::warn!(job = %job.tag(), error = %b.hooks.egress.redact(&e.to_string()), "cannot create a spool file");
                continue;
            }
        };
        tracing::debug!(job = %job.tag(), endpoint = %mirror.alias(), "blob request");
        match fetch_into(mirror, &url, job, cap, &want, &mut spool).await {
            Ok(len) => {
                if !job.try_charge_bytes(len) {
                    return Outcome::status(FetchStatus::Exhausted);
                }
                return Outcome::spool(spool, permit);
            }
            Err(MirrorFail::Missing) => missing += 1,
            Err(MirrorFail::TooLarge) => {
                oversize = true;
                tracing::info!(job = %job.tag(), endpoint = %mirror.alias(), cap, "blob body larger than the cap");
            }
            Err(MirrorFail::Operator) => {
                operator = true;
                job.note_operator_fault();
            }
            Err(MirrorFail::Own) => own = true,
        }
    }
    if oversize && cap == job_cap {
        return Outcome::status(FetchStatus::Exhausted);
    }
    Outcome::failed(if operator || oversize {
        Failure::Operator
    } else if missing > 0 && !own {
        Failure::Unanswerable
    } else {
        Failure::Own
    })
}

/// Streams one mirror's body into `spool`, hashing it; the body's length when it hashes to `want`.
async fn fetch_into(
    mirror: &crate::net::Endpoint,
    url: &str,
    job: &Job,
    cap: u64,
    want: &[u8; 32],
    spool: &mut SpoolFile,
) -> Result<u64, MirrorFail> {
    let classify = |e: EndpointError| match e {
        EndpointError::Status(404 | 410) => MirrorFail::Missing,
        EndpointError::TooLarge => MirrorFail::TooLarge,
        e => {
            mirror.log_failure("blob request failed", &e);
            if e.operator_side() {
                MirrorFail::Operator
            } else {
                MirrorFail::Own
            }
        }
    };
    let mut body = mirror.get(url, job.held_lock, cap, &job.wait).await.map_err(classify)?;
    let mut hasher = Sha256::new();
    let mut buf = Vec::with_capacity(SPOOL_WRITE_CHUNK);
    let spool_err = |e: std::io::Error| {
        tracing::warn!(job = %job.tag(), endpoint = %mirror.alias(), error = %e, "spooling the blob failed");
        MirrorFail::Operator
    };
    loop {
        let before = buf.len();
        let more = body.next_into(&mut buf).await.map_err(classify)?;
        hasher.update(&buf[before..]);
        if !more || buf.len() >= SPOOL_WRITE_CHUNK {
            spool.append(std::mem::replace(&mut buf, Vec::with_capacity(SPOOL_WRITE_CHUNK))).await.map_err(spool_err)?;
        }
        if !more {
            break;
        }
    }
    if hasher.finalize()[..] != want[..] {
        tracing::warn!(job = %job.tag(), endpoint = %mirror.alias(), "blob body does not hash to the requested id");
        return Err(MirrorFail::Operator);
    }
    Ok(body.total())
}
