//! `blob/v1` serving (plan §11.3): the request is exactly the 32-byte sha256 of the content. The
//! broker builds each mirror's URL from its template (builders never supply paths), spools the body
//! to a quota'd file while hashing it, and returns the bytes only when the hash matches.
//!
//! The cap is `min(config maxBytes, maxResponseBytes, the job's remaining maxFetchBytes)`. A
//! mismatched, failed or missing body counts against that mirror and the next is tried. When no
//! mirror delivers: status 3 if some mirror's body exceeded the cap (the content is larger than the
//! job allows), else status 2.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zkminer_witness::ipc::FetchStatus;

use crate::broker::Broker;
use crate::job::{Job, Outcome};
use crate::net::EndpointError;

pub(crate) async fn serve(b: &Arc<Broker>, job: &Arc<Job>, max_bytes: u64, request: &[u8]) -> Outcome {
    let Ok(want) = <[u8; 32]>::try_from(request) else {
        job.charge_refused();
        return Outcome::status(FetchStatus::Denied);
    };
    if !job.try_charge_units(1) {
        return Outcome::status(FetchStatus::Exhausted);
    }
    let cap = max_bytes.min(u64::from(job.budget.max_response_bytes)).min(job.bytes_left());
    let _bytes = b.bytes.acquire(job.held_lock, cap).await;
    let id = hex::encode(want);
    let mut oversize = false;
    for mirror in &b.blob_mirrors {
        let url = mirror.spec.url_with(&[("sha256", &id)]);
        let mut spool = match b.spool.create() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(job = %job.tag(), error = %b.hooks.egress.redact(&e.to_string()), "cannot create a spool file");
                continue;
            }
        };
        let mut hasher = Sha256::new();
        tracing::debug!(job = %job.tag(), endpoint = %mirror.alias(), "blob request");
        let r = mirror
            .get_into(&url, job.held_lock, cap, &mut |chunk| {
                hasher.update(chunk);
                spool.write(chunk)
            })
            .await;
        match r {
            Ok(len) => {
                if hasher.finalize()[..] == want[..] {
                    if !job.try_charge_bytes(len) {
                        return Outcome::status(FetchStatus::Exhausted);
                    }
                    return Outcome::spool(spool);
                }
                tracing::warn!(job = %job.tag(), endpoint = %mirror.alias(), "blob body does not hash to the requested id");
            }
            Err(EndpointError::TooLarge) => {
                oversize = true;
                tracing::info!(job = %job.tag(), endpoint = %mirror.alias(), cap, "blob body larger than the job allows");
            }
            Err(e) => mirror.log_failure("blob request failed", &e),
        }
    }
    Outcome::status(if oversize { FetchStatus::Exhausted } else { FetchStatus::Failed })
}
