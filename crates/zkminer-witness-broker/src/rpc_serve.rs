//! `evm-rpc/v1` serving (plan §11.2, §11.4).
//!
//! 1. Parse under the capability's method set; any refusal is status 1.
//! 2. Charge one unit per call (status 3 past `maxFetches`).
//! 3. Resolve symbolic tags by asking an endpoint, once per fetch: every call of the fetch sees the
//!    same numbers.
//! 4. Answer calls pinned to a block hash from the cache; send the rest (a subset with the broker's
//!    own ids) through the endpoints in order: transport errors, non-2xx (429 included), malformed
//!    or mismatched answers and lagging nodes move to the next endpoint, an endpoint whose operator
//!    budget is spent is skipped, and when none is left the fetch is status 2. Execution errors are
//!    answers. Errors are never cached.
//! 5. Render, and charge the bytes delivered (status 3 past `maxResponseBytes` or `maxFetchBytes`).

use std::collections::BTreeMap;
use std::sync::Arc;

use zkminer_witness::envelope::MethodSet;
use zkminer_witness::ipc::FetchStatus;

use crate::broker::Broker;
use crate::cache::RpcKey;
use crate::evm_rpc::{BlockTag, CallAnswer, ResponseError};
use crate::hooks::RpcReq;
use crate::job::{Job, Outcome};
use crate::net::{Endpoint, EndpointError};

/// Response cap for a tag query (a block without transaction bodies).
const TAG_RESPONSE_CAP: u64 = 4 << 20;

/// What an answer from one endpoint means.
pub(crate) enum Attempt<T> {
    Done(T),
    /// Unusable from this endpoint: try the next.
    Next(&'static str),
    /// Final for the fetch.
    Stop(FetchStatus),
}

/// Sends `body` to each endpoint in order until `accept` takes an answer. `units` are charged to
/// each attempted endpoint's operator budget; a raw body over `cap` is status 3 when
/// `too_large_is_job`, else an endpoint failure. All endpoints failing is status 2.
pub(crate) async fn failover<T>(
    job: &Job,
    endpoints: &[Arc<Endpoint>],
    body: &[u8],
    units: u64,
    cap: u64,
    too_large_is_job: bool,
    mut accept: impl FnMut(&[u8]) -> Attempt<T>,
) -> Result<T, FetchStatus> {
    for ep in endpoints {
        if !ep.try_spend(units) {
            tracing::info!(job = %job.tag(), endpoint = %ep.alias(), "operator budget spent; skipping endpoint");
            continue;
        }
        tracing::debug!(job = %job.tag(), endpoint = %ep.alias(), "evm-rpc request");
        match ep.post_json(job.held_lock, body.to_vec(), cap).await {
            Ok(bytes) => match accept(&bytes) {
                Attempt::Done(t) => return Ok(t),
                Attempt::Next(why) => {
                    tracing::warn!(job = %job.tag(), endpoint = %ep.alias(), "unusable answer: {why}");
                }
                Attempt::Stop(s) => return Err(s),
            },
            Err(EndpointError::TooLarge) if too_large_is_job => return Err(FetchStatus::Exhausted),
            Err(e) => ep.log_failure("evm-rpc request failed", &e),
        }
    }
    Err(FetchStatus::Failed)
}

fn response_attempt<T>(e: ResponseError) -> Attempt<T> {
    match e {
        ResponseError::TooLarge => Attempt::Stop(FetchStatus::Exhausted),
        ResponseError::Lagging => Attempt::Next("the node lags or lacks the state"),
        ResponseError::Malformed => Attempt::Next("malformed body"),
        ResponseError::Mismatch => Attempt::Next("ids or count do not match"),
    }
}

pub(crate) async fn serve(
    b: &Arc<Broker>,
    job: &Arc<Job>,
    chain_id: u64,
    method_set: MethodSet,
    endpoints: &[Arc<Endpoint>],
    request: &[u8],
) -> Outcome {
    let codec = &b.hooks.codec;
    let req = match codec.parse(request, method_set) {
        Ok(r) => r,
        Err(d) => {
            job.charge_refused();
            tracing::debug!(job = %job.tag(), reason = %d, "evm-rpc request refused");
            return Outcome::status(FetchStatus::Denied);
        }
    };
    let n = req.len();
    if !job.try_charge_units(u32::try_from(n).unwrap_or(u32::MAX)) {
        return Outcome::status(FetchStatus::Exhausted);
    }
    let max_response = job.budget.max_response_bytes as usize;
    // The raw body may be larger than its canonical form (whitespace, error messages).
    let raw_cap = 2 * job.budget.max_response_bytes as u64 + (64 << 10);
    let _bytes = b.bytes.acquire(job.held_lock, raw_cap).await;

    // Tags, fixed for this fetch.
    let mut tags: BTreeMap<BlockTag, u64> = BTreeMap::new();
    for tag in req.tags() {
        if tags.contains_key(&tag) {
            continue;
        }
        let id = b.next_ids(1);
        let body = codec.tag_query(tag, id);
        let number = failover(job, endpoints, &body, 1, TAG_RESPONSE_CAP, false, |bytes| {
            match codec.parse_tag_answer(bytes, id) {
                Ok(n) => Attempt::Done(n),
                Err(e) => match response_attempt::<u64>(e) {
                    Attempt::Stop(_) => Attempt::Next("tag answer too large"),
                    a => a,
                },
            }
        })
        .await;
        match number {
            Ok(v) => {
                tags.insert(tag, v);
            }
            Err(s) => return Outcome::status(s),
        }
    }
    let resolve = |t: BlockTag| tags.get(&t).copied().expect("every tag of the request was resolved");
    if let Err(d) = req.check_after_resolution(&resolve) {
        tracing::debug!(job = %job.tag(), reason = %d, "evm-rpc request refused after tag resolution");
        return Outcome::status(FetchStatus::Denied);
    }

    // Cache hits (calls pinned to a block hash only).
    let keys: Vec<Option<RpcKey>> = (0..n).map(|i| req.cache_key(i).map(|call| RpcKey { chain_id, call })).collect();
    let mut answers: Vec<Option<CallAnswer>> = vec![None; n];
    {
        let mut cache = b.rpc_cache.lock().unwrap_or_else(|p| p.into_inner());
        for (i, k) in keys.iter().enumerate() {
            if let Some(v) = k.as_ref().and_then(|k| cache.get(k)) {
                answers[i] = Some(CallAnswer { canonical: v.clone(), is_error: false });
            }
        }
    }
    let misses: Vec<usize> = (0..n).filter(|&i| answers[i].is_none()).collect();
    if !misses.is_empty() {
        let subset;
        let sub: &dyn RpcReq = if misses.len() == n {
            &*req
        } else {
            subset = req.subset(&misses);
            &*subset
        };
        let first_id = b.next_ids(misses.len() as u64);
        let body = sub.outgoing(&resolve, first_id);
        let got = failover(job, endpoints, &body, misses.len() as u64, raw_cap, true, |bytes| {
            match sub.parse_answers(bytes, first_id, max_response) {
                Ok(a) if a.len() == misses.len() => Attempt::Done(a),
                Ok(_) => Attempt::Next("answer count does not match"),
                Err(e) => response_attempt(e),
            }
        })
        .await;
        let got = match got {
            Ok(a) => a,
            Err(s) => return Outcome::status(s),
        };
        let mut cache = b.rpc_cache.lock().unwrap_or_else(|p| p.into_inner());
        for (answer, &i) in got.into_iter().zip(&misses) {
            if !answer.is_error {
                if let Some(k) = &keys[i] {
                    let size = (k.call.len() + answer.canonical.len()) as u64;
                    cache.insert(k.clone(), answer.canonical.clone(), size);
                }
            }
            answers[i] = Some(answer);
        }
    }
    let answers: Vec<CallAnswer> = answers.into_iter().map(|a| a.expect("every call answered")).collect();
    let rendered = req.render(&answers);
    if rendered.len() > max_response || !job.try_charge_bytes(rendered.len() as u64) {
        return Outcome::status(FetchStatus::Exhausted);
    }
    Outcome::bytes(rendered)
}
