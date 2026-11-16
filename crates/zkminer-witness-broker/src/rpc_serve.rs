//! `evm-rpc/v1` serving (plan §11.2, §11.4).
//!
//! 1. Parse under the capability's method set; any refusal is status 1.
//! 2. Charge one unit per call (status 3 past `maxFetches`).
//! 3. Take the in-flight byte permit for the raw answer (`2·maxResponseBytes + 64 KiB`, clamped to
//!    the permit granted); it is held until the result is written.
//! 4. Resolve symbolic tags by asking an endpoint, once per fetch: every call of the fetch sees the
//!    same numbers. A request that names an explicit block number also resolves `latest`; a
//!    number above the head (the highest `latest` of at most [`MAX_LAGGING_ATTEMPTS`] endpoints)
//!    is refused, status 1, with no failover. A refusal after resolution costs the one unit of a
//!    refused request, not one per call.
//! 5. Answer calls pinned to a block hash from the cache, charging the operator budget for them as
//!    if they missed (status 2 when no endpoint can spend them, as for a miss). Send the rest (a
//!    subset with the broker's own ids) through the endpoints in order:
//!    - transport errors, connect timeouts, non-2xx (429 included), malformed or mismatched
//!      answers and spent operator budgets move to the next endpoint and make a final status 2 the
//!      operator's ([`Failure::Operator`]);
//!    - a lagging answer (the lagging heuristics, `null` where an answer must exist, or a suspect
//!      error on a pinned call that the endpoint's head or `eth_getBlockByHash` shows it lacks)
//!      moves on too, but at most [`MAX_LAGGING_ATTEMPTS`] endpoints are asked per request: if they
//!      all lag the fetch is status 2 [`Failure::Unanswerable`] (a builder can ask for an unknown
//!      hash on demand; that must not buy a blameless retry or cost every endpoint);
//!    - a timeout once the request was sent is the request's own ([`Failure::Own`]).
//!
//!    Every attempt, tag queries and head checks included, is charged to that endpoint's operator
//!    budget. Execution errors are answers. Errors are never cached.
//! 6. Render, and charge the bytes delivered (status 3 past `maxResponseBytes` or `maxFetchBytes`).

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::B256;
use zkminer_witness::envelope::MethodSet;
use zkminer_witness::ipc::FetchStatus;

use crate::broker::Broker;
use crate::cache::RpcKey;
use crate::evm_rpc::{BlockPin, BlockTag, CallAnswer, ResponseError};
use crate::hooks::RpcReq;
use crate::job::{Failure, Job, Outcome};
use crate::jsonrpc::RpcClient;
use crate::lanes::permit_bytes;
use crate::net::{Endpoint, EndpointError};

/// Response cap for a tag query (a block without transaction bodies).
const TAG_RESPONSE_CAP: u64 = 4 << 20;
/// The most endpoints one builder request may be sent to while they answer that they lack the
/// block or state (review F2: bounds what an unanswerable request costs the operator).
pub(crate) const MAX_LAGGING_ATTEMPTS: usize = 2;
/// The most distinct block hashes one answer's suspect errors are checked for.
const MAX_HASH_PROBES: usize = 4;

/// What an answer from one endpoint means.
pub(crate) enum Attempt<T> {
    Done(T),
    /// Done, unless the endpoint lacks one of these blocks (then lagging).
    Check(T, Vec<BlockPin>),
    /// The node lags or lacks the state: try the next endpoint, within the lagging cap.
    Lagging,
    /// Unusable from this endpoint (malformed, mismatched): the operator's side.
    Bad(&'static str),
    /// Final for the fetch.
    Stop(FetchStatus),
}

/// Who a raw body over its cap is attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TooLarge {
    /// The job's own limit: status 3.
    Job,
    /// The operator's (a cap the operator set, or a lane narrower than the job's limit).
    Operator,
}

/// Sends `body` to the endpoints in order until `accept` takes an answer; returns it and the index
/// of the endpoint that gave it. `units` are charged to each attempted endpoint's operator budget.
/// See the module doc for the failover rules and how a failure is classified.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn failover<T>(
    b: &Broker,
    job: &Job,
    endpoints: &[Arc<Endpoint>],
    body: &[u8],
    units: u64,
    cap: u64,
    too_large: TooLarge,
    mut accept: impl FnMut(&[u8]) -> Attempt<T>,
) -> Result<(T, usize), Outcome> {
    let (mut lagging, mut operator, mut own) = (0usize, false, false);
    let fault = |what: &str, ep: &Endpoint| {
        job.note_operator_fault();
        tracing::warn!(job = %job.tag(), endpoint = %ep.alias(), "{what}");
    };
    for (i, ep) in endpoints.iter().enumerate() {
        if lagging >= MAX_LAGGING_ATTEMPTS {
            break;
        }
        if !ep.try_spend(units, job.held_lock) {
            operator = true;
            fault("operator budget spent; skipping endpoint", ep);
            continue;
        }
        tracing::debug!(job = %job.tag(), endpoint = %ep.alias(), "evm-rpc request");
        match ep.post_json(job.held_lock, body.to_vec(), cap, &job.wait).await {
            Ok(bytes) => match accept(&bytes) {
                Attempt::Done(t) => return Ok((t, i)),
                Attempt::Check(t, pins) => match lacks_a_block(b, job, ep, &pins).await {
                    Ok(false) => return Ok((t, i)),
                    Ok(true) => {
                        lagging += 1;
                        tracing::info!(job = %job.tag(), endpoint = %ep.alias(), "the node lacks a block the request is pinned to");
                    }
                    Err(e) => {
                        operator = true;
                        fault(&format!("checking the node's head failed: {}", ep.redact(&e.to_string())), ep);
                    }
                },
                Attempt::Lagging => {
                    lagging += 1;
                    tracing::info!(job = %job.tag(), endpoint = %ep.alias(), "the node lags or lacks the state");
                }
                Attempt::Bad(why) => {
                    operator = true;
                    fault(&format!("unusable answer: {why}"), ep);
                }
                Attempt::Stop(s) => return Err(Outcome::status(s)),
            },
            Err(EndpointError::TooLarge) if too_large == TooLarge::Job => return Err(Outcome::status(FetchStatus::Exhausted)),
            // For a JSON-RPC endpoint every non-2xx is the operator's (a 404 is a wrong URL).
            Err(e) if e.operator_side() || matches!(e, EndpointError::Status(_) | EndpointError::TooLarge) => {
                operator = true;
                job.note_operator_fault();
                ep.log_failure("evm-rpc request failed", &e);
            }
            Err(e) => {
                own = true;
                ep.log_failure("evm-rpc request failed", &e);
            }
        }
    }
    let failure = if operator {
        Failure::Operator
    } else if lagging > 0 && !own {
        Failure::Unanswerable
    } else {
        Failure::Own
    };
    Err(Outcome::failed(failure))
}

/// Asks `ep` whether it lacks any block in `pins`: its head against the highest number, and
/// `eth_getBlockByHash` for (at most [`MAX_HASH_PROBES`]) hashes. Each probe is charged one unit
/// of the endpoint's operator budget.
async fn lacks_a_block(b: &Broker, job: &Job, ep: &Endpoint, pins: &[BlockPin]) -> Result<bool, crate::jsonrpc::RpcError> {
    let rpc = RpcClient { ep, held: job.held_lock, ids: &b.ids, wait: &job.wait };
    let spend = || {
        if ep.try_spend(1, job.held_lock) {
            Ok(())
        } else {
            Err(crate::jsonrpc::RpcError::Endpoint(EndpointError::Local("operator budget spent".into())))
        }
    };
    if let Some(n) = pins.iter().filter_map(|p| if let BlockPin::Number(n) = p { Some(*n) } else { None }).max() {
        spend()?;
        if rpc.block_number().await? < n {
            return Ok(true);
        }
    }
    let mut hashes: Vec<B256> = Vec::new();
    for p in pins {
        if let BlockPin::Hash(h) = p {
            let h = B256::from(*h);
            if !hashes.contains(&h) && hashes.len() < MAX_HASH_PROBES {
                hashes.push(h);
            }
        }
    }
    for h in hashes {
        spend()?;
        if rpc.block_by_hash(h).await?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn response_attempt<T>(e: ResponseError) -> Attempt<T> {
    match e {
        ResponseError::TooLarge => Attempt::Stop(FetchStatus::Exhausted),
        ResponseError::Lagging => Attempt::Lagging,
        ResponseError::Malformed => Attempt::Bad("malformed body"),
        ResponseError::Mismatch => Attempt::Bad("ids or count do not match"),
    }
}

/// `latest` from `ep` alone (for the explicit-number check).
async fn latest_of(b: &Broker, job: &Job, ep: &Arc<Endpoint>) -> Option<u64> {
    let codec = &b.hooks.codec;
    let id = b.next_ids(1);
    let body = codec.tag_query(BlockTag::Latest, id);
    failover(b, job, std::slice::from_ref(ep), &body, 1, TAG_RESPONSE_CAP, TooLarge::Operator, |bytes| {
        match codec.parse_tag_answer(bytes, id) {
            Ok(n) => Attempt::Done(n),
            Err(_) => Attempt::Bad("tag answer"),
        }
    })
    .await
    .ok()
    .map(|(n, _)| n)
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
    let units = u32::try_from(n).unwrap_or(u32::MAX);
    if !job.try_charge_units(units) {
        return Outcome::status(FetchStatus::Exhausted);
    }
    // A refusal once the tags are known costs what any refused request costs: one unit.
    let refuse = || {
        job.refund_units(units);
        job.charge_refused();
        Outcome::status(FetchStatus::Denied)
    };
    let max_response = job.budget.max_response_bytes as usize;
    // The raw body may be larger than its canonical form (whitespace, error messages).
    let raw_want = 2 * job.budget.max_response_bytes as u64 + (64 << 10);
    let permit = job.wait.during(b.bytes.acquire(job.held_lock, raw_want)).await;
    let raw_cap = raw_want.min(permit_bytes(&permit));
    let too_large = if raw_cap < raw_want { TooLarge::Operator } else { TooLarge::Job };

    // Tags, fixed for this fetch (and `latest` for a request with an explicit number).
    let highest = req.max_block_number();
    let mut wanted = req.tags();
    if highest.is_some() && !wanted.contains(&BlockTag::Latest) {
        wanted.push(BlockTag::Latest);
    }
    let mut tags: BTreeMap<BlockTag, u64> = BTreeMap::new();
    let mut latest_from = 0;
    for tag in wanted {
        let id = b.next_ids(1);
        let body = codec.tag_query(tag, id);
        let got = failover(b, job, endpoints, &body, 1, TAG_RESPONSE_CAP, TooLarge::Operator, |bytes| {
            match codec.parse_tag_answer(bytes, id) {
                Ok(n) => Attempt::Done(n),
                Err(ResponseError::Lagging) => Attempt::Lagging,
                Err(_) => Attempt::Bad("tag answer"),
            }
        })
        .await;
        match got {
            Ok((v, i)) => {
                if tag == BlockTag::Latest {
                    latest_from = i;
                }
                tags.insert(tag, v);
            }
            Err(o) => return o,
        }
    }
    if let Some(n) = highest {
        let mut head = tags[&BlockTag::Latest];
        // The first answer may come from a node behind the others: ask one more before refusing.
        if n > head {
            for (i, ep) in endpoints.iter().enumerate().filter(|(i, _)| *i != latest_from).take(MAX_LAGGING_ATTEMPTS - 1) {
                if let Some(h) = latest_of(b, job, ep).await {
                    tracing::debug!(job = %job.tag(), endpoint = i, head = h, "second head for an explicit block number");
                    head = head.max(h);
                }
            }
        }
        if n > head {
            tracing::debug!(job = %job.tag(), number = n, head, "evm-rpc request names a block above the head");
            return refuse();
        }
    }
    let resolve = |t: BlockTag| tags.get(&t).copied().expect("every tag of the request was resolved");
    if let Err(d) = req.check_after_resolution(&resolve) {
        tracing::debug!(job = %job.tag(), reason = %d, "evm-rpc request refused after tag resolution");
        return refuse();
    }

    // Cache hits (calls pinned to a block hash only), charged to an operator budget as misses.
    // Per requester (trust domain): another requester's answers are never served from the cache.
    let keys: Vec<Option<RpcKey>> =
        (0..n).map(|i| req.cache_key(i).map(|call| RpcKey { caller: job.caller, chain_id, call })).collect();
    let mut answers: Vec<Option<CallAnswer>> = vec![None; n];
    {
        let mut cache = b.rpc_cache.lock().unwrap_or_else(|p| p.into_inner());
        for (i, k) in keys.iter().enumerate() {
            if let Some(v) = k.as_ref().and_then(|k| cache.get(k)) {
                answers[i] = Some(CallAnswer { canonical: v.clone(), is_error: false, suspect: false });
            }
        }
    }
    let hits = answers.iter().filter(|a| a.is_some()).count() as u64;
    if hits > 0 && !endpoints.iter().any(|ep| ep.try_spend(hits, job.held_lock)) {
        tracing::info!(job = %job.tag(), "operator budgets spent (cached answers are charged as misses)");
        return Outcome::failed(Failure::Operator);
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
        let got = failover(b, job, endpoints, &body, misses.len() as u64, raw_cap, too_large, |bytes| {
            match sub.parse_answers(bytes, first_id, max_response) {
                Ok(a) if a.len() == misses.len() => {
                    let pins: Vec<BlockPin> =
                        a.iter().enumerate().filter(|(_, x)| x.suspect).filter_map(|(i, _)| sub.pin(i, &resolve)).collect();
                    if pins.is_empty() {
                        Attempt::Done(a)
                    } else {
                        Attempt::Check(a, pins)
                    }
                }
                Ok(_) => Attempt::Bad("answer count does not match"),
                Err(e) => response_attempt(e),
            }
        })
        .await;
        let got = match got {
            Ok((a, _)) => a,
            Err(o) => return o,
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
    Outcome::bytes(rendered, permit)
}
