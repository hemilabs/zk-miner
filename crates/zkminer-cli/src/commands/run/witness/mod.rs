//! Witness-construction jobs in the miner loop (docs/witness-construction-jobs.md §5, §15, §18).
//!
//! A job whose `inputData` starts with `WITNESS_JOB_TAG_V1` is a witness job. It never reaches the
//! inline path (the measure path, the inline caches, the inline claim and lifecycle): the brain
//! routes it here ([`route`]), and a witness job that slips through anyway is recognised where the
//! inline path first sees its descriptor (`measure_cycles`, the watch-only inspector, the
//! lifecycle's pre-claim gate, its recovery re-drive) and dropped there with [`note_class`].
//!
//! On Linux, [`WitnessRuntime`] (`runtime.rs`) serves them: it simulates each one in the sandbox
//! before any lock (`zkminer_witness_host::pipeline`), runs the claim gate, pins the bundle in the
//! retention store before the claim intent is journaled and before the lock is signed, locks it
//! exactly as the inline path claims, proves the bundle (execute, compare, prove), fulfils with
//! `fulfillJobHashed` under the DA rules, and deletes the bundle once the job is terminal. Recovery
//! re-drives witness locks from the store's pins, never from the chain's descriptor or the lock
//! journal. The pure decisions live in [`policy`].
//!
//! **The journal-prefix marker.** The inline path refuses jobs whose binding carries the prefix
//! marker `0xffffffff` (its guest input would have to be `abi.encode(jobId, prover) ‖ inputData`).
//! Witness jobs are routed away before those refusals, and the pipeline builds the guest input as
//! `prefix ‖ W` (`guest_input_prefix`), so for risc0 witness jobs the refusal is lifted; the SP1
//! proof-nonce marker `0xfffffffe` and every non-risc0 proof system stay refused (the pipeline's
//! static gates).
//!
//! Elsewhere than Linux the sandbox and the store do not exist: `[witness] enabled` is refused at
//! startup with a page, witness jobs are recognised and skipped, and no runtime is built.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use alloy::primitives::B256;

pub(super) mod policy;

#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
pub(super) use runtime::WitnessRuntime;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub(super) use stub::WitnessRuntime;

/// How the brain treats a candidate job this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Route {
    /// An inline job (or not known yet to be anything else): the inline path as before.
    Inline,
    /// A witness job (or one being classified): not the inline path's.
    Witness,
}

/// What a job's `inputData` says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    Inline,
    Witness,
}

/// Jobs classified so far, bounded (the oldest forgotten first: a forgotten job is classified again,
/// by one descriptor read, and a forgotten witness job is caught again where the inline path sees
/// its descriptor).
type ClassMemory = (HashMap<B256, Class>, VecDeque<B256>);
static CLASSES: Mutex<Option<ClassMemory>> = Mutex::new(None);
const CLASSES_CAP: usize = 65_536;

/// Records what `job_id`'s descriptor says it is.
pub(super) fn note_class(job_id: B256, class: Class) {
    let mut g = CLASSES.lock().unwrap_or_else(|e| e.into_inner());
    let (map, order) = g.get_or_insert_with(Default::default);
    if map.insert(job_id, class).is_none() {
        order.push_back(job_id);
        while order.len() > CLASSES_CAP {
            if let Some(old) = order.pop_front() {
                map.remove(&old);
            }
        }
    }
}

/// What `job_id` is known to be, if it was classified.
pub(super) fn known_class(job_id: B256) -> Option<Class> {
    CLASSES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|(m, _)| m.get(&job_id).copied())
}

/// The brain's routing of one candidate (§18 "Classify and route"). With a runtime, a known witness
/// job is offered to it, and an unknown job from an allowlisted caller is classified first (one
/// descriptor read) and held off the inline path meanwhile. Without one (witness serving off or not
/// available here), a known witness job is skipped, and everything else is inline: the inline path's
/// own descriptor read recognises a witness job and stops there.
pub(super) fn route(
    rt: Option<&std::sync::Arc<WitnessRuntime>>,
    job: &zkminer_tui::state::TrackedJob,
    descriptor_hash: B256,
    claim_predicate_jobs: bool,
) -> Route {
    match rt {
        Some(rt) => rt.route(job, descriptor_hash, claim_predicate_jobs),
        None => match known_class(job.info.job_id) {
            Some(Class::Witness) => Route::Witness,
            _ => Route::Inline,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_remembered_and_bounded() {
        let id = |i: u64| B256::from(alloy::primitives::U256::from(i));
        note_class(id(1), Class::Witness);
        note_class(id(2), Class::Inline);
        assert_eq!(known_class(id(1)), Some(Class::Witness));
        assert_eq!(known_class(id(2)), Some(Class::Inline));
        assert_eq!(known_class(id(3)), None);
        // A reclassification overwrites (the inline path's own read catching a witness job).
        note_class(id(2), Class::Witness);
        assert_eq!(known_class(id(2)), Some(Class::Witness));
        for i in 10..(10 + CLASSES_CAP as u64 + 5) {
            note_class(id(i), Class::Inline);
        }
        assert_eq!(known_class(id(1)), None, "the oldest are forgotten past the cap");
        assert_eq!(known_class(id(10 + CLASSES_CAP as u64 + 4)), Some(Class::Inline));
    }

    #[test]
    fn without_a_runtime_only_known_witness_jobs_leave_the_inline_path() {
        let job = |id: B256| zkminer_tui::state::TrackedJob {
            info: zkminer_chain::jobs::JobInfo { job_id: id, ..Default::default() },
            status: zkminer_tui::state::MinerJobStatus::Open,
            current_price: 0,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        };
        let (w, i) = (B256::repeat_byte(0xa1), B256::repeat_byte(0xa2));
        note_class(w, Class::Witness);
        assert_eq!(route(None, &job(w), B256::ZERO, true), Route::Witness);
        assert_eq!(route(None, &job(i), B256::ZERO, true), Route::Inline, "unknown: inline, which catches it");
    }
}
