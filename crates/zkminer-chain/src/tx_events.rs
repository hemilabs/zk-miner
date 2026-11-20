//! What a job's on-chain transaction is doing, for whoever shows the job's status.
//!
//! `claim_job`, `fulfill_job` and `release_job` retry on their own: a transaction that is not
//! confirmed in time is checked against the chain and sent again, and a send the RPC refuses is
//! tried again after a pause. That can take minutes on a slow or rate-limited endpoint, and the
//! caller only learns of it when the call returns. These events say, as it happens, which attempt
//! is out and whether it is waiting for its receipt, so a dashboard can show "waiting for the
//! testnet to confirm" rather than an older stage of the job.
//!
//! One process-wide observer (`set_tx_observer`), as the miner shows one set of jobs; without one,
//! events go nowhere.

use alloy::primitives::B256;
use std::sync::OnceLock;

/// Which of a job's transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    Claim,
    Fulfil,
    Release,
}

/// What happened to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxEvent {
    /// Attempt `attempt` of `of` was sent; its receipt is awaited.
    Sent { attempt: u32, of: u32 },
    /// Attempt `attempt` was not confirmed in time; the chain is read before sending again.
    Unconfirmed { attempt: u32, of: u32 },
    /// Attempt `attempt` could not be sent (`rate_limited`: the RPC refused for load); tried again
    /// after a pause.
    SendFailed {
        attempt: u32,
        of: u32,
        rate_limited: bool,
    },
}

type Observer = Box<dyn Fn(B256, TxKind, TxEvent) + Send + Sync>;

static OBSERVER: OnceLock<Observer> = OnceLock::new();

/// Register the observer of every job transaction's events. The first registration stands; a
/// later one is ignored (and reported as `false`).
pub fn set_tx_observer(observer: impl Fn(B256, TxKind, TxEvent) + Send + Sync + 'static) -> bool {
    OBSERVER.set(Box::new(observer)).is_ok()
}

/// Report an event to the observer, if there is one.
pub(crate) fn emit(job_id: B256, kind: TxKind, event: TxEvent) {
    if let Some(observer) = OBSERVER.get() {
        observer(job_id, kind, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Events reach the one observer registered; a second registration is refused.
    #[test]
    fn events_reach_the_registered_observer() {
        use std::sync::{Arc, Mutex};
        let seen: Arc<Mutex<Vec<(B256, TxKind, TxEvent)>>> = Arc::default();
        let sink = seen.clone();
        assert!(set_tx_observer(move |job, kind, event| {
            sink.lock().unwrap().push((job, kind, event))
        }));
        assert!(!set_tx_observer(|_, _, _| {}));
        let job = B256::repeat_byte(7);
        emit(job, TxKind::Claim, TxEvent::Sent { attempt: 1, of: 5 });
        emit(job, TxKind::Fulfil, TxEvent::Unconfirmed { attempt: 2, of: 5 });
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                (job, TxKind::Claim, TxEvent::Sent { attempt: 1, of: 5 }),
                (job, TxKind::Fulfil, TxEvent::Unconfirmed { attempt: 2, of: 5 }),
            ]
        );
    }
}
