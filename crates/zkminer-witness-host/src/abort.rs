//! The abort token of one simulation (plan §5.2): the chain watchers fire it on `JobCancelled`,
//! `JobClaimed` by another prover or `BidSubmitted`, and on governance events that end the attempt;
//! the pipeline checks it between steps and kills its in-flight sandboxes when it fires.
//!
//! The first reason wins. It can be read without blocking (the builder's waiter thread polls it) and
//! awaited (the pipeline races it against each step).

use std::sync::Arc;

use tokio::sync::watch;

/// Why a simulation was abandoned. None of these judges the job: an aborted attempt records no
/// verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbortReason {
    /// `JobCancelled`.
    JobCancelled,
    /// `JobClaimed` by another prover.
    JobClaimed,
    /// `BidSubmitted`: the job moved into a bid round.
    BidSubmitted,
    /// A pause, an adapter disable, a verifier swap or an upgrade that ends the attempt.
    Governance,
    /// The miner is shutting down.
    Shutdown,
}

/// A shared, fire-once abort signal. Cloning shares it.
#[derive(Debug, Clone)]
pub struct AbortToken {
    tx: Arc<watch::Sender<Option<AbortReason>>>,
}

impl Default for AbortToken {
    fn default() -> Self {
        Self::new()
    }
}

impl AbortToken {
    pub fn new() -> Self {
        Self { tx: Arc::new(watch::channel(None).0) }
    }

    /// Fires the token with `reason`; returns whether this call fired it (the first reason wins).
    pub fn abort(&self, reason: AbortReason) -> bool {
        self.tx.send_if_modified(|cur| {
            if cur.is_some() {
                return false;
            }
            *cur = Some(reason);
            true
        })
    }

    /// The reason it fired with, if it has.
    pub fn reason(&self) -> Option<AbortReason> {
        *self.tx.borrow()
    }

    pub fn is_aborted(&self) -> bool {
        self.reason().is_some()
    }

    /// Resolves once the token fires (at once if it has).
    pub async fn aborted(&self) -> AbortReason {
        let mut rx = self.tx.subscribe();
        let fired = rx.wait_for(Option::is_some).await.map(|r| r.expect("waited for Some"));
        match fired {
            Ok(reason) => reason,
            // The sender lives in `self`, so it cannot be dropped while this runs.
            Err(_) => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fires_once_and_wakes_waiters() {
        let t = AbortToken::new();
        assert!(!t.is_aborted());
        let waiter = tokio::spawn({
            let t = t.clone();
            async move { t.aborted().await }
        });
        tokio::task::yield_now().await;
        assert!(t.abort(AbortReason::JobClaimed));
        assert!(!t.abort(AbortReason::JobCancelled), "the first reason wins");
        assert_eq!(waiter.await.unwrap(), AbortReason::JobClaimed);
        assert_eq!(t.reason(), Some(AbortReason::JobClaimed));
        // Already fired: resolves at once.
        assert_eq!(t.aborted().await, AbortReason::JobClaimed);
    }
}
