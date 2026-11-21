//! Witness-construction jobs need the Linux sandbox and retention store: elsewhere no runtime is
//! built ([`WitnessRuntime::start`] pages and returns `None`), so none of the other methods is ever
//! reached. They exist so that run.rs compiles unchanged.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::B256;
use tokio::sync::mpsc;
use zkminer_chain::client::ChainClient;
use zkminer_config::ZkMinerConfig;

use super::Route;

pub(crate) struct WitnessRuntime {
    _private: (),
}

/// See the Linux runtime's `ReleaseClaim`: elsewhere no lock is a witness lock.
pub(crate) enum ReleaseClaim {
    #[allow(dead_code)]
    Owned,
    NotWitness,
    #[allow(dead_code)]
    Witness(WitnessRelease),
}

pub(crate) struct WitnessRelease;

impl WitnessRelease {
    pub(crate) async fn record_verdict(&self, _why: &str) {}
}

impl WitnessRuntime {
    pub(crate) async fn start(
        config: &ZkMinerConfig,
        _config_path: Option<&Path>,
        _client: &ChainClient,
        _state: &zkminer_tui::state::SharedState,
        _journal: &super::super::SharedJournal,
        _proving_timeout: Duration,
    ) -> Option<Arc<Self>> {
        if config.witness.enabled {
            tracing::error!(
                "PAGE: WITNESS-DISABLED witness-construction jobs are served on Linux only (the \
                 sandbox and the retention store need it); inline jobs are unaffected"
            );
        }
        None
    }

    pub(crate) fn attach_brain(&self, _held: mpsc::UnboundedSender<(B256, u128, u64)>, _done: mpsc::UnboundedSender<B256>) {}

    pub(crate) fn route(
        self: &Arc<Self>,
        _job: &zkminer_tui::state::TrackedJob,
        _descriptor_hash: B256,
        _claim_predicate_jobs: bool,
    ) -> Route {
        Route::Inline
    }

    pub(crate) fn owned_jobs(&self) -> HashSet<B256> {
        HashSet::new()
    }

    pub(crate) fn is_witness_lock(&self, _job_id: B256) -> bool {
        false
    }

    pub(crate) fn drive_recovered(self: &Arc<Self>, _job_id: B256) -> bool {
        false
    }

    pub(crate) fn shutdown(&self) {}

    pub(crate) fn owns(&self, _job_id: B256) -> bool {
        false
    }

    pub(crate) fn note_cards(&self, _inline_needing: usize, _max_concurrent: usize, _busy: Vec<String>) {}

    pub(crate) fn note_recovery_pass(&self, _scan_complete: bool, _undecided: Vec<B256>) {}

    pub(crate) fn claim_release(self: &Arc<Self>, _job_id: B256) -> ReleaseClaim {
        ReleaseClaim::NotWitness
    }

    pub(crate) async fn note_release(&self, _job_id: B256, _why: &str) {}
}
