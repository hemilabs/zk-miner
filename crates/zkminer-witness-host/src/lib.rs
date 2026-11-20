//! The miner side of witness-construction jobs (docs/witness-construction-jobs.md §5.2, §10, §15):
//! a long-lived spawner thread for sandboxed children, the broker process, the retention store, the
//! builder run and the pre-claim pipeline. `zkminer-cli` drives these; nothing here signs or sends.

pub mod abort;
pub mod adversarial;
pub mod broker_proc;
pub mod builder_run;
pub mod paths;
pub mod pipeline;
pub mod spawner;
pub mod store_open;
