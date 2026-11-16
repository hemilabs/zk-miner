//! The witness-job fetch broker (plan §11, §13.3–13.4, §14): typed `evm-rpc/v1` and `blob/v1`
//! capabilities served to builders over per-job sockets, and `hemi-code` artifact reads.

pub mod egress;
pub mod evm_rpc;
