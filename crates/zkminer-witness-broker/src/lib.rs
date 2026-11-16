//! The witness-job fetch broker (plan §11, §13.3–13.4, §14): typed `evm-rpc/v1` and `blob/v1`
//! capabilities served to builders over per-job sockets, and `hemi-code` artifact reads.
//!
//! The process: `main` reads the config and key files and the host facts, applies the sandbox, then
//! runs [`serve`] on the control socket at fd 3. The miner drives it with [`client::BrokerClient`].

pub mod artifact;
pub mod blob;
pub(crate) mod broker;
pub mod cache;
pub mod client;
pub mod config;
pub(crate) mod control;
pub mod egress;
pub mod evm_rpc;
pub mod fdpass;
pub mod hooks;
pub mod hostinfo;
pub(crate) mod job;
pub mod jsonrpc;
pub mod lanes;
pub mod net;
pub(crate) mod rpc_serve;
pub(crate) mod selftest;
pub mod spool;
#[doc(hidden)]
pub mod testkit;

use std::os::fd::{AsFd, OwnedFd};

pub use client::BrokerClient;
pub use config::{BrokerConfig, HostFacts};
pub use hooks::Hooks;

/// The tokio worker threads `main` runs with.
pub const WORKER_THREADS: usize = 4;
/// The most blocking-pool threads (DNS lookups, artifact cache copies, spool reads).
pub const MAX_BLOCKING_THREADS: usize = 8;

/// Serves the control channel `control` (a connected `AF_UNIX` stream socket) until the miner
/// closes it. Uses `config.host` when present (read before the sandbox) and reads the host facts
/// itself otherwise.
pub async fn serve(config: BrokerConfig, control: OwnedFd) -> anyhow::Result<()> {
    serve_with(config, control, Hooks::real()).await
}

/// [`serve`] with explicit seams (tests).
pub async fn serve_with(mut config: BrokerConfig, control: OwnedFd, hooks: Hooks) -> anyhow::Result<()> {
    if !fdpass::is_unix_stream(control.as_fd()) {
        anyhow::bail!("the control fd is not a Unix stream socket");
    }
    let host = match config.host.take() {
        Some(h) => h,
        None => {
            let (c, e) = (config.clone(), hooks.egress.clone());
            tokio::task::spawn_blocking(move || HostFacts::gather(&c, &*e)).await??
        }
    };
    let broker = broker::Broker::new(config, host, hooks)?;
    if let Some(ep) = broker.artifacts.endpoint().cloned() {
        let want = broker.artifacts.chain_id();
        tokio::spawn(async move {
            let ids = std::sync::atomic::AtomicU64::new(1);
            match (jsonrpc::RpcClient { ep: &ep, held: false, ids: &ids }).chain_id().await {
                Ok(got) if got == want => tracing::info!(endpoint = %ep.alias(), chain_id = got, "artifact endpoint chain id checked"),
                Ok(got) => tracing::error!(endpoint = %ep.alias(), got, want, "PAGE: ARTIFACT-ENDPOINT wrong chain id"),
                Err(e) => tracing::warn!(endpoint = %ep.alias(), error = %ep.redact(&e.to_string()), "artifact endpoint chain id check failed"),
            }
        });
    }
    fdpass::set_nonblocking(&control)?;
    let sock = tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(control))?;
    control::run(broker, sock).await
}
