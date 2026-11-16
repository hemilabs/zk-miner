//! The broker process (§10.1): one per host, spawned through the sandbox launcher into its own
//! cgroup with its control socket at fd 3. The miner talks to it with [`BrokerClient`].
//!
//! The broker runs in the miner's network mode and no other: [`BrokerProcess::start`] takes the
//! miner's config and passes `--dev-private-network` exactly when its
//! [`ZkMinerConfig::net_mode`] is [`NetMode::DevPrivate`] (`[dev] private_network`, never on
//! mainnet). The broker's config file has no key for it.

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use zkminer_witness_broker::client::BrokerClient;
use zkminer_witness_broker::egress::sanitize_log;
use zkminer_config::ZkMinerConfig;
use zkminer_netguard::NetMode;
use zkminer_witness_sandbox::{prepare_command, Cgroup, CgroupSpec};

use crate::spawner::Spawner;

/// Threads the broker may run (its main thread, 4 runtime workers, ≤ 8 blocking threads) plus slack.
pub const BROKER_PIDS_MAX: u32 = 32;
/// Longest broker log line forwarded to the miner's log.
const MAX_LOG_LINE: usize = 2_048;
/// Makes each broker's cgroup name unique within the delegated root (one broker per miner, but tests
/// run several in one process).
static BROKER_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct BrokerProcess {
    child: Child,
    cgroup: Option<Cgroup>,
    pub client: Arc<BrokerClient>,
}

impl BrokerProcess {
    /// Spawns the broker with its config file `config`, in the network mode of `miner` (the miner's
    /// own config: [`ZkMinerConfig::net_mode`]). Must be called inside a tokio runtime (the client
    /// is async). In public mode the broker refuses, and exits with status 2, a config with an
    /// endpoint that is not on the public internet.
    pub fn start(
        spawner: &Spawner,
        binary: &Path,
        config: &Path,
        cgroup_root: &Path,
        memory_bytes: u64,
        miner: &ZkMinerConfig,
    ) -> Result<Self> {
        let net_mode = miner.net_mode();
        if net_mode == NetMode::DevPrivate {
            tracing::warn!("{}: the witness broker's endpoints may be on the local network", zkminer_netguard::DEV_MODE_BANNER);
        }
        let cgroup = Cgroup::create(
            cgroup_root,
            &CgroupSpec {
                name: format!("broker-{}", BROKER_SEQ.fetch_add(1, Ordering::Relaxed)),
                memory_max: memory_bytes,
                pids_max: BROKER_PIDS_MAX,
                cpu_max: None,
                cpu_weight: 100,
            },
        )
        .context("creating the broker's cgroup")?;
        let (miner_end, broker_end) = UnixStream::pair().context("control socketpair")?;
        let binary = binary.to_path_buf();
        let config = config.to_path_buf();
        let (spawned, cgroup) = spawner
            .run(move || {
                let mut cmd = Command::new(&binary);
                cmd.arg("--config").arg(&config).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
                if net_mode == NetMode::DevPrivate {
                    cmd.arg("--dev-private-network");
                }
                cmd.env_clear();
                let child = prepare_command(&mut cmd, &cgroup, &[(broker_end.as_fd(), 3)])
                    .map_err(std::io::Error::other)
                    .and_then(|()| cmd.spawn());
                drop(broker_end);
                (child, cgroup)
            })
            .context("the spawner thread")?;
        let mut child = spawned.context("spawning the broker")?;
        if let Some(stderr) = child.stderr.take() {
            std::thread::Builder::new()
                .name("broker-log".into())
                .spawn(move || {
                    for line in BufReader::new(stderr).split(b'\n').map_while(Result::ok) {
                        tracing::info!(target: "zkminer::broker", "{}", sanitize_log(&line, MAX_LOG_LINE));
                    }
                })
                .ok();
        }
        let client = Arc::new(BrokerClient::new(miner_end).context("broker client")?);
        Ok(Self { child, cgroup: Some(cgroup), client })
    }

    /// The broker's pid (for logs and `/proc` checks).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether the broker has exited.
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        if let Some(cg) = self.cgroup.take() {
            let _ = cg.kill();
            let _ = self.child.wait();
            let _ = cg.remove();
        }
    }
}
