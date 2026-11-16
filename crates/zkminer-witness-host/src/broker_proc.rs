//! The broker process (§10.1): one per host, spawned through the sandbox launcher into its own
//! cgroup with its control socket at fd 3. The miner talks to it with [`BrokerClient`].

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result};
use zkminer_witness_broker::client::BrokerClient;
use zkminer_witness_broker::egress::sanitize_log;
use zkminer_witness_sandbox::{prepare_command, Cgroup, CgroupSpec};

use crate::spawner::Spawner;

/// Threads the broker may run (its main thread, 4 runtime workers, ≤ 8 blocking threads) plus slack.
pub const BROKER_PIDS_MAX: u32 = 32;
/// Longest broker log line forwarded to the miner's log.
const MAX_LOG_LINE: usize = 2_048;

pub struct BrokerProcess {
    child: Child,
    cgroup: Option<Cgroup>,
    pub client: Arc<BrokerClient>,
}

impl BrokerProcess {
    /// Spawns the broker. Must be called inside a tokio runtime (the client is async).
    pub fn start(
        spawner: &Spawner,
        binary: &Path,
        config: &Path,
        cgroup_root: &Path,
        memory_bytes: u64,
    ) -> Result<Self> {
        let cgroup = Cgroup::create(
            cgroup_root,
            &CgroupSpec { name: "broker".into(), memory_max: memory_bytes, pids_max: BROKER_PIDS_MAX, cpu_max: None, cpu_weight: 100 },
        )
        .context("creating the broker's cgroup")?;
        let (miner_end, broker_end) = UnixStream::pair().context("control socketpair")?;
        let binary = binary.to_path_buf();
        let config = config.to_path_buf();
        let (spawned, cgroup) = spawner
            .run(move || {
                let mut cmd = Command::new(&binary);
                cmd.arg("--config").arg(&config).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
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
