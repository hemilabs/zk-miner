//! The broker process (§10.1): one per host, spawned through the sandbox launcher into its own
//! cgroup with its control socket at fd 3 and its connector socket at fd 4. The miner talks to it
//! with [`BrokerClient`].
//!
//! # The connector (review r2 F5)
//!
//! The broker has no network of its own: its sandbox denies `socket`, `connect`, `bind`, `listen`
//! and `accept*`. Every TCP connection it uses is made here, in the miner, by
//! [`Connector`]: [`BrokerProcess::start`] loads the broker's config file **itself**
//! ([`BrokerConfig::load_for_connector`], in the miner's network mode, without reading keys),
//! builds the connector from that copy with the miner's `[egress] deny_cidrs` and facts options,
//! and serves the broker's requests on a socketpair created before `exec`. The broker can only
//! name an endpoint index; the connector resolves, admits (netguard's floor with the miner's facts)
//! and connects, and hands back the connected socket. A broker that breaks the protocol is cut off:
//! the socket is closed, the miner pages (`WITNESS-BROKER-CUT-OFF`) and kills the broker's cgroup,
//! and witness serving stops. So is a broker that breaks the control protocol ([`BrokerClient`]
//! raises it) or closes its connector socket and is still running
//! [`BROKER_EXIT_GRACE`] later (an honest one closes it only by exiting). When the session ends,
//! for any reason, the builder runners registered with the broker
//! ([`zkminer_witness_broker::client::RunnerCgroups`]) are killed too: a socket the broker passed
//! one over its job socket would outlive the broker in it.
//!
//! The broker runs in the miner's network mode and no other: [`BrokerProcess::start`] takes the
//! miner's config and passes `--dev-private-network` exactly when its
//! [`ZkMinerConfig::net_mode`] is [`NetMode::DevPrivate`] (`[dev] private_network`, never on
//! mainnet). The broker's config file has no key for it.
//!
//! The broker cannot read the host's interfaces or routes once sandboxed, so the miner keeps its
//! second-layer view current: every [`BROKER_FACTS_REFRESH_EVERY`] it gathers netguard's facts with
//! its own `[egress]` options and, when they changed (and once at start), sends them with
//! `RefreshPrefixes` (every prefix they refuse plus the miner's `[egress] deny_cidrs`, and the own
//! addresses, public NAT ones included). The broker unions them with what it read at startup.

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use zkminer_witness_broker::client::{BrokerClient, ClientError, SelfTestResult};
use zkminer_witness_broker::connector::{Connector, SessionEnd};
use zkminer_witness_broker::egress::sanitize_log;
use zkminer_witness_broker::BrokerConfig;
use zkminer_config::ZkMinerConfig;
use zkminer_netguard::NetMode;
use zkminer_witness::ipc::{BROKER_CONNECTOR_FD, BROKER_CONTROL_FD};
use zkminer_witness_sandbox::{prepare_command, Cgroup, CgroupSpec};

use crate::spawner::Spawner;

/// Threads the broker may run (its main thread, 4 runtime workers, ≤ 8 blocking threads) plus slack.
pub const BROKER_PIDS_MAX: u32 = 32;
/// Longest broker log line forwarded to the miner's log.
const MAX_LOG_LINE: usize = 2_048;
/// Makes each broker's cgroup name unique within the delegated root (one broker per miner, but tests
/// run several in one process).
static BROKER_SEQ: AtomicU64 = AtomicU64::new(0);
/// How often the miner re-reads the host's facts for the broker (see the module doc).
pub const BROKER_FACTS_REFRESH_EVERY: Duration = Duration::from_secs(5);

pub struct BrokerProcess {
    child: Child,
    cgroup: Option<Cgroup>,
    pub client: Arc<BrokerClient>,
    /// The miner's connector: every connection the broker uses.
    pub connector: Arc<Connector>,
    session: Option<tokio::task::JoinHandle<SessionEnd>>,
    cut: Arc<std::sync::atomic::AtomicBool>,
    refresher: Option<tokio::task::JoinHandle<()>>,
}

/// §11.1: the broker refuses every endpoint on its `chain_rpc_host`, which only keeps the builder's
/// and the artifact reader's traffic off the miner's chain RPC if it is that RPC's host. So the file's
/// value must be the host of this miner's own `[chain] rpc_url`; anything else refuses the start.
/// Developer mode (`[dev] private_network`, never on a production chain) only warns: its tests run
/// the chain and the broker's endpoints on one loopback host.
pub fn check_chain_rpc_host(broker: &BrokerConfig, miner: &ZkMinerConfig) -> Result<()> {
    let ours = zkminer_witness_broker::config::chain_rpc_host_of(&miner.chain.rpc_url)
        .context("[chain] rpc_url names no host")?;
    if broker.chain_rpc_host == ours {
        return Ok(());
    }
    if miner.net_mode() == NetMode::DevPrivate {
        tracing::warn!(
            "{}: the broker's chain_rpc_host {:?} is not [chain] rpc_url's host {ours:?}, so its endpoints may share \
             the miner's chain RPC",
            zkminer_netguard::DEV_MODE_BANNER,
            broker.chain_rpc_host
        );
        return Ok(());
    }
    anyhow::bail!(
        "its chain_rpc_host is {:?}, but this miner's [chain] rpc_url is on {ours:?}: set chain_rpc_host = {ours:?} \
         (the broker refuses endpoints on the miner's chain-RPC host, and only that host)",
        broker.chain_rpc_host
    )
}

impl BrokerProcess {
    /// Spawns the broker with its config file `config`, in the network mode of `miner` (the miner's
    /// own config: [`ZkMinerConfig::net_mode`]), and serves its connector. Must be called inside a
    /// tokio runtime (the client and the connector are async). In public mode a config with an
    /// endpoint that is not on the public internet is refused here, by the miner's own load, before
    /// anything is spawned (and the broker would refuse it too, exiting with status 2); so is one
    /// whose `chain_rpc_host` is not this miner's chain RPC host ([`check_chain_rpc_host`]).
    pub fn start(
        spawner: &Spawner,
        binary: &Path,
        config: &Path,
        cgroup_root: &Path,
        memory_bytes: u64,
        miner: &ZkMinerConfig,
    ) -> Result<Self> {
        let net_mode = miner.net_mode();
        let facts_options = miner.egress_facts_options()?;
        let miner_deny = miner.egress_deny()?;
        if net_mode == NetMode::DevPrivate {
            tracing::warn!("{}: the witness broker's endpoints may be on the local network", zkminer_netguard::DEV_MODE_BANNER);
        }
        // The connector's only source: the operator's file as the miner reads it, in the miner's
        // mode. Nothing the broker says ever reaches it.
        let broker_cfg = BrokerConfig::load_for_connector(config, net_mode)
            .with_context(|| format!("the broker config {}", config.display()))?;
        check_chain_rpc_host(&broker_cfg, miner)
            .with_context(|| format!("the broker config {}", config.display()))?;
        let connector = Connector::for_miner(&broker_cfg, &miner_deny, facts_options.clone()).context("the broker's connector")?;
        let artifact_fetch = broker_cfg.timeouts.artifact_fetch();
        drop(broker_cfg);
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
        let (connector_end, broker_connector_end) = UnixStream::pair().context("connector socketpair")?;
        // Absolute: the sandbox launcher starts the broker in `/`.
        let binary = std::path::absolute(binary).context("the broker binary's path")?;
        let config = std::path::absolute(config).context("the broker config's path")?;
        let (spawned, cgroup) = spawner
            .run(move || {
                let mut cmd = Command::new(&binary);
                cmd.arg("--config").arg(&config).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
                if net_mode == NetMode::DevPrivate {
                    cmd.arg("--dev-private-network");
                }
                cmd.env_clear();
                let child = prepare_command(
                    &mut cmd,
                    &cgroup,
                    &[(broker_end.as_fd(), BROKER_CONTROL_FD), (broker_connector_end.as_fd(), BROKER_CONNECTOR_FD)],
                )
                .map_err(std::io::Error::other)
                .and_then(|()| cmd.spawn());
                drop(broker_end);
                drop(broker_connector_end);
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
        let client = Arc::new(BrokerClient::new(miner_end).context("broker client")?.with_artifact_fetch_timeout(artifact_fetch));
        connector.warm_up();
        let cgroup_dir = cgroup.path().to_path_buf();
        let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let session = tokio::spawn({
            let (connector, cut, runners) = (connector.clone(), cut.clone(), client.runners().clone());
            let violated = client.violated();
            async move {
                let serve = connector.serve(connector_end);
                tokio::pin!(serve);
                // A broker that broke the control protocol (review r3 W1) is cut off as one that
                // broke the connector's.
                let (end, violation) = tokio::select! {
                    end = &mut serve => (Some(end), None),
                    why = violated => (None, Some(why)),
                };
                let why = match (&end, violation) {
                    (_, Some(v)) => Some(format!("it broke the control protocol: {v}")),
                    (Some(SessionEnd::CutOff(why)), None) => Some(why.to_string()),
                    // An honest broker closes its connector socket only by exiting.
                    (Some(SessionEnd::Closed), None) if still_running(&cgroup_dir, BROKER_EXIT_GRACE).await => {
                        Some(format!("it closed its connector socket and was still running {BROKER_EXIT_GRACE:?} later"))
                    }
                    (Some(SessionEnd::Closed), None) | (None, None) => None,
                };
                if let Some(why) = &why {
                    cut.store(true, Ordering::SeqCst);
                    // The broker broke a protocol: treat it as compromised.
                    let killed = std::fs::write(cgroup_dir.join("cgroup.kill"), "1");
                    tracing::error!("PAGE: WITNESS-BROKER-CUT-OFF: the broker was killed ({why}; cgroup.kill: {killed:?})");
                }
                // A socket the broker passed over a job socket lives on in the runner that got
                // it: the runners registered with this broker end with its session, and any
                // registered later is killed at once.
                let runners_killed = runners.close_and_kill();
                if runners_killed > 0 {
                    tracing::warn!(runners_killed, cut_off = why.is_some(), "the builder runners of the broker's session were killed with it");
                }
                match end {
                    Some(end) => end,
                    // The broker was killed: its connector session ends with it.
                    None => tokio::time::timeout(BROKER_EXIT_GRACE, serve)
                        .await
                        .unwrap_or(SessionEnd::Closed),
                }
            }
        });
        let refresher = Some(tokio::spawn(refresh_facts(client.clone(), facts_options, miner_deny)));
        Ok(Self { child, cgroup: Some(cgroup), client, connector, session: Some(session), cut, refresher })
    }

    /// Whether the broker was cut off (and killed): by the connector, or for breaking the control
    /// protocol.
    pub fn cut_off(&self) -> bool {
        self.cut.load(Ordering::SeqCst)
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

/// How long a broker whose connector session closed may take to exit before it counts as cut off
/// (an honest broker closes its connector socket only by exiting).
pub const BROKER_EXIT_GRACE: Duration = Duration::from_secs(5);

/// Whether the cgroup at `dir` still holds a process after `grace` (`cgroup.events` `populated`;
/// a process that exited no longer counts, reaped or not).
async fn still_running(dir: &Path, grace: Duration) -> bool {
    let until = tokio::time::Instant::now() + grace;
    loop {
        let events = tokio::fs::read_to_string(dir.join("cgroup.events")).await.unwrap_or_default();
        if !events.lines().any(|l| l.trim() == "populated 1") {
            return false;
        }
        if tokio::time::Instant::now() >= until {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The broker's self-test (from inside its sandbox) and its connector's (here, in the miner), as
/// one result: `ok` only if every check of both passed.
pub async fn self_test(client: &BrokerClient, connector: &Arc<Connector>) -> Result<SelfTestResult, ClientError> {
    let mut r = client.self_test().await?;
    let own = connector.self_test().await;
    r.ok &= own.iter().all(|(_, ok)| *ok);
    r.checks.extend(own);
    Ok(r)
}

/// Sends the host's facts to the broker at start and whenever they change (see the module doc).
async fn refresh_facts(client: Arc<BrokerClient>, opts: zkminer_netguard::FactsOptions, deny: Vec<zkminer_netguard::Prefix>) {
    let mut sent = None;
    let mut tick = tokio::time::interval(BROKER_FACTS_REFRESH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let o = opts.clone();
        let facts = match tokio::task::spawn_blocking(move || zkminer_netguard::HostFacts::gather_with(&o)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                tracing::warn!("network guard: re-reading this host's facts for the witness broker failed: {e}");
                continue;
            }
            Err(_) => continue,
        };
        let zkminer_witness::ipc::ControlRequest::RefreshPrefixes { prefixes, own_addresses } =
            zkminer_witness_broker::hostinfo::refresh_message_for(&facts, &deny)
        else {
            continue;
        };
        let now = Some((prefixes.clone(), own_addresses.clone()));
        if now == sent {
            continue;
        }
        match client.refresh_prefixes(prefixes, own_addresses).await {
            Ok(count) => {
                tracing::debug!(count, "the witness broker's host facts refreshed");
                sent = now;
            }
            Err(ClientError::Closed | ClientError::Violation) => return,
            Err(e) => tracing::warn!("network guard: refreshing the witness broker's host facts failed: {e}"),
        }
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        if let Some(r) = self.refresher.take() {
            r.abort();
        }
        if let Some(s) = self.session.take() {
            s.abort();
        }
        if let Some(cg) = self.cgroup.take() {
            let _ = cg.kill();
            let _ = self.child.wait();
            let _ = cg.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn miner(rpc_url: &str, dev: bool) -> ZkMinerConfig {
        let mut c = ZkMinerConfig::default();
        c.chain.chain_id = 31337;
        c.chain.rpc_url = rpc_url.to_string();
        if dev {
            c.dev.private_network = true;
            c.dev.chain_id = Some(31337);
        }
        assert_eq!(c.net_mode() == NetMode::DevPrivate, dev);
        c
    }

    fn broker_file(dir: &Path, chain_rpc_host: &str) -> std::path::PathBuf {
        let path = dir.join("broker.toml");
        std::fs::write(
            &path,
            format!(
                "chain_rpc_host = \"{chain_rpc_host}\"\nspool_dir = \"{}\"\n",
                dir.join("spool").display()
            ),
        )
        .unwrap();
        path
    }

    fn check(dir: &Path, chain_rpc_host: &str, miner: &ZkMinerConfig) -> Result<()> {
        let cfg =
            BrokerConfig::load_for_connector(&broker_file(dir, chain_rpc_host), miner.net_mode())
                .unwrap();
        check_chain_rpc_host(&cfg, miner)
    }

    /// The broker's own-host refusal is only as good as `chain_rpc_host`: it must be the host of the
    /// miner's `[chain] rpc_url`, compared as the broker normalizes hosts.
    #[test]
    fn chain_rpc_host_must_be_the_miners_chain_rpc_host() {
        let dir = tempfile::tempdir().unwrap();
        let public = miner("https://RPC.example.org/v1/some-key", false);
        for same in [
            "rpc.example.org",
            "https://rpc.example.org:8443/other",
            "RPC.EXAMPLE.ORG",
        ] {
            check(dir.path(), same, &public).unwrap_or_else(|e| panic!("{same}: {e:#}"));
        }
        for other in ["chain-rpc.invalid", "rpc2.example.org", "example.org"] {
            let e = format!("{:#}", check(dir.path(), other, &public).unwrap_err());
            assert!(
                e.contains("set chain_rpc_host = \"rpc.example.org\""),
                "{other}: {e}"
            );
        }
        // Developer mode's loopback tests run the chain and the endpoints on one host: a warning.
        check(
            dir.path(),
            "chain-rpc.invalid",
            &miner("http://127.0.0.1:8545", true),
        )
        .unwrap();
    }

    /// And the miner refuses to start a broker whose file names another host, before anything is
    /// spawned (the binary and the cgroup root here could never be).
    #[tokio::test]
    async fn a_broker_file_naming_another_chain_rpc_host_is_refused_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let config = broker_file(dir.path(), "chain-rpc.invalid");
        let spawner = Spawner::new().unwrap();
        let public = miner("https://rpc.example.org", false);
        let e = match BrokerProcess::start(
            &spawner,
            Path::new("/nonexistent/broker"),
            &config,
            dir.path(),
            1 << 26,
            &public,
        ) {
            Ok(_) => panic!("a broker was started with another host's chain_rpc_host"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            e.contains("chain_rpc_host is \"chain-rpc.invalid\"") && e.contains("rpc.example.org"),
            "{e}"
        );
        // A file without the key is refused too (it is required).
        std::fs::write(
            &config,
            format!("spool_dir = \"{}\"\n", dir.path().join("spool").display()),
        )
        .unwrap();
        let e = match BrokerProcess::start(
            &spawner,
            Path::new("/nonexistent/broker"),
            &config,
            dir.path(),
            1 << 26,
            &public,
        ) {
            Ok(_) => panic!("a broker was started without chain_rpc_host"),
            Err(e) => format!("{e:#}"),
        };
        assert!(e.contains("chain_rpc_host"), "{e}");
    }
}
