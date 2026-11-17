//! What ends with a broker's connector session: a broker that breaks the connector protocol (or
//! closes its connector socket and keeps running) is killed, and so is every builder runner
//! registered with it — a socket the broker passed a runner over its job socket must not outlive
//! it. A runner registered after the end is killed at once. A broker that exits is not a cut-off.
//!
//! The brokers here are shell scripts started by the real `BrokerProcess::start` (sandbox launcher,
//! cgroup, fds 3 and 4), the "runners" `sleep`s in cgroups of their own, each holding a TCP
//! connection to a local listener, as a runner holding a socket from the broker would.
//!
//! Needs a delegated cgroup (`systemd-run --user --scope -p Delegate=yes`); skipped otherwise,
//! unless `ZKMINER_SANDBOX_TESTS_REQUIRED` is set.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zkminer_witness_host::broker_proc::{BrokerProcess, BROKER_EXIT_GRACE};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_sandbox::{delegated_root, landlock_abi, prepare_command, Cgroup, CgroupSpec, SandboxError, MIN_LANDLOCK_ABI};

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    if landlock_abi() < MIN_LANDLOCK_ABI {
        skip(test, "Landlock too old");
        return None;
    }
    match delegated_root() {
        Ok(r) => Some(r),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: {e}"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

/// A broker config the miner loads (developer mode: a loopback endpoint), and a fake broker script
/// with `body` as its shell code.
fn fake_broker(dir: &Path, body: &str) -> (PathBuf, PathBuf) {
    let config = dir.join("broker.toml");
    std::fs::write(
        &config,
        format!(
            "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n[egress]\ndiscover_public_addresses = false\n\
             [[evm_rpc]]\nalias = \"n\"\nurl = \"http://127.0.0.1:9\"\nchain_id = 31337\nmethod_sets = [\"state-read\"]\n\
             cidrs = [\"127.0.0.1/32\"]\n",
            dir.join("spool").display()
        ),
    )
    .unwrap();
    let script = dir.join("fake-broker.sh");
    std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, config)
}

fn dev_miner() -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.chain_id = 31337;
    c.dev.private_network = true;
    c.dev.chain_id = Some(31337);
    assert_eq!(c.net_mode(), zkminer_netguard::NetMode::DevPrivate);
    c
}

/// A stand-in for a builder runner holding a socket: `sleep` in a cgroup of its own with a TCP
/// connection to `listener` at fd 3 (this process keeps no copy). Returns the child, its cgroup
/// and the listener's side of the connection.
fn runner_with_socket(root: &Path, name: &str, listener: &TcpListener) -> (Child, Cgroup, TcpStream) {
    let cg = Cgroup::create(
        root,
        &CgroupSpec { name: format!("{name}-{}", std::process::id()), memory_max: 64 << 20, pids_max: 4, cpu_max: None, cpu_weight: 20 },
    )
    .unwrap();
    let held = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (served, _) = listener.accept().unwrap();
    let mut cmd = Command::new("/usr/bin/sleep");
    cmd.arg("60").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    prepare_command(&mut cmd, &cg, &[(held.as_fd(), 3)]).unwrap();
    let child = cmd.spawn().unwrap();
    drop(held);
    drop(cmd);
    (child, cg, served)
}

/// Waits up to `within` for `child` to exit; its status.
fn exited_within(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + within;
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return Some(st);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the peer of `s` closed (end-of-file within `within`).
fn closed(s: &mut TcpStream, within: Duration) -> bool {
    s.set_read_timeout(Some(within)).unwrap();
    let mut b = [0u8; 8];
    matches!(s.read(&mut b), Ok(0))
}

async fn wait_cut_off(bp: &BrokerProcess, within: Duration) -> bool {
    let until = Instant::now() + within;
    while !bp.cut_off() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bp.cut_off()
}

/// A malformed connector frame: the broker is cut off and killed, the runner registered with it
/// is killed (the socket it held closes), and a runner registered afterwards is killed at once.
#[test]
fn a_cut_off_kills_the_runners_registered_with_the_broker() {
    let Some(root) = delegated("a_cut_off_kills_the_runners_registered_with_the_broker") else { return };
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    // Waits until the test has registered its runner (the marker file), then breaks the protocol.
    let marker = dir.path().join("go");
    let (script, config) = fake_broker(
        dir.path(),
        &format!(
            "while [ ! -e {} ]; do /usr/bin/sleep 0.05; done\nprintf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >&4\nexec /usr/bin/sleep 60",
            marker.display()
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    runtime().block_on(async {
        let spawner = Spawner::new().unwrap();
        let mut bp = BrokerProcess::start(&spawner, &script, &config, &root, 64 << 20, &dev_miner()).unwrap();
        let (mut runner, runner_cg, mut served) = runner_with_socket(&root, "cut-off-runner", &listener);
        let id = bp.client.runners().add(runner_cg.path()).expect("registered while the session is up");
        assert!(exited_within(&mut runner, Duration::from_millis(300)).is_none(), "the runner runs");
        std::fs::write(&marker, b"").unwrap();
        assert!(wait_cut_off(&bp, Duration::from_secs(10)).await, "the connector cut the broker off");
        // The broker and the runner are killed; the runner's socket is closed.
        let until = Instant::now() + Duration::from_secs(5);
        while bp.exited().is_none() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(bp.exited().map(|s| s.signal()), Some(Some(libc::SIGKILL)), "the broker was killed");
        let st = exited_within(&mut runner, Duration::from_secs(5)).expect("the runner was killed with its broker");
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        assert!(closed(&mut served, Duration::from_secs(2)), "the socket the runner held is closed");
        bp.client.runners().remove(id);
        runner_cg.remove().unwrap();
        // A runner registered after the end (one spawned with a socket already queued on its job
        // socket) is killed at once.
        let (mut late, late_cg, mut late_served) = runner_with_socket(&root, "late-runner", &listener);
        assert!(bp.client.runners().add(late_cg.path()).is_none());
        let st = exited_within(&mut late, Duration::from_secs(5)).expect("the late runner was killed");
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        assert!(closed(&mut late_served, Duration::from_secs(2)));
        late_cg.remove().unwrap();
        drop(bp);
    });
}

/// A broker that closes its connector socket and keeps running is cut off (an honest broker closes
/// it only by exiting), and its runners are killed.
#[test]
fn a_broker_that_drops_its_connector_and_keeps_running_is_cut_off() {
    let Some(root) = delegated("a_broker_that_drops_its_connector_and_keeps_running_is_cut_off") else { return };
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let marker = dir.path().join("go");
    let (script, config) =
        fake_broker(dir.path(), &format!("while [ ! -e {} ]; do /usr/bin/sleep 0.05; done\nexec 4>&-\nexec /usr/bin/sleep 60", marker.display()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    runtime().block_on(async {
        let spawner = Spawner::new().unwrap();
        let mut bp = BrokerProcess::start(&spawner, &script, &config, &root, 64 << 20, &dev_miner()).unwrap();
        let (mut runner, runner_cg, mut served) = runner_with_socket(&root, "closed-runner", &listener);
        bp.client.runners().add(runner_cg.path()).expect("registered");
        std::fs::write(&marker, b"").unwrap();
        let started = Instant::now();
        assert!(wait_cut_off(&bp, BROKER_EXIT_GRACE + Duration::from_secs(5)).await, "cut off");
        assert!(started.elapsed() >= BROKER_EXIT_GRACE - Duration::from_millis(500), "only after the grace");
        let until = Instant::now() + Duration::from_secs(5);
        while bp.exited().is_none() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(bp.exited().map(|s| s.signal()), Some(Some(libc::SIGKILL)));
        let st = exited_within(&mut runner, Duration::from_secs(5)).expect("the runner was killed");
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        assert!(closed(&mut served, Duration::from_secs(2)));
        runner_cg.remove().unwrap();
        drop(bp);
    });
}

/// A broker that exits is not cut off (no page, serving follows the self-test), but the runners
/// registered with it still end with its session.
#[test]
fn a_broker_that_exits_is_not_cut_off() {
    let Some(root) = delegated("a_broker_that_exits_is_not_cut_off") else { return };
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let marker = dir.path().join("go");
    let (script, config) = fake_broker(dir.path(), &format!("while [ ! -e {} ]; do /usr/bin/sleep 0.05; done\nexit 0", marker.display()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    runtime().block_on(async {
        let spawner = Spawner::new().unwrap();
        let mut bp = BrokerProcess::start(&spawner, &script, &config, &root, 64 << 20, &dev_miner()).unwrap();
        let (mut runner, runner_cg, _served) = runner_with_socket(&root, "exit-runner", &listener);
        bp.client.runners().add(runner_cg.path()).expect("registered");
        std::fs::write(&marker, b"").unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while bp.exited().is_none() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(bp.exited().and_then(|s| s.code()), Some(0));
        let st = exited_within(&mut runner, Duration::from_secs(5)).expect("the runner ended with the broker's session");
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        assert!(!wait_cut_off(&bp, BROKER_EXIT_GRACE + Duration::from_secs(1)).await, "an exit is not a cut-off");
        runner_cg.remove().unwrap();
        drop(bp);
    });
}
