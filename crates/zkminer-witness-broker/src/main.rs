//! `zkminer-witness-broker --config <path>`: the control socket is fd 3 (plan §10.1).
//!
//! Order matters: everything that needs the filesystem, netlink or a resolver without the sandbox
//! happens first, single-threaded — the config and key files, the host facts (endpoint addresses,
//! connected prefixes, own addresses), the spool directory — then `restrict_self` (which refuses a
//! process that already has a second thread), and only then logging, the tokio runtime and the
//! HTTP clients.
//!
//! Threads: the main thread, [`WORKER_THREADS`] runtime workers and at most
//! [`MAX_BLOCKING_THREADS`] blocking-pool threads: 13 in all, the broker cgroup's `pids.max` floor.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;

use zkminer_witness::ipc::BROKER_CONTROL_FD;
use zkminer_witness_broker::hooks::RealEgress;
use zkminer_witness_broker::{serve, BrokerConfig, HostFacts, MAX_BLOCKING_THREADS, WORKER_THREADS};
use zkminer_witness_sandbox::{restrict_self, Profile};

/// Files the system resolver reads (each granted read-only if it exists).
const RESOLVER_FILES: [&str; 4] = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/gai.conf"];

fn config_path() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => Ok(PathBuf::from(path)),
        _ => Err("usage: zkminer-witness-broker --config <path> (control socket at fd 3)".into()),
    }
}

fn main() -> ExitCode {
    let path = match config_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut config = match BrokerConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zkminer-witness-broker: {e}");
            return ExitCode::from(2);
        }
    };
    // SAFETY: fcntl(F_GETFD) only checks that fd 3 is open; it is then owned here alone.
    if unsafe { libc::fcntl(BROKER_CONTROL_FD, libc::F_GETFD) } < 0 {
        eprintln!("zkminer-witness-broker: no control socket at fd {BROKER_CONTROL_FD}");
        return ExitCode::from(2);
    }
    // SAFETY: fd 3 is open (checked above) and nothing else in this process owns it.
    let control = unsafe { OwnedFd::from_raw_fd(BROKER_CONTROL_FD) };
    match HostFacts::gather(&config, &RealEgress) {
        Ok(h) => config.host = Some(h),
        Err(e) => {
            eprintln!("zkminer-witness-broker: reading the host's interfaces: {e}");
            return ExitCode::from(2);
        }
    }
    if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&config.spool_dir) {
        eprintln!("zkminer-witness-broker: creating spool_dir: {e}");
        return ExitCode::from(2);
    }
    let readable: Vec<PathBuf> = RESOLVER_FILES.iter().map(PathBuf::from).filter(|p| p.exists()).collect();
    // TODO(merge): the sandbox's Profile::Broker gains `writable`; pass
    // `writable: vec![config.spool_dir.clone()]` (blob/v1 spool files are created there).
    let profile = Profile::Broker { readable, tcp_connect_ports: config.tcp_connect_ports() };
    if let Err(e) = restrict_self(&profile) {
        eprintln!("zkminer-witness-broker: sandbox: {e}");
        return ExitCode::from(3);
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "tokio runtime");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(serve(config, control)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "broker stopped");
            ExitCode::from(1)
        }
    }
}
