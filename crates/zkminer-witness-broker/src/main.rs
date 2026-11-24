//! `zkminer-witness-broker --config <path> [--dev-private-network]`: the control socket is fd 3
//! (plan §10.1), the socket to the miner's connector fd 4 (review r2 F5).
//!
//! `--dev-private-network` is developer mode ([`NetMode::DevPrivate`]): the miner passes it only
//! when its own config has `[dev] private_network = true`, and the broker config file has no key
//! for it. Refused when an endpoint serves a production chain (Hemi mainnet); announced in the log.
//! Without it the broker refuses, before its sandbox, any endpoint that is not on the public
//! internet (see [`zkminer_witness_broker::config`]).
//!
//! Order matters: everything that needs the filesystem or netlink without the sandbox happens
//! first, single-threaded — the config and key files, the host facts for the broker's own floor
//! (the DNS servers from `/etc/resolv.conf` unless `[dns] servers` is set, connected prefixes, own
//! addresses), the spool directory — then `restrict_self` (which refuses a process that already has
//! a second thread), then the tokio runtime (whose signal driver makes the one socket pair the
//! broker ever creates), then `seal_socket_creation`, and only then logging (every line redacted at
//! the writer), the HTTP clients and the first untrusted byte. The sandbox grants no file but the
//! spool directory and **no network**: no `socket`, `connect`, `bind`, `listen` or `accept*`, and
//! no TCP port in Landlock. Every connection comes from the miner's connector, already connected,
//! for an endpoint the broker names by index ([`zkminer_witness_broker::connector`]); the broker
//! resolves no names.
//!
//! Threads: the main thread, [`WORKER_THREADS`] runtime workers and at most
//! [`MAX_BLOCKING_THREADS`] blocking-pool threads: 13 in all, the broker cgroup's `pids.max` floor.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;

use zkminer_witness::ipc::{BROKER_CONNECTOR_FD, BROKER_CONTROL_FD};
use zkminer_witness_broker::egress::NetMode;
use zkminer_witness_broker::hooks::RealEgress;
use zkminer_witness_broker::logging::{env_filter, Redacting};
use zkminer_witness_broker::{serve, BrokerConfig, HostFacts, MAX_BLOCKING_THREADS, WORKER_THREADS};
use zkminer_witness_sandbox::{restrict_self, seal_socket_creation, Profile};

const USAGE: &str =
    "usage: zkminer-witness-broker --config <path> [--dev-private-network] (control socket at fd 3, connector at fd 4)";

/// `--config <path>` once, and `--dev-private-network` at most once, in either order.
fn args() -> Result<(PathBuf, NetMode), String> {
    let mut path = None;
    let mut mode = NetMode::Public;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" && path.is_none() {
            path = Some(PathBuf::from(args.next().ok_or(USAGE)?));
        } else if a == "--dev-private-network" && mode == NetMode::Public {
            mode = NetMode::DevPrivate;
        } else {
            return Err(USAGE.into());
        }
    }
    Ok((path.ok_or(USAGE)?, mode))
}

fn main() -> ExitCode {
    let (path, mode) = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut config = match BrokerConfig::load(&path, mode) {
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
    // SAFETY: as for fd 3.
    if unsafe { libc::fcntl(BROKER_CONNECTOR_FD, libc::F_GETFD) } < 0 {
        eprintln!("zkminer-witness-broker: no connector socket at fd {BROKER_CONNECTOR_FD}");
        return ExitCode::from(2);
    }
    // SAFETY: fd 4 is open (checked above) and nothing else in this process owns it.
    let connector = unsafe { OwnedFd::from_raw_fd(BROKER_CONNECTOR_FD) };
    // The facts are read once, here, and `restrict_self` refuses a second thread: netguard must
    // not start its PREF64 listener, whose thread outlives the read (the miner keeps one).
    zkminer_netguard::nat64::without_listener();
    match HostFacts::gather(&config, &RealEgress) {
        Ok(h) => {
            if let Err(e) = config.validate_host(&h) {
                eprintln!("zkminer-witness-broker: {e}");
                return ExitCode::from(2);
            }
            config.host = Some(h);
        }
        Err(e) => {
            eprintln!("zkminer-witness-broker: reading the host's interfaces: {e}");
            return ExitCode::from(2);
        }
    }
    if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&config.spool_dir) {
        eprintln!("zkminer-witness-broker: creating spool_dir: {e}");
        return ExitCode::from(2);
    }
    // No readable files; blob/v1 spool files are created in spool_dir. No network.
    let profile = Profile::Broker { readable: Vec::new(), writable: vec![config.spool_dir.clone()] };
    if let Err(e) = restrict_self(&profile) {
        eprintln!("zkminer-witness-broker: sandbox: {e}");
        return ExitCode::from(3);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zkminer-witness-broker: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    // The runtime made its socket pair; from here on the broker can make no socket at all.
    if let Err(e) = seal_socket_creation() {
        eprintln!("zkminer-witness-broker: sandbox: {e}");
        return ExitCode::from(3);
    }
    tracing_subscriber::fmt()
        .with_writer(Redacting(std::io::stderr))
        .with_ansi(false)
        .with_env_filter(env_filter(std::env::var("RUST_LOG").ok().as_deref()))
        .init();
    match runtime.block_on(serve(config, control, connector)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "broker stopped");
            ExitCode::from(1)
        }
    }
}
