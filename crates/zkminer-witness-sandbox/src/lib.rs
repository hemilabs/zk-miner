//! Process sandbox for witness builders, execute workers and the broker (plan §10.2, §10.3).
//!
//! This crate implements the **rootless** mode of §10.3: Landlock + seccomp + a cgroup in the
//! user's delegated cgroup v2 subtree, all under the miner's own uid. The system mode (namespaces, a
//! separate uid, an nftables floor) needs root and is not implemented here.
//!
//! Two halves:
//! - the **parent side** (the miner): [`delegated_root`] makes the miner's own delegated cgroup
//!   usable, [`Cgroup`] creates one cgroup per sandboxed process with resource caps, and
//!   [`prepare_command`] installs a `pre_exec` hook that moves the child into that cgroup before
//!   `exec` (so caps apply from the new program's first instruction), places the listed fds at fixed
//!   numbers, sets `NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)` (re-checked with `getppid`),
//!   `RLIMIT_CORE=0`, and makes sure no other fd survives the `exec` and none of the miner's
//!   environment reaches the child;
//! - the **child side** (the sandboxed binary itself, at startup, before it starts threads or reads
//!   any untrusted input): [`restrict_self`] applies Landlock (no filesystem access, no TCP
//!   bind/connect, scoped signals and abstract Unix sockets), a seccomp denylist (no `socket`,
//!   `connect`, `bind`, `listen` or `accept*` for any profile; no socket option but the broker's
//!   `TCP_NODELAY`; SysV IPC; metadata writes through inherited fds; for the runner and the
//!   worker, host metadata), `NO_NEW_PRIVS`, `PR_SET_DUMPABLE(0)` (locked) and `RLIMIT_CORE=0`.
//!   The broker, whose only socket calls are
//!   `socketpair(AF_UNIX, SOCK_STREAM)` for its runtime, then calls [`seal_socket_creation`] once
//!   its runtime is up. Its network connections are made for it by the miner's connector.
//!
//! The miner's inline measuring and proving workers, which run requester guests outside these
//! profiles (the GPU stack needs files, devices and threads a profile does not allow), confine
//! themselves with [`confine`] before their first guest: Landlock and seccomp, no sockets. An SP1
//! worker's `sp1-gpu-server` runs under [`supervise`].
//!
//! [`self_test`] checks the resulting *properties* (plan §10.3) by running the
//! `zkminer-witness-sandbox-probe` binary inside each sandbox profile, not just that calls
//! succeeded.
//!
//! # Requirements
//! - Linux with Landlock ABI >= 6 (Linux 6.12+), seccomp filters and cgroup v2.
//! - The miner must run in a **delegated** cgroup owned by its uid, e.g. launched with
//!   `systemd-run --user --scope -p Delegate=yes -- zkminer ...` (or a user unit with
//!   `Delegate=yes`), with `cpu`, `memory` and `pids` available. [`delegated_root`] asks the unit's
//!   systemd manager (`systemctl [--user] show --property=Delegate`) and fails with
//!   [`SandboxError::NotDelegated`] otherwise, before changing anything.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

mod cgroup;
pub mod confine;
#[doc(hidden)]
pub mod confine_probe;
pub mod netdeny;
#[doc(hidden)]
pub mod probe;
mod restrict;
mod selftest;
mod spawn;
pub mod supervise;

pub use cgroup::{delegated_root, Cgroup};
pub use restrict::{
    landlock_abi, restrict_self, seal_socket_creation, set_socket_option, SocketOption, BROKER_SOCKET_OPTION,
    MIN_LANDLOCK_ABI, REFUSED_SOCKET_OPTIONS,
};
pub use selftest::{self_test, self_test_profile};
pub use spawn::prepare_command;

/// Which mode the operator configured (`[witness] sandbox_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Namespaces, a separate uid and an nftables floor, set up by `zkminer witness setup` (root).
    /// Not implemented by this crate: [`self_test`] reports it as a failed check.
    System,
    /// Landlock + seccomp + delegated cgroup under the miner's uid (no kernel egress floor).
    Rootless,
}

/// What a sandboxed process may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// The WASM builder runner: no filesystem, no network, no new processes.
    BuilderRunner,
    /// The CPU-only risc0 execute worker: no filesystem, no network, no new processes.
    ExecuteWorker,
    /// The broker: no filesystem except read-only `readable` paths and read-write `writable`
    /// directories (its quota'd spool), and **no network of its own**: `socket`, `connect`,
    /// `bind`, `listen` and `accept*` are denied outright, as for the runner and the worker, and
    /// Landlock handles TCP bind and connect with no rule. It keeps the fds it was started with:
    /// its control socket (fd 3) and its socket to the miner's connector (fd 4), which hands it
    /// already-connected TCP sockets to the operator's endpoints by `SCM_RIGHTS`, on which it may
    /// set `TCP_NODELAY` and no other option ([`REFUSED_SOCKET_OPTIONS`]). Its only way to
    /// make a socket is `socketpair(AF_UNIX, SOCK_STREAM, ..)` (a connected pair reaches nothing;
    /// tokio's signal driver makes one when the runtime starts), which
    /// [`seal_socket_creation`] then denies too. Every listed path must exist when
    /// [`restrict_self`] runs.
    Broker {
        readable: Vec<PathBuf>,
        writable: Vec<PathBuf>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("landlock is unavailable or too old (need ABI >= {need}, have {have})")]
    LandlockUnavailable { need: i32, have: i32 },
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error(
        "restrict_self must run before the process starts threads: {threads} threads in /proc/self/task"
    )]
    MultiThreaded { threads: usize },
    #[error(
        "cgroup {} is not a delegated cgroup this uid can manage ({reason}); run the miner under \
         `systemd-run --user --scope -p Delegate=yes -- ...` or a user unit with Delegate=yes",
        cgroup.display()
    )]
    NotDelegated { cgroup: PathBuf, reason: String },
    #[error("cgroup: {0}")]
    Cgroup(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// What [`restrict_self`] applied, each field verified after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictReport {
    /// The kernel's Landlock ABI (>= [`MIN_LANDLOCK_ABI`]).
    pub landlock_abi: i32,
    /// `prctl(PR_GET_SECCOMP) == 2` (filter mode) after installing the filters.
    pub seccomp: bool,
    /// `prctl(PR_GET_NO_NEW_PRIVS) == 1`.
    pub no_new_privs: bool,
    /// `prctl(PR_GET_DUMPABLE) == 0`.
    pub dumpable_cleared: bool,
    /// `RLIMIT_CORE` is 0 (soft and hard).
    pub core_dumps_disabled: bool,
}

/// Resource caps for one sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupSpec {
    /// Name of the child cgroup under the delegated root (one per job): 1–128 characters of
    /// `[A-Za-z0-9_-]`, starting with a letter or digit.
    pub name: String,
    /// `memory.max` in bytes (`memory.swap.max` is always 0).
    pub memory_max: u64,
    /// `pids.max`: processes *and threads*.
    pub pids_max: u32,
    /// `cpu.max` quota and period in microseconds, if limited.
    pub cpu_max: Option<(u64, u64)>,
    /// `cpu.weight`, 1..=10000 (the kernel default is 100).
    pub cpu_weight: u32,
}

/// One self-test check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// `<profile>/<check>`, e.g. `builder_runner/socket_inet`.
    pub name: String,
    pub passed: bool,
    /// What was observed (errno, values read back), for logs and the page.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    pub mode: SandboxMode,
    pub checks: Vec<Check>,
}

impl SelfTestReport {
    /// True when there is at least one check and every check passed.
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.passed)
    }

    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| !c.passed)
    }
}
