//! Process sandbox for witness builders, execute workers and the broker (plan §10.2, §10.3).
//!
//! Two halves:
//! - the **parent side** (the miner): [`Cgroup`] creates a cgroup in the user's delegated cgroup v2
//!   subtree with resource caps, and [`prepare_command`] installs a `pre_exec` hook that moves the
//!   child into that cgroup before `exec` (so caps apply from the child's first instruction), sets
//!   `NO_NEW_PRIVS`, `PR_SET_PDEATHSIG` (re-checked with `getppid`), `RLIMIT_CORE=0`, and closes every
//!   fd except the ones listed;
//! - the **child side** (the sandboxed binary itself, at startup, before it reads any untrusted
//!   input): [`restrict_self`] applies Landlock (no filesystem access, no TCP bind/connect except the
//!   profile's ports, scoped signals and abstract Unix sockets), a seccomp denylist, and
//!   `PR_SET_DUMPABLE(0)`.
//!
//! [`self_test`] checks the resulting *properties* (plan §10.3), not just that calls succeeded.
//!
//! This host-independent API is fixed for milestone 2; bodies are filled in by the sandbox work.

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which mode the operator configured (`[witness] sandbox_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Namespaces, a separate uid and an nftables floor, set up by `zkminer witness setup` (root).
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
    /// The broker: no filesystem except read-only `readable` paths (its endpoints file), outbound TCP
    /// only to `tcp_connect_ports`.
    Broker { readable: Vec<PathBuf>, tcp_connect_ports: Vec<u16> },
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("landlock is unavailable or too old (need ABI >= {need}, have {have})")]
    LandlockUnavailable { need: i32, have: i32 },
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error("cgroup: {0}")]
    Cgroup(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// What [`restrict_self`] applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictReport {
    pub landlock_abi: i32,
    pub seccomp: bool,
    pub no_new_privs: bool,
    pub dumpable_cleared: bool,
}

/// Child side: applies the profile to the calling process (all threads created afterwards inherit
/// it; call it before spawning threads that must be restricted, and before reading untrusted input).
pub fn restrict_self(profile: &Profile) -> Result<RestrictReport, SandboxError> {
    let _ = profile;
    todo!("milestone 2: sandbox crate")
}

/// Resource caps for one sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupSpec {
    /// Name of the child cgroup under the delegated root (one per job).
    pub name: String,
    pub memory_max: u64,
    pub pids_max: u32,
    /// `cpu.max` quota and period in microseconds, if limited.
    pub cpu_max: Option<(u64, u64)>,
    pub cpu_weight: u32,
}

/// A cgroup the miner created and owns.
#[derive(Debug)]
pub struct Cgroup {
    pub path: PathBuf,
}

impl Cgroup {
    /// Creates `spec.name` under `root` (see [`delegated_root`]) and writes its limits
    /// (`memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`, `cpu.weight`).
    pub fn create(root: &Path, spec: &CgroupSpec) -> Result<Self, SandboxError> {
        let _ = (root, spec);
        todo!("milestone 2: sandbox crate")
    }

    /// Kills every process in the cgroup (`cgroup.kill`).
    pub fn kill(&self) -> Result<(), SandboxError> {
        todo!("milestone 2: sandbox crate")
    }

    /// `memory.peak` in bytes, if the kernel exposes it.
    pub fn memory_peak(&self) -> Option<u64> {
        todo!("milestone 2: sandbox crate")
    }

    /// Whether the cgroup recorded an OOM kill (`memory.events` oom_kill > 0).
    pub fn oom_killed(&self) -> bool {
        todo!("milestone 2: sandbox crate")
    }

    /// Kills, waits for emptiness, and removes the cgroup directory.
    pub fn remove(self) -> Result<(), SandboxError> {
        todo!("milestone 2: sandbox crate")
    }
}

/// The delegated cgroup v2 directory this process may create children in (for a systemd user
/// session, a sub-cgroup of `user@<uid>.service`; created if needed).
pub fn delegated_root() -> Result<PathBuf, SandboxError> {
    todo!("milestone 2: sandbox crate")
}

/// Parent side: configures `cmd` so the child joins `cgroup` before `exec`, gets `NO_NEW_PRIVS`,
/// `PR_SET_PDEATHSIG(SIGKILL)` (then exits if the parent already died), `RLIMIT_CORE=0`, and keeps
/// only fds 0–2 plus `keep_fds` (which must already be at their intended numbers).
pub fn prepare_command(cmd: &mut Command, cgroup: &Cgroup, keep_fds: &[RawFd]) -> Result<(), SandboxError> {
    let _ = (cmd, cgroup, keep_fds);
    todo!("milestone 2: sandbox crate")
}

/// One self-test check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    pub mode: SandboxMode,
    pub checks: Vec<Check>,
}

impl SelfTestReport {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

/// Runs the self-test (plan §10.3) by spawning `probe_binary` under each profile: the probe tries
/// the forbidden operations and reports which succeeded. `secret_path` is a file the probe must not
/// be able to read (e.g. `~/.zkminer/config.toml`).
pub fn self_test(mode: SandboxMode, probe_binary: &Path, secret_path: &Path) -> SelfTestReport {
    let _ = (mode, probe_binary, secret_path);
    todo!("milestone 2: sandbox crate")
}
