//! Parent side: the delegated cgroup v2 subtree and per-job cgroups.

use std::ffi::CString;
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{CgroupSpec, SandboxError};

/// Where the miner's own processes go inside its delegated cgroup (cgroup v2 forbids processes in
/// a cgroup that has controllers enabled for its children).
pub(crate) const SUPERVISOR: &str = "supervisor";
/// The parent of every per-job cgroup, returned by [`delegated_root`].
pub(crate) const SANDBOXES: &str = "sandboxes";
/// Controllers the sandboxes need.
pub(crate) const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
/// How long [`Cgroup::remove`] waits for a killed cgroup to empty.
const REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

fn cg_err(msg: impl Into<String>) -> SandboxError {
    SandboxError::Cgroup(msg.into())
}

fn io_ctx(path: &Path, e: std::io::Error) -> SandboxError {
    cg_err(format!("{}: {e}", path.display()))
}

fn read_file(path: &Path) -> Result<String, SandboxError> {
    std::fs::read_to_string(path).map_err(|e| io_ctx(path, e))
}

/// Writes `value` in a single `write(2)`, as cgroup interface files require.
fn write_file(path: &Path, value: &str) -> Result<(), std::io::Error> {
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(value.as_bytes())
}

fn write_ctl(path: &Path, value: &str) -> Result<(), SandboxError> {
    write_file(path, value)
        .map_err(|e| cg_err(format!("write {value:?} to {}: {e}", path.display())))
}

/// The cgroup v2 path in `/proc/<pid>/cgroup` (the `0::` line), e.g. `/user.slice/...`.
pub(crate) fn parse_proc_cgroup(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim_end)
        .filter(|p| p.starts_with('/'))
}

/// Undoes the octal escapes (`\040` etc.) of `/proc/self/mountinfo`.
fn unescape_mountinfo(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount point of the cgroup2 filesystem in `/proc/self/mountinfo` text.
pub(crate) fn parse_cgroup2_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        let (pre, post) = line.split_once(" - ")?;
        if post.split_whitespace().next()? != "cgroup2" {
            return None;
        }
        // id parent major:minor root mount_point ...
        let mount_point = pre.split_whitespace().nth(4)?;
        Some(PathBuf::from(unescape_mountinfo(mount_point)))
    })
}

/// A `key value` field of a flat-keyed cgroup file (`memory.events`, `cgroup.events`, ...).
pub(crate) fn parse_keyed(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == key).then_some(())?;
        it.next()?.parse().ok()
    })
}

/// Pids, one per line (`cgroup.procs`).
pub(crate) fn parse_pids(text: &str) -> Vec<i32> {
    text.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

/// Whether `memory.events` text records an OOM kill (`oom_kill` or `oom_group_kill` > 0).
pub(crate) fn events_record_oom_kill(memory_events: &str) -> bool {
    parse_keyed(memory_events, "oom_kill").unwrap_or(0) > 0
        || parse_keyed(memory_events, "oom_group_kill").unwrap_or(0) > 0
}

/// A cgroup name is one path component the kernel and every interface file agree on: 1–128 of
/// `[A-Za-z0-9_-]`, starting with a letter or digit (so never `.`, `..`, a hidden name, a slash,
/// or an interface-file-like `memory.max`).
pub(crate) fn validate_name(name: &str) -> Result<(), SandboxError> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(SandboxError::InvalidArgument(format!(
            "cgroup name {name:?} must be 1-128 of [A-Za-z0-9_-] starting with a letter or digit"
        )))
    }
}

fn validate_spec(spec: &CgroupSpec) -> Result<(), SandboxError> {
    validate_name(&spec.name)?;
    let bad = |m: String| Err(SandboxError::InvalidArgument(m));
    if spec.memory_max == 0 {
        return bad("memory_max must be > 0".into());
    }
    if spec.pids_max == 0 {
        return bad("pids_max must be > 0".into());
    }
    if !(1..=10_000).contains(&spec.cpu_weight) {
        return bad(format!("cpu_weight {} not in 1..=10000", spec.cpu_weight));
    }
    if let Some((quota, period)) = spec.cpu_max {
        if !(1_000..=1_000_000).contains(&period) || quota < 1_000 {
            return bad(format!(
                "cpu_max ({quota}, {period}) needs period 1000..=1000000 us and quota >= 1000 us"
            ));
        }
    }
    Ok(())
}

/// The mount point of cgroup2 (normally `/sys/fs/cgroup`).
pub(crate) fn cgroup2_mount() -> Result<PathBuf, SandboxError> {
    let text = read_file(Path::new("/proc/self/mountinfo"))?;
    parse_cgroup2_mount(&text)
        .ok_or_else(|| cg_err("no cgroup2 filesystem is mounted (cgroup v1 host?)"))
}

/// This process's cgroup directory.
pub(crate) fn own_cgroup() -> Result<PathBuf, SandboxError> {
    let mount = cgroup2_mount()?;
    let text = read_file(Path::new("/proc/self/cgroup"))?;
    let rel = parse_proc_cgroup(&text)
        .ok_or_else(|| cg_err("no cgroup v2 entry in /proc/self/cgroup"))?;
    Ok(mount.join(rel.trim_start_matches('/')))
}

fn euid() -> u32 {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() }
}

fn writable(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn owned_by_us(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.uid() == euid())
        .unwrap_or(false)
}

/// The controllers of [`CONTROLLERS`] missing from `cgroup.controllers` text.
pub(crate) fn missing_controllers(available: &str) -> Vec<&'static str> {
    CONTROLLERS
        .into_iter()
        .filter(|c| !available.split_whitespace().any(|a| a == *c))
        .collect()
}

/// Which systemd manager owns the unit a cgroup belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemdUnit {
    /// No unit on the path (a cgroup namespace root, a host without systemd): nothing to ask.
    None,
    /// A unit of the system manager (`systemctl show`).
    System(String),
    /// A unit of a user manager (`systemctl --user show`).
    User(String),
    /// A cgroup systemd never delegates to us: a slice, or a user manager's own `user@N.service`.
    NotDelegable(String),
}

/// The innermost systemd unit (`*.service` or `*.scope`) on cgroup path `rel` (relative to the
/// cgroup2 mount), and its manager: a user manager when a `user@<uid>.service` lies above it.
/// Components below the unit are the unit's own (delegated) subtree, e.g. `<unit>/supervisor`.
pub(crate) fn systemd_unit(rel: &Path) -> SystemdUnit {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    let is_user_manager = |p: &str| {
        p.strip_prefix("user@")
            .and_then(|r| r.strip_suffix(".service"))
            .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
    };
    for (i, p) in parts.iter().enumerate().rev() {
        if p.ends_with(".slice") {
            return SystemdUnit::NotDelegable(format!("{p} is a systemd slice"));
        }
        if p.ends_with(".service") || p.ends_with(".scope") {
            if is_user_manager(p) {
                return SystemdUnit::NotDelegable(format!("{p} is the user manager's own cgroup"));
            }
            return if parts[..i].iter().any(|q| is_user_manager(q)) {
                SystemdUnit::User(p.clone())
            } else {
                SystemdUnit::System(p.clone())
            };
        }
    }
    SystemdUnit::None
}

/// Asks the unit's systemd manager for its `Delegate` property; a problem unless it says `yes`.
///
/// systemd owns every cgroup of its units unless the unit has `Delegate=yes`: a user manager runs
/// as the user, so its units' cgroups are owned by the user whether delegated or not, and on a
/// reload or a property change it re-applies its own `cgroup.subtree_control` (which would remove
/// the job cgroups' `memory.max`, `pids.max` and `cpu.max` files, and with them the caps) and may
/// move or kill processes it finds in sub-cgroups. Ownership and controllers cannot tell the two
/// apart, so the manager is asked. If it cannot be asked (no `systemctl`, no bus), this fails
/// closed.
fn systemd_delegation_problem(rel: &Path) -> Option<String> {
    let (unit, user) = match systemd_unit(rel) {
        SystemdUnit::None => return None,
        SystemdUnit::NotDelegable(why) => {
            return Some(format!("{why}, which systemd never delegates"))
        }
        SystemdUnit::System(u) => (u, false),
        SystemdUnit::User(u) => (u, true),
    };
    let mut cmd = std::process::Command::new("systemctl");
    if user {
        cmd.arg("--user");
    }
    cmd.args(["show", "--property=Delegate", "--value", "--"])
        .arg(&unit)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let manager = if user {
        "the user manager"
    } else {
        "the system manager"
    };
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if value == "yes" {
                None
            } else {
                Some(format!(
                    "systemd unit {unit} has Delegate={value:?} ({manager})"
                ))
            }
        }
        Ok(out) => Some(format!(
            "could not ask {manager} whether {unit} is delegated: systemctl {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => Some(format!(
            "could not ask {manager} whether {unit} is delegated: systemctl: {e}"
        )),
    }
}

/// Why `dir` is not a cgroup this uid can manage, if it is not. Reads only: nothing is changed.
fn delegation_problem(dir: &Path) -> Option<String> {
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) => return Some(e.to_string()),
    };
    if meta.uid() != euid() {
        return Some(format!(
            "owned by uid {}, we are uid {}",
            meta.uid(),
            euid()
        ));
    }
    for f in ["", "cgroup.procs", "cgroup.subtree_control"] {
        let p = if f.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(f)
        };
        if !owned_by_us(&p) || !writable(&p) {
            return Some(format!(
                "{} is not owned by and writable for this uid",
                p.display()
            ));
        }
    }
    let rel = match cgroup2_mount() {
        Ok(m) => dir
            .strip_prefix(&m)
            .map(Path::to_path_buf)
            .unwrap_or_default(),
        Err(e) => return Some(e.to_string()),
    };
    if let Some(p) = systemd_delegation_problem(&rel) {
        return Some(p);
    }
    match std::fs::read_to_string(dir.join("cgroup.controllers")) {
        Ok(text) => {
            let missing = missing_controllers(&text);
            if !missing.is_empty() {
                return Some(format!(
                    "controllers {missing:?} are not available (cgroup.controllers: {:?})",
                    text.trim()
                ));
            }
        }
        Err(e) => return Some(format!("{}/cgroup.controllers: {e}", dir.display())),
    }
    None
}

fn mkdir_if_missing(dir: &Path) -> Result<(), SandboxError> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(io_ctx(dir, e)),
    }
}

/// Moves every process in `from` into `to` (both ours, `from` an ancestor of nothing but `to`'s
/// siblings), until `from` holds none.
fn move_all_procs(from: &Path, to: &Path) -> Result<(), SandboxError> {
    let dest = to.join("cgroup.procs");
    for _ in 0..100 {
        let pids = parse_pids(&read_file(&from.join("cgroup.procs"))?);
        if pids.is_empty() {
            return Ok(());
        }
        for pid in pids {
            match write_file(&dest, &pid.to_string()) {
                Ok(()) => {}
                // Exited in the meantime.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => {
                    return Err(cg_err(format!(
                        "move pid {pid} into {}: {e}",
                        dest.display()
                    )))
                }
            }
        }
    }
    Err(cg_err(format!(
        "{} keeps gaining processes",
        from.display()
    )))
}

/// Enables [`CONTROLLERS`] for the children of `dir`.
fn enable_controllers(dir: &Path) -> Result<(), SandboxError> {
    let available = read_file(&dir.join("cgroup.controllers"))?;
    let enabled = read_file(&dir.join("cgroup.subtree_control"))?;
    let mut want = Vec::new();
    for c in CONTROLLERS {
        if !available.split_whitespace().any(|a| a == c) {
            return Err(cg_err(format!(
                "controller {c} is not available in {} (has: {})",
                dir.display(),
                available.trim()
            )));
        }
        if !enabled.split_whitespace().any(|a| a == c) {
            want.push(format!("+{c}"));
        }
    }
    if want.is_empty() {
        return Ok(());
    }
    write_ctl(&dir.join("cgroup.subtree_control"), &want.join(" "))
}

/// The delegated cgroup v2 directory per-job cgroups are created in: `<own>/sandboxes`, where
/// `<own>` is this process's cgroup from `/proc/self/cgroup`.
///
/// Before changing anything it checks that `<own>` is delegated to this uid, else
/// [`SandboxError::NotDelegated`]:
/// - `<own>`, its `cgroup.procs` and its `cgroup.subtree_control` are owned by and writable for
///   this uid (the kernel's delegation model). The shell's `session-N.scope` is root-owned and does
///   not qualify;
/// - when `<own>` belongs to a systemd unit (the innermost `*.service`/`*.scope` on its path), that
///   unit's manager reports `Delegate=yes` (`systemctl [--user] show --property=Delegate`). Under a
///   user manager ownership proves nothing — the manager runs as the user, so every unit's cgroup
///   is the user's — and a manager that was not asked to delegate re-applies its own
///   `cgroup.subtree_control` on reloads, which would take the caps away. A slice, or the user
///   manager's own `user@N.service`, never qualifies; if `systemctl` cannot be asked, this fails;
/// - `cpu`, `memory` and `pids` are listed in `<own>/cgroup.controllers` (the parent grants them).
///
/// Launch the miner with `systemd-run --user --scope -p Delegate=yes -- zkminer ...` or from a
/// unit with `Delegate=yes`.
///
/// It then makes `<own>` usable under cgroup v2's rules: no process may live in a cgroup that
/// enables controllers for its children, and moving a process needs write access to the common
/// ancestor's `cgroup.procs`, so everything must stay inside `<own>`. Hence:
/// - create `<own>/supervisor` and move **every** process in `<own>` into it (all of them are this
///   uid's processes in a delegated scope: the miner, and e.g. cargo in tests);
/// - enable `+cpu +memory +pids` in `<own>/cgroup.subtree_control`;
/// - create `<own>/sandboxes` with the same controllers enabled, and return it.
///
/// Idempotent: a later call (from this process, now in `supervisor`, or from a child of it)
/// recognises `<own>/supervisor` and returns the same directory. Call it once at startup before
/// spawning workers; processes the miner spawns afterwards without [`crate::prepare_command`]
/// land in `supervisor` with it.
pub fn delegated_root() -> Result<PathBuf, SandboxError> {
    let mut own = own_cgroup()?;
    if own.file_name().is_some_and(|n| n == SUPERVISOR) {
        if let Some(parent) = own.parent() {
            if delegation_problem(parent).is_none() {
                own = parent.to_path_buf();
            }
        }
    }
    if let Some(reason) = delegation_problem(&own) {
        return Err(SandboxError::NotDelegated {
            cgroup: own,
            reason,
        });
    }

    let supervisor = own.join(SUPERVISOR);
    mkdir_if_missing(&supervisor)?;
    // A process forked between the move and the controller write lands in `<own>` again and makes
    // the write fail with EBUSY: retry.
    let mut last = None;
    for _ in 0..10 {
        move_all_procs(&own, &supervisor)?;
        match enable_controllers(&own) {
            Ok(()) => {
                last = None;
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        return Err(e);
    }

    let sandboxes = own.join(SANDBOXES);
    mkdir_if_missing(&sandboxes)?;
    enable_controllers(&sandboxes)?;
    Ok(sandboxes)
}

/// A cgroup the miner created and owns, one per sandboxed process.
///
/// Dropping it without [`Cgroup::remove`] still kills its processes and removes it, best effort
/// (waiting at most about a second).
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
    removed: bool,
}

impl Cgroup {
    /// Creates `spec.name` under `root` (see [`delegated_root`]) and writes its limits:
    /// `memory.max`, `memory.swap.max=0` (tolerating only a missing file, i.e. a kernel without
    /// swap accounting), `memory.oom.group=1` (an OOM kills the whole job), `pids.max`, `cpu.max`
    /// and `cpu.weight`. Fails if the name is invalid or already exists; on any error the directory
    /// is removed again.
    pub fn create(root: &Path, spec: &CgroupSpec) -> Result<Self, SandboxError> {
        validate_spec(spec)?;
        let path = root.join(&spec.name);
        std::fs::create_dir(&path).map_err(|e| io_ctx(&path, e))?;
        let cg = Cgroup {
            path,
            removed: false,
        };
        cg.write_limits(spec)?;
        Ok(cg)
    }

    fn write_limits(&self, spec: &CgroupSpec) -> Result<(), SandboxError> {
        write_ctl(&self.path.join("memory.max"), &spec.memory_max.to_string())?;
        let swap = self.path.join("memory.swap.max");
        match write_file(&swap, "0") {
            Ok(()) => {}
            // Without swap accounting (swapaccount=0 / no CONFIG_MEMCG_SWAP) the memory.swap.*
            // files do not exist; with memory.max present the cap still holds RSS.
            Err(e)
                if e.kind() == ErrorKind::NotFound
                    && !self.path.join("memory.swap.current").exists() => {}
            Err(e) => return Err(cg_err(format!("write \"0\" to {}: {e}", swap.display()))),
        }
        write_ctl(&self.path.join("memory.oom.group"), "1")?;
        write_ctl(&self.path.join("pids.max"), &spec.pids_max.to_string())?;
        let cpu_max = match spec.cpu_max {
            Some((quota, period)) => format!("{quota} {period}"),
            None => "max".to_string(),
        };
        write_ctl(&self.path.join("cpu.max"), &cpu_max)?;
        write_ctl(&self.path.join("cpu.weight"), &spec.cpu_weight.to_string())?;
        Ok(())
    }

    /// The cgroup's directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Kills every process in the cgroup (`cgroup.kill`, Linux 5.14+): `SIGKILL` to each, without
    /// the pid-reuse races of signalling pids, and reaching processes the miner could not signal.
    pub fn kill(&self) -> Result<(), SandboxError> {
        write_ctl(&self.path.join("cgroup.kill"), "1")
    }

    /// Whether any process is still in the cgroup (`cgroup.events` `populated`).
    pub fn populated(&self) -> Result<bool, SandboxError> {
        let text = read_file(&self.path.join("cgroup.events"))?;
        parse_keyed(&text, "populated")
            .map(|v| v != 0)
            .ok_or_else(|| {
                cg_err(format!(
                    "no populated field in {}/cgroup.events",
                    self.path.display()
                ))
            })
    }

    /// `memory.peak` in bytes, if the kernel exposes it.
    pub fn memory_peak(&self) -> Option<u64> {
        std::fs::read_to_string(self.path.join("memory.peak"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Whether the cgroup recorded an OOM kill (`memory.events` `oom_kill` or `oom_group_kill`
    /// > 0).
    pub fn oom_killed(&self) -> bool {
        std::fs::read_to_string(self.path.join("memory.events"))
            .map(|t| events_record_oom_kill(&t))
            .unwrap_or(false)
    }

    /// Kills, waits until `cgroup.events` reports `populated 0` (at most 5 s), and removes the
    /// cgroup directory.
    pub fn remove(mut self) -> Result<(), SandboxError> {
        let r = self.kill_and_rmdir(REMOVE_TIMEOUT);
        self.removed = true;
        r
    }

    fn kill_and_rmdir(&self, timeout: Duration) -> Result<(), SandboxError> {
        if !self.path.exists() {
            return Ok(());
        }
        self.kill()?;
        let deadline = Instant::now() + timeout;
        loop {
            if !self.populated()? {
                // The kernel may still be tearing down the last task briefly after populated
                // drops; rmdir then says EBUSY.
                match std::fs::remove_dir(&self.path) {
                    Ok(()) => return Ok(()),
                    Err(e)
                        if e.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline => {}
                    Err(e) => return Err(io_ctx(&self.path, e)),
                }
            } else if Instant::now() >= deadline {
                return Err(cg_err(format!(
                    "{} still populated {timeout:?} after cgroup.kill",
                    self.path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.kill_and_rmdir(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in [
            "job-1",
            "a",
            "selftest_123-runner",
            "0xabc",
            &"a".repeat(128),
        ] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "-x",
            "_x",
            "a/b",
            "../x",
            "a b",
            "memory.max",
            "a\0b",
            "é",
            &"a".repeat(129),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn spec_validation() {
        let spec = CgroupSpec {
            name: "j".into(),
            memory_max: 1 << 20,
            pids_max: 4,
            cpu_max: Some((50_000, 100_000)),
            cpu_weight: 10,
        };
        assert!(validate_spec(&spec).is_ok());
        assert!(validate_spec(&CgroupSpec {
            cpu_weight: 0,
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            cpu_weight: 10_001,
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            pids_max: 0,
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            memory_max: 0,
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            cpu_max: Some((500, 100_000)),
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            cpu_max: Some((50_000, 10)),
            ..spec.clone()
        })
        .is_err());
        assert!(validate_spec(&CgroupSpec {
            cpu_max: None,
            ..spec
        })
        .is_ok());
    }

    #[test]
    fn proc_cgroup() {
        let v2 = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p1-i2.scope\n";
        assert_eq!(
            parse_proc_cgroup(v2),
            Some("/user.slice/user-1000.slice/user@1000.service/app.slice/run-p1-i2.scope")
        );
        let hybrid = "12:pids:/user.slice\n1:name=systemd:/user.slice/x\n0::/user.slice/x.scope\n";
        assert_eq!(parse_proc_cgroup(hybrid), Some("/user.slice/x.scope"));
        assert_eq!(parse_proc_cgroup("0::/\n"), Some("/"));
        assert_eq!(parse_proc_cgroup("12:pids:/user.slice\n"), None);
        assert_eq!(parse_proc_cgroup(""), None);
    }

    #[test]
    fn mountinfo() {
        let text = "\
22 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
27 22 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate
";
        assert_eq!(
            parse_cgroup2_mount(text),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
        let escaped = "27 22 0:25 / /mnt/my\\040cgroups rw - cgroup2 none rw\n";
        assert_eq!(
            parse_cgroup2_mount(escaped),
            Some(PathBuf::from("/mnt/my cgroups"))
        );
        let v1 = "30 22 0:26 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n";
        assert_eq!(parse_cgroup2_mount(v1), None);
    }

    #[test]
    fn events() {
        let ev = "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n";
        assert_eq!(parse_keyed(ev, "max"), Some(12));
        assert_eq!(parse_keyed(ev, "oom"), Some(1));
        assert_eq!(parse_keyed(ev, "missing"), None);
        assert!(events_record_oom_kill(ev));
        assert!(events_record_oom_kill(
            "oom 1\noom_kill 0\noom_group_kill 2\n"
        ));
        assert!(!events_record_oom_kill(
            "low 0\nhigh 0\nmax 3\noom 1\noom_kill 0\noom_group_kill 0\n"
        ));
        assert!(!events_record_oom_kill(""));
        assert_eq!(parse_keyed("populated 1\nfrozen 0\n", "populated"), Some(1));
        // "oom" must not match the "oom_kill" line, and vice versa.
        assert_eq!(parse_keyed("oom_kill 5\n", "oom"), None);
    }

    #[test]
    fn controllers() {
        assert!(missing_controllers("cpuset cpu io memory hugetlb pids rdma misc\n").is_empty());
        assert_eq!(missing_controllers("memory pids\n"), vec!["cpu"]);
        assert_eq!(missing_controllers(""), vec!["cpu", "memory", "pids"]);
        // Whole words only.
        assert_eq!(missing_controllers("cpuset memory pids"), vec!["cpu"]);
    }

    #[test]
    fn systemd_units_on_a_path() {
        let u = |s: &str| systemd_unit(Path::new(s));
        let user = "user.slice/user-1000.slice/user@1000.service";
        assert_eq!(
            u(&format!("{user}/app.slice/run-p1-i2.scope")),
            SystemdUnit::User("run-p1-i2.scope".into())
        );
        // The unit's own subtree: still that unit.
        assert_eq!(
            u(&format!("{user}/app.slice/zkminer.service/supervisor")),
            SystemdUnit::User("zkminer.service".into())
        );
        assert_eq!(
            u("system.slice/zkminer.service"),
            SystemdUnit::System("zkminer.service".into())
        );
        assert_eq!(
            u("system.slice/zkminer.service/sandboxes"),
            SystemdUnit::System("zkminer.service".into())
        );
        assert!(matches!(
            u(&format!("{user}/app.slice")),
            SystemdUnit::NotDelegable(_)
        ));
        assert!(matches!(u(user), SystemdUnit::NotDelegable(_)));
        assert!(matches!(
            u(&format!("{user}/init.scope")),
            SystemdUnit::User(_)
        ));
        assert!(matches!(
            u("user.slice/user-1000.slice/session-1.scope"),
            SystemdUnit::System(_)
        ));
        assert_eq!(u(""), SystemdUnit::None);
        assert_eq!(u("my-container/workers"), SystemdUnit::None);
        // A name that only looks like a user manager.
        assert_eq!(
            u("system.slice/user@x.service/a.scope"),
            SystemdUnit::System("a.scope".into())
        );
    }

    #[test]
    fn pids() {
        assert_eq!(parse_pids("12\n345\n\n"), vec![12, 345]);
        assert!(parse_pids("").is_empty());
    }
}
