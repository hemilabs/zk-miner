//! Nothing a worker starts outlives it.
//!
//! Workers that run requester guests are confined (`zkminer_witness_sandbox::confine`), and a guest
//! that escaped its executor can fork. What it starts must end with the worker: the confinement
//! refuses `setsid` and `setpgid`, so it cannot leave the worker's process group, and this module
//! makes sure it can neither outlive the miner nor run on once a filesystem that is not local
//! appears in the mount table.
//!
//! - **A cgroup of its own.** Where the miner runs in a cgroup delegated to it
//!   ([`zkminer_witness_sandbox::delegated_root`], as witness jobs need), each worker starts in a
//!   new `zkminer-worker-<miner pid>-<n>` below it, joined in the child before `exec`, so everything
//!   it ever starts is inside, with the worker's memory ceiling as its `memory.max`. Elsewhere the
//!   worker is adopted into a transient scope of the user's systemd manager
//!   (`memory::cap_process_memory`), and its handle waits until the scope holds it before the
//!   worker is sent anything. Every end of a worker writes that cgroup's `cgroup.kill`, which
//!   reaches every process in it whatever its process group; without either cgroup the worker's
//!   process group is killed, as before.
//! - **The reaper.** A small process in a session of its own (`/bin/sh` running [`REAPER_SCRIPT`])
//!   holds the list of live workers, read from a pipe only the miner writes. When the pipe ends —
//!   the miner is gone, however it died — it kills each worker's cgroup and process group. No
//!   worker starts without it.
//! - **The mount watch.** A thread of the miner, outside every confinement (no guest can stop it),
//!   watches the mount table and kills every worker when a mount they could reach is not local
//!   ([`zkminer_witness_sandbox::localfs::check_mount_table`]); the workers started after that
//!   refuse to run a guest until it is gone.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use zkminer_witness_sandbox::{Cgroup, CgroupSpec};

/// The prefix of the cgroups this module makes for workers below a delegated root.
pub const WORKER_CGROUP_PREFIX: &str = "zkminer-worker-";

/// How long a handle waits for systemd to move a worker into its scope.
pub(crate) const SCOPE_WAIT: Duration = Duration::from_secs(3);

/// A memory ceiling for a worker cgroup when none could be sized: no limit in practice.
const NO_CEILING: u64 = 1 << 50;

/// Threads count as tasks: CUDA, rayon and the SP1 server start many. Below the kernel's
/// `PID_MAX_LIMIT`, which `pids.max` must stay under.
const WORKER_PIDS_MAX: u32 = 1 << 20;

/// The reaper. Lines on stdin: `add <pid> <kill target> <cgroup dir or ->` and `del <pid>`. At the
/// end of stdin it writes `cgroup.kill` of every cgroup listed and SIGKILLs every target (`-<pgid>`
/// for a worker that leads its process group, else its pid). POSIX `sh`: no allocation-free code
/// after `fork` in a multi-threaded miner, and none of the miner's memory or descriptors held.
pub const REAPER_SCRIPT: &str = r#"set -f
nl='
'
live=''
while IFS= read -r line; do
  case $line in
    'add '*) live="$live$nl${line#add }" ;;
    'del '*)
      gone=${line#del }
      keep=''
      IFS=$nl
      for e in $live; do
        case $e in "$gone "*) ;; *) keep="$keep$nl$e" ;; esac
      done
      unset IFS
      live=$keep ;;
  esac
done
IFS=$nl
for e in $live; do
  rest=${e#* }
  target=${rest%% *}
  dir=${rest#* }
  if [ "$dir" != - ]; then { echo 1 > "$dir/cgroup.kill"; } 2>/dev/null; fi
  kill -s KILL -- "$target" 2>/dev/null
done
"#;

/// What the miner knows about a live worker.
struct Live {
    /// The leaf name of the worker's cgroup, for the memory readers' provenance check.
    leaf: Option<String>,
    /// The worker's cgroup directory, whose `cgroup.kill` ends it.
    dir: Option<PathBuf>,
    /// A cgroup this module made (delegated), removed when the worker ends.
    owned: Option<Cgroup>,
    /// Whether the worker leads its own process group.
    leads_group: bool,
}

/// Live workers by pid. A pid stays here until just before its handle reaps it, so the number is
/// pinned (a zombie at worst) for as long as anything here may signal it.
static LIVE: Mutex<BTreeMap<u32, Live>> = Mutex::new(BTreeMap::new());

struct Reaper {
    child: Child,
    stdin: ChildStdin,
}

/// Lock order: `REAPER`, then `LIVE`.
static REAPER: Mutex<Option<Reaper>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The delegated cgroup root, if the miner runs in one (looked up once).
fn delegated_root() -> Option<&'static Path> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| match zkminer_witness_sandbox::delegated_root() {
        Ok(root) => {
            remove_stale(&root);
            tracing::info!(
                "workers start in cgroups of their own below {}",
                root.display()
            );
            Some(root)
        }
        Err(e) => {
            tracing::info!(
                "the miner's cgroup is not delegated to it ({e}); workers are adopted into scopes \
                 of the user's systemd manager instead"
            );
            None
        }
    })
    .as_deref()
}

/// Worker cgroups left below `root` by a miner that is gone (its reaper killed too): killed and
/// removed, in the background.
fn remove_stale(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let me = std::process::id();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(owner) = name
            .strip_prefix(WORKER_CGROUP_PREFIX)
            .and_then(|r| r.split('-').next())
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        if owner == me || Path::new(&format!("/proc/{owner}")).exists() {
            continue;
        }
        let dir = e.path();
        tracing::warn!(
            "killing and removing {}, a worker cgroup of a miner that is gone",
            dir.display()
        );
        let _ = std::thread::Builder::new()
            .name("zkminer-stale-cgroup".into())
            .spawn(move || remove_dir_when_empty(&dir));
    }
}

/// `cgroup.kill`, then `rmdir` once the cgroup is empty (a task in uninterruptible sleep inside a
/// GPU driver can take a while to go).
fn remove_dir_when_empty(dir: &Path) {
    let until = Instant::now() + Duration::from_secs(120);
    loop {
        let _ = std::fs::write(dir.join("cgroup.kill"), "1");
        match std::fs::remove_dir(dir) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) if Instant::now() >= until => {
                tracing::warn!("cannot remove the worker cgroup {}: {e}", dir.display());
                return;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// A cgroup made for a worker about to be spawned, and the fd its child joins it through.
pub(crate) struct Prepared {
    cgroup: Cgroup,
    procs: OwnedFd,
}

impl Prepared {
    /// For the launch hook: [`zkminer_witness_sandbox::join_cgroup_in_child`].
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// The cgroup's leaf name.
    pub(crate) fn leaf(&self) -> String {
        self.cgroup
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// Before a worker is spawned: the reaper and the mount watch running (an error means no worker may
/// start), and, below a delegated root, a cgroup of its own with `memory_max` as its ceiling.
pub(crate) fn prepare(memory_max: Option<u64>) -> Result<Option<Prepared>, String> {
    ensure_reaper()?;
    start_mount_watch()?;
    let Some(root) = delegated_root() else {
        return Ok(None);
    };
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "{WORKER_CGROUP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let spec = CgroupSpec {
        name,
        memory_max: memory_max.unwrap_or(NO_CEILING),
        pids_max: WORKER_PIDS_MAX,
        cpu_max: None,
        cpu_weight: 100,
    };
    let cgroup = Cgroup::create(root, &spec)
        .map_err(|e| format!("the worker's cgroup below {}: {e}", root.display()))?;
    let procs = zkminer_witness_sandbox::cgroup_procs_fd(&cgroup).map_err(|e| e.to_string())?;
    Ok(Some(Prepared { cgroup, procs }))
}

/// After the spawn: the worker in its own cgroup, made by [`prepare`].
pub(crate) fn started_in(pid: u32, prepared: Prepared) {
    let leaf = prepared.leaf();
    let dir = prepared.cgroup.path().to_path_buf();
    register(pid, Some(leaf), Some(dir), Some(prepared.cgroup));
}

/// After the spawn: the worker adopted into the systemd scope `unit` (waited for here, at most
/// [`SCOPE_WAIT`]), or into nothing (`None`). Returns the scope's directory if the worker is in it.
pub(crate) fn started_in_scope(pid: u32, unit: Option<&str>) -> Option<PathBuf> {
    let dir = unit.and_then(|u| await_scope(pid, u, SCOPE_WAIT));
    register(
        pid,
        unit.filter(|_| dir.is_some()).map(str::to_string),
        dir.clone(),
        None,
    );
    dir
}

/// Waits until `pid` is in the cgroup whose leaf is `unit`; its directory then.
fn await_scope(pid: u32, unit: &str, budget: Duration) -> Option<PathBuf> {
    let until = Instant::now() + budget;
    loop {
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            let rel = text
                .lines()
                .next()
                .and_then(|l| l.rsplit_once("::"))
                .map(|(_, p)| p.trim().to_string());
            if let Some(rel) = rel {
                if rel.rsplit('/').next() == Some(unit) {
                    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
                    return dir.join("cgroup.kill").exists().then_some(dir);
                }
            }
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn register(pid: u32, leaf: Option<String>, dir: Option<PathBuf>, owned: Option<Cgroup>) {
    // SAFETY: getpgid of a pid this process spawned and has not reaped.
    let leads_group = unsafe { libc::getpgid(pid as libc::pid_t) } == pid as libc::pid_t;
    let line = add_line(pid, leads_group, dir.as_deref());
    let mut reaper = lock(&REAPER);
    lock(&LIVE).insert(
        pid,
        Live {
            leaf,
            dir,
            owned,
            leads_group,
        },
    );
    if let Err(e) = send(&mut reaper, &line) {
        tracing::error!("the worker reaper: {e}; a worker may outlive a miner that dies abruptly");
    }
}

fn add_line(pid: u32, leads_group: bool, dir: Option<&Path>) -> String {
    let target = if leads_group {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    let dir = dir
        .and_then(Path::to_str)
        .filter(|d| !d.contains('\n') && !d.is_empty())
        .unwrap_or("-");
    format!("add {pid} {target} {dir}\n")
}

/// The leaf name of `pid`'s cgroup as this module registered it, or the scope name
/// `memory::cap_process_memory` gives it: what the memory readers require the worker's cgroup to
/// be called before they trust its counters.
pub fn cgroup_leaf(backend: &str, pid: u32) -> String {
    lock(&LIVE)
        .get(&pid)
        .and_then(|l| l.leaf.clone())
        .unwrap_or_else(|| crate::memory::cap_unit_name(backend, pid))
}

/// The worker `pid` ends (call before reaping it): its cgroup killed, its registration gone, a
/// cgroup made for it removed once empty.
pub(crate) fn end(pid: u32) {
    let live = {
        let mut reaper = lock(&REAPER);
        let live = lock(&LIVE).remove(&pid);
        if live.is_some() {
            let _ = send(&mut reaper, &format!("del {pid}\n"));
        }
        live
    };
    let Some(live) = live else { return };
    if let Some(dir) = &live.dir {
        let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    }
    if let Some(cg) = live.owned {
        let dir = cg.path().to_path_buf();
        // `remove_dir_when_empty` takes over; the handle's own removal would wait here.
        std::mem::forget(cg);
        let _ = std::thread::Builder::new()
            .name("zkminer-worker-cgroup".into())
            .spawn(move || remove_dir_when_empty(&dir));
    }
}

/// Kills every live worker: its cgroup, else its process group (or itself). Their handles see the
/// death and respawn them.
fn kill_all() -> usize {
    let live = lock(&LIVE);
    for (&pid, l) in live.iter() {
        if let Some(dir) = &l.dir {
            let _ = std::fs::write(dir.join("cgroup.kill"), "1");
        }
        let target = if l.leads_group {
            -(pid as libc::pid_t)
        } else {
            pid as libc::pid_t
        };
        // SAFETY: a registered pid is unreaped (see `LIVE`), so neither number is recycled.
        unsafe { libc::kill(target, libc::SIGKILL) };
    }
    live.len()
}

/// Starts the reaper if it is not running (or has died), registering every live worker with it.
fn ensure_reaper() -> Result<(), String> {
    let mut reaper = lock(&REAPER);
    let alive = reaper
        .as_mut()
        .is_some_and(|r| matches!(r.child.try_wait(), Ok(None)));
    if alive {
        return Ok(());
    }
    restart(&mut reaper)
}

fn restart(reaper: &mut Option<Reaper>) -> Result<(), String> {
    if let Some(mut old) = reaper.take() {
        let _ = old.child.kill();
        let _ = old.child.wait();
    }
    let mut cmd = Command::new("/bin/sh");
    cmd.arg0("zkminer-worker-reaper")
        .args(["-c", REAPER_SCRIPT])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe. A session of its own: the terminal's signals for the
    // miner's process group (Ctrl-C, a hang-up) do not reach it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start the worker reaper (/bin/sh): {e}"))?;
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the worker reaper has no stdin".into());
    };
    let mut r = Reaper { child, stdin };
    let lines: Vec<String> = lock(&LIVE)
        .iter()
        .map(|(&pid, l)| add_line(pid, l.leads_group, l.dir.as_deref()))
        .collect();
    for line in lines {
        r.stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("registering with the worker reaper: {e}"))?;
    }
    *reaper = Some(r);
    Ok(())
}

/// One line to the reaper, restarting it once if it is gone.
fn send(reaper: &mut Option<Reaper>, line: &str) -> Result<(), String> {
    if let Some(r) = reaper.as_mut() {
        if r.stdin.write_all(line.as_bytes()).is_ok() {
            return Ok(());
        }
    }
    // `restart` registers every live worker, this one's change included.
    restart(reaper)
}

/// The miner's own mount watch (see the module docs), started once.
fn start_mount_watch() -> Result<(), String> {
    static STARTED: OnceLock<Result<(), String>> = OnceLock::new();
    STARTED
        .get_or_init(|| {
            use std::io::{Read, Seek};
            let mut table = std::fs::File::open("/proc/self/mountinfo")
                .map_err(|e| format!("the mount table: {e}"))?;
            let mut sink = Vec::new();
            table
                .read_to_end(&mut sink)
                .map_err(|e| format!("the mount table: {e}"))?;
            std::thread::Builder::new()
                .name("zkminer-worker-mounts".into())
                .spawn(move || loop {
                    let mut pfd = libc::pollfd {
                        fd: table.as_raw_fd(),
                        events: libc::POLLPRI,
                        revents: 0,
                    };
                    // SAFETY: one valid pollfd.
                    let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
                    if rc < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        tracing::error!(
                            "the mount watch failed ({}); killing every worker",
                            std::io::Error::last_os_error()
                        );
                        kill_all();
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                    // Reading the table again from the start acknowledges the change.
                    sink.clear();
                    let reread = table.rewind().and_then(|()| table.read_to_end(&mut sink));
                    let verdict = match reread {
                        Err(e) => Err(format!("reading the mount table: {e}")),
                        Ok(_) => zkminer_witness_sandbox::localfs::check_mount_table()
                            .map(|_| ())
                            .map_err(|e| e.to_string()),
                    };
                    if let Err(e) = verdict {
                        let n = kill_all();
                        tracing::error!(
                            "a filesystem the workers could reach is not local ({e}): killed \
                             {n} worker(s); no guest runs until it is unmounted"
                        );
                    }
                })
                .map(|_| ())
                .map_err(|e| format!("the mount watch thread: {e}"))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reaper script, driven as the miner drives it: registered workers (a process group, a
    /// lone process, one removed again) are killed when its stdin ends, and only those.
    #[test]
    fn the_reaper_kills_what_is_registered_when_the_miner_goes() {
        let spawn_leader = || {
            let mut c = Command::new("sleep");
            c.arg("300").process_group(0);
            c.spawn().unwrap()
        };
        let mut group = spawn_leader();
        // A member of `group`'s process group that is not its child.
        let member = {
            let mut c = Command::new("sleep");
            c.arg("300").process_group(group.id() as i32);
            c.spawn().unwrap()
        };
        let mut member = member;
        let mut lone = Command::new("sleep").arg("300").spawn().unwrap();
        let mut removed = spawn_leader();
        let mut reaper = Command::new("/bin/sh")
            .args(["-c", REAPER_SCRIPT])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut w = reaper.stdin.take().unwrap();
        let lines = [
            add_line(group.id(), true, None),
            add_line(lone.id(), false, Some(Path::new("/nonexistent/cgroup dir"))),
            add_line(removed.id(), true, None),
            format!("del {}\n", removed.id()),
        ];
        for l in &lines {
            w.write_all(l.as_bytes()).unwrap();
        }
        drop(w);
        assert!(reaper.wait().unwrap().success());
        use std::os::unix::process::ExitStatusExt;
        for (what, c) in [
            ("group leader", &mut group),
            ("group member", &mut member),
            ("lone", &mut lone),
        ] {
            let st = c.wait().unwrap();
            assert_eq!(st.signal(), Some(libc::SIGKILL), "{what}: {st:?}");
        }
        assert!(
            matches!(removed.try_wait(), Ok(None)),
            "a worker removed from the list was killed"
        );
        let _ = removed.kill();
        let _ = removed.wait();
    }

    #[test]
    fn registration_lines() {
        assert_eq!(add_line(7, true, None), "add 7 -7 -\n");
        assert_eq!(
            add_line(7, false, Some(Path::new("/sys/fs/cgroup/a b"))),
            "add 7 7 /sys/fs/cgroup/a b\n"
        );
        assert_eq!(add_line(7, true, Some(Path::new("/x\ny"))), "add 7 -7 -\n");
    }
}
