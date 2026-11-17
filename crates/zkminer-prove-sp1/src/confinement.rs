//! Workers that run requester guests are confined (`zkminer_witness_sandbox::confine`), and so is
//! the `sp1-gpu-server` an SP1 worker starts, which runs the guests of every proof.
//!
//! **The worker.** The first command that runs a guest or reaches the server (`Execute`,
//! `ProgramId`, `Prove`, `Benchmark`) first confines this process, every thread it has and
//! everything it starts, for the rest of its life ([`confine`]): no new socket, no `connect` (only
//! Unix stream and seqpacket pairs, which the SDK's tokio runtime and Rust's `Command` make, and
//! which connect only their two ends). A worker that only measures ([`crate::sp1_measure_only`])
//! keeps no socket. A proving worker first starts its server and connects to it (`build_prover`),
//! then confines itself keeping that one connection and nothing else. Files: read the system's, this binary's directory,
//! `LD_LIBRARY_PATH` and `~/.sp1`; write only its private temporary directory (`TMPDIR`, made at
//! startup by [`prepare`], where the SDK's executor puts its runner, which it may also execute).
//! Nothing in `/dev/shm`: SP1's executor shares the guest's memory and trace ring with its runner
//! through file descriptors (memfds), which no path reaches, and what SP1's final-wrap provers would
//! put in `/dev/shm` goes to the private directory too (`SP1_SHM_DIR`). No signal to the miner or
//! another worker; `/proc` is readable (the executor's memory monitor reads its runner child's
//! entries), but not another process's memory or environment.
//!
//! **The server.** The SDK starts the server as `~/.sp1/bin/<SP1_GPU_SERVER_NAME>`. A proving worker
//! points that name at [`SHIM_PREFIX`]`<the real name>`, a link to this binary, and the real
//! server's path in [`REAL_SERVER_ENV`] ([`route_server_through_shim`]). Started under that name,
//! this binary is the shim ([`run_if_shim`]): it runs the real server confined, under a supervisor
//! (`zkminer_witness_sandbox::supervise`): its own listener and the CUDA driver's until it accepts
//! its first connection, no socket, `bind` or `listen` after, never `connect`; Landlock as for the
//! worker, plus executing itself (its Groth16 CPU helper), the host-wide Groth16 queue's lock files
//! (`SP1_GROTH16_QUEUE_DIR`, `~/.zkminer/locks` unless the operator put it elsewhere) and creating
//! its socket under `/tmp`; `/dev/null` for stdin. The server's socket is therefore
//! `/tmp/zkminer-confined-<name>-<id>.sock`.
//! The server ends when the worker does.
//!
//! Neither may change a file's mode. The SDK's executor unpacks its runner into `TMPDIR` and makes
//! it executable: the worker puts its runner there before it confines itself, without running
//! anything (`place_executor_runner`, in `main`), and the server's supervisor makes the server's
//! executable for it (the runner directory given to `run_supervised`).
//!
//! The one-time setup that needs the network (`Warmup`: the Groth16 circuit download) runs before;
//! a `Warmup` after refuses rather than download. A server the SDK would download (absent, or another
//! version) is refused (`server_needs_no_download`).

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

/// The prefix of the name the SDK runs the server under, which makes this binary the shim.
pub(crate) const SHIM_PREFIX: &str = "zkminer-confined-";

/// The absolute path of the real `sp1-gpu-server`, for the shim.
#[cfg(target_os = "linux")]
pub(crate) const REAL_SERVER_ENV: &str = "ZKMINER_SP1_REAL_SERVER";

/// The name the SDK runs the server under, and names its socket after: `SP1_GPU_SERVER_NAME` as it
/// is now (the shim's name once [`route_server_through_shim`] ran), else the SDK's default.
#[cfg(target_os = "linux")]
pub(crate) fn sdk_server_name() -> String {
    std::env::var("SP1_GPU_SERVER_NAME")
        .ok()
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .unwrap_or_else(|| "sp1-gpu-server".to_string())
}

/// `~/.sp1/bin`, as the SDK finds it.
#[cfg(target_os = "linux")]
fn sp1_bin_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".sp1/bin"))
}

/// Whether the SDK will start the server through the shim: the name it runs points at a link to this
/// binary and the real server is named. `build_prover` starts no server otherwise.
#[cfg(target_os = "linux")]
pub(crate) fn server_routed_through_shim() -> Result<(), String> {
    let name = sdk_server_name();
    if !name.starts_with(SHIM_PREFIX) {
        return Err(format!(
            "SP1_GPU_SERVER_NAME is {name:?}, not the confining shim: the server would run \
             unconfined"
        ));
    }
    let real = std::env::var_os(REAL_SERVER_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .ok_or_else(|| format!("{REAL_SERVER_ENV} names no server"))?;
    let shim = sp1_bin_dir().ok_or("$HOME is not set")?.join(&name);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let target = std::fs::canonicalize(&shim).map_err(|e| format!("{}: {e}", shim.display()))?;
    if target != std::fs::canonicalize(&exe).map_err(|e| e.to_string())? {
        return Err(format!(
            "{} is not this worker ({}), so it would not confine the server",
            shim.display(),
            exe.display()
        ));
    }
    let _ = real;
    Ok(())
}

/// At startup, while the process has one thread, for a worker that proves: makes the SDK start the
/// server through the shim (see the module docs). The real server stays where it is
/// (`warmup::server_path`); the link `~/.sp1/bin/zkminer-confined-<name>` to this binary is (re)made.
#[cfg(target_os = "linux")]
pub(crate) fn route_server_through_shim() -> Result<(), String> {
    let real = crate::warmup::server_path().map_err(|e| e.to_string())?;
    let real_name = crate::warmup::server_name();
    let shim_name = format!("{SHIM_PREFIX}{real_name}");
    let dir = sp1_bin_dir().ok_or("$HOME is not set")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The servers' host-wide Groth16 queue (lock files): the miner's (as the dispatcher sets it),
    // never `/dev/shm`, which a confined server cannot reach: an operator's directory there is
    // refused, as the server's confinement would grant it. It must exist before the server is
    // confined to it; where it cannot be made, SP1 proves without the queue, and says so. The
    // default, `~/.zkminer/locks`, is private to this user.
    let queue = std::env::var_os("SP1_GROTH16_QUEUE_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| zkminer_prover_protocol::types::sp1_groth16_queue_dir(&h)))
        .ok_or("$HOME is not set")?;
    if imp::reaches_dev_shm(&queue) {
        return Err(format!(
            "SP1_GROTH16_QUEUE_DIR is {}, which is or holds /dev/shm: a confined SP1 server is \
             given no part of /dev/shm. Point it at a directory on disk, or unset it for \
             ~/.zkminer/locks",
            queue.display()
        ));
    }
    if home().is_some_and(|h| queue == zkminer_prover_protocol::types::sp1_groth16_queue_dir(&h)) {
        private_dir(&queue);
    } else {
        let _ = std::fs::create_dir_all(&queue);
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let link = dir.join(&shim_name);
    let current = std::fs::read_link(&link).ok();
    if current.as_deref() != Some(exe.as_path()) {
        // A new link under a temporary name, renamed over the old one: never a moment without it.
        let tmp = dir.join(format!(".{shim_name}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&exe, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &link).map_err(|e| format!("{}: {e}", link.display()))?;
    }
    // SAFETY: called from `main` before any thread exists.
    unsafe {
        std::env::set_var(REAL_SERVER_ENV, &real);
        std::env::set_var("SP1_GPU_SERVER_NAME", &shim_name);
        std::env::set_var("SP1_GROTH16_QUEUE_DIR", &queue);
    }
    server_routed_through_shim()
}

/// Makes `dir` (and its parents) with mode 0700, or makes an existing one of this user's 0700: the
/// default Groth16 queue's lock files are this user's alone. Best effort, as making the queue is.
#[cfg(target_os = "linux")]
fn private_dir(dir: &Path) {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if let Some(parent) = dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Not through a link: only a directory of this user's own is changed.
            let Ok(meta) = std::fs::symlink_metadata(dir) else {
                return;
            };
            // SAFETY: geteuid has no preconditions.
            let me = unsafe { libc::geteuid() };
            if meta.is_dir() && meta.uid() == me && meta.mode() & 0o077 != 0 {
                if let Err(e) =
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                {
                    tracing::warn!("cannot make {} private: {e}", dir.display());
                }
            }
        }
        Err(e) => tracing::warn!("cannot make {}: {e}", dir.display()),
    }
}

/// `$HOME`, if set.
#[cfg(target_os = "linux")]
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use zkminer_witness_sandbox::confine::{self, Confinement, Rights, Sockets};

    use super::home;

    /// The private temporary directory [`prepare`] made.
    static TMPDIR: OnceLock<PathBuf> = OnceLock::new();

    /// At startup, while the process has one thread: a private temporary directory, which `TMPDIR`
    /// then names for everything in this process and its server (the SDK's executor runner, gnark's
    /// files), and `SP1_SHM_DIR` for whatever SP1's final-wrap provers would put in `/dev/shm`.
    pub fn prepare() {
        match confine::private_tmpdir("sp1") {
            Ok(dir) => {
                // SAFETY: called from `main` before any thread exists.
                unsafe {
                    std::env::set_var("TMPDIR", &dir);
                    std::env::set_var("SP1_SHM_DIR", &dir);
                }
                let _ = TMPDIR.set(dir);
            }
            Err(e) => eprintln!(
                "cannot make a private temporary directory ({e}); this worker will refuse to run \
                 guests"
            ),
        }
    }

    pub fn is_confined() -> bool {
        confine::is_active()
    }

    /// Confines this worker; `keep_server`: it proves, and keeps its connection to its server.
    /// Either way the SDK's runtime needs a stream pair, which only the [`Sockets::KeepConnected`]
    /// policy allows; a measuring worker has no connection to keep.
    pub fn confine(keep_server: bool) -> Result<(), String> {
        if confine::report().is_some() {
            // Confined already: the sockets and the filesystems within reach, again.
            return confine::recheck().map_err(|e| e.to_string());
        }
        let tmp = TMPDIR
            .get()
            .ok_or("no private temporary directory to confine this worker to")?;
        let c = worker_policy(tmp, keep_server);
        let report = confine::confine_all_threads(&c).map_err(|e| e.to_string())?;
        tracing::info!("worker confined: {report}");
        Ok(())
    }

    /// The worker's confinement: see the module docs.
    fn worker_policy(tmp: &Path, keep_server: bool) -> Confinement {
        let mut c = Confinement::with_system(Sockets::KeepConnected);
        common_rules(&mut c, tmp);
        if keep_server {
            // A later warm-up asks the server about its Groth16 helper (`--sp1-groth16-cpu-helper
            // --help`, `--prepare`); what it starts is confined as this worker is.
            if let Ok(server) = crate::warmup::server_path() {
                c.allow(server, Rights::EXEC);
            }
        }
        c
    }

    /// What the worker and its server both need.
    fn common_rules(c: &mut Confinement, tmp: &Path) {
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(PathBuf::from))
        {
            c.allow(dir, Rights::READ);
        }
        for dir in confine::library_path_dirs() {
            c.allow(dir, Rights::READ);
        }
        // The SDK's executor extracts its runner here and runs it. (It shares the guest's memory
        // image and trace ring with the runner through file descriptors, which need no path.)
        c.allow(tmp, Rights::WRITE | Rights::EXEC);
        // All of `/proc`, not only this process's: the executor's memory monitor (`sysinfo`) reads
        // its runner child's `/proc/<pid>/{stat,statm,io,exe}`, and the worker its server's
        // `/proc/<pid>/stat`, at pids no rule can name in advance.
        c.allow("/proc", Rights::READ);
        if let Some(h) = home() {
            c.allow(h.join(".sp1"), Rights::READ);
        }
        for var in ["SP1_GROTH16_CIRCUIT_PATH", "SP1_PLONK_CIRCUIT_PATH"] {
            if let Some(p) = std::env::var_os(var).filter(|p| !p.is_empty()) {
                c.allow(PathBuf::from(p), Rights::READ);
            }
        }
    }

    /// Whether `path` is `/dev/shm`, is in it, or holds it, once resolved (through a symbolic link
    /// such as `/run/shm` too, and for a path that does not exist yet, through its nearest existing
    /// ancestor). No SP1 process is given any of it.
    pub(crate) fn reaches_dev_shm(path: &Path) -> bool {
        let shm = Path::new("/dev/shm");
        let real_shm = std::fs::canonicalize(shm).unwrap_or_else(|_| shm.to_path_buf());
        let resolved = resolve(path);
        [path.to_path_buf(), resolved].iter().any(|p| {
            [shm, real_shm.as_path()]
                .iter()
                .any(|s| s.starts_with(p) || p.starts_with(s))
        })
    }

    /// `path` with every symbolic link resolved, as far as it exists; the rest as it is.
    fn resolve(path: &Path) -> PathBuf {
        let mut rest = Vec::new();
        let mut at = path;
        loop {
            if let Ok(real) = std::fs::canonicalize(at) {
                return rest.iter().rev().fold(real, |p, part| p.join(part));
            }
            match (at.parent(), at.file_name()) {
                (Some(parent), Some(name)) => {
                    rest.push(name.to_os_string());
                    at = parent;
                }
                _ => return path.to_path_buf(),
            }
        }
    }

    /// The server's confinement: see the module docs. `queue`: the host-wide Groth16 queue
    /// (`SP1_GROTH16_QUEUE_DIR`, which `route_server_through_shim` names), never granted where it
    /// reaches `/dev/shm`.
    fn server_policy(real: &Path, tmp: &Path, queue: Option<&Path>) -> Confinement {
        let mut c = Confinement::with_system(Sockets::Supervised);
        common_rules(&mut c, tmp);
        // Its own listener, before its first connection (bind is the supervisor's to allow).
        c.allow("/tmp", Rights::MAKE_SOCK);
        // Its Groth16 CPU helper is itself, started again.
        c.allow(real, Rights::EXEC);
        if let Some(dir) = queue.filter(|dir| !reaches_dev_shm(dir)) {
            c.allow(dir, Rights::WRITE);
        }
        if let Some(dir) = real.parent() {
            c.allow(dir, Rights::READ);
        }
        c.allow_gpu_devices();
        if crate::warmup::server_name().ends_with("-hip") {
            // ROCm starts its threads with a CPU set, which glibc applies by thread id: without
            // this the HIP server finds no device.
            c.allow_thread_affinity();
        }
        if let Some(h) = home() {
            // The CUDA driver's JIT cache, read only: the server carries code for its cards.
            c.allow(h.join(".nv"), Rights::READ);
        }
        // The SYCL build compiles kernels on first use and caches them.
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".cache")));
        if let Some(cache) = cache {
            if crate::warmup::server_name().ends_with("-sycl") {
                for name in ["libsycl_cache", "neo_compiler_cache"] {
                    let dir = cache.join(name);
                    let _ = std::fs::create_dir_all(&dir);
                    c.allow(dir, Rights::WRITE);
                }
            }
        }
        c
    }

    /// The shim's work, in server mode: run the real server confined and supervised; its exit
    /// code.
    pub fn shim_server(real: &Path) -> i32 {
        // The SDK leaves the worker's stdin (the miner's command pipe) to what it starts: the
        // supervisor reads nothing, and the server gets `/dev/null` (`supervise`).
        // SAFETY: opening /dev/null and duplicating it onto fd 0.
        unsafe {
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::close(null);
            }
        }
        let Some(tmp) = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .filter(|t| t.is_absolute() && t.is_dir() && t != Path::new("/tmp"))
        else {
            eprintln!("zkminer: no private TMPDIR for sp1-gpu-server; refusing to start it");
            return 1;
        };
        // A killed server's socket, which the server could not remove once confined.
        let device = std::env::var("CUDA_VISIBLE_DEVICES")
            .ok()
            .and_then(|d| d.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let socket = PathBuf::from(format!("/tmp/{}-{device}.sock", super::sdk_server_name()));
        if std::fs::symlink_metadata(&socket).is_ok_and(|m| {
            use std::os::unix::fs::FileTypeExt;
            m.file_type().is_socket()
        }) {
            let _ = std::fs::remove_file(&socket);
        }
        let queue = std::env::var_os("SP1_GROTH16_QUEUE_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from);
        if let Some(dir) = queue.as_deref().filter(|dir| reaches_dev_shm(dir)) {
            eprintln!(
                "zkminer: SP1_GROTH16_QUEUE_DIR ({}) is or holds /dev/shm, which no SP1 process \
                 is given; refusing to start sp1-gpu-server",
                dir.display()
            );
            return 1;
        }
        let c = server_policy(real, &tmp, queue.as_deref());
        let args: Vec<OsString> = Vec::new();
        // The executor in the server unpacks its runner into `TMPDIR` and makes it executable,
        // which the supervisor does for it (the server may not change a file's mode itself).
        match zkminer_witness_sandbox::supervise::run_supervised(real, &args, &c, Some(&tmp)) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("zkminer: cannot run sp1-gpu-server confined: {e}");
                1
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Neither the worker (measuring or proving) nor its server may open, create or remove
        /// anything in `/dev/shm`, whatever queue directory an operator names. The one rule above
        /// it is the system's listing of `/dev`, which opens no file.
        #[test]
        fn no_confinement_reaches_dev_shm() {
            let tmp =
                std::env::temp_dir().join(format!("zkminer-sp1-policy-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let server = std::env::current_exe().unwrap();
            let home_queue = tmp.join(".zkminer/locks");
            let mut policies = vec![
                ("measuring worker", worker_policy(&tmp, false)),
                ("proving worker", worker_policy(&tmp, true)),
                ("server", server_policy(&server, &tmp, None)),
                ("server", server_policy(&server, &tmp, Some(&home_queue))),
            ];
            // An operator's queue directory in /dev/shm, of it, above it, or through a link.
            let link = tmp.join("shm-link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink("/dev/shm", &link).unwrap();
            let queues = [
                PathBuf::from("/dev/shm"),
                PathBuf::from("/dev/shm/"),
                PathBuf::from("/dev/shm/zkminer-locks"),
                PathBuf::from("/dev/shm/not/made/yet"),
                PathBuf::from("/dev"),
                PathBuf::from("/"),
                link.clone(),
                link.join("locks"),
                PathBuf::from("/dev/./shm/../shm/locks"),
            ];
            for queue in &queues {
                assert!(
                    reaches_dev_shm(queue),
                    "{} is not seen to reach /dev/shm",
                    queue.display()
                );
                policies.push(("server", server_policy(&server, &tmp, Some(queue))));
            }
            assert!(!reaches_dev_shm(&home_queue));
            assert!(!reaches_dev_shm(Path::new("/run/lock")));
            for (what, c) in policies {
                for (path, rights) in c.rules() {
                    if reaches_dev_shm(path) {
                        assert!(
                            *rights == Rights::LIST && path == Path::new("/dev"),
                            "the {what}'s rule on {} ({rights:?}) reaches /dev/shm",
                            path.display()
                        );
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod private_dir_tests {
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The default queue directory is made 0700, its parents too if missing, and an existing one
    /// of the user's own that others could reach is made 0700; a link in its place is left alone.
    #[test]
    fn the_default_queue_directory_is_private() {
        let tmp = std::env::temp_dir().join(format!("zkminer-locks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let made = tmp.join("home/.zkminer/locks");
        super::private_dir(&made);
        assert_eq!(mode(&made), 0o700);

        let open = tmp.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        super::private_dir(&open);
        assert_eq!(mode(&open), 0o700);

        let target = tmp.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        super::private_dir(&link);
        assert_eq!(mode(&target), 0o755, "a link's target is not changed");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(target_os = "linux")]
pub(crate) use imp::{confine, is_confined, prepare};

#[cfg(not(target_os = "linux"))]
pub(crate) fn confine(_keep_server: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn is_confined() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn prepare() {}

/// First thing in `main`: if this binary was started as the shim (under a [`SHIM_PREFIX`] name),
/// do the shim's work and exit. Otherwise returns.
#[cfg(target_os = "linux")]
pub(crate) fn run_if_shim() {
    let Some(argv0) = std::env::args_os().next() else {
        return;
    };
    let is_shim = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(SHIM_PREFIX));
    if !is_shim {
        return;
    }
    let Some(real) = std::env::var_os(REAL_SERVER_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
    else {
        eprintln!("zkminer: {REAL_SERVER_ENV} names no sp1-gpu-server; refusing to start one");
        std::process::exit(1);
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if !args.is_empty() {
        // `--version` and the like, which no requester's bytes reach: the real server as it is.
        use std::os::unix::process::CommandExt;
        let e = std::process::Command::new(&real).args(&args).exec();
        eprintln!("zkminer: cannot run {}: {e}", real.display());
        std::process::exit(127);
    }
    std::process::exit(imp::shim_server(&real));
}
