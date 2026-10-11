//! End-to-end test harness for the `zkminer` binary.
//!
//! Tests only run built binaries and observe them from the outside: exit code,
//! stdout/stderr, `--json` output, files written, and leftover processes.
//!
//! Each case runs in its own [`Sandbox`]:
//! - `HOME`, `TMPDIR` and the XDG dirs point inside a temp folder, so nothing
//!   touches the real `~/.zkminer`.
//! - `zkminer` is copied into `<sandbox>/bin`. Worker discovery also searches
//!   the folder the `zkminer` binary is in (`zkminer-prover/src/discovery.rs`),
//!   so running it from `target/` would pick up real workers built next to it.
//! - Workers are installed into `<sandbox>/provers`, which the generated config
//!   lists in `worker_search_paths`.
//! - `<sandbox>/shims` is first on `PATH` (for fake GPU tools).
//!
//! Tables of [`Case`]s are run with [`run_case`], usually through `rstest` so
//! each case shows up as its own test.
#![cfg(unix)]

use std::fmt::Write as _;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// How long to wait for workers to exit after `zkminer` returns (shutdown is async).
const LEFTOVER_GRACE: Duration = Duration::from_secs(5);

/// Default per-case timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Folder holding the built binaries (`zkminer`, `mock-worker`).
///
/// `ZKMINER_E2E_BIN_DIR`, else `$CARGO_TARGET_DIR/debug`, else `<workspace>/target/debug`.
pub fn bin_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZKMINER_E2E_BIN_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir).join("debug");
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug")
}

/// Path to a built binary in [`bin_dir`]. Panics with a hint if it's missing.
pub fn built_binary(name: &str) -> PathBuf {
    let path = bin_dir().join(name);
    assert!(
        path.is_file(),
        "{} not found; run `make e2e` (or set ZKMINER_E2E_BIN_DIR)",
        path.display()
    );
    path
}

/// An isolated folder tree that one `zkminer` invocation runs in.
pub struct Sandbox {
    dir: Option<tempfile::TempDir>,
    root: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("zkminer-e2e-")
            .tempdir()
            .expect("create sandbox temp dir");
        let root = dir.path().to_path_buf();
        for sub in ["home/.zkminer", "bin", "provers", "shims", "tmp"] {
            std::fs::create_dir_all(root.join(sub)).expect("create sandbox dir");
        }

        let sandbox = Self { dir: Some(dir), root };
        copy_executable(&built_binary("zkminer"), &sandbox.zkminer());
        sandbox.write_config(&format!(
            "[prover]\nworker_search_paths = [{:?}]\nbenchmark_timeout_secs = 30\n",
            sandbox.provers_dir().display().to_string()
        ));
        sandbox
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A path relative to the sandbox root.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn home(&self) -> PathBuf {
        self.path("home")
    }

    pub fn zkminer(&self) -> PathBuf {
        self.path("bin/zkminer")
    }

    pub fn provers_dir(&self) -> PathBuf {
        self.path("provers")
    }

    pub fn shims_dir(&self) -> PathBuf {
        self.path("shims")
    }

    /// The config file `zkminer` loads by default (`~/.zkminer/config.toml`).
    pub fn config_path(&self) -> PathBuf {
        self.path("home/.zkminer/config.toml")
    }

    /// Overwrite the generated config.
    pub fn write_config(&self, toml: &str) {
        std::fs::write(self.config_path(), toml).expect("write sandbox config");
    }

    /// Copy an executable into `provers/` under `name` (e.g. `zkminer-prove-sp1`).
    pub fn install_worker(&self, src: &Path, name: &str) -> PathBuf {
        let dst = self.provers_dir().join(name);
        copy_executable(src, &dst);
        dst
    }

    /// Write an executable script into `shims/`, which is first on `PATH`.
    pub fn install_shim(&self, name: &str, script: &str) -> PathBuf {
        let dst = self.shims_dir().join(name);
        let _writing = EXEC_LOCK.write().unwrap_or_else(|e| e.into_inner());
        std::fs::write(&dst, script).expect("write shim");
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shim");
        dst
    }

    /// `PATH` given to `zkminer`: shims first, then the system folders.
    pub fn path_env(&self) -> String {
        format!("{}:/usr/local/bin:/usr/bin:/bin", self.shims_dir().display())
    }

    /// A `zkminer` command with a cleared environment pointing inside the sandbox.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(self.zkminer());
        cmd.env_clear()
            .current_dir(&self.root)
            .env("HOME", self.home())
            .env("TMPDIR", self.path("tmp"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("XDG_DATA_HOME", self.path("home/.local/share"))
            .env("XDG_CACHE_HOME", self.path("home/.cache"))
            .env("XDG_STATE_HOME", self.path("home/.local/state"))
            .env("PATH", self.path_env());
        cmd
    }

    /// Keep the folder on disk after the sandbox is dropped and return its path.
    fn keep(&mut self) -> PathBuf {
        if let Some(dir) = self.dir.take() {
            let _ = dir.keep();
        }
        self.root.clone()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Writing an executable and starting a process must not overlap. A process forked while this test
/// binary has an executable open for writing inherits that descriptor until it execs, and exec'ing
/// the file meanwhile fails with ETXTBSY ("Text file busy"). Tests run on parallel threads, so one
/// test's copy raced another's spawn. Writers take this exclusively; spawns share it.
static EXEC_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

fn copy_executable(src: &Path, dst: &Path) {
    let _writing = EXEC_LOCK.write().unwrap_or_else(|e| e.into_inner());
    std::fs::copy(src, dst)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), dst.display()));
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .expect("chmod executable");
}

/// `zkminer` / `zkminer-prove-*` processes whose binary lives under the sandbox.
///
/// Matching on the sandbox path (not just the name) keeps cases that run in
/// parallel from seeing each other's workers.
pub fn leftover_workers(sandbox: &Sandbox) -> Vec<(i32, PathBuf)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Some(exe) = process_exe(&entry.path()) else {
            continue;
        };
        let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if exe.starts_with(sandbox.root()) && name.starts_with("zkminer") {
            found.push((pid, exe));
        }
    }
    found
}

fn process_exe(proc_dir: &Path) -> Option<PathBuf> {
    if let Ok(exe) = std::fs::read_link(proc_dir.join("exe")) {
        return Some(exe);
    }
    // Fallback when `exe` can't be read: argv[0].
    let cmdline = std::fs::read(proc_dir.join("cmdline")).ok()?;
    let argv0 = cmdline.split(|b| *b == 0).next()?;
    (!argv0.is_empty()).then(|| PathBuf::from(String::from_utf8_lossy(argv0).into_owned()))
}

/// Checks a parsed `--json` document. Returns a description of the mismatch.
pub type JsonCheck = fn(&serde_json::Value) -> Result<(), String>;

/// What a case expects to observe.
pub struct Expect {
    pub code: Option<i32>,
    pub stdout_contains: Vec<&'static str>,
    pub stdout_not_contains: Vec<&'static str>,
    pub stderr_contains: Vec<&'static str>,
    pub stderr_not_contains: Vec<&'static str>,
    /// Parse stdout as JSON and run this check on it.
    pub json: Option<JsonCheck>,
    /// Paths relative to the sandbox root.
    pub files_exist: Vec<&'static str>,
    pub files_absent: Vec<&'static str>,
    /// No `zkminer-prove-*` (or `zkminer`) processes from this sandbox are still alive.
    pub no_leftover_workers: bool,
}

impl Default for Expect {
    fn default() -> Self {
        Self {
            code: None,
            stdout_contains: Vec::new(),
            stdout_not_contains: Vec::new(),
            stderr_contains: Vec::new(),
            stderr_not_contains: Vec::new(),
            json: None,
            files_exist: Vec::new(),
            files_absent: Vec::new(),
            no_leftover_workers: true,
        }
    }
}

/// One row of a test table.
pub struct Case {
    pub name: &'static str,
    pub args: Vec<&'static str>,
    /// Extra environment for `zkminer` (workers inherit it).
    pub env: Vec<(&'static str, &'static str)>,
    /// Runs after the sandbox is built, before `zkminer` starts.
    pub setup: fn(&Sandbox),
    pub expect: Expect,
    pub timeout: Duration,
}

impl Case {
    pub fn new(name: &'static str, args: &[&'static str]) -> Self {
        Self {
            name,
            args: args.to_vec(),
            ..Default::default()
        }
    }
}

impl Default for Case {
    fn default() -> Self {
        Self {
            name: "",
            args: Vec::new(),
            env: Vec::new(),
            setup: |_| {},
            expect: Expect::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// What one `zkminer` invocation produced.
pub struct Outcome {
    /// `None` when the process was killed after timing out.
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
}

/// Run `cmd` to completion, killing it after `timeout`.
pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Outcome {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = {
        let _spawning = EXEC_LOCK.read().unwrap_or_else(|e| e.into_inner());
        cmd.spawn().expect("spawn zkminer")
    };
    let stdout = drain(&mut child, true);
    let stderr = drain(&mut child, false);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().expect("wait for zkminer") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                // Workers die with zkminer via PR_SET_PDEATHSIG.
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    Outcome {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    }
}

fn drain(child: &mut Child, stdout: bool) -> std::thread::JoinHandle<String> {
    let mut pipe: Box<dyn Read + Send> = if stdout {
        Box::new(child.stdout.take().expect("piped stdout"))
    } else {
        Box::new(child.stderr.take().expect("piped stderr"))
    };
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Snapshot of the real `~/.zkminer`, used to catch writes outside the sandbox.
fn real_zkminer_dir_state() -> Option<(PathBuf, Option<SystemTime>)> {
    let home = std::env::var_os("HOME")?;
    let dir = PathBuf::from(home).join(".zkminer");
    let mtime = std::fs::metadata(&dir).and_then(|m| m.modified()).ok();
    Some((dir, mtime))
}

/// Run one case and panic with a full report if any expectation fails.
pub fn run_case(case: Case) {
    let real_before = real_zkminer_dir_state();
    let mut sandbox = Sandbox::new();
    (case.setup)(&sandbox);

    let mut cmd = sandbox.command();
    cmd.args(&case.args);
    for (k, v) in &case.env {
        cmd.env(k, v);
    }
    let out = run_with_timeout(cmd, case.timeout);

    let mut failures = check(&case.expect, &sandbox, &out);
    if out.status.is_none() {
        failures.insert(0, format!("timed out after {:?}", case.timeout));
    }
    if real_zkminer_dir_state() != real_before {
        let dir = real_before.map(|(d, _)| d.display().to_string()).unwrap_or_default();
        failures.push(format!("{dir} changed: something was written outside the sandbox"));
    }

    if failures.is_empty() {
        return;
    }
    let kept = std::env::var_os("ZKMINER_E2E_KEEP").is_some_and(|v| v == "1");
    let sandbox_note = if kept {
        sandbox.keep().display().to_string()
    } else {
        format!("{} (deleted; set ZKMINER_E2E_KEEP=1 to keep it)", sandbox.root().display())
    };
    panic!("{}", report(&case, &out, &failures, &sandbox_note));
}

fn check(expect: &Expect, sandbox: &Sandbox, out: &Outcome) -> Vec<String> {
    let mut failures = Vec::new();

    if let (Some(want), Some(status)) = (expect.code, out.status) {
        if status.code() != Some(want) {
            failures.push(format!("exit code: want {want}, got {status}"));
        }
    }
    for s in &expect.stdout_contains {
        if !out.stdout.contains(s) {
            failures.push(format!("stdout should contain {s:?}"));
        }
    }
    for s in &expect.stdout_not_contains {
        if out.stdout.contains(s) {
            failures.push(format!("stdout should not contain {s:?}"));
        }
    }
    for s in &expect.stderr_contains {
        if !out.stderr.contains(s) {
            failures.push(format!("stderr should contain {s:?}"));
        }
    }
    for s in &expect.stderr_not_contains {
        if out.stderr.contains(s) {
            failures.push(format!("stderr should not contain {s:?}"));
        }
    }
    if let Some(json_check) = expect.json {
        match serde_json::from_str::<serde_json::Value>(&out.stdout) {
            Ok(value) => {
                if let Err(e) = json_check(&value) {
                    failures.push(format!("json: {e}"));
                }
            }
            Err(e) => failures.push(format!("stdout is not valid JSON: {e}")),
        }
    }
    for rel in &expect.files_exist {
        if !sandbox.path(rel).exists() {
            failures.push(format!("file should exist: {rel}"));
        }
    }
    for rel in &expect.files_absent {
        if sandbox.path(rel).exists() {
            failures.push(format!("file should not exist: {rel}"));
        }
    }

    // Always reap leftovers so nothing leaks past the case, even when not asserted.
    let deadline = Instant::now() + LEFTOVER_GRACE;
    let mut leftovers = leftover_workers(sandbox);
    while !leftovers.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        leftovers = leftover_workers(sandbox);
    }
    for (pid, _) in &leftovers {
        let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
    }
    if expect.no_leftover_workers && !leftovers.is_empty() {
        let list: Vec<String> = leftovers
            .iter()
            .map(|(pid, exe)| format!("{pid} {}", exe.display()))
            .collect();
        failures.push(format!("leftover processes: {}", list.join(", ")));
    }

    failures
}

fn report(case: &Case, out: &Outcome, failures: &[String], sandbox_note: &str) -> String {
    let mut msg = format!("e2e case `{}` failed:\n", case.name);
    for f in failures {
        let _ = writeln!(msg, "  - {f}");
    }
    let _ = write!(msg, "command: zkminer {}", case.args.join(" "));
    if !case.env.is_empty() {
        let env: Vec<String> = case.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let _ = write!(msg, "   (env: {})", env.join(" "));
    }
    let exit = match out.status {
        Some(status) => status.to_string(),
        None => format!("timed out after {:?}", case.timeout),
    };
    let _ = writeln!(msg, "\nexit: {exit}\nsandbox: {sandbox_note}");
    let _ = writeln!(msg, "--- stdout ---\n{}", out.stdout);
    let _ = write!(msg, "--- stderr ---\n{}", out.stderr);
    msg
}
