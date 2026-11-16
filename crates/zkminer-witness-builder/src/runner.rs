//! [`run`]: pre-pass, compile, instantiate and call `run()` under fuel, the epoch watchdog and the
//! store limits, then classify the outcome into one of the [`exit`] codes.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use wasmtime::{Engine, Module, Store, Trap};
use zkminer_witness::abi;
use zkminer_witness::envelope::{
    HARD_MAX_BUILDER_MEMORY_BYTES, HARD_MAX_BUILDER_SECONDS, HARD_MAX_WITNESS_BYTES, MAX_REQUEST_BYTES,
};
use zkminer_witness::ipc::{exit, BuilderSummary};

use crate::engine::{self, EXEC_THREAD_STACK_BYTES};
use crate::host::{self, Fault, HostState, Limiter, Progress};
use crate::prepass::{self, PrepassError};

/// How long past the deadline the calling thread waits for the execution thread before it reports
/// WALL_CLOCK on its own. Wasm code stops at the deadline through the epoch and `fetch` through its
/// socket timeout, so only work that cannot be interrupted (compilation, a blocked W or log write)
/// can still be running then.
pub const DEADLINE_GRACE: Duration = Duration::from_millis(500);
/// How often the watchdog bumps the epoch once the deadline has passed.
const WATCHDOG_TICK: Duration = Duration::from_millis(10);

/// Limits for one run. [`run`] applies the hard ceilings of plan §9.1 on top of these, whatever they
/// say: memory ≤ 1 GiB, wall time ≤ 300 s from the call, `W` ≤ 1 GiB, requests ≤ 64 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerConfig {
    /// Fuel for the whole run, start function included (`maxBuilderFuel`).
    pub fuel: u64,
    /// The clamp on linear memory (`maxBuilderMemoryBytes`), rounded down to whole 64 KiB pages.
    pub memory_bytes: u64,
    /// Absolute deadline. The binary counts it from process start, so compilation spends it too.
    pub deadline: Instant,
    /// `maxWitnessBytes`.
    pub max_witness_bytes: u64,
    /// `maxRequestBytes`: a `fetch` with a longer request traps without reaching the broker.
    pub max_request_bytes: u32,
    /// `maxResponseBytes`: the largest fetch result frame the runner reads from the broker.
    pub max_response_bytes: u32,
}

impl RunnerConfig {
    fn clamped(&self) -> Self {
        let pages = self.memory_bytes.min(HARD_MAX_BUILDER_MEMORY_BYTES) / 65_536;
        let latest = Instant::now() + Duration::from_secs(HARD_MAX_BUILDER_SECONDS.into());
        Self {
            fuel: self.fuel,
            memory_bytes: pages * 65_536,
            deadline: self.deadline.min(latest),
            max_witness_bytes: self.max_witness_bytes.min(HARD_MAX_WITNESS_BYTES),
            max_request_bytes: self.max_request_bytes.min(MAX_REQUEST_BYTES),
            max_response_bytes: self.max_response_bytes,
        }
    }
}

/// The broker socket: a byte stream (`SOCK_STREAM`) carrying `ipc` frames, with per-call timeouts
/// so a `fetch` never waits past the deadline.
pub trait BrokerChannel: Read + Write + Send + 'static {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl BrokerChannel for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

/// Where a run's output goes.
pub struct RunnerIo<W, B, L> {
    /// The W sink, written in pieces of at most [`abi::W_CHUNK_BYTES`]. Kept by the miner only on
    /// exit 0.
    pub witness: W,
    /// The job's socket to the broker.
    pub broker: B,
    /// The diagnostic sink: the guest's `log` output (at most [`abi::LOG_CAP_BYTES`] in total) and
    /// the runner's own one-line reasons for a rejected module or an internal error, prefixed
    /// `[runner]`. The miner sanitizes it.
    pub log: L,
}

/// Runs one builder and returns its summary. Never panics on guest input.
///
/// Threads: the caller's thread waits; one execution thread (8 MiB of stack) compiles, instantiates
/// and runs the module; one watchdog thread bumps the epoch once the deadline passes. Three in all,
/// and wasmtime starts none of its own in this build.
///
/// If the execution thread has not finished [`DEADLINE_GRACE`] after the deadline (it is stuck in
/// compilation or in a blocking write), this returns WALL_CLOCK and leaves that thread behind; the
/// binary then exits, which ends it.
pub fn run<W, B, L>(module: &[u8], context: &[u8], cfg: &RunnerConfig, io: RunnerIo<W, B, L>) -> BuilderSummary
where
    W: Write + Send + 'static,
    B: BrokerChannel,
    L: Write + Send + 'static,
{
    let started = Instant::now();
    let cfg = cfg.clamped();
    let progress = Arc::new(Progress::default());
    let (tx, rx) = mpsc::channel();
    let job = Job {
        module: module.to_vec(),
        context: context.to_vec(),
        cfg,
        witness: Box::new(io.witness),
        broker: Box::new(io.broker),
        log: Box::new(io.log),
        progress: progress.clone(),
    };
    let spawned =
        thread::Builder::new().name("builder-exec".into()).stack_size(EXEC_THREAD_STACK_BYTES).spawn(move || {
            let _ = tx.send(job.execute());
        });
    if spawned.is_err() {
        return BuilderSummary { exit_code: exit::INTERNAL, ..Default::default() };
    }
    let wait = cfg.deadline.saturating_duration_since(Instant::now()) + DEADLINE_GRACE;
    match rx.recv_timeout(wait) {
        Ok(summary) => summary,
        Err(mpsc::RecvTimeoutError::Timeout) => BuilderSummary {
            exit_code: exit::WALL_CLOCK,
            transient: progress.transient.load(Ordering::Relaxed),
            fetches: progress.fetches.load(Ordering::Relaxed),
            fetch_bytes: progress.fetch_bytes.load(Ordering::Relaxed),
            fuel_used: 0,
            witness_bytes: progress.witness_bytes.load(Ordering::Relaxed),
            compile_ms: 0,
            run_ms: millis(started.elapsed()),
        },
        // The execution thread panicked: a runner bug.
        Err(mpsc::RecvTimeoutError::Disconnected) => BuilderSummary { exit_code: exit::INTERNAL, ..Default::default() },
    }
}

fn millis(d: Duration) -> u32 {
    d.as_millis().min(u128::from(u32::MAX)) as u32
}

struct Job {
    module: Vec<u8>,
    context: Vec<u8>,
    cfg: RunnerConfig,
    witness: Box<dyn Write + Send>,
    broker: Box<dyn BrokerChannel>,
    log: Box<dyn Write + Send>,
    progress: Arc<Progress>,
}

/// Bumps the engine's epoch every [`WATCHDOG_TICK`] from the deadline on, until dropped. Bumping
/// repeatedly (not once) makes the store's deadline fire however late it was armed.
struct Watchdog {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(engine: Engine, deadline: Instant) -> std::io::Result<Self> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = stop.clone();
        let handle = thread::Builder::new().name("builder-epoch".into()).stack_size(64 << 10).spawn(move || {
            let (lock, cv) = &*flag;
            let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*stopped {
                let now = Instant::now();
                let wait = if now >= deadline {
                    engine.increment_epoch();
                    WATCHDOG_TICK
                } else {
                    deadline - now
                };
                stopped = cv.wait_timeout(stopped, wait).unwrap_or_else(|e| e.into_inner()).0;
            }
        })?;
        Ok(Self { stop, handle: Some(handle) })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let (lock, cv) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The checks of the pre-pass, repeated on wasmtime's own view of the compiled module, which is
/// what instantiation uses.
fn check_compiled(module: &Module) -> Result<(), PrepassError> {
    use wasmtime::{ExternType, ValType};
    for import in module.imports() {
        let name = format!("{}::{}", import.module(), import.name());
        let (params, results) = (import.module() == abi::MODULE)
            .then(|| prepass::import_signature(import.name()))
            .flatten()
            .ok_or_else(|| PrepassError::UnknownImport(name.clone()))?;
        let ExternType::Func(f) = import.ty() else {
            return Err(PrepassError::UnknownImport(name));
        };
        let same = |got: &mut dyn ExactSizeIterator<Item = ValType>, want: &[wasmparser::ValType]| {
            got.len() == want.len()
                && got.zip(want).all(|(g, w)| match w {
                    wasmparser::ValType::I32 => g.is_i32(),
                    wasmparser::ValType::I64 => g.is_i64(),
                    _ => false,
                })
        };
        if !same(&mut f.params(), params) || !same(&mut f.results(), results) {
            return Err(PrepassError::UnknownImport(name));
        }
    }
    let memory_ok = matches!(module.get_export(abi::EXPORT_MEMORY), Some(ExternType::Memory(m)) if !m.is_64());
    let run_ok = matches!(module.get_export(abi::EXPORT_RUN), Some(ExternType::Func(f))
        if f.params().len() == 0 && f.results().len() == 1 && f.results().all(|r| r.is_i32()));
    if !memory_ok || !run_ok {
        return Err(PrepassError::Invalid("required exports".into()));
    }
    Ok(())
}

impl Job {
    fn execute(mut self) -> BuilderSummary {
        let t0 = Instant::now();
        let cfg = self.cfg;
        let mut summary = BuilderSummary::default();

        if let Err(e) = prepass::prepass(&self.module, cfg.memory_bytes) {
            let _ = writeln!(self.log, "[runner] {e}");
            summary.exit_code = e.exit_code();
            summary.compile_ms = millis(t0.elapsed());
            return summary;
        }
        let engine = match engine::engine() {
            Ok(e) => e,
            Err(e) => return self.internal(summary, format!("engine: {e}")),
        };
        let module = match Module::from_binary(&engine, &self.module) {
            Ok(m) => m,
            Err(e) => {
                let _ = writeln!(self.log, "[runner] invalid module: {e}");
                summary.exit_code = exit::INVALID_MODULE;
                summary.compile_ms = millis(t0.elapsed());
                return summary;
            }
        };
        drop(std::mem::take(&mut self.module));
        summary.compile_ms = millis(t0.elapsed());
        if let Err(e) = check_compiled(&module) {
            let _ = writeln!(self.log, "[runner] {e}");
            summary.exit_code = e.exit_code();
            return summary;
        }
        if Instant::now() >= cfg.deadline {
            summary.exit_code = exit::WALL_CLOCK;
            return summary;
        }

        let t1 = Instant::now();
        let progress = self.progress.clone();
        let mut log_for_runner: Option<String> = None;
        let state = HostState {
            limiter: Limiter { memory_bytes: cfg.memory_bytes as usize, memory_denied: false },
            context: std::mem::take(&mut self.context),
            response: Vec::new(),
            witness: self.witness,
            broker: self.broker,
            log: self.log,
            log_remaining: abi::LOG_CAP_BYTES,
            witness_written: 0,
            witness_over_limit: false,
            max_witness_bytes: cfg.max_witness_bytes,
            max_request_bytes: cfg.max_request_bytes,
            max_response_bytes: cfg.max_response_bytes,
            deadline: cfg.deadline,
            progress: progress.clone(),
        };
        let mut store = Store::new(&engine, state);
        store.limiter(|s| &mut s.limiter);
        // Armed before instantiation: a start function runs inside `instantiate`.
        if let Err(e) = store.set_fuel(cfg.fuel) {
            return internal_with(store, summary, format!("fuel: {e}"));
        }
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();
        let watchdog = match Watchdog::start(engine.clone(), cfg.deadline) {
            Ok(w) => w,
            Err(e) => return internal_with(store, summary, format!("watchdog: {e}")),
        };
        let linker = match host::linker(&engine) {
            Ok(l) => l,
            Err(e) => return internal_with(store, summary, format!("linker: {e}")),
        };

        let outcome = linker.instantiate(&mut store, &module).and_then(|instance| {
            let run = instance.get_typed_func::<(), i32>(&mut store, abi::EXPORT_RUN)?;
            run.call(&mut store, ())
        });
        drop(watchdog);

        let mut code = match &outcome {
            Ok(0) => exit::OK,
            Ok(_) => exit::NONZERO_RETURN,
            Err(e) => {
                let (code, why) = classify(e, store.data().limiter.memory_denied);
                if code == exit::INTERNAL {
                    log_for_runner = Some(why);
                }
                code
            }
        };
        if code != exit::INTERNAL && store.data().witness_over_limit {
            code = exit::WITNESS_TOO_LARGE;
        }
        if code == exit::OK {
            if let Err(e) = store.data_mut().witness.flush() {
                code = exit::INTERNAL;
                log_for_runner = Some(format!("W sink: {e}"));
            }
        }
        summary.exit_code = code;
        summary.fuel_used = cfg.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        summary.run_ms = millis(t1.elapsed());
        fill_counters(&progress, &mut summary);
        if let Some(why) = log_for_runner {
            let _ = writeln!(store.data_mut().log, "\n[runner] internal: {why}");
        }
        let _ = store.data_mut().log.flush();
        summary
    }

    fn internal(mut self, mut summary: BuilderSummary, why: String) -> BuilderSummary {
        let _ = writeln!(self.log, "[runner] internal: {why}");
        summary.exit_code = exit::INTERNAL;
        summary
    }
}

fn fill_counters(p: &Progress, s: &mut BuilderSummary) {
    s.transient = p.transient.load(Ordering::Relaxed);
    s.fetches = p.fetches.load(Ordering::Relaxed);
    s.fetch_bytes = p.fetch_bytes.load(Ordering::Relaxed);
    s.witness_bytes = p.witness_bytes.load(Ordering::Relaxed);
}

fn internal_with(mut store: Store<HostState>, mut summary: BuilderSummary, why: String) -> BuilderSummary {
    let _ = writeln!(store.data_mut().log, "[runner] internal: {why}");
    summary.exit_code = exit::INTERNAL;
    summary
}

/// Maps a failed instantiation or call to an exit code (and, for INTERNAL, a reason to log).
fn classify(e: &wasmtime::Error, memory_denied: bool) -> (i32, String) {
    let trap = if memory_denied { exit::MEMORY } else { exit::TRAP };
    if let Some(f) = e.downcast_ref::<Fault>() {
        let code = match f {
            Fault::OutOfBounds | Fault::RequestTooLarge(_) | Fault::NoMemory => trap,
            Fault::Fuel => exit::FUEL,
            Fault::WallClock => exit::WALL_CLOCK,
            Fault::Internal(_) => exit::INTERNAL,
        };
        return (code, f.to_string());
    }
    if let Some(t) = e.downcast_ref::<Trap>() {
        let code = match t {
            Trap::OutOfFuel => exit::FUEL,
            Trap::Interrupt => exit::WALL_CLOCK,
            _ => trap,
        };
        return (code, t.to_string());
    }
    // Not a trap: an instantiation failure the pre-pass should have made impossible (a memory the
    // limiter refused counts as MEMORY; anything else is ours).
    if memory_denied {
        return (exit::MEMORY, e.to_string());
    }
    (exit::INTERNAL, e.to_string())
}
