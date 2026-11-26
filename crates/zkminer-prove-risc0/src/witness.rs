//! Witness-construction jobs in the risc0 worker (plan §5.4, §10.1, §15.3).
//!
//! - **The prove path** (`WorkerCommand::Prove` with `witness`, [`run_witness_proof`]): the input is
//!   `prefix ‖ W`, read from the bundle's file through one descriptor and refused unless it has the
//!   bundle's length and hash. The guest is executed ONCE, with the env an inline job gets (the input,
//!   the public rule's seed for it, the po2) plus the slot's segment directory, and NO
//!   coprocessor callback: the measure path's keccak audit takes the keccak requests out of the
//!   session, which would leave it unprovable. The measure checks run on that session, its journal is
//!   compared with the bundle's, and only then is that same session proven, across the invalid-proof
//!   retries. A run that does not reproduce the bundle is a typed `JournalDiverged`, never proven.
//! - **The sandboxed execute** (`--witness-execute`, the CPU worker only, [`execute_main`]): a
//!   one-shot process that restricts itself before anything else, then executes the guest at each po2
//!   the miner may prove at, with the seed it is handed (it derives none), and reports journals,
//!   cycles and serialized segment bytes.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use risc0_zkvm::ExitCode;
use sha2::{Digest as _, Sha256};
use zkminer_prover_protocol::{
    ErrorKind, WitnessProve, EXECUTE_JOURNAL_MAX_BYTES, GUEST_EXIT_HALTED, GUEST_EXIT_PAUSED,
    GUEST_EXIT_SESSION_LIMIT, GUEST_EXIT_SYSTEM_SPLIT, GUEST_EXIT_UNKNOWN,
};

use super::{
    check_claim_output, groth16_proof_output, job_segment_po2, prove_session_cycle_limit,
    prove_with_retries, sys_rand_seed, verify_program_id,
    KECCAK_REQUEST_CYCLES,
};

/// The only non-empty prefix: `abi.encode(jobId, prover)`.
const PREFIX_BYTES: usize = 64;

/// How much of `W` is read at a time.
const READ_CHUNK_BYTES: usize = 1 << 20;

/// A witness proof the worker refuses for a reason it types itself, before or without trusting any
/// text: the host branches on the [`ErrorKind`], never on the message.
#[derive(Debug)]
pub(crate) enum WitnessRefusal {
    /// The command breaks the witness contract (inline input beside a witness, a prefix of another
    /// length, a relative segment directory): a host bug.
    Protocol(String),
    /// Read in full, the input does not have the bundle's length or `sha256(prefix ‖ W)`.
    InputMismatch(String),
    /// The input could not be opened or read: the retention store may be unavailable (plan §15.2).
    InputUnreadable(String),
    /// The segment directory could not be created or emptied.
    SegmentDir(String),
    /// The guest halted with code 0 but no proof of the run can verify (no output, or an assumption
    /// other than its keccak root): a bad job, as on the measure path.
    Unprovable(String),
}

impl WitnessRefusal {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::Protocol(_) => ErrorKind::ProtocolError,
            Self::InputMismatch(_) => ErrorKind::InputMismatch,
            Self::InputUnreadable(_) | Self::SegmentDir(_) => ErrorKind::Internal,
            Self::Unprovable(_) => ErrorKind::InvalidInput,
        }
    }
}

impl std::fmt::Display for WitnessRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(m) => write!(f, "witness proof refused (host protocol): {m}"),
            Self::InputMismatch(m) => write!(f, "witness input does not match its bundle: {m}"),
            Self::InputUnreadable(m) => write!(f, "witness input unreadable: {m}"),
            Self::SegmentDir(m) => write!(f, "segment directory: {m}"),
            Self::Unprovable(m) => write!(f, "witness session unprovable: {m}"),
        }
    }
}

impl std::error::Error for WitnessRefusal {}

/// How a witness execution ended, where it did not reproduce its bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Divergence {
    pub journal: Vec<u8>,
    pub journal_len: u32,
    pub journal_sha256: [u8; 32],
    pub exit_kind: u8,
    pub exit_code: u32,
    pub cycles: u64,
}

pub(crate) enum WitnessOutcome {
    /// `(journal, seal, duration_secs, cycles)`, as an inline proof's.
    Proved((Vec<u8>, Vec<u8>, f64, u64)),
    /// The execution did not reproduce the bundle; nothing was proven.
    Diverged(Divergence),
}

/// `(kind, code)` of a guest's exit, as the protocol carries it.
pub(crate) fn exit_parts(exit: ExitCode) -> (u8, u32) {
    match exit {
        ExitCode::Halted(c) => (GUEST_EXIT_HALTED, c),
        ExitCode::Paused(c) => (GUEST_EXIT_PAUSED, c),
        ExitCode::SystemSplit => (GUEST_EXIT_SYSTEM_SPLIT, 0),
        ExitCode::SessionLimit => (GUEST_EXIT_SESSION_LIMIT, 0),
        _ => (GUEST_EXIT_UNKNOWN, 0),
    }
}

/// `(the journal as carried, its length, its sha256)`: carried only up to
/// [`EXECUTE_JOURNAL_MAX_BYTES`], which no fulfil can exceed.
pub(crate) fn journal_parts(journal: &[u8]) -> (Vec<u8>, u32, [u8; 32]) {
    let carried = if journal.len() <= EXECUTE_JOURNAL_MAX_BYTES {
        journal.to_vec()
    } else {
        Vec::new()
    };
    (
        carried,
        u32::try_from(journal.len()).unwrap_or(u32::MAX),
        Sha256::digest(journal).into(),
    )
}

/// What one keccak request at keccak po2 `po2` costs in sized cycles: as [`super::KeccakAudit`]
/// charges it.
fn keccak_request_cycles(po2: u32) -> u64 {
    KECCAK_REQUEST_CYCLES << po2.saturating_sub(17).min(8)
}

/// The keccak po2 this process's executor uses: `RISC0_KECCAK_PO2` (which `ExecutorEnvBuilder::build`
/// reads), else risc0's default, 17.
fn keccak_po2_in_effect() -> u32 {
    std::env::var("RISC0_KECCAK_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(risc0_circuit_keccak::KECCAK_DEFAULT_PO2 as u32)
}

/// `prefix ‖ (exactly w_len bytes of r)`, hashed as it streams in. Refused unless `prefix` is 0 or
/// [`PREFIX_BYTES`] long, `r` holds exactly `w_len` bytes, and the whole input hashes to `expect`.
fn read_prefixed(
    mut r: impl Read,
    prefix: &[u8],
    w_len: u64,
    expect: &[u8; 32],
) -> Result<Vec<u8>, WitnessRefusal> {
    if !(prefix.is_empty() || prefix.len() == PREFIX_BYTES) {
        return Err(WitnessRefusal::Protocol(format!(
            "a {}-byte prefix (0 or {PREFIX_BYTES})",
            prefix.len()
        )));
    }
    let total = usize::try_from(w_len)
        .ok()
        .and_then(|w| w.checked_add(prefix.len()))
        .ok_or_else(|| WitnessRefusal::InputMismatch(format!("|W| = {w_len} does not fit")))?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(total)
        .map_err(|e| WitnessRefusal::InputUnreadable(format!("{total} bytes of input: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    input.extend_from_slice(prefix);
    let mut buf = vec![0u8; READ_CHUNK_BYTES.min(total.saturating_sub(prefix.len()) + 1)];
    let mut read = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(WitnessRefusal::InputUnreadable(format!("read: {e}"))),
        };
        read += n as u64;
        if read > w_len {
            return Err(WitnessRefusal::InputMismatch(format!(
                "W holds more than the bundle's {w_len} bytes"
            )));
        }
        hasher.update(&buf[..n]);
        input.extend_from_slice(&buf[..n]);
    }
    if read != w_len {
        return Err(WitnessRefusal::InputMismatch(format!(
            "W holds {read} bytes, the bundle {w_len}"
        )));
    }
    let got: [u8; 32] = hasher.finalize().into();
    if got != *expect {
        return Err(WitnessRefusal::InputMismatch(
            "sha256(prefix ‖ W) is not the bundle's".to_string(),
        ));
    }
    Ok(input)
}

/// `prefix ‖ W` of a witness proof, read through ONE descriptor of `input_path`: opened once,
/// checked with `fstat`, streamed and hashed.
fn read_witness_input(w: &WitnessProve) -> Result<Vec<u8>, WitnessRefusal> {
    let file = File::open(&w.input_path)
        .map_err(|e| WitnessRefusal::InputUnreadable(format!("open {}: {e}", w.input_path)))?;
    let meta = file
        .metadata()
        .map_err(|e| WitnessRefusal::InputUnreadable(format!("fstat {}: {e}", w.input_path)))?;
    if !meta.is_file() {
        return Err(WitnessRefusal::InputMismatch(format!(
            "{} is not a regular file",
            w.input_path
        )));
    }
    if meta.len() != w.w_len {
        return Err(WitnessRefusal::InputMismatch(format!(
            "{} holds {} bytes, the bundle {}",
            w.input_path,
            meta.len(),
            w.w_len
        )));
    }
    read_prefixed(file, &w.prefix, w.w_len, &w.input_sha256)
}

/// The segment directory a witness proof names: absolute, and not `/`.
fn segment_dir(w: &WitnessProve) -> Result<PathBuf, WitnessRefusal> {
    let dir = PathBuf::from(&w.segment_dir);
    if !dir.is_absolute() || dir.parent().is_none() {
        return Err(WitnessRefusal::Protocol(format!(
            "segment_dir {:?} is not an absolute path below /",
            w.segment_dir
        )));
    }
    Ok(dir)
}

/// Create `dir` if it is missing and delete everything in it. A symlink in its place is refused (the
/// wipe would empty whatever it points at); symlinks inside it are removed, never followed.
fn prepare_segment_dir(dir: &Path) -> Result<(), WitnessRefusal> {
    let err = |what: &str, e: std::io::Error| {
        WitnessRefusal::SegmentDir(format!("{what} {}: {e}", dir.display()))
    };
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(WitnessRefusal::SegmentDir(format!(
                "{} is a symlink",
                dir.display()
            )))
        }
        Ok(m) if !m.is_dir() => {
            return Err(WitnessRefusal::SegmentDir(format!(
                "{} is not a directory",
                dir.display()
            )))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|e| err("create", e))?
        }
        Err(e) => return Err(err("stat", e)),
    }
    wipe_dir_contents(dir).map_err(|e| err("empty", e))
}

fn wipe_dir_contents(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // `file_type` does not follow a symlink, so a link is removed as a file.
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Empties the segment directory when the proof is over, whatever its outcome: a session's segments
/// are as large as its proof's working set on disk.
struct WipeOnDrop<'a>(&'a Path);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        if let Err(e) = wipe_dir_contents(self.0) {
            tracing::warn!("could not empty {}: {e}", self.0.display());
        }
    }
}

/// The proof of a witness job (see the module docs). Errors other than a [`WitnessRefusal`] are
/// classified exactly as an inline proof's.
pub(crate) fn run_witness_proof(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
    program_id: Option<[u8; 32]>,
    witness: &WitnessProve,
) -> Result<WitnessOutcome> {
    if !input_data.is_empty() {
        return Err(WitnessRefusal::Protocol(format!(
            "{} bytes of inline input beside a witness, whose input is read from its bundle",
            input_data.len()
        ))
        .into());
    }
    // As an inline job: bound to its programId, at a job size.
    let image_id = verify_program_id(elf, program_id)?;
    let po2 = job_segment_po2(po2)?;
    crate::begin_proof_at(po2);
    let dir = segment_dir(witness)?;
    let input = read_witness_input(witness)?;
    // The seed an inline proof of this input would use, by the public rule: the same the miner
    // derived for the sandboxed execute from the bundle's `sha256(prefix ‖ W)`.
    let seed = sys_rand_seed(&image_id, &input);
    prepare_segment_dir(&dir)?;
    // Declared before the session, so it empties the directory after the session is gone.
    let _wipe = WipeOnDrop(&dir);
    let session = execute_witness_session(elf, &input, seed, po2, &dir)?;
    drop(input);
    if let Some(divergence) = check_witness_session(&session, &witness.expect_journal_sha256)? {
        return Ok(WitnessOutcome::Diverged(divergence));
    }
    let image_id = risc0_zkvm::Digest::from(image_id);
    // The SAME session on every attempt: an invalid-proof retry re-proves, it never re-executes.
    prove_with_retries(|| witness_prove_once(&session, image_id)).map(WitnessOutcome::Proved)
}

/// Execute the guest once as an inline proof of `input` at `po2` would (`run_proof_once`: the input,
/// the seed, the segment size, the operator's session limit), with its segments written under `dir`
/// and no coprocessor callback, so the session keeps its keccak requests for the prover.
fn execute_witness_session(
    elf: &[u8],
    input: &[u8],
    seed: [u8; 32],
    po2: u8,
    dir: &Path,
) -> Result<risc0_zkvm::Session> {
    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    env_builder.write_slice(input);
    env_builder.random_seed(seed);
    tracing::info!("Setting segment_limit_po2 = {po2}");
    env_builder.segment_limit_po2(po2 as u32);
    if let Some(limit) = prove_session_cycle_limit() {
        tracing::info!("Setting session_limit = {limit} cycles (operator override)");
        env_builder.session_limit(Some(limit));
    }
    env_builder.segment_path(dir);
    let env = env_builder.build()?;
    let started = Instant::now();
    let session = risc0_zkvm::ExecutorImpl::from_elf(env, elf)?.run()?;
    tracing::info!(
        "Executed the witness session: {} segments, {} cycles in {:.2}s",
        session.segments.len(),
        session.total_cycles,
        started.elapsed().as_secs_f64()
    );
    Ok(session)
}

/// The measure checks on the session to be proven, and its journal against the bundle's. `None`: it
/// may be proven. `Some`: it did not reproduce the bundle (it did not halt with code 0, or its journal
/// hashes otherwise). An error: it halted with code 0 but cannot be proven.
fn check_witness_session(
    session: &risc0_zkvm::Session,
    expect_journal_sha256: &[u8; 32],
) -> Result<Option<Divergence>, WitnessRefusal> {
    let (exit_kind, exit_code) = exit_parts(session.exit_code);
    let journal = session
        .journal
        .as_ref()
        .map(|j| j.bytes.as_slice())
        .unwrap_or_default();
    if session.exit_code != ExitCode::Halted(0) {
        let (journal, journal_len, journal_sha256) = journal_parts(journal);
        return Ok(Some(Divergence {
            journal,
            journal_len,
            journal_sha256,
            exit_kind,
            exit_code,
            cycles: session.total_cycles,
        }));
    }
    // The claim the prover proves: its assumptions leave out the root of the keccak requests the
    // session keeps (risc0 recomputes their claim digests from their inputs), so assuming nothing
    // else is assuming nothing at all here.
    keccak_assumptions::reset();
    let claim = session.claim();
    let keccak_requests = keccak_assumptions::take();
    let claim = claim.map_err(|e| WitnessRefusal::Unprovable(format!("{e:#}")))?;
    check_claim_output(Some(&claim), None)
        .map_err(|e| WitnessRefusal::Unprovable(format!("{e:#}")))?;
    let (journal, journal_len, journal_sha256) = journal_parts(journal);
    if journal_sha256 == *expect_journal_sha256 {
        return Ok(None);
    }
    Ok(Some(Divergence {
        journal,
        journal_len,
        journal_sha256,
        exit_kind,
        exit_code,
        cycles: session.total_cycles.saturating_add(
            keccak_requests.saturating_mul(keccak_request_cycles(keccak_po2_in_effect())),
        ),
    }))
}

/// One Groth16 proof of `session`, as `prove_with_opts` makes one after its own execution
/// (`ProverImpl::prove_with_ctx` is `ExecutorImpl::run` then `prove_session`), checked as
/// `run_proof_once` checks its receipt.
fn witness_prove_once(
    session: &risc0_zkvm::Session,
    image_id: risc0_zkvm::Digest,
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    // TEST-ONLY, as in `run_proof_once`: RISC0_TEST_INJECT_INVALID=N fails the first N attempts as an
    // invalid proof, before proving (so a test sees the retries reuse the session).
    if let Ok(n) = std::env::var("RISC0_TEST_INJECT_INVALID") {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let c = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if c < n.parse::<usize>().unwrap_or(0) {
            anyhow::bail!(
                "verify segment: verification indicates proof is invalid (TEST INJECTED)"
            );
        }
    }
    let start = Instant::now();
    // On Metal, every proof returns this thread's cached provers (the owner's RAM), on unwind too,
    // as `run_proof_once` does; elsewhere the Groth16 cache decision alone, after the proof.
    #[cfg(feature = "metal")]
    let proved = {
        let _release = crate::ReleaseOnDrop;
        crate::groth16_wrap::prove_session(session)
    };
    #[cfg(not(feature = "metal"))]
    let proved = crate::groth16_wrap::prove_session(session);
    #[cfg(not(feature = "metal"))]
    crate::release_groth16_cache_if_tight();
    let prove_info = proved?;
    groth16_proof_output(prove_info, image_id, start.elapsed().as_secs_f64())
}

/// Counts the keccak requests a witness session holds, for a divergence's cycles.
///
/// `Session::pending_keccaks` is crate-private in risc0; `Session::claim` logs one DEBUG line per
/// request as it folds them into its keccak root (`risc0/zkvm/src/host/server/session.rs`:
/// `adding keccak assumption: <claim>`), which a layer that sees that target only counts, on the
/// thread that calls `claim`. A fork that stops logging it counts 0 (cycles then leave out the
/// keccak charge). Installed by the IPC worker's subscriber; mirrors `sys_rand_draws`.
pub(crate) mod keccak_assumptions {
    use std::cell::Cell;

    pub(crate) const TARGET: &str = "risc0_zkvm::host::server::session";
    const PREFIX: &str = "adding keccak assumption: ";

    thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn reset() {
        COUNT.with(|c| c.set(0));
    }

    pub(crate) fn take() -> u64 {
        COUNT.with(|c| c.replace(0))
    }

    pub(crate) fn filter() -> tracing_subscriber::filter::Targets {
        tracing_subscriber::filter::Targets::new().with_target(TARGET, tracing::Level::DEBUG)
    }

    pub(crate) struct Counter;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Counter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != TARGET {
                return;
            }
            struct Message(bool);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}").starts_with(PREFIX);
                    }
                }
            }
            let mut m = Message(false);
            event.record(&mut m);
            if m.0 {
                COUNT.with(|c| c.set(c.get().saturating_add(1)));
            }
        }
    }
}

/// `--witness-execute` on a build without the mode: refuse, with the typed code.
#[cfg(not(all(target_os = "linux", feature = "cpu")))]
pub(crate) fn execute_main() -> ! {
    eprintln!("this worker has no witness execute mode: use zkminer-prove-risc0-cpu on Linux");
    std::process::exit(zkminer_prover_protocol::WitnessExecuteFailure::Unsupported.code())
}

#[cfg(all(target_os = "linux", feature = "cpu"))]
pub(crate) use execute::execute_main;

/// The one-shot sandboxed execute (plan §10.1, §5.2 step 6).
///
/// # Contract (with `zkminer_prover::witness_exec::run_witness_execute`)
/// - fd 0: one [`WitnessExecuteRequest`] frame; fd 1: one [`WitnessExecuteResponse`] frame, written
///   only on success; fd 2: logs (guest text included: never parsed); fd 3: `W`, a read-only regular
///   file or a write-sealed memfd, read with `pread`.
/// - Exit 0, or a [`WitnessExecuteFailure`] code.
/// - With [`WITNESS_EXECUTE_BUILD_ARG`] after the mode argument: one [`WitnessExecuteBuild`] frame on
///   fd 1 (what every response of this binary names as its build), exit 0; no request, no `W`, no
///   guest, under the same restriction.
/// - The first thing the process does is [`zkminer_witness_sandbox::restrict_self`] with
///   `Profile::ExecuteWorker`, while it has one thread: from then on it opens no file and keeps only
///   its inherited fds. It derives no `sys_rand` seed: it uses the one in the request.
/// - **`RISC0_KECCAK_PO2`.** risc0 reads the keccak po2 from the process environment in
///   `ExecutorEnvBuilder::build`, overriding `keccak_max_po2`. The request is the one source: the
///   launcher passes an empty environment, and the worker sets the variable from
///   `WitnessExecuteRequest::keccak_po2` after reading the request and before it starts any thread
///   (the executor's segment thread is the first). An inherited value is overwritten.
///
/// [`WitnessExecuteRequest`]: zkminer_prover_protocol::WitnessExecuteRequest
/// [`WitnessExecuteResponse`]: zkminer_prover_protocol::WitnessExecuteResponse
/// [`WitnessExecuteFailure`]: zkminer_prover_protocol::WitnessExecuteFailure
/// [`WITNESS_EXECUTE_BUILD_ARG`]: zkminer_prover_protocol::WITNESS_EXECUTE_BUILD_ARG
/// [`WitnessExecuteBuild`]: zkminer_prover_protocol::WitnessExecuteBuild
#[cfg(all(target_os = "linux", feature = "cpu"))]
mod execute {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::FileExt;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    use risc0_zkvm::{CoprocessorCallback, ExitCode};
    use zkminer_prover_protocol::{
        read_message, write_message, WitnessExecuteBuild, WitnessExecuteFailure as Failure,
        WitnessExecutePo2, WitnessExecuteRequest, WitnessExecuteResponse, GUEST_EXIT_HALTED,
        RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN, WITNESS_EXECUTE_BUILD_ARG, WITNESS_EXECUTE_W_FD,
    };

    use super::super::{
        check_claim_output, dup_cloexec, sys_rand_draws, GuestBuiltWithOldRisc0, KeccakAudit,
    };
    use super::{exit_parts, journal_parts, read_prefixed, WitnessRefusal, PREFIX_BYTES};

    pub(crate) fn execute_main() -> ! {
        // 1. The sandbox, while this is still the only thread: Landlock with no filesystem rights,
        //    the execute worker's seccomp denylist (no open, socket, exec or fork), no new
        //    privileges, not dumpable, no core. Nothing is read before it.
        if let Err(e) =
            zkminer_witness_sandbox::restrict_self(&zkminer_witness_sandbox::Profile::ExecuteWorker)
        {
            let _ = writeln!(
                std::io::stderr(),
                "witness execute: the sandbox could not be applied: {e}"
            );
            std::process::exit(Failure::Sandbox.code());
        }
        // 2. The response goes out on a copy of fd 1, and fd 1 itself becomes fd 2: risc0 wires a
        //    guest's stdout to this process's fd 1, and no guest byte may reach the response (the IPC
        //    worker isolates its stream the same way). `dup` and `dup2` open nothing.
        let response = match dup_cloexec(1).and_then(|fd| {
            // SAFETY: `fd` was just duplicated and is owned by nothing else.
            let file = unsafe { File::from_raw_fd(fd) };
            // SAFETY: plain dup2 on two open descriptors.
            if unsafe { libc::dup2(2, 1) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(file)
        }) {
            Ok(f) => f,
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "witness execute: fd 1: {e}");
                std::process::exit(Failure::Internal.code());
            }
        };
        // 3. Logs to fd 2, from this thread: neither layer starts a thread of its own. Whatever
        //    RUST_LOG says, the guest's `sys_rand` calls are counted, as an Execute's are.
        {
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(false)
                        .with_filter(
                            tracing_subscriber::EnvFilter::try_from_default_env()
                                .unwrap_or_else(|_| "warn".into()),
                        ),
                )
                .with(sys_rand_draws::Counter.with_filter(sys_rand_draws::filter()))
                .init();
        }
        // The build handshake: what this binary's responses name, before any guest runs in it.
        if std::env::args_os().nth(2).as_deref()
            == Some(std::ffi::OsStr::new(WITNESS_EXECUTE_BUILD_ARG))
        {
            let mut out = BufWriter::new(response);
            let sent = write_message(&mut out, &build()).is_ok() && out.flush().is_ok();
            std::process::exit(if sent { 0 } else { Failure::Internal.code() });
        }
        let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(response))) {
            Ok(Ok(())) => 0,
            Ok(Err(failure)) => failure.code(),
            // A malformed or hostile ELF can panic risc0 (the measure path contains the same).
            Err(_) => Failure::Panicked.code(),
        };
        std::process::exit(code)
    }

    /// This executor's build, as every response and the build handshake name it.
    fn build() -> WitnessExecuteBuild {
        WitnessExecuteBuild {
            sdk_version: format!("risc0-zkvm {}", risc0_zkvm::VERSION),
            worker_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn run(response: File) -> Result<(), Failure> {
        let req: WitnessExecuteRequest =
            read_message(&mut std::io::stdin().lock()).map_err(|e| {
                tracing::error!("reading the request: {e}");
                Failure::BadRequest
            })?;
        validate(&req)?;
        // Still the only thread (see the module docs): `ExecutorEnvBuilder::build` reads it.
        std::env::set_var("RISC0_KECCAK_PO2", req.keccak_po2.to_string());
        let input = read_w(&req)?;
        let image_id = risc0_zkvm::compute_image_id(&req.elf).map_err(|e| {
            tracing::error!("the ELF: {e:#}");
            Failure::InvalidElf
        })?;
        let mut results = Vec::with_capacity(req.po2s.len());
        for &po2 in &req.po2s {
            let result = execute_po2(&req.elf, &input, req.sys_rand_seed, po2, req.max_cycles)?;
            let halted_zero = result.exit_kind == GUEST_EXIT_HALTED && result.exit_code == 0;
            results.push(result);
            // No later po2 can make the job claimable: stop paying for it.
            if !halted_zero {
                break;
            }
        }
        let WitnessExecuteBuild {
            sdk_version,
            worker_version,
        } = build();
        let resp = WitnessExecuteResponse {
            image_id: image_id
                .as_bytes()
                .try_into()
                .expect("a digest is 32 bytes"),
            results,
            sdk_version,
            worker_version,
        };
        let mut out = BufWriter::new(response);
        write_message(&mut out, &resp)
            .and_then(|()| out.flush().map_err(Into::into))
            .map_err(|e| {
                tracing::error!("writing the response: {e}");
                Failure::Internal
            })
    }

    pub(super) fn validate(req: &WitnessExecuteRequest) -> Result<(), Failure> {
        let bad = |what: String| {
            tracing::error!("bad request: {what}");
            Failure::BadRequest
        };
        if !(req.prefix.is_empty() || req.prefix.len() == PREFIX_BYTES) {
            return Err(bad(format!("a {}-byte prefix", req.prefix.len())));
        }
        if req.po2s.is_empty() {
            return Err(bad("no po2".to_string()));
        }
        for (i, po2) in req.po2s.iter().enumerate() {
            if !(RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX).contains(po2) {
                return Err(bad(format!(
                    "po2 {po2} outside {RISC0_JOB_PO2_MIN}..={RISC0_JOB_PO2_MAX}"
                )));
            }
            if req.po2s[..i].contains(po2) {
                return Err(bad(format!("po2 {po2} twice")));
            }
        }
        if !risc0_circuit_keccak::KECCAK_PO2_RANGE.contains(&(req.keccak_po2 as usize)) {
            return Err(bad(format!(
                "keccak po2 {} outside {:?}",
                req.keccak_po2,
                risc0_circuit_keccak::KECCAK_PO2_RANGE
            )));
        }
        Ok(())
    }

    /// `pread` from offset 0 up, as a reader.
    struct Pread<'a> {
        file: &'a File,
        offset: u64,
    }

    impl std::io::Read for Pread<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.file.read_at(buf, self.offset)?;
            self.offset += n as u64;
            Ok(n)
        }
    }

    /// Whether `file` cannot change under us: opened read-only, or a memfd sealed against writes and
    /// resizing.
    fn read_only_or_sealed(file: &File) -> bool {
        let fd = file.as_raw_fd();
        // SAFETY: fcntl getters on an open descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY {
            return true;
        }
        // SAFETY: as above.
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        seals >= 0
            && seals & libc::F_SEAL_GROW != 0
            && seals & libc::F_SEAL_SHRINK != 0
            && seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0
    }

    /// `prefix ‖ W`, with `W` from fd 3.
    fn read_w(req: &WitnessExecuteRequest) -> Result<Vec<u8>, Failure> {
        // SAFETY: fd 3 is ours by the launcher's contract; nothing else in this process uses it.
        let w = unsafe { File::from_raw_fd(WITNESS_EXECUTE_W_FD) };
        let meta = w.metadata().map_err(|e| {
            tracing::error!("fd {WITNESS_EXECUTE_W_FD}: {e}");
            Failure::BadRequest
        })?;
        if !meta.is_file() || !read_only_or_sealed(&w) {
            tracing::error!(
                "fd {WITNESS_EXECUTE_W_FD} is not a read-only regular file or a sealed memfd"
            );
            return Err(Failure::BadRequest);
        }
        if meta.len() != req.w_len {
            tracing::error!("W holds {} bytes, the request {}", meta.len(), req.w_len);
            return Err(Failure::InputMismatch);
        }
        read_prefixed(
            Pread {
                file: &w,
                offset: 0,
            },
            &req.prefix,
            req.w_len,
            &req.input_sha256,
        )
        .map_err(|e| {
            tracing::error!("{e}");
            match e {
                WitnessRefusal::InputMismatch(_) => Failure::InputMismatch,
                WitnessRefusal::InputUnreadable(_) => Failure::Internal,
                _ => Failure::BadRequest,
            }
        })
    }

    /// The typed error a run's cycle budget stops it with.
    #[derive(Debug)]
    struct CycleLimitExceeded {
        limit: u64,
    }

    impl std::fmt::Display for CycleLimitExceeded {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "the execution exceeded its cap of {} sized cycles",
                self.limit
            )
        }
    }

    impl std::error::Error for CycleLimitExceeded {}

    /// Sized cycles charged so far in one run (segments as they are cut, keccak requests as they are
    /// made), against the request's cap.
    #[derive(Clone)]
    pub(super) struct CycleBudget {
        used: Arc<AtomicU64>,
        exceeded: Arc<AtomicBool>,
        limit: Option<u64>,
    }

    impl CycleBudget {
        pub(super) fn new(limit: Option<u64>) -> Self {
            CycleBudget {
                used: Arc::new(AtomicU64::new(0)),
                exceeded: Arc::new(AtomicBool::new(false)),
                limit,
            }
        }

        fn charge(&self, cycles: u64) -> anyhow::Result<()> {
            let before = self
                .used
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |u| {
                    Some(u.saturating_add(cycles))
                })
                .expect("the update always returns Some");
            match self.limit {
                Some(limit) if before.saturating_add(cycles) > limit => {
                    self.exceeded.store(true, Ordering::SeqCst);
                    Err(anyhow::Error::new(CycleLimitExceeded { limit }))
                }
                _ => Ok(()),
            }
        }

        /// Whether a charge went over the cap. Set by this code only, so a run that failed after it
        /// is classified by it, whatever the error says.
        fn exceeded(&self) -> bool {
            self.exceeded.load(Ordering::SeqCst)
        }
    }

    /// The measure path's keccak audit, charging each request to the budget.
    struct BudgetedKeccak {
        audit: KeccakAudit,
        budget: CycleBudget,
    }

    impl CoprocessorCallback for BudgetedKeccak {
        fn prove_keccak(&mut self, request: risc0_zkvm::ProveKeccakRequest) -> anyhow::Result<()> {
            let before = self.audit.cycles;
            self.audit.prove_keccak(request)?;
            self.budget.charge(self.audit.cycles - before)
        }
    }

    /// This process's peak resident set, in bytes (`getrusage`: `/proc` is out of reach).
    fn peak_rss_bytes() -> u64 {
        // SAFETY: getrusage fills the zeroed struct it is given.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return 0;
        }
        (usage.ru_maxrss.max(0) as u64).saturating_mul(1024)
    }

    /// Execute the guest on `input` at `po2` as the measure path does (`run_execute`: the input, the
    /// seed, the segment size, the keccak audit as the coprocessor callback, its checks and its cycle
    /// unit), counting what its segments serialize to without keeping or writing them.
    pub(super) fn execute_po2(
        elf: &[u8],
        input: &[u8],
        seed: [u8; 32],
        po2: u8,
        max_cycles: Option<u64>,
    ) -> Result<WitnessExecutePo2, Failure> {
        let budget = CycleBudget::new(max_cycles);
        let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
        if !input.is_empty() {
            env_builder.write_slice(input);
        }
        env_builder.random_seed(seed);
        env_builder.segment_limit_po2(po2 as u32);
        let keccak = Rc::new(RefCell::new(BudgetedKeccak {
            audit: KeccakAudit::default(),
            budget: budget.clone(),
        }));
        env_builder.coprocessor_callback_ref(keccak.clone());
        let env = env_builder.build().map_err(|e| {
            tracing::error!("the executor environment: {e:#}");
            Failure::BadRequest
        })?;
        let mut exec = risc0_zkvm::ExecutorImpl::from_elf(env, elf).map_err(|e| {
            tracing::error!("the ELF: {e:#}");
            Failure::InvalidElf
        })?;
        let segment_bytes = AtomicU64::new(0);
        let segment_cycles = AtomicU64::new(0);
        // The guest runs on this thread, which is where its `sys_rand` calls are counted.
        sys_rand_draws::reset();
        // On the executor's segment thread: count each segment and drop it.
        let run = exec.run_with_callback(|segment| {
            segment_bytes.fetch_add(bincode::serialized_size(&segment)?, Ordering::SeqCst);
            let cycles = 1u64 << segment.po2();
            segment_cycles.fetch_add(cycles, Ordering::SeqCst);
            budget.charge(cycles)?;
            Ok(Box::new(risc0_zkvm::NullSegmentRef) as Box<dyn risc0_zkvm::SegmentRef>)
        });
        drop(exec);
        let sys_rand_draws = sys_rand_draws::host_entropy_reads(sys_rand_draws::take());
        let session = match run {
            Ok(session) => session,
            Err(_) if budget.exceeded() => {
                tracing::error!("po2 {po2}: over the cap of {max_cycles:?} sized cycles");
                return Err(Failure::CycleLimit);
            }
            Err(e) => {
                tracing::error!("po2 {po2}: the execution failed: {e:#}");
                return Err(Failure::GuestFault);
            }
        };
        let keccak = keccak.borrow();
        if session.exit_code == ExitCode::Halted(0) {
            let claim = session.claim().map_err(|e| {
                tracing::error!("po2 {po2}: {e:#}");
                Failure::Unprovable
            })?;
            check_claim_output(Some(&claim), keccak.audit.root().as_ref()).map_err(|e| {
                tracing::error!("po2 {po2}: {e:#}");
                if e.downcast_ref::<GuestBuiltWithOldRisc0>().is_some() {
                    Failure::OldRisc0Guest
                } else {
                    Failure::Unprovable
                }
            })?;
        }
        let (exit_kind, exit_code) = exit_parts(session.exit_code);
        let journal = session
            .journal
            .as_ref()
            .map(|j| j.bytes.as_slice())
            .unwrap_or_default();
        let (journal, journal_len, journal_sha256) = journal_parts(journal);
        Ok(WitnessExecutePo2 {
            po2,
            // The measure path's unit: every segment padded to its power of two, plus each keccak
            // request at its keccak po2.
            cycles: segment_cycles
                .load(Ordering::SeqCst)
                .saturating_add(keccak.audit.cycles),
            journal,
            journal_len,
            journal_sha256,
            exit_kind,
            exit_code,
            segment_bytes: segment_bytes.load(Ordering::SeqCst),
            peak_host_bytes: peak_rss_bytes(),
            sys_rand_draws,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FIBONACCI_ELF;

    fn sha256(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    fn witness_for(dir: &Path, w: &[u8], prefix: &[u8], expect_journal: &[u8]) -> WitnessProve {
        let path = dir.join("w.bin");
        std::fs::write(&path, w).unwrap();
        WitnessProve {
            input_path: path.to_str().unwrap().to_string(),
            prefix: prefix.to_vec(),
            input_sha256: sha256(&[prefix, w].concat()),
            w_len: w.len() as u64,
            expect_journal_sha256: sha256(expect_journal),
            segment_dir: dir.join("segments").to_str().unwrap().to_string(),
        }
    }

    #[test]
    fn the_input_is_refused_unless_it_is_the_bundles() {
        let w = b"the witness".to_vec();
        let prefix = [7u8; 64];
        let expect = sha256(&[&prefix[..], &w].concat());
        let read = |r: &[u8], prefix: &[u8], len: u64, expect: &[u8; 32]| {
            read_prefixed(r, prefix, len, expect)
        };
        assert_eq!(
            read(&w, &prefix, w.len() as u64, &expect).unwrap(),
            [&prefix[..], &w].concat()
        );
        let without = sha256(&w);
        assert_eq!(read(&w, &[], w.len() as u64, &without).unwrap(), w);
        let mismatch =
            |r: Result<Vec<u8>, WitnessRefusal>| matches!(r, Err(WitnessRefusal::InputMismatch(_)));
        // Short, long, tampered, and without the prefix the hash covers.
        assert!(mismatch(read(&w[..5], &prefix, w.len() as u64, &expect)));
        assert!(mismatch(read(
            &[&w[..], b"!"].concat(),
            &prefix,
            w.len() as u64,
            &expect
        )));
        let mut tampered = w.clone();
        tampered[0] ^= 1;
        assert!(mismatch(read(&tampered, &prefix, w.len() as u64, &expect)));
        assert!(mismatch(read(&w, &[], w.len() as u64, &expect)));
        // A prefix of another length is the host's mistake.
        assert!(matches!(
            read(&w, &[1u8; 32], w.len() as u64, &expect),
            Err(WitnessRefusal::Protocol(_))
        ));
        assert!(matches!(
            WitnessRefusal::InputMismatch(String::new()).kind(),
            ErrorKind::InputMismatch
        ));
    }

    #[test]
    fn the_file_is_read_through_one_descriptor_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let w = vec![3u8; 3 * READ_CHUNK_BYTES + 17];
        let mut witness = witness_for(dir.path(), &w, &[], b"");
        assert_eq!(read_witness_input(&witness).unwrap(), w);
        // A length the file does not have is refused before reading it.
        witness.w_len += 1;
        assert!(matches!(
            read_witness_input(&witness),
            Err(WitnessRefusal::InputMismatch(_))
        ));
        witness.w_len -= 1;
        // A tampered file of the right length, after hashing it.
        let mut tampered = w.clone();
        tampered[READ_CHUNK_BYTES + 1] ^= 0x80;
        std::fs::write(&witness.input_path, &tampered).unwrap();
        assert!(matches!(
            read_witness_input(&witness),
            Err(WitnessRefusal::InputMismatch(_))
        ));
        // A missing file is unreadable (the store may be down), not corrupt.
        witness.input_path = dir.path().join("gone").to_str().unwrap().to_string();
        let err = read_witness_input(&witness).unwrap_err();
        assert!(matches!(err, WitnessRefusal::InputUnreadable(_)), "{err}");
        assert!(matches!(err.kind(), ErrorKind::Internal));
        // A directory is no W.
        witness.input_path = dir.path().to_str().unwrap().to_string();
        assert!(matches!(
            read_witness_input(&witness),
            Err(WitnessRefusal::InputMismatch(_))
        ));
    }

    // Unix symlinks (`std::os::unix::fs::symlink`).
    #[cfg(unix)]
    #[test]
    fn the_segment_dir_is_created_and_emptied_without_following_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"x").unwrap();

        let dir = root.path().join("slot").join("segments");
        prepare_segment_dir(&dir).unwrap();
        assert!(dir.is_dir());
        std::fs::write(dir.join("0.bincode"), b"stale").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("1.bincode"), b"stale").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        prepare_segment_dir(&dir).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "emptied");
        assert!(
            outside.join("keep").exists(),
            "a link inside is removed, not followed"
        );

        // A symlink in the directory's place is refused; so is a file, or a relative path.
        let link = root.path().join("link-dir");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            prepare_segment_dir(&link),
            Err(WitnessRefusal::SegmentDir(_))
        ));
        assert!(outside.join("keep").exists());
        assert!(matches!(
            prepare_segment_dir(&outside.join("keep")),
            Err(WitnessRefusal::SegmentDir(_))
        ));
        let mut w = witness_for(root.path(), b"", &[], b"");
        w.segment_dir = "relative/segments".to_string();
        assert!(matches!(segment_dir(&w), Err(WitnessRefusal::Protocol(_))));
        w.segment_dir = "/".to_string();
        assert!(matches!(segment_dir(&w), Err(WitnessRefusal::Protocol(_))));
    }

    #[test]
    fn a_journal_is_carried_up_to_the_fulfil_cap() {
        let (j, len, h) = journal_parts(b"abc");
        assert_eq!((j.as_slice(), len, h), (&b"abc"[..], 3, sha256(b"abc")));
        let big = vec![1u8; EXECUTE_JOURNAL_MAX_BYTES + 1];
        let (j, len, h) = journal_parts(&big);
        assert!(j.is_empty());
        assert_eq!((len as usize, h), (big.len(), sha256(&big)));
        let edge = vec![2u8; EXECUTE_JOURNAL_MAX_BYTES];
        assert_eq!(journal_parts(&edge).0, edge);
        assert_eq!(journal_parts(&[]), (vec![], 0, sha256(&[])));
    }

    #[test]
    fn exits_map_to_their_protocol_kinds() {
        assert_eq!(exit_parts(ExitCode::Halted(0)), (GUEST_EXIT_HALTED, 0));
        assert_eq!(exit_parts(ExitCode::Halted(3)), (GUEST_EXIT_HALTED, 3));
        assert_eq!(exit_parts(ExitCode::Paused(9)), (GUEST_EXIT_PAUSED, 9));
        assert_eq!(
            exit_parts(ExitCode::SystemSplit),
            (GUEST_EXIT_SYSTEM_SPLIT, 0)
        );
        assert_eq!(
            exit_parts(ExitCode::SessionLimit),
            (GUEST_EXIT_SESSION_LIMIT, 0)
        );
        assert_eq!(keccak_request_cycles(17), 1 << 20);
        assert_eq!(keccak_request_cycles(14), 1 << 20, "never less than at 17");
        assert_eq!(keccak_request_cycles(18), 1 << 21);
    }

    /// The miner derives the execute's seed from the bundle's input hash
    /// (`zkminer_prover_protocol::sys_rand::risc0_seed`); a prove worker derives its own from the input
    /// it read. They must be one seed, or a guest that reads randomness diverges at every proof.
    #[test]
    fn the_miners_seed_is_the_prove_workers_seed() {
        for input in [&b""[..], b"x", &[9u8; 100_000]] {
            let image = [4u8; 32];
            assert_eq!(
                sys_rand_seed(&image, input),
                zkminer_prover_protocol::sys_rand::risc0_seed(&image, &sha256(input))
            );
        }
    }

    fn fibonacci_image() -> Option<[u8; 32]> {
        if FIBONACCI_ELF.is_empty() {
            return None; // stubbed guests; nothing to execute
        }
        Some(verify_program_id(FIBONACCI_ELF, None).unwrap())
    }

    /// The witness session writes its segments into the slot's directory (and nowhere else), and the
    /// directory is emptied once the proof is over.
    #[test]
    fn the_session_writes_its_segments_to_the_segment_dir() {
        let Some(image) = fibonacci_image() else {
            return;
        };
        let _serial = crate::serial_guest_execution();
        let dir = tempfile::tempdir().unwrap();
        let segments = dir.path().join("segments");
        prepare_segment_dir(&segments).unwrap();
        // ~400k cycles: several segments at po2 16.
        let input = 40_000u32.to_le_bytes();
        let seed = sys_rand_seed(&image, &input);
        {
            let _wipe = WipeOnDrop(&segments);
            let session =
                execute_witness_session(FIBONACCI_ELF, &input, seed, 16, &segments).unwrap();
            assert!(
                session.segments.len() > 1,
                "{} segments",
                session.segments.len()
            );
            let mut written: Vec<String> = std::fs::read_dir(&segments)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            written.sort();
            let mut want: Vec<String> = (0..session.segments.len())
                .map(|i| format!("{i}.bincode"))
                .collect();
            want.sort();
            assert_eq!(written, want);
            // The session reads them back for the prover.
            assert_eq!(session.segments[0].resolve().unwrap().po2(), 16);
            assert_eq!(
                check_witness_session(&session, &sha256(&fib(40_000).to_le_bytes())).unwrap(),
                None
            );
        }
        assert_eq!(
            std::fs::read_dir(&segments).unwrap().count(),
            0,
            "emptied after"
        );
    }

    fn fib(n: u32) -> u64 {
        let (mut a, mut b) = (0u64, 1u64);
        for _ in 0..n {
            (a, b) = (b, a.wrapping_add(b));
        }
        a
    }

    /// A journal other than the bundle's is a divergence, reported with what the run did and never
    /// proven: a full proof would take minutes, this returns at once. The stale segment directory is
    /// emptied first and after.
    #[test]
    fn a_wrong_journal_hash_diverges_before_any_proving() {
        let Some(image) = fibonacci_image() else {
            return;
        };
        let _serial = crate::serial_guest_execution();
        let dir = tempfile::tempdir().unwrap();
        let mut witness = witness_for(dir.path(), &10u32.to_le_bytes(), &[], b"not this journal");
        std::fs::create_dir_all(&witness.segment_dir).unwrap();
        let stale = Path::new(&witness.segment_dir).join("stale.bincode");
        std::fs::write(&stale, b"from a crashed proof").unwrap();
        let started = Instant::now();
        let outcome =
            run_witness_proof(FIBONACCI_ELF, &[], Some(20), Some(image), &witness).unwrap();
        let WitnessOutcome::Diverged(d) = outcome else {
            panic!("proved a run whose journal is not the bundle's")
        };
        assert!(started.elapsed().as_secs() < 60, "no proof ran");
        assert_eq!(d.journal, 55u64.to_le_bytes());
        assert_eq!(d.journal_len, 8);
        assert_eq!(d.journal_sha256, sha256(&55u64.to_le_bytes()));
        assert_eq!((d.exit_kind, d.exit_code), (GUEST_EXIT_HALTED, 0));
        // One segment, padded to the power of two that holds it (not the limit).
        assert!(
            d.cycles.is_power_of_two() && d.cycles <= 1 << 20,
            "{}",
            d.cycles
        );
        assert!(!stale.exists(), "the stale segment was wiped");
        assert_eq!(std::fs::read_dir(&witness.segment_dir).unwrap().count(), 0);

        // With the prefix: the guest reads its first word as n.
        let mut prefix = [0u8; 64];
        prefix[..4].copy_from_slice(&12u32.to_le_bytes());
        witness = witness_for(dir.path(), b"ignored by fibonacci", &prefix, b"nope");
        let WitnessOutcome::Diverged(d) =
            run_witness_proof(FIBONACCI_ELF, &[], Some(18), Some(image), &witness).unwrap()
        else {
            panic!("proved a diverged run")
        };
        assert_eq!(d.journal, 144u64.to_le_bytes());
        assert!(
            d.cycles.is_power_of_two() && d.cycles <= 1 << 18,
            "{}",
            d.cycles
        );
    }

    #[test]
    fn a_witness_proof_is_refused_before_any_execution_when_its_input_is_not_the_bundles() {
        let Some(image) = fibonacci_image() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let witness = witness_for(dir.path(), &10u32.to_le_bytes(), &[], &55u64.to_le_bytes());
        std::fs::write(&witness.input_path, 11u32.to_le_bytes()).unwrap();
        let err = run_witness_proof(FIBONACCI_ELF, &[], Some(20), Some(image), &witness)
            .err()
            .expect("refused");
        let refusal = err.downcast_ref::<WitnessRefusal>().expect("typed");
        assert!(
            matches!(refusal.kind(), ErrorKind::InputMismatch),
            "{err:#}"
        );
        assert!(
            !Path::new(&witness.segment_dir).exists(),
            "nothing executed"
        );
        // Inline input beside a witness is the host's protocol error.
        let err = run_witness_proof(FIBONACCI_ELF, &[1], Some(20), Some(image), &witness)
            .err()
            .expect("refused");
        assert!(matches!(
            err.downcast_ref::<WitnessRefusal>().unwrap().kind(),
            ErrorKind::ProtocolError
        ));
        // And a size outside the job range, as for an inline job.
        let err = run_witness_proof(FIBONACCI_ELF, &[], Some(15), Some(image), &witness)
            .err()
            .expect("refused");
        assert!(format!("{err:#}").contains("po2 value"), "{err:#}");
    }

    #[cfg(all(target_os = "linux", feature = "cpu"))]
    mod execute_mode {
        use super::super::execute::{execute_po2, validate};
        use super::*;
        use zkminer_prover_protocol::{WitnessExecuteFailure, WitnessExecuteRequest};

        fn request(po2s: Vec<u8>) -> WitnessExecuteRequest {
            WitnessExecuteRequest {
                elf: vec![],
                prefix: vec![],
                w_len: 0,
                input_sha256: [0; 32],
                sys_rand_seed: [0; 32],
                po2s,
                keccak_po2: 17,
                max_cycles: None,
            }
        }

        #[test]
        fn a_request_is_validated_before_anything_runs() {
            assert!(validate(&request(vec![16, 20, 22])).is_ok());
            for bad in [vec![], vec![15], vec![23], vec![20, 20]] {
                assert_eq!(
                    validate(&request(bad.clone())),
                    Err(WitnessExecuteFailure::BadRequest),
                    "{bad:?}"
                );
            }
            let mut r = request(vec![20]);
            r.keccak_po2 = 13;
            assert_eq!(validate(&r), Err(WitnessExecuteFailure::BadRequest));
            r.keccak_po2 = 18;
            r.prefix = vec![0; 63];
            assert_eq!(validate(&r), Err(WitnessExecuteFailure::BadRequest));
        }

        /// The core of the sandboxed execute, unsandboxed: the measure path's cycles, the journal at
        /// every po2, the segment bytes a proof would write, and the cap.
        #[test]
        fn each_po2_reports_cycles_journal_and_segment_bytes() {
            if FIBONACCI_ELF.is_empty() {
                return;
            }
            let _serial = crate::serial_guest_execution();
            let input = 40_000u32.to_le_bytes();
            let at = |po2| execute_po2(FIBONACCI_ELF, &input, [1; 32], po2, None).unwrap();
            let (a, b) = (at(16), at(20));
            assert_eq!(a.journal, fib(40_000).to_le_bytes());
            assert_eq!(
                (a.journal.clone(), a.journal_sha256),
                (b.journal.clone(), b.journal_sha256)
            );
            assert_eq!((a.exit_kind, a.exit_code), (GUEST_EXIT_HALTED, 0));
            // Several segments at 16 (each padded to its power of two), one at 20.
            assert!(a.cycles > 1 << 16, "{}", a.cycles);
            assert!(
                b.cycles.is_power_of_two() && b.cycles <= 1 << 20,
                "{}",
                b.cycles
            );
            assert!(
                a.segment_bytes > b.segment_bytes / 2,
                "more segments, more bytes"
            );
            assert!(a.segment_bytes > 0 && b.segment_bytes > 0);
            assert!(a.peak_host_bytes > 0);
            // The cap, in the same unit: one segment fewer than the run needs.
            let err = execute_po2(
                FIBONACCI_ELF,
                &input,
                [1; 32],
                16,
                Some(a.cycles - (1 << 16)),
            );
            assert_eq!(err, Err(WitnessExecuteFailure::CycleLimit));
            assert!(execute_po2(FIBONACCI_ELF, &input, [1; 32], 16, Some(a.cycles)).is_ok());
            // An ELF risc0 refuses.
            assert_eq!(
                execute_po2(b"\x7fELF not really", &input, [1; 32], 16, None),
                Err(WitnessExecuteFailure::InvalidElf)
            );
        }

        /// Each po2 reports the guest's `sys_rand` calls past its runtime's own draw, counted as
        /// the execute worker's subscriber counts them: none for fibonacci, one for the echo guest,
        /// whose journal is the seed's words. Without the count the miner could not tell a guest
        /// whose journal ignores the seed but whose checks follow it.
        #[test]
        fn each_po2_reports_the_guests_own_sys_rand_draws() {
            use tracing_subscriber::prelude::*;
            if FIBONACCI_ELF.is_empty() || crate::SYS_RAND_ECHO_ELF.is_empty() {
                return;
            }
            let _serial = crate::serial_guest_execution();
            let counting = tracing_subscriber::registry()
                .with(crate::sys_rand_draws::Counter.with_filter(crate::sys_rand_draws::filter()));
            tracing::subscriber::with_default(counting, || {
                let fib =
                    execute_po2(FIBONACCI_ELF, &10u32.to_le_bytes(), [1; 32], 16, None).unwrap();
                assert_eq!(fib.sys_rand_draws, Some(0), "only the runtime's draw");
                for po2 in [16, 20] {
                    let echo =
                        execute_po2(crate::SYS_RAND_ECHO_ELF, &[], [7; 32], po2, None).unwrap();
                    assert_eq!(echo.sys_rand_draws, Some(1), "po2 {po2}: its one draw");
                    assert_eq!(echo.journal.len(), 32);
                }
            });
            // With nothing counting there is no draw at all: unknown, never 0.
            let uncounted = execute_po2(crate::SYS_RAND_ECHO_ELF, &[], [7; 32], 16, None).unwrap();
            assert_eq!(uncounted.sys_rand_draws, None);
        }
    }
}
