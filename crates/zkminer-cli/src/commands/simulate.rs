//! `zkminer simulate`: measure jobs the way the miner sizes them before a claim, whatever their
//! state, and report each as one JSON line.
//!
//! For an indexer or a dashboard that wants the work a job took (or would take), which the chain
//! does not record: `JobFulfilled.actualCycles` is 0 for every adapter but PoVW, and
//! `expectedCycles` is whatever the submitter declared. This runs the miner's own pre-claim steps on
//! each job, minus the ones that only decide whether THIS host should claim it:
//!
//! 1. the job's status view (its proof system and descriptor hash);
//! 2. its descriptor, rebuilt from the submit transaction and checked against that hash
//!    (`fetch_job_descriptor_checked`; a `submitTx` hint takes the one-request fast path);
//! 3. the program's ELF from the ProgramRegistry (`fetch_or_download_elf`, with its SSRF guards,
//!    size cap and timeouts), in a cache of this command's own that holds only bytes step 4 bound;
//! 4. the binding of those bytes to the job's `programId`, derived on a measure worker
//!    (`WorkerPool::derive_program_id`): the risc0 image id, or the SP1 verifying-key hash. SP1's
//!    takes minutes of CPU, so it is cached per ELF on disk. A measurement of an ELF that is not the
//!    job's program says nothing about the job, so it is never reported;
//! 5. one `Execute` on a dedicated measure worker (`WorkerPool::execute_cycles`, with its watchdog
//!    and host-RAM ledger), at the segment size given (risc0);
//! 6. the job's journal binding checked against the measured journal, as advice.
//!
//! The pool starts measure workers only (`WorkerPool::measure_only`): no prove worker, no GPU
//! context, no `sp1-gpu-server`. A host with no GPU names `zkminer-prove-risc0-cpu` (and an SP1
//! worker) in `[prover.worker_binaries]`, or passes `--risc0-worker` / `--sp1-worker`.
//!
//! Nothing is signed or sent: the client is watch-only (a throwaway key behind a transport that
//! refuses every send), as `run --watch-only` uses.

use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, B256};
use anyhow::{Context, Result};
use serde::Serialize;

use zkminer_chain::client::ChainClient;
use zkminer_chain::programs::sanitize_log;
use zkminer_config::ZkMinerConfig;
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::init_worker_pool;
use zkminer_prover_protocol::{BACKEND_RISC0, BACKEND_SP1};

use super::run::{
    fetch_or_download_elf, is_measure_preempted, is_measure_wall_clock_timeout,
    measured_binding_verdict, resolve_backend, MEASURE_FETCH_BUDGET,
};

/// The report's schema version. Bump it on any change a reader could misread.
pub const REPORT_SCHEMA: u32 = 1;

/// The longest request line read from stdin. A job id with a tx hint is under 200 bytes.
const MAX_REQUEST_LINE: usize = 4096;

/// Options for one `simulate` run (see the `Simulate` command's flags).
pub struct SimulateOptions {
    /// Job ids from the command line.
    pub jobs: Vec<B256>,
    /// Read requests from stdin, one per line, until EOF.
    pub stdin: bool,
    /// The risc0 segment size to measure at.
    pub po2: u8,
    /// Bound on one execution.
    pub execute_timeout: Duration,
    /// Bound on one program-id derivation (SP1's setup).
    pub program_id_timeout: Duration,
    /// Worker binaries that override `[prover.worker_binaries]`.
    pub risc0_worker: Option<PathBuf>,
    pub sp1_worker: Option<PathBuf>,
    /// Where this command keeps its ELF and program-id caches.
    pub cache_dir: Option<PathBuf>,
}

/// One request: a job, and optionally the transaction that submitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub job_id: B256,
    pub submit_tx: Option<B256>,
}

/// Parse one stdin line: a bare `0x…` job id, or `{"jobId": "0x…", "submitTx": "0x…"}`.
pub fn parse_request(line: &str) -> Result<Request> {
    let line = line.trim();
    anyhow::ensure!(line.len() <= MAX_REQUEST_LINE, "request line too long");
    if line.starts_with('{') {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Json {
            job_id: B256,
            #[serde(default)]
            submit_tx: Option<B256>,
        }
        let j: Json = serde_json::from_str(line).context("not a simulate request")?;
        Ok(Request {
            job_id: j.job_id,
            submit_tx: j.submit_tx,
        })
    } else {
        Ok(Request {
            job_id: line.parse().context("not a 32-byte job id")?,
            submit_tx: None,
        })
    }
}

/// How a job came out. `measured` is the only one with a cycle count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Executed: `cycles` is the count.
    Measured,
    /// Its proof system is not one this build measures (SP1 PLONK, OpenVM, unknown).
    NotServed,
    /// This build measures it, but no measure worker for its backend runs here (none was named, or
    /// it could not start). Says nothing about the job; changes when the operator adds the worker.
    NoWorker,
    /// Its descriptor can never be rebuilt (a proxy/multicall submit tx, or a hash mismatch).
    Undecodable,
    /// No ELF source: the program is not in the ProgramRegistry, or has no storage URIs. May change.
    NoProgram,
    /// The ELF served for the program is not the job's program (its image id / vkey differs).
    ProgramMismatch,
    /// The guest ran past the executor's cycle cap.
    TooHeavy,
    /// The guest failed on this input, or the worker did. Retry a few times at most.
    Failed,
    /// The execution or the program-id derivation hit its wall-clock bound. Retry a few times at most.
    Timeout,
    /// Nothing conclusive: the RPC, the registry or the ELF host failed, or every measure slot was
    /// busy. Retry later.
    Unavailable,
}

impl Outcome {
    /// Whether asking again can change the answer.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Outcome::NoWorker
                | Outcome::NoProgram
                | Outcome::Failed
                | Outcome::Timeout
                | Outcome::Unavailable
        )
    }
}

/// One job's report: a line of JSON on stdout. Numbers a JavaScript reader cannot hold exactly
/// (`cycles`) are decimal strings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema: u32,
    pub job_id: B256,
    pub outcome: Outcome,
    pub retryable: bool,
    /// Why, when not `measured`; sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_hash: Option<B256>,
    /// keccak256 of the job's `inputData`, and its length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_bytes: Option<u64>,
    /// keccak256 of the ELF measured, and its length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf_bytes: Option<u64>,
    /// How the ELF was bound to `programId`: `image_id` (risc0) or `vkey` (SP1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_check: Option<&'static str>,
    /// Seconds the binding took to derive now; 0 when it came from the cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_check_secs: Option<f64>,
    /// Total cycles as proving reports them: risc0, every segment padded to its power of two at
    /// `po2` (plus keccak proofs); SP1, its instruction count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<String>,
    /// The risc0 segment size measured at; absent for SP1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub po2: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execute_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_host_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_bytes: Option<u64>,
    /// keccak256 of the journal, when the worker reported all of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_hash: Option<B256>,
    /// The job's journal binding against the measured journal: `none` (no binding), `satisfied`,
    /// `fails`, or `unchecked` (no whole journal). Advice: a guest that reads randomness commits
    /// what its seed gives, and this host's seed is not the prover's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<&'static str>,
    pub zkminer_version: &'static str,
    pub protocol_version: u32,
}

impl Report {
    fn new(job_id: B256) -> Self {
        Self {
            schema: REPORT_SCHEMA,
            job_id,
            outcome: Outcome::Unavailable,
            retryable: true,
            reason: None,
            proof_system: None,
            backend: None,
            program_id: None,
            descriptor_hash: None,
            input_hash: None,
            input_bytes: None,
            elf_hash: None,
            elf_bytes: None,
            program_check: None,
            program_check_secs: None,
            cycles: None,
            po2: None,
            execute_secs: None,
            peak_host_bytes: None,
            journal_bytes: None,
            journal_hash: None,
            binding: None,
            zkminer_version: env!("CARGO_PKG_VERSION"),
            protocol_version: zkminer_prover_protocol::PROTOCOL_VERSION,
        }
    }

    /// End the report with `outcome`, saying why.
    fn end(mut self, outcome: Outcome, reason: impl AsRef<str>) -> Self {
        self.outcome = outcome;
        self.retryable = outcome.retryable();
        if outcome != Outcome::Measured {
            self.reason = Some(sanitize_log(&redact_urls(reason.as_ref())));
        }
        self
    }
}

/// `text` with every URL cut to its scheme and host. An RPC client's error embeds the request URL,
/// and an operator's RPC URL carries its API key in the path, the query or the userinfo: a report is
/// stored and served by its reader, so no reason may carry one.
pub fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        // The scheme: the ASCII letters (and + - .) just before "://".
        let head = &rest[..i];
        let scheme_start = head
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |p| p + 1);
        let after = &rest[i + 3..];
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | '<'))
            .unwrap_or(after.len());
        let authority_end = after[..end].find(['/', '?', '#']).unwrap_or(end);
        let authority = &after[..authority_end];
        // Drop userinfo (`user:pass@host`).
        let host = authority.rsplit('@').next().unwrap_or(authority);
        out.push_str(&rest[..scheme_start]);
        if scheme_start == i {
            // No scheme letters: not a URL, keep the text as it is.
            out.push_str("://");
            rest = after;
            continue;
        }
        out.push_str(&head[scheme_start..]);
        out.push_str("://");
        out.push_str(host);
        if end > authority_end || authority.contains('@') {
            out.push_str("/…");
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Whether `derived` (as a worker reports it) is `program_id`. risc0: the native order only, the one
/// the deployed adapter verifies (see the risc0 worker's `image_id_matches`). SP1: either order, as
/// the SP1 worker's prove-path gate accepts, since the on-chain order of a vkey hash is
/// deployment-defined and a wrong ELF matches neither.
pub fn program_id_matches(backend: &str, derived: &[u8; 32], program_id: &B256) -> bool {
    if derived == &program_id.0 {
        return true;
    }
    backend == BACKEND_SP1 && derived.iter().rev().eq(program_id.0.iter())
}

/// Classify a failed `execute_cycles` the way the miner's measure path does: typed transients first
/// (never by message, which carries guest bytes), then risc0's or SP1's clean cycle-cap trip.
fn classify_execute_error(e: &anyhow::Error) -> Outcome {
    if e.downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .is_some()
        || e.downcast_ref::<zkminer_prover_protocol::types::MeasureSlotsBusy>()
            .is_some()
        || is_measure_preempted(e)
    {
        return Outcome::Unavailable;
    }
    if is_measure_wall_clock_timeout(e) {
        return Outcome::Timeout;
    }
    let lower = format!("{e:#}").to_lowercase();
    // A guest's panic message is its own text: one that names the cap is still a failure, not a
    // verdict that the program is too heavy.
    if lower.contains("panicked") {
        return Outcome::Failed;
    }
    if lower.contains("session limit")
        || lower.contains("exceeded cycle limit")
        || lower.contains("exceededcyclelimit")
    {
        return Outcome::TooHeavy;
    }
    Outcome::Failed
}

/// Classify a failed `derive_program_id`. Only the worker's own refusal of the bytes is about the
/// program, and only risc0's is conclusive (computing an image id is deterministic); SP1's `setup`
/// can also fail for reasons of the host, so its refusal is a strike-counted failure. Everything else
/// (no worker, a dead or killed one, an internal error) says nothing about the program.
fn classify_program_id_error(backend: &str, e: &anyhow::Error) -> Outcome {
    if e.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>()
        .is_some()
    {
        return if backend == BACKEND_RISC0 {
            Outcome::ProgramMismatch
        } else {
            Outcome::Failed
        };
    }
    match classify_execute_error(e) {
        Outcome::Unavailable => Outcome::Unavailable,
        Outcome::Timeout => Outcome::Timeout,
        _ => Outcome::Failed,
    }
}

/// The on-disk cache of derived program ids, keyed by backend and keccak256(ELF). A derived id is a
/// pure function of the bytes, so an entry never goes stale.
///
/// The id is also a function of the SDK (an SP1 vkey depends on its circuit version), so the key
/// carries the worker's SDK version: an upgraded worker derives afresh rather than reading ids the
/// old one derived.
struct ProgramIdCache {
    dir: PathBuf,
}

impl ProgramIdCache {
    fn path(&self, backend: &str, sdk: &str, elf_hash: &B256) -> PathBuf {
        let sdk = alloy::hex::encode(&keccak256(sdk.as_bytes())[..8]);
        self.dir
            .join(format!("{backend}-{sdk}-{}", alloy::hex::encode(elf_hash)))
    }

    fn get(&self, backend: &str, sdk: &str, elf_hash: &B256) -> Option<[u8; 32]> {
        let text = std::fs::read_to_string(self.path(backend, sdk, elf_hash)).ok()?;
        let bytes = alloy::hex::decode(text.trim()).ok()?;
        bytes.try_into().ok()
    }

    fn put(&self, backend: &str, sdk: &str, elf_hash: &B256, id: &[u8; 32]) {
        let path = self.path(backend, sdk, elf_hash);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        let write = std::fs::create_dir_all(&self.dir)
            .and_then(|()| std::fs::write(&tmp, alloy::hex::encode(id)))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!(
                "simulate: could not cache a program id ({e}); it is derived again next time"
            );
        }
    }
}

/// Everything one job's simulation reads.
struct Simulator {
    client: ChainClient,
    state: zkminer_tui::state::SharedState,
    pool: &'static WorkerPool,
    /// The backends with a measure worker running, and each one's SDK version (see
    /// [`ProgramIdCache`]).
    served: HashMap<&'static str, String>,
    ids: ProgramIdCache,
    po2: u8,
    execute_timeout: Duration,
    program_id_timeout: Duration,
}

impl Simulator {
    async fn simulate(&self, req: &Request) -> Report {
        let job_id = req.job_id;
        let mut r = Report::new(job_id);
        if let Some(tx) = req.submit_tx {
            // The descriptor's one-request fast path. Hash-verified, with the full scan behind it, so
            // a wrong hint costs a request and changes nothing.
            self.client.note_submit_tx(job_id, tx);
        }

        let view = match self.client.get_job_status_view(job_id).await {
            Ok(v) => v,
            Err(e) => {
                return r.end(
                    Outcome::Unavailable,
                    format!("status view unreadable: {e:#}"),
                )
            }
        };
        if view.caller == Address::ZERO {
            // The router has no record of it (the contracts never delete one): unknown here, or the
            // RPC node is behind the caller. Nothing to measure, for now.
            return r.end(Outcome::Unavailable, "the router has no record of this job");
        }
        r.descriptor_hash = Some(view.descriptorHash);
        r.proof_system = Some(
            zkminer_chain::auction::ProofSystem::from_id(view.proofSystemId).map_or_else(
                || format!("unknown proof system {}", view.proofSystemId),
                |p| p.label().to_string(),
            ),
        );
        // Decided before the descriptor and the ELF, which cost requests a job we cannot measure
        // here does not need.
        let Some(backend) = resolve_backend(view.proofSystemId) else {
            return r.end(
                Outcome::NotServed,
                "this build does not measure its proof system",
            );
        };
        r.backend = Some(backend);
        let Some(sdk) = self.served.get(backend).cloned() else {
            return r.end(
                Outcome::NoWorker,
                format!("no {backend} measure worker runs here"),
            );
        };

        // The descriptor's log scan (when the submit-tx fast path misses) ends at the cached head,
        // which nothing else here moves: a long-running `--stdin` process would otherwise never find
        // a job submitted after its first scan.
        if let Ok(head) = self.client.get_block_number().await {
            self.client.set_head_block(head);
        }
        let d = match tokio::time::timeout(
            MEASURE_FETCH_BUDGET,
            zkminer_chain::descriptor::fetch_job_descriptor_checked(
                &self.client,
                job_id,
                view.descriptorHash,
            ),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                let undecodable = e
                    .downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                    .is_some();
                return r.end(
                    if undecodable {
                        Outcome::Undecodable
                    } else {
                        Outcome::Unavailable
                    },
                    format!("descriptor: {e:#}"),
                );
            }
            Err(_) => return r.end(Outcome::Unavailable, "descriptor fetch timed out"),
        };
        let program_id = d.programId;
        r.program_id = Some(program_id);
        r.input_hash = Some(keccak256(&d.inputData));
        r.input_bytes = Some(d.inputData.len() as u64);

        if program_id == B256::ZERO {
            return r.end(Outcome::ProgramMismatch, "its programId is zero");
        }

        // The registry's `elf_hash` is not enforced, for either backend: the program id derived
        // below binds the bytes to the job, which a registrant-set hash cannot. And nothing unbound is
        // cached: with no hash to enforce, `fetch_or_download_elf` returns fresh bytes without caching
        // them, and this caches them itself once they are bound. (A cached entry is bytes a program id
        // check passed for, so it is served as it is.)
        let elf = match tokio::time::timeout(
            MEASURE_FETCH_BUDGET,
            fetch_or_download_elf(&self.client, &self.state, program_id, None, false),
        )
        .await
        {
            Ok(Ok(elf)) => elf,
            Ok(Err(e)) => {
                let outcome = if e
                    .downcast_ref::<zkminer_chain::programs::NoStorageUris>()
                    .is_some()
                {
                    Outcome::NoProgram
                } else {
                    // The registry unreadable (RPC, or a program it does not know), or every URI failed.
                    Outcome::Unavailable
                };
                return r.end(outcome, format!("ELF: {e:#}"));
            }
            Err(_) => return r.end(Outcome::Unavailable, "ELF fetch timed out"),
        };
        let elf_hash = keccak256(&elf);
        r.elf_hash = Some(elf_hash);
        r.elf_bytes = Some(elf.len() as u64);
        let elf = std::sync::Arc::new(elf);

        // Bind the bytes to the job's program before measuring them.
        r.program_check = Some(if backend == BACKEND_SP1 {
            "vkey"
        } else {
            "image_id"
        });
        let derived = match self.ids.get(backend, &sdk, &elf_hash) {
            Some(id) => {
                r.program_check_secs = Some(0.0);
                id
            }
            None => {
                let (pool, elf2, timeout) = (self.pool, elf.clone(), self.program_id_timeout);
                let backend_owned = backend.to_string();
                let started = Instant::now();
                let out = tokio::task::spawn_blocking(move || {
                    pool.derive_program_id(&backend_owned, &elf2, Some(timeout))
                })
                .await;
                match out {
                    Ok(Ok(d)) => {
                        r.program_check_secs = Some(started.elapsed().as_secs_f64());
                        self.ids.put(backend, &sdk, &elf_hash, &d.program_id);
                        d.program_id
                    }
                    Ok(Err(e)) => {
                        return r.end(
                            classify_program_id_error(backend, &e),
                            format!("program id: {e:#}"),
                        )
                    }
                    Err(join) => return r.end(Outcome::Failed, format!("program id task: {join}")),
                }
            }
        };
        if !program_id_matches(backend, &derived, &program_id) {
            return r.end(
                Outcome::ProgramMismatch,
                format!(
                    "the ELF served for {program_id} derives to 0x{}",
                    alloy::hex::encode(derived)
                ),
            );
        }
        {
            // Bound: these bytes ARE the program, so later jobs of it skip the download.
            let elf = elf.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let cache = zkminer_chain::programs::ElfCache::new();
                if !cache.contains(&program_id) {
                    if let Err(e) = cache.put(&program_id, &elf) {
                        tracing::warn!("simulate: could not cache an ELF ({e:#})");
                    }
                }
            })
            .await;
        }

        let input = std::sync::Arc::new(d.inputData.to_vec());
        let size = (backend == BACKEND_RISC0).then_some(self.po2);
        let (pool, elf2, input2, timeout) =
            (self.pool, elf.clone(), input.clone(), self.execute_timeout);
        let backend_owned = backend.to_string();
        let out = tokio::task::spawn_blocking(move || {
            pool.execute_cycles(
                &backend_owned,
                &elf2,
                &input2,
                Some(timeout),
                Some(program_id.0),
                size,
            )
        })
        .await;
        let m = match out {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => return r.end(classify_execute_error(&e), format!("execute: {e:#}")),
            Err(join) => return r.end(Outcome::Failed, format!("execute task: {join}")),
        };
        r.cycles = Some(m.cycles.to_string());
        r.po2 = size;
        r.execute_secs = Some(m.duration_secs);
        r.peak_host_bytes = Some(m.peak_host_bytes);
        r.journal_bytes = Some(m.journal_len);
        r.journal_hash = m.journal.as_ref().map(keccak256);
        r.binding = Some(if d.expectedJournalHash == B256::ZERO {
            "none"
        } else {
            let measured = m.journal.as_ref().map(|j| {
                (
                    keccak256(&d.inputData),
                    std::sync::Arc::<[u8]>::from(j.as_slice()),
                )
            });
            match measured_binding_verdict(&d, &measured, job_id, view.prover) {
                Some(Ok(())) => "satisfied",
                Some(Err(_)) => "fails",
                None => "unchecked",
            }
        });
        r.end(Outcome::Measured, "")
    }
}

/// The directory this command keeps its caches in: `--cache-dir`, else `~/.zkminer/simulate`.
fn cache_root(opt: &Option<PathBuf>) -> Result<PathBuf> {
    match opt {
        Some(d) => Ok(d.clone()),
        None => Ok(dirs::home_dir()
            .context("no home directory: pass --cache-dir")?
            .join(".zkminer")
            .join("simulate")),
    }
}

/// One line from `r`, without its newline: `Ok(None)` at EOF, `Ok(Some(Err(why)))` for a line longer
/// than `max` bytes (the rest of it is read and dropped, never buffered) or not UTF-8.
fn read_bounded_line(
    r: &mut impl BufRead,
    max: usize,
) -> std::io::Result<Option<Result<String, String>>> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if buf.len() > max {
        // Drop the rest of the line in bounded chunks.
        loop {
            let mut sink = Vec::new();
            let m = r.by_ref().take(64 * 1024).read_until(b'\n', &mut sink)?;
            if m == 0 || sink.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(Err(format!("request line longer than {max} bytes"))));
    }
    Ok(Some(
        String::from_utf8(buf).map_err(|_| "request line is not UTF-8".to_string()),
    ))
}

/// Answer a line that is not a request, so a reader that writes a line and waits for one never hangs.
fn emit_invalid(out: &mut impl Write, reason: &str) -> Result<()> {
    let v = serde_json::json!({
        "schema": REPORT_SCHEMA,
        "error": "invalid_request",
        "reason": sanitize_log(reason),
    });
    serde_json::to_writer(&mut *out, &v)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Write one report as a JSON line and flush, so a reader on a pipe sees it at once.
fn emit(out: &mut impl Write, report: &Report) -> Result<()> {
    serde_json::to_writer(&mut *out, report)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

pub async fn run(config_path: Option<&Path>, opts: SimulateOptions) -> Result<()> {
    anyhow::ensure!(
        !opts.jobs.is_empty() || opts.stdin,
        "name at least one --job, or pass --stdin"
    );
    anyhow::ensure!(
        (zkminer_prover_protocol::RISC0_JOB_PO2_MIN..=zkminer_prover_protocol::RISC0_JOB_PO2_MAX)
            .contains(&opts.po2),
        "--po2 must be within {}..={}",
        zkminer_prover_protocol::RISC0_JOB_PO2_MIN,
        zkminer_prover_protocol::RISC0_JOB_PO2_MAX
    );
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    // No key is read (the client signs with a throwaway one), so none must reach a worker either.
    if config.wallet.key_source == "env" {
        std::env::remove_var(&config.wallet.key_env_var);
    }
    let root = cache_root(&opts.cache_dir)?;
    // An ELF cache of its own, like watch-only's: pruning the shared one could cost a miner on this
    // host an ELF it holds a lock for.
    zkminer_chain::programs::set_elf_cache_dir(root.join("elfs"));
    let client = ChainClient::new_watch_only(&config, Address::ZERO).await?;

    let mut binaries: HashMap<String, PathBuf> = config
        .prover
        .worker_binaries
        .iter()
        .map(|(k, v)| (k.clone(), PathBuf::from(v)))
        .collect();
    if let Some(p) = &opts.risc0_worker {
        binaries.insert(BACKEND_RISC0.to_string(), p.clone());
    }
    if let Some(p) = &opts.sp1_worker {
        binaries.insert(BACKEND_SP1.to_string(), p.clone());
    }
    let mut pool = WorkerPool::new(
        binaries,
        config
            .prover
            .worker_search_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        None,
    );
    pool.only_backends([BACKEND_RISC0, BACKEND_SP1]);
    pool.measure_only();
    {
        // The guest's `sys_rand` seed, as the miner seeds it: from this host's key file.
        let (key, err) = zkminer_prover_protocol::sys_rand::host_key(dirs::home_dir().as_deref());
        if let Some(e) = &err {
            tracing::warn!("risc0 sys_rand key file unusable ({e}): using a key for this run only");
        }
        zkminer_prover::worker::set_risc0_sys_rand_key(key, err.is_some());
    }
    let pool = tokio::task::spawn_blocking(move || {
        pool.discover_and_spawn();
        pool
    })
    .await
    .map_err(|e| anyhow::anyhow!("worker discovery task panicked: {e}"))?;
    init_worker_pool(pool);
    let pool = zkminer_prover::engine::worker_pool().context("worker pool not initialised")?;
    // The backends with a live measure worker, and each one's SDK version (it keys the program-id
    // cache). A job for any other backend is answered `no_worker` without a request to the chain
    // beyond its status view.
    let mut served: HashMap<&'static str, String> = HashMap::new();
    for b in [BACKEND_RISC0, BACKEND_SP1] {
        if pool.measure_workers_live(b) > 0 {
            served.insert(b, pool.measure_worker_sdk_version(b).unwrap_or_default());
        }
    }
    if served.is_empty() {
        anyhow::bail!(
            "no measure worker started: name a risc0 and/or an SP1 worker binary (--risc0-worker, \
             --sp1-worker, or [prover.worker_binaries])"
        );
    }
    let mut names: Vec<&str> = served.keys().copied().collect();
    names.sort_unstable();
    tracing::info!("simulate: measuring with {} workers", names.join(" and "));

    let sim = Simulator {
        client,
        state: zkminer_tui::state::new_shared_state(),
        pool,
        served,
        ids: ProgramIdCache {
            dir: root.join("program-ids"),
        },
        po2: opts.po2,
        execute_timeout: opts.execute_timeout,
        program_id_timeout: opts.program_id_timeout,
    };
    let mut out = std::io::stdout().lock();
    for job_id in &opts.jobs {
        let report = sim
            .simulate(&Request {
                job_id: *job_id,
                submit_tx: None,
            })
            .await;
        emit(&mut out, &report)?;
    }
    if opts.stdin {
        // Read on a blocking thread, a bounded line at a time, so a slow writer never stalls the
        // runtime and an endless line cannot grow a buffer. Every non-empty line gets exactly one
        // line back: a report, or an `invalid_request` for a line that is not a request.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<String, String>>(16);
        std::thread::spawn(move || {
            let mut stdin = std::io::BufReader::new(std::io::stdin().lock());
            loop {
                match read_bounded_line(&mut stdin, MAX_REQUEST_LINE) {
                    Ok(None) => break,
                    Ok(Some(line)) => {
                        if tx.blocking_send(line).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("simulate: reading stdin failed: {e}");
                        break;
                    }
                }
            }
        });
        while let Some(line) = rx.recv().await {
            let request = line.and_then(|l| {
                if l.trim().is_empty() {
                    Ok(None)
                } else {
                    parse_request(&l).map(Some).map_err(|e| format!("{e:#}"))
                }
            });
            match request {
                Ok(None) => {}
                Ok(Some(req)) => {
                    let report = sim.simulate(&req).await;
                    emit(&mut out, &report)?;
                }
                Err(why) => {
                    tracing::warn!("simulate: skipping a request line: {}", sanitize_log(&why));
                    emit_invalid(&mut out, &why)?;
                }
            }
        }
    }
    if let Some(p) = zkminer_prover::engine::worker_pool() {
        p.close();
        p.shutdown_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    #[test]
    fn a_request_is_a_bare_id_or_json() {
        let bare = format!("{}", id(0xab));
        assert_eq!(
            parse_request(&format!("  {bare} \n")).unwrap(),
            Request {
                job_id: id(0xab),
                submit_tx: None
            }
        );
        let json = format!(r#"{{"jobId":"{}","submitTx":"{}"}}"#, id(1), id(2));
        assert_eq!(
            parse_request(&json).unwrap(),
            Request {
                job_id: id(1),
                submit_tx: Some(id(2))
            }
        );
        let no_tx = format!(r#"{{"jobId":"{}"}}"#, id(3));
        assert_eq!(parse_request(&no_tx).unwrap().submit_tx, None);
    }

    #[test]
    fn a_malformed_request_is_refused() {
        assert!(parse_request("0x1234").is_err(), "short id");
        assert!(parse_request("hello").is_err());
        assert!(parse_request(r#"{"jobId":"0x12"}"#).is_err());
        assert!(
            parse_request(&format!(r#"{{"jobId":"{}","extra":1}}"#, id(1))).is_err(),
            "unknown fields are refused, not ignored"
        );
        assert!(parse_request(&"0".repeat(MAX_REQUEST_LINE + 1)).is_err());
    }

    #[test]
    fn risc0_binds_in_native_order_only_and_sp1_in_either() {
        let pid = B256::from(std::array::from_fn::<u8, 32, _>(|i| i as u8));
        let native = pid.0;
        let mut reversed = native;
        reversed.reverse();
        assert!(program_id_matches(BACKEND_RISC0, &native, &pid));
        assert!(!program_id_matches(BACKEND_RISC0, &reversed, &pid));
        assert!(program_id_matches(BACKEND_SP1, &native, &pid));
        assert!(program_id_matches(BACKEND_SP1, &reversed, &pid));
        assert!(!program_id_matches(BACKEND_SP1, &[0u8; 32], &pid));
    }

    #[test]
    fn execute_errors_classify_by_type_before_text() {
        use zkminer_prover_protocol::types::{MeasureSlotsBusy, MeasureWallClockTimeout};
        let busy = anyhow::Error::new(MeasureSlotsBusy {
            backend: "risc0".into(),
            slots: 2,
        });
        assert_eq!(classify_execute_error(&busy), Outcome::Unavailable);
        let timeout = anyhow::Error::new(MeasureWallClockTimeout {
            slot_key: "risc0:measure:0".into(),
        });
        assert_eq!(classify_execute_error(&timeout), Outcome::Timeout);
        // A guest cannot forge the typed timeout by writing its text.
        let forged = anyhow::anyhow!("cycle measurement failed: wall-clock watchdog timeout");
        assert_eq!(classify_execute_error(&forged), Outcome::Failed);
        let cap = anyhow::anyhow!("cycle measurement failed: Session limit exceeded");
        assert_eq!(classify_execute_error(&cap), Outcome::TooHeavy);
        // Nor can it forge the cap trip from its own panic message.
        let panic =
            anyhow::anyhow!("cycle measurement failed: Guest panicked: Session limit exceeded");
        assert_eq!(classify_execute_error(&panic), Outcome::Failed);
    }

    #[test]
    fn only_a_risc0_refusal_of_the_bytes_is_a_mismatch() {
        use zkminer_prover_protocol::types::{
            MeasureSlotsBusy, MeasureWallClockTimeout, ProgramIdRefused,
        };
        let refused = || {
            anyhow::Error::new(ProgramIdRefused {
                message: "not an ELF".into(),
            })
        };
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &refused()),
            Outcome::ProgramMismatch
        );
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &refused()),
            Outcome::Failed,
            "SP1 setup can fail for the host"
        );
        // Anything not the worker's verdict says nothing about the program.
        let dead = anyhow::anyhow!("Worker sp1 died");
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &dead),
            Outcome::Failed
        );
        let no_worker = anyhow::anyhow!("no worker registered for backend 'sp1'");
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &no_worker),
            Outcome::Failed
        );
        let busy = anyhow::Error::new(MeasureSlotsBusy {
            backend: "sp1".into(),
            slots: 2,
        });
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &busy),
            Outcome::Unavailable
        );
        let slow = anyhow::Error::new(MeasureWallClockTimeout {
            slot_key: "sp1:measure:0".into(),
        });
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &slow),
            Outcome::Timeout
        );
        // A forged refusal text is not the typed refusal.
        let forged = anyhow::anyhow!("the worker refused to derive a program id: x");
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &forged),
            Outcome::Failed
        );
    }

    #[test]
    fn reasons_never_carry_a_url_path_query_or_userinfo() {
        assert_eq!(
            redact_urls(
                "error sending request for url (https://rpc.example.com/v2/SECRET?k=1): timed out"
            ),
            "error sending request for url (https://rpc.example.com/…): timed out"
        );
        assert_eq!(
            redact_urls("http://user:pw@host:8545 down"),
            "http://host:8545/… down"
        );
        assert_eq!(
            redact_urls("wss://node.example/ws/KEY"),
            "wss://node.example/…"
        );
        assert_eq!(
            redact_urls("at http://127.0.0.1:9 refused"),
            "at http://127.0.0.1:9 refused"
        );
        assert_eq!(redact_urls("no url here :// odd"), "no url here :// odd");
        assert_eq!(
            redact_urls("two: https://a/x and https://b/y?z"),
            "two: https://a/… and https://b/…"
        );
        let r = Report::new(id(1)).end(
            Outcome::Unavailable,
            "status view unreadable: https://rpc.example.com/KEY123",
        );
        assert!(!r.reason.unwrap().contains("KEY123"));
    }

    #[test]
    fn stdin_lines_are_bounded_and_utf8() {
        let input = b"first\n\xff\xfe\n".to_vec();
        let long = format!("{}\nafter\n", "x".repeat(10_000));
        let mut all = input;
        all.extend_from_slice(long.as_bytes());
        all.extend_from_slice(b"last-no-newline");
        let mut r = std::io::BufReader::new(&all[..]);
        assert_eq!(
            read_bounded_line(&mut r, 4096).unwrap(),
            Some(Ok("first".into()))
        );
        assert!(
            matches!(read_bounded_line(&mut r, 4096).unwrap(), Some(Err(e)) if e.contains("UTF-8"))
        );
        assert!(
            matches!(read_bounded_line(&mut r, 4096).unwrap(), Some(Err(e)) if e.contains("longer"))
        );
        assert_eq!(
            read_bounded_line(&mut r, 4096).unwrap(),
            Some(Ok("after".into())),
            "the long line's tail is dropped"
        );
        assert_eq!(
            read_bounded_line(&mut r, 4096).unwrap(),
            Some(Ok("last-no-newline".into()))
        );
        assert_eq!(read_bounded_line(&mut r, 4096).unwrap(), None);
        let mut crlf = std::io::BufReader::new(&b"a\r\n"[..]);
        assert_eq!(
            read_bounded_line(&mut crlf, 4096).unwrap(),
            Some(Ok("a".into()))
        );
    }

    #[test]
    fn a_report_says_why_only_when_unmeasured_and_keeps_cycles_a_string() {
        let mut r = Report::new(id(7));
        r.cycles = Some(u64::MAX.to_string());
        let r = r.end(Outcome::Measured, "ignored");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["outcome"], "measured");
        assert_eq!(v["retryable"], false);
        assert_eq!(
            v["cycles"],
            u64::MAX.to_string(),
            "a JS reader would round a number"
        );
        assert!(v.get("reason").is_none());
        assert_eq!(v["schema"], REPORT_SCHEMA);

        let r = Report::new(id(7)).end(Outcome::NoProgram, "no URIs\u{1b}[31m");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["outcome"], "no_program");
        assert_eq!(v["retryable"], true);
        assert_eq!(v["reason"], "no URIs[31m", "control bytes are stripped");
        assert!(v.get("cycles").is_none());
    }

    #[test]
    fn only_conclusive_outcomes_are_final() {
        for o in [
            Outcome::Measured,
            Outcome::NotServed,
            Outcome::Undecodable,
            Outcome::ProgramMismatch,
            Outcome::TooHeavy,
        ] {
            assert!(!o.retryable(), "{o:?}");
        }
        for o in [
            Outcome::NoWorker,
            Outcome::NoProgram,
            Outcome::Failed,
            Outcome::Timeout,
            Outcome::Unavailable,
        ] {
            assert!(o.retryable(), "{o:?}");
        }
    }

    #[test]
    fn the_program_id_cache_round_trips_and_ignores_garbage() {
        let dir = std::env::temp_dir().join(format!("zkminer-sim-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = ProgramIdCache { dir: dir.clone() };
        let h = id(9);
        let sdk = "sp1-sdk 6.8.1";
        assert_eq!(c.get(BACKEND_SP1, sdk, &h), None);
        let v: [u8; 32] = std::array::from_fn(|i| 255 - i as u8);
        c.put(BACKEND_SP1, sdk, &h, &v);
        assert_eq!(c.get(BACKEND_SP1, sdk, &h), Some(v));
        assert_eq!(c.get(BACKEND_RISC0, sdk, &h), None, "keyed by backend too");
        assert_eq!(
            c.get(BACKEND_SP1, "sp1-sdk 6.9.0", &h),
            None,
            "and by SDK: an upgrade derives afresh"
        );
        std::fs::write(c.path(BACKEND_RISC0, sdk, &h), "not hex").unwrap();
        assert_eq!(c.get(BACKEND_RISC0, sdk, &h), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
