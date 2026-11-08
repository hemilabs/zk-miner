//! `zkminer simulate`: measure jobs the way the miner sizes them before a claim, whatever their
//! state, and report each as one JSON line.
//!
//! For an indexer or a dashboard that wants the work a job took (or would take), which the chain
//! does not record: `JobFulfilled.actualCycles` is 0 under every governance adapter (only a custom
//! verifier, which the job's caller chose, reports one), and `expectedCycles` is whatever the
//! submitter declared. This runs the miner's own pre-claim steps on each job, minus the ones that
//! only decide whether THIS host should claim it:
//!
//! 1. the job's status view (its proof system and descriptor hash);
//! 2. its descriptor, rebuilt from the submit transaction and checked against that hash. A
//!    `submitTx` hint whose receipt holds the job's `JobSubmitted` is that transaction, so its
//!    calldata decides alone (no log scan); any other hint is only a fast path;
//! 3. the program's registry entry, and its ELF: bytes that bound before (a cache of this command's
//!    own, which holds only those), else the bytes the registry's `elf_hash` names from any URI
//!    that serves them, else the first URI that answers (`download_elf`, with its SSRF guards, size
//!    cap and timeouts);
//! 4. the binding of those bytes to the job's `programId`, derived on a measure worker
//!    (`WorkerPool::derive_program_id`): the risc0 image id, or the SP1 verifying-key hash. SP1's
//!    takes minutes of CPU, so it is cached per ELF on disk. A measurement of an ELF that is not the
//!    job's program says nothing about the job, so it is never reported;
//! 5. one `Execute` on a dedicated measure worker (`WorkerPool::execute_cycles`, with its watchdog
//!    and host-RAM ledger), at the segment size given (risc0), on the input its prover ran: the
//!    job's `inputData`, after `abi.encode(jobId, prover)` for a journal-prefix job (risc0 only);
//! 6. the measured journal against the job's binding, and against the fulfil's `publicValues` when
//!    the request carries them (`proven`), and whether the guest read host entropy (`hostInput`).
//!    A count is evidence of the proven run only when the journal is the proven one and the guest
//!    read nothing a prover chooses.
//!
//! risc0 guests' `sys_rand` is seeded from a key of this run's own (never `~/.zkminer`'s, which is
//! neither read nor created), and the journal comes back for it: here it backs no proof.
//!
//! A program whose ELF did not bind (refused, another id, a derivation past its bound, or a worker
//! that died deriving it), or could not be fetched, is remembered on disk (`<cache-dir>/program-
//! failures`), so its other jobs do not each pay a download and a derivation (an SP1 `setup` is
//! minutes): they are answered `unavailable` from the memory (`program_mismatch` when that was the
//! verdict) until it expires, for `--program-failure-ttl-secs`, or [`FETCH_FAILURE_TTL`] for a fetch.
//! A memory holds only while the program's registry entry reads as it did (its `elf_hash` and
//! URIs), and only for this zkminer build. A count above `--max-cycles` is `too_heavy`, never
//! `measured`.
//!
//! Every network read is bounded: [`RPC_READ_BUDGET`] for each chain read outside the descriptor
//! and ELF fetches, `MEASURE_FETCH_BUDGET` for each of those two; the derivation and the execution
//! by their flags. The README's Simulate section gives the worst case of one request.
//!
//! In `--stdin` mode a READY line comes first, once the measure workers run (an SP1 one with its CPU
//! prover built) and before any request is read:
//! `{"schema":1,"ready":true,"backends":[…],"zkminerVersion":"…","protocolVersion":…}`.
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
use serde::{Deserialize, Serialize};

use zkminer_chain::binding::{
    check_journal_binding, BindingMismatch, JOURNAL_PREFIX_BYTES, JOURNAL_PREFIX_MARKER,
};
use zkminer_chain::client::ChainClient;
use zkminer_chain::descriptor::UndecodableDescriptor;
use zkminer_chain::programs::{download_elf, sanitize_log, ElfCache, NoStorageUris, ProgramInfo};
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::init_worker_pool;
use zkminer_prover_protocol::{BACKEND_RISC0, BACKEND_SP1};

use super::run::{
    is_measure_preempted, is_measure_wall_clock_timeout, MEASURE_FETCH_BUDGET,
};

/// The report's schema version. Bump it on any change a reader could misread.
pub const REPORT_SCHEMA: u32 = 1;

/// The longest `publicValues` a request may carry, decoded (twice the router's journal cap).
pub const MAX_PUBLIC_VALUES_BYTES: usize = 65_536;

/// The longest request line read from stdin: a job id, a tx hint and the longest `publicValues`
/// as hex, with room for the JSON around them.
pub const MAX_REQUEST_LINE: usize = 2 * MAX_PUBLIC_VALUES_BYTES + 1024;

/// `--max-cycles`: the largest count reported as `measured`. Ten times the largest proof seen on
/// this market (~9.3e7 cycles, the bound the workers' own execute caps are sized from), and half
/// those caps (2e9: a guest above them is `too_heavy` already), where a count is one proof of more
/// than 7 minutes on the fastest card zk-miner has measured (an RTX 5090 proves a 92.8M-cycle job in
/// ~40 s, ~2.3M cycles/s). Every count up to it is a guest's to choose (a keccak request is charged
/// 2^20 for a few hundred cycles of guest work, and a guest can branch on host entropy a prover
/// controls), so it bounds what one job can add to a sum; a real job above it is too heavy for the
/// market as it is.
pub const DEFAULT_MAX_CYCLES: u64 = 1_000_000_000;

/// `--program-failure-ttl-secs`: how long a program whose ELF did not bind is answered from memory.
pub const DEFAULT_PROGRAM_FAILURE_TTL_SECS: u64 = 6 * 3600;

/// How long a program whose ELF could not be fetched (every URI failed, none could be used, or the
/// fetch ran past its budget) is answered from memory: short, as an ELF host can come back, but
/// long enough that the jobs of a dead host cost one fetch per this, not one each. At most
/// `--program-failure-ttl-secs`.
pub const FETCH_FAILURE_TTL: Duration = Duration::from_secs(15 * 60);

/// The bound on each chain read a request makes outside the descriptor and ELF fetches (each of
/// which has `MEASURE_FETCH_BUDGET`): the status view, the head refresh, the program's registry
/// entry and each re-read of it. One read may be several calls (a registry entry is three); healthy,
/// each is well under a second.
pub const RPC_READ_BUDGET: Duration = Duration::from_secs(30);

/// The bound on setting an SP1 measure worker up (building its CPU prover, ~15 s), outside any
/// request's own bound: before READY, and before an SP1 request whose worker was respawned.
pub const SP1_SETUP_BOUND: Duration = Duration::from_secs(120);

/// The least `--execute-timeout-secs` and `--program-id-timeout-secs` (a lower value is raised to
/// it): a request's own bound must hold the worker's per-request overhead (an ELF of up to 248 MiB
/// sent over the pipe, and parsed) beside the guest.
pub const MIN_BOUND_SECS: u64 = 60;

/// The longest SDK version string a report carries.
const MAX_SDK_VERSION_CHARS: usize = 128;

/// The failure memo's own format: part of its key, so a change to it, or to how its verdicts are
/// reached, starts afresh.
const MEMO_SCHEMA: u32 = 2;

/// How far in the future a remembered failure's date may be (clock skew between writes) before it
/// is taken for a clock that was wrong when it was written, and forgotten.
const MEMO_FUTURE_SLACK_SECS: u64 = 60;

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
    /// The largest cycle count reported as `measured` (see [`DEFAULT_MAX_CYCLES`]).
    pub max_cycles: u64,
    /// How long a program whose ELF did not bind is answered from memory; zero = never.
    pub program_failure_ttl: Duration,
    /// Worker binaries that override `[prover.worker_binaries]`.
    pub risc0_worker: Option<PathBuf>,
    pub sp1_worker: Option<PathBuf>,
    /// Where this command keeps its ELF and program-id caches.
    pub cache_dir: Option<PathBuf>,
}

/// One request: a job, and optionally the transaction that submitted it and the public values its
/// fulfil proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub job_id: B256,
    pub submit_tx: Option<B256>,
    /// The fulfil's on-chain `publicValues`, which the measured journal is compared with
    /// (`proven`).
    pub public_values: Option<Vec<u8>>,
}

/// Parse one stdin line: a bare `0x…` job id, or
/// `{"jobId": "0x…", "submitTx": "0x…", "publicValues": "0x…"}` (both optional; any other field is
/// refused).
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
            #[serde(default)]
            public_values: Option<String>,
        }
        let j: Json = serde_json::from_str(line).context("not a simulate request")?;
        Ok(Request {
            job_id: j.job_id,
            submit_tx: j.submit_tx,
            public_values: j
                .public_values
                .as_deref()
                .map(parse_public_values)
                .transpose()?,
        })
    } else {
        Ok(Request {
            job_id: line.parse().context("not a 32-byte job id")?,
            submit_tx: None,
            public_values: None,
        })
    }
}

/// `publicValues`: `0x` and an even number of hex digits, at most [`MAX_PUBLIC_VALUES_BYTES`]
/// decoded (`0x` alone is a guest that committed nothing).
fn parse_public_values(s: &str) -> Result<Vec<u8>> {
    let hex = s
        .strip_prefix("0x")
        .context("publicValues must be 0x-prefixed hex")?;
    anyhow::ensure!(
        hex.len() % 2 == 0,
        "publicValues has an odd number of hex digits"
    );
    anyhow::ensure!(
        hex.len() / 2 <= MAX_PUBLIC_VALUES_BYTES,
        "publicValues is longer than {MAX_PUBLIC_VALUES_BYTES} bytes"
    );
    alloy::hex::decode(hex).context("publicValues is not hex")
}

/// How a job came out. `measured` is the only one with a cycle count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Executed: `cycles` is the count.
    Measured,
    /// This build cannot measure it, and never will: its proof system is not one it measures
    /// (OpenVM, a custom verifier, unknown), or the run its prover proved cannot be reproduced here
    /// (an SP1 journal-prefix job). The reason says which.
    NotServed,
    /// This build measures it, but no measure worker for its backend runs here (none was named, or
    /// it could not start). Says nothing about the job; changes when the operator adds the worker.
    NoWorker,
    /// Its descriptor can never be rebuilt (a proxy/multicall submit tx, or a hash mismatch).
    Undecodable,
    /// No ELF source: the program is not in the ProgramRegistry, or has no storage URIs. May change.
    NoProgram,
    /// The ELF the registry declares for the program (its keccak256 is the registry's `elf_hash` or
    /// a URI's content hash) is not the job's program: its image id / vkey differs, or the risc0
    /// worker refuses it. Bytes the registry does not vouch for say this as `failed`.
    ProgramMismatch,
    /// The guest ran past the executor's cycle cap, or its count is above `--max-cycles`.
    TooHeavy,
    /// The guest failed on this input, or the worker did. Retry a few times at most.
    Failed,
    /// The execution or the program-id derivation hit its wall-clock bound. Retry a few times at most.
    Timeout,
    /// Nothing conclusive: the RPC, the registry or the ELF host failed, every measure slot was
    /// busy, or the answer is remembered from a failure of the program's (see the reason). Retry
    /// later.
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
    /// `po2`, plus a 2^20 charge per keccak proof request; SP1, its RV64 instruction count (a
    /// precompile counts once). Not one unit: never add the two. At most `--max-cycles`.
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
    /// The job's journal binding against the measured journal: `none` (the journal is bound by
    /// nothing; an SP1 proof-nonce job with no statement included, as the nonce binds the seal),
    /// `satisfied`, `fails`, or `unchecked` (no whole journal came back). Advice: a guest that reads
    /// host entropy commits what its seed gives, and this run's seed is not the prover's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<&'static str>,
    /// The measured journal against the `publicValues` the request carried (the fulfil's, as
    /// proven): `matches` (the same bytes), `differs`, or `unknown` (none was sent, or no whole
    /// journal came back). On every `measured` report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proven: Option<&'static str>,
    /// Whether the guest read host-supplied nondeterministic input during the run: risc0, a
    /// `sys_rand` call past its runtime's own start-up draw; never for SP1, whose executor serves
    /// none. True too when the worker could not count. A guest that branched on such input may
    /// have run another path when proven, so its count is no evidence. On every `measured` report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_input: Option<bool>,
    /// How many such reads, when counted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_input_reads: Option<u64>,
    /// The measure worker's SDK, as its handshake names it (sanitized, bounded): a program id is a
    /// function of the SDK too (an SP1 vkey of its circuit version). On every report from the point
    /// the job's backend is known to have a worker here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
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
            proven: None,
            host_input: None,
            host_input_reads: None,
            sdk_version: None,
            zkminer_version: env!("CARGO_PKG_VERSION"),
            protocol_version: zkminer_prover_protocol::PROTOCOL_VERSION,
        }
    }

    /// End the report with `outcome`, saying why.
    fn end(mut self, outcome: Outcome, reason: impl AsRef<str>) -> Self {
        self.outcome = outcome;
        self.retryable = outcome.retryable();
        if outcome != Outcome::Measured {
            self.reason = Some(clean_reason(reason.as_ref()));
        }
        self
    }
}

/// A reason as a report or the memory keeps it: control and bidi characters stripped and the length
/// bounded first, so none can hide a URL from the redaction (a control char between a scheme and its
/// `://`, stripped after, would rejoin it), then every URL cut to its scheme and host.
fn clean_reason(text: &str) -> String {
    redact_urls(&sanitize_log(text))
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
        // On a char boundary: the char before the scheme may be multi-byte ("“https://…").
        let scheme_start = head
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(p, c)| p + c.len_utf8());
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
        // The worker was already dead when the request was sent (it died while idle): nothing ran.
        || e.downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerGone>()
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
/// program, and only risc0's is conclusive (computing an image id is deterministic), and only about
/// bytes the registry vouches for (`vouched`, see [`bytes_vouched`]): a mirror's 200 error page or a
/// cut-short body is refused too, and says nothing about the program, so it is a strike-counted
/// failure. SP1's `setup` can also fail for reasons of the host, so its refusal is a failure too.
/// Everything else (no worker, a dead or killed one, an internal error) says nothing about the
/// program.
fn classify_program_id_error(backend: &str, e: &anyhow::Error, vouched: bool) -> Outcome {
    if is_program_id_refusal(e) {
        return if backend == BACKEND_RISC0 && vouched {
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

fn is_program_id_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>()
        .is_some()
}

/// Whether the registry vouches for these bytes: their keccak256 is the program's registry
/// `elf_hash`, or a storage URI's (nonzero) content hash. Only then does a failure to bind them say
/// something about the program; otherwise the download may be anything a URI answered with.
fn bytes_vouched(
    registry_elf_hash: Option<B256>,
    content_hashes: impl IntoIterator<Item = B256>,
    elf_hash: &B256,
) -> bool {
    registry_elf_hash == Some(*elf_hash)
        || content_hashes
            .into_iter()
            .any(|h| h != B256::ZERO && h == *elf_hash)
}

/// The parts of a program's registry entry a verdict about its ELF rests on: its `elf_hash` and its
/// storage URIs (kind, text, content hash), in order. The registrant can change each at any time
/// (`setBuildInfo`, `addStorageURI`, `removeStorageURI`), and a failure remembered under another
/// entry is forgotten.
fn registry_fingerprint(info: &ProgramInfo) -> B256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(info.elf_hash.unwrap_or_default().as_slice());
    for u in &info.storage_uris {
        buf.push(u.storage_type as u8);
        buf.extend_from_slice(&(u.uri.len() as u64).to_be_bytes());
        buf.extend_from_slice(u.uri.as_bytes());
        buf.extend_from_slice(u.content_hash.as_slice());
    }
    keccak256(&buf)
}

/// Whether `info` vouches for the bytes whose keccak256 is `elf_hash` (see [`bytes_vouched`]).
fn info_vouches(info: &ProgramInfo, elf_hash: &B256) -> bool {
    bytes_vouched(
        info.elf_hash,
        info.storage_uris.iter().map(|u| u.content_hash),
        elf_hash,
    )
}

/// What a reason adds when the bytes that failed to bind were not vouched for.
const UNVERIFIED_DOWNLOAD: &str = "; the download was not verified (its keccak256 is neither the \
     registry's elf_hash nor a URI's content hash), so this says nothing final about the program";

/// The job's journal binding against the measured `journal` (`None`: no whole journal came back),
/// as a report states it, the way the router checks it for `prover`.
///
/// The SP1 proof-nonce marker binds the SEAL (its nonce word), which no measurement has; the router
/// then clears slot 0 of `journalFields` and still checks FULL or FIELDS over the whole journal. So
/// the statement is checked here on a copy with slot 0 cleared: a mismatch `fails`; a match is
/// `satisfied` (the journal is all a measurement can be checked against); no statement is `none`.
fn binding_label(
    d: &JobDescriptor,
    journal: Option<&[u8]>,
    job_id: B256,
    prover: Address,
) -> &'static str {
    let marker = zkminer_chain::binding::marker(d.journalFields);
    if d.expectedJournalHash == B256::ZERO && marker.is_none() {
        return "none";
    }
    let Some(journal) = journal else {
        return "unchecked";
    };
    match check_journal_binding(d, journal, job_id, prover) {
        Ok(()) => "satisfied",
        Err(BindingMismatch::NonceUnchecked) => {
            let mut statement = d.clone();
            statement.journalFields.0[..4].fill(0);
            if statement.expectedJournalHash == B256::ZERO {
                return "none";
            }
            match check_journal_binding(&statement, journal, job_id, prover) {
                Ok(()) => "satisfied",
                Err(_) => "fails",
            }
        }
        Err(_) => "fails",
    }
}

/// The measured journal against the fulfil's `publicValues`: the same bytes, exactly.
///
/// For every job, an SP1 proof-nonce one included: the nonce is public input 4 of the SP1 wrapper,
/// in the seal (bytes 68..100), and the guest cannot read it (the executor keeps it beside the VM and
/// answers no syscall with it), so a nonce job's public values are the guest's journal as for any
/// other, and its requester's FULL hash is over all of them. A journal-prefix job's journal begins
/// with the prefix both runs were given. The router's fulfil passes these bytes as they are: risc0's
/// receipt journal and SP1's public values (`run.rs`, `public_values = proof.journal`).
fn proven_label(journal: Option<&[u8]>, public_values: Option<&[u8]>) -> &'static str {
    match (journal, public_values) {
        (Some(j), Some(p)) if j == p => "matches",
        (Some(_), Some(_)) => "differs",
        _ => "unknown",
    }
}

/// The backend that measures `proof_system_id` here: risc0 for RISC Zero Groth16, SP1 for both SP1
/// ids (PLONK too, which the miner does not claim, as it cannot prove PLONK, but which executes and
/// binds exactly as SP1 Groth16 does: the same ELF, the same vkey hash), and nothing else, whatever
/// the miner's own opt-ins (`ZKMINER_ENABLE_OPENVM` makes the miner serve OpenVM; its worker
/// measures nothing).
pub fn simulate_backend(proof_system_id: B256) -> Option<&'static str> {
    use zkminer_chain::auction::ProofSystem;
    match ProofSystem::from_id(proof_system_id)? {
        ProofSystem::Risc0Groth16 => Some(BACKEND_RISC0),
        ProofSystem::Sp1Groth16 | ProofSystem::Sp1Plonk => Some(BACKEND_SP1),
        ProofSystem::OpenVmHalo2 => None,
    }
}

/// The input the job's prover ran the guest on: its `inputData`, after the 64-byte
/// `abi.encode(jobId, prover)` for a journal-prefix job (INTERACTION_GUIDE §3a: the host passes the
/// prefix as input, the guest commits it first). risc0's input is one byte stream, so the prefix and
/// the input written one after the other are those bytes concatenated, exactly. SP1's stdin is a list
/// of buffers (the guest reads the prefix as one of its own), which one `Execute` input cannot
/// reproduce: an SP1 prefix job is never measured here (`not_served`, final). Nor, for now, is one
/// with no lock holder: the prefix names the prover.
fn guest_input(
    d: &JobDescriptor,
    job_id: B256,
    prover: Address,
    backend: &str,
) -> Result<Vec<u8>, (Outcome, &'static str)> {
    if zkminer_chain::binding::marker(d.journalFields) != Some(JOURNAL_PREFIX_MARKER) {
        return Ok(d.inputData.to_vec());
    }
    if backend != BACKEND_RISC0 {
        return Err((
            Outcome::NotServed,
            "a journal-prefix job: its prover passed abi.encode(jobId, prover) as an SP1 stdin buffer \
             of its own, which this build's one Execute input cannot reproduce, so it cannot measure \
             the proven run",
        ));
    }
    if prover == Address::ZERO {
        return Err((
            Outcome::Unavailable,
            "a journal-prefix job with no prover: its input begins with abi.encode(jobId, prover), \
             and no one holds its lock",
        ));
    }
    let mut input = Vec::with_capacity(JOURNAL_PREFIX_BYTES + d.inputData.len());
    input.extend_from_slice(job_id.as_slice());
    input.extend_from_slice(B256::left_padding_from(prover.as_slice()).as_slice());
    input.extend_from_slice(&d.inputData);
    Ok(input)
}

/// Why a measured count is not reported as one: above `max`.
fn over_cycle_cap(cycles: u64, max: u64) -> Option<String> {
    (cycles > max).then(|| {
        format!("measured {cycles} cycles, above the {max} reported at most (--max-cycles)")
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One program whose ELF did not bind, or could not be fetched, as remembered (see
/// [`ProgramFailureMemo`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RememberedFailure {
    /// The outcome the job it happened on got.
    outcome: Outcome,
    /// Its reason, sanitized and redacted.
    reason: String,
    /// When, in Unix seconds.
    at: u64,
    /// For how long, in seconds (a fetch failure is remembered for less than a binding verdict).
    ttl: u64,
    /// The program's registry entry it was reached under ([`registry_fingerprint`]).
    registry: B256,
    /// keccak256 of the bytes it is about; none for a fetch failure.
    elf_hash: Option<B256>,
}

impl RememberedFailure {
    fn new(
        outcome: Outcome,
        reason: &str,
        ttl: Duration,
        registry: B256,
        elf_hash: Option<B256>,
    ) -> Self {
        Self {
            outcome,
            reason: clean_reason(reason),
            at: unix_now(),
            ttl: ttl.as_secs(),
            registry,
            elf_hash,
        }
    }
}

/// What a remembered failure answers for a later job of its program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recall {
    /// This outcome, from the memory.
    Answer(Outcome),
    /// Nothing: the program is downloaded and derived afresh (and the entry removed).
    Forget,
}

/// What `m` answers now, given the program's registry entry as read for this request (`registry`,
/// its fingerprint, and `vouched`, whether it vouches for given bytes). Only while the entry reads as
/// it did when `m` was reached: a registrant who fixed the program's `elf_hash` or URIs meanwhile
/// gets a fresh look. A final verdict (`program_mismatch`) stays final, and only while the registry
/// still vouches for the very bytes it was about; anything else is `unavailable`. Nothing new was
/// learned about this job, so a reader must not count that as one more strike against it.
fn recall(m: &RememberedFailure, registry: B256, vouched: impl Fn(&B256) -> bool) -> Recall {
    if m.registry != registry {
        return Recall::Forget;
    }
    if m.outcome == Outcome::ProgramMismatch {
        return match m.elf_hash {
            Some(h) if vouched(&h) => Recall::Answer(Outcome::ProgramMismatch),
            _ => Recall::Forget,
        };
    }
    Recall::Answer(Outcome::Unavailable)
}

/// What a remembered failure is keyed by beside its backend, SDK and program: the memo's format,
/// this zkminer's version, and this binary's length and modification time. An upgraded (or rebuilt)
/// zkminer then derives afresh rather than answer from its predecessor's verdicts. (The workspace
/// version alone does not move between commits.)
fn memo_build_identity() -> String {
    let exe = std::env::current_exe()
        .and_then(|p| std::fs::metadata(p))
        .map(|m| {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            format!("{}:{mtime}", m.len())
        })
        .unwrap_or_default();
    format!(
        "memo v{MEMO_SCHEMA}; zkminer {}; {exe}",
        env!("CARGO_PKG_VERSION")
    )
}

/// Programs whose ELF lately failed to bind (the worker refused it, it derived to another id, the
/// derivation hit its bound, or the worker died deriving it), or could not be fetched, on disk,
/// keyed by this build ([`memo_build_identity`]), backend, SDK and `programId`, each for its own
/// TTL (at most `ttl`). Without it a program's every job pays a download and a derivation, an SP1
/// `setup` being minutes of CPU on the one queue, and a dead ELF host the whole fetch budget. A
/// program whose bytes bound is unaffected: binding clears its entry, and an ELF cached for it
/// (bytes that bound) overrides the memory. See [`recall`] for what an entry answers.
struct ProgramFailureMemo {
    dir: PathBuf,
    ttl: Duration,
    build: String,
}

impl ProgramFailureMemo {
    fn path(&self, backend: &str, sdk: &str, program_id: &B256) -> PathBuf {
        let key = alloy::hex::encode(&keccak256(format!("{}\n{sdk}", self.build))[..8]);
        self.dir
            .join(format!("{backend}-{key}-{}", alloy::hex::encode(program_id)))
    }

    /// The remembered failure, and its age in seconds, while it is younger than its TTL (and
    /// `ttl`). One dated more than [`MEMO_FUTURE_SLACK_SECS`] ahead was written under a wrong clock:
    /// it is forgotten, as is an unreadable one (both removed).
    fn get(&self, backend: &str, sdk: &str, program_id: &B256) -> Option<(RememberedFailure, u64)> {
        if self.ttl.is_zero() {
            return None;
        }
        let path = self.path(backend, sdk, program_id);
        let text = std::fs::read_to_string(&path).ok()?;
        let Ok(m) = serde_json::from_str::<RememberedFailure>(&text) else {
            let _ = std::fs::remove_file(&path);
            return None;
        };
        let now = unix_now();
        let age = now.saturating_sub(m.at);
        if m.at > now.saturating_add(MEMO_FUTURE_SLACK_SECS) || age >= self.ttl_of(&m) {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        Some((m, age))
    }

    /// How long `m` lives, in seconds.
    fn ttl_of(&self, m: &RememberedFailure) -> u64 {
        m.ttl.min(self.ttl.as_secs())
    }

    fn put(&self, backend: &str, sdk: &str, program_id: &B256, m: &RememberedFailure) {
        if self.ttl.is_zero() {
            return;
        }
        let path = self.path(backend, sdk, program_id);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        let write = std::fs::create_dir_all(&self.dir)
            .and_then(|()| std::fs::write(&tmp, serde_json::to_vec(m).unwrap_or_default()))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!("simulate: could not remember a program's failure ({e})");
        }
    }

    fn clear(&self, backend: &str, sdk: &str, program_id: &B256) {
        let _ = std::fs::remove_file(self.path(backend, sdk, program_id));
    }
}

/// The on-disk cache of derived program ids, keyed by backend and keccak256(ELF). A derived id is a
/// pure function of the bytes, so an entry never goes stale.
///
/// The id is also a function of the SDK (an SP1 vkey depends on its circuit version), so the key
/// carries the worker's SDK version: an upgraded worker derives afresh rather than reading ids the
/// old one derived.
///
/// It is never pruned, unlike the ELF cache (4 GiB, oldest first), so it is also the lasting record
/// that program P bound with bytes H: bytes for P downloaded again after the ELF cache dropped them
/// hash to H when they are the same bytes, and are bound from here without a derivation. Other bytes
/// hash otherwise and are derived afresh: an id is never trusted for bytes it was not derived from.
/// (So a registrant who serves fresh trailing bytes on each download costs one derivation per
/// download that misses the ELF cache: one per fulfilled job of theirs, each a proof they paid for.)
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
    pool: &'static WorkerPool,
    /// The backends with a measure worker running, and each one's SDK version (see
    /// [`ProgramIdCache`]).
    served: HashMap<&'static str, String>,
    ids: ProgramIdCache,
    failures: ProgramFailureMemo,
    po2: u8,
    execute_timeout: Duration,
    program_id_timeout: Duration,
    max_cycles: u64,
}

/// The SDK version as a report carries it.
fn bounded_sdk_version(sdk: &str) -> String {
    sanitize_log(sdk).chars().take(MAX_SDK_VERSION_CHARS).collect()
}

impl Simulator {
    /// The program's registry entry, within [`RPC_READ_BUDGET`] (usually from the client's
    /// 10-minute cache); `Err` says why not.
    async fn registry_info(&self, program_id: B256) -> Result<ProgramInfo, String> {
        match tokio::time::timeout(RPC_READ_BUDGET, self.client.get_program_info(program_id)).await
        {
            Ok(Ok(info)) => Ok(info),
            Ok(Err(e)) => Err(format!("the ProgramRegistry could not be read: {e:#}")),
            Err(_) => Err(format!(
                "the ProgramRegistry read took over {} s",
                RPC_READ_BUDGET.as_secs()
            )),
        }
    }

    /// The job's descriptor, hash-checked: from `hint` alone when its receipt shows it is the
    /// job's submit tx (so undecodable calldata is final with no scan), else the usual way (a hint
    /// the RPC could not settle is its fast path).
    async fn descriptor(
        &self,
        job_id: B256,
        hint: Option<B256>,
        expected: B256,
    ) -> Result<JobDescriptor> {
        if let Some(tx) = hint {
            match zkminer_chain::descriptor::fetch_job_descriptor_from_submit_tx(
                &self.client,
                job_id,
                tx,
                expected,
            )
            .await
            {
                Ok(Some(d)) => return Ok(d),
                // Not the submit tx: the scan finds the real one.
                Ok(None) => {}
                Err(e) if e.downcast_ref::<UndecodableDescriptor>().is_some() => return Err(e),
                Err(e) => {
                    tracing::debug!(
                        "simulate: the submit-tx hint for {job_id} could not be checked ({}); \
                         trying it as the fast path",
                        clean_reason(&format!("{e:#}"))
                    );
                    self.client.note_submit_tx(job_id, tx);
                }
            }
        }
        zkminer_chain::descriptor::fetch_job_descriptor_checked(&self.client, job_id, expected).await
    }

    /// The program's ELF: bytes that bound before (this command's ELF cache holds only those), else
    /// the bytes the registry's `elf_hash` names, from any URI that serves them, else what the first
    /// URI that answers serves (`download_elf`'s own checks: a URI's content hash, the size cap, the
    /// SSRF guards). So a stale or hostile first mirror does not decide for a program whose hash
    /// names other bytes another URI serves.
    async fn fetch_elf(&self, program_id: B256, info: &ProgramInfo) -> Result<Vec<u8>> {
        let cache = ElfCache::new();
        if let Some(elf) = tokio::task::spawn_blocking(move || cache.get(&program_id, None))
            .await
            .ok()
            .flatten()
        {
            return Ok(elf);
        }
        if let Some(h) = info.elf_hash {
            match download_elf(&info.storage_uris, Some(h)).await {
                Ok(elf) => return Ok(elf),
                Err(e) if e.downcast_ref::<NoStorageUris>().is_some() => return Err(e),
                Err(e) => tracing::info!(
                    "simulate: no URI of {program_id} serves the bytes its elf_hash names ({}); \
                     taking what the first that answers serves",
                    clean_reason(&format!("{e:#}"))
                ),
            }
        }
        download_elf(&info.storage_uris, None).await
    }

    /// SP1: set up the measure worker the next request runs on (its CPU prover), outside that
    /// request's bound, if it has not been since it was spawned. Nothing for risc0.
    async fn set_up_worker(&self, backend: &'static str) {
        if backend == BACKEND_SP1 {
            let pool = self.pool;
            let _ = tokio::task::spawn_blocking(move || {
                pool.warm_measure_worker(BACKEND_SP1, SP1_SETUP_BOUND)
            })
            .await;
        }
    }

    async fn simulate(&self, req: &Request) -> Report {
        let job_id = req.job_id;
        let mut r = Report::new(job_id);

        let view = match tokio::time::timeout(
            RPC_READ_BUDGET,
            self.client.get_job_status_view(job_id),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return r.end(
                    Outcome::Unavailable,
                    format!("status view unreadable: {e:#}"),
                )
            }
            Err(_) => {
                return r.end(
                    Outcome::Unavailable,
                    format!(
                        "the status view read took over {} s",
                        RPC_READ_BUDGET.as_secs()
                    ),
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
        let Some(backend) = simulate_backend(view.proofSystemId) else {
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
        r.sdk_version = Some(bounded_sdk_version(&sdk));

        // The descriptor's log scan (when no hint settles it) ends at the cached head, which nothing
        // else here moves: a long-running `--stdin` process would otherwise never find a job
        // submitted after its first scan. Best effort.
        if let Ok(Ok(head)) =
            tokio::time::timeout(RPC_READ_BUDGET, self.client.get_block_number()).await
        {
            self.client.set_head_block(head);
        }
        let d = match tokio::time::timeout(
            MEASURE_FETCH_BUDGET,
            self.descriptor(job_id, req.submit_tx, view.descriptorHash),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                let undecodable = e.downcast_ref::<UndecodableDescriptor>().is_some();
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
        // Decided before the ELF: a job whose proven run cannot be reproduced here costs no download.
        let input = match guest_input(&d, job_id, view.prover, backend) {
            Ok(input) => std::sync::Arc::new(input),
            Err((outcome, why)) => return r.end(outcome, why),
        };
        let info = match self.registry_info(program_id).await {
            Ok(info) => info,
            Err(why) => return r.end(Outcome::Unavailable, why),
        };
        let registry = registry_fingerprint(&info);

        // A program whose ELF lately failed to bind, or to download, is not downloaded and derived
        // again for each of its jobs; bytes cached for it (bytes that bound) override the memory.
        if !ElfCache::new().contains(&program_id) {
            if let Some((m, age)) = self.failures.get(backend, &sdk, &program_id) {
                match recall(&m, registry, |h| info_vouches(&info, h)) {
                    Recall::Answer(outcome) => {
                        let left = self.failures.ttl_of(&m).saturating_sub(age);
                        return r.end(
                            outcome,
                            format!(
                                "remembered from {age} s ago (asked again in {left} s): {}",
                                m.reason
                            ),
                        );
                    }
                    Recall::Forget => self.failures.clear(backend, &sdk, &program_id),
                }
            }
        }

        // The registry's `elf_hash` is preferred but not enforced, for either backend: the program
        // id derived below binds the bytes to the job, which a registrant-set hash cannot. Nothing
        // unbound is cached: this caches the bytes itself once they are bound.
        let elf = match tokio::time::timeout(MEASURE_FETCH_BUDGET, self.fetch_elf(program_id, &info))
            .await
        {
            Ok(Ok(elf)) => elf,
            Ok(Err(e)) if e.downcast_ref::<NoStorageUris>().is_some() => {
                return r.end(Outcome::NoProgram, format!("ELF: {e:#}"));
            }
            fetched => {
                // Every URI failed (or none could be used: unparseable, or not a kind this build
                // fetches), or the ELF host is too slow. The registrant can change the URIs, so this
                // stays patient, but the program's other jobs are answered from memory for a while
                // (or until its registry entry changes) instead of each paying the fetch again.
                let reason = match fetched {
                    Ok(Err(e)) => format!("ELF: {e:#}"),
                    _ => format!(
                        "the ELF fetch took over {} s",
                        MEASURE_FETCH_BUDGET.as_secs()
                    ),
                };
                self.failures.put(
                    backend,
                    &sdk,
                    &program_id,
                    &RememberedFailure::new(
                        Outcome::Unavailable,
                        &reason,
                        FETCH_FAILURE_TTL,
                        registry,
                        None,
                    ),
                );
                return r.end(Outcome::Unavailable, reason);
            }
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
                self.set_up_worker(backend).await;
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
                        return self
                            .derivation_failed(r, backend, &sdk, program_id, elf_hash, registry, e)
                            .await
                    }
                    Err(join) => return r.end(Outcome::Failed, format!("program id task: {join}")),
                }
            }
        };
        if !program_id_matches(backend, &derived, &program_id) {
            let derived_hex = alloy::hex::encode(derived);
            // Read again: a long derivation outlives the client's cache, and the entry may have
            // changed meanwhile.
            let info = match self.registry_info(program_id).await {
                Ok(info) => info,
                Err(why) => {
                    return r.end(
                        Outcome::Unavailable,
                        format!(
                            "the ELF served for {program_id} derives to 0x{derived_hex}; and {why}, to \
                             tell whether it declares these bytes"
                        ),
                    )
                }
            };
            let (outcome, note) = if !info_vouches(&info, &elf_hash) {
                (Outcome::Failed, UNVERIFIED_DOWNLOAD.to_string())
            } else if backend == BACKEND_RISC0 {
                // An image id is a function of the bytes alone.
                (Outcome::ProgramMismatch, String::new())
            } else {
                // A verifying key is a function of the bytes AND the SDK's circuit version.
                (
                    Outcome::Failed,
                    format!(
                        " under {}; an SP1 verifying key depends on the SDK's circuit version, so a \
                         program built for another SP1 release derives another one here, and this \
                         says nothing final about the program",
                        bounded_sdk_version(&sdk)
                    ),
                )
            };
            let reason =
                format!("the ELF served for {program_id} derives to 0x{derived_hex}{note}");
            self.failures.put(
                backend,
                &sdk,
                &program_id,
                &RememberedFailure::new(
                    outcome,
                    &reason,
                    self.failures.ttl,
                    registry_fingerprint(&info),
                    Some(elf_hash),
                ),
            );
            return r.end(outcome, reason);
        }
        // Bound: nothing to remember against the program.
        self.failures.clear(backend, &sdk, &program_id);
        {
            // Bound: these bytes ARE the program, so later jobs of it skip the download.
            let elf = elf.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let cache = ElfCache::new();
                if !cache.contains(&program_id) {
                    if let Err(e) = cache.put(&program_id, &elf) {
                        tracing::warn!("simulate: could not cache an ELF ({e:#})");
                    }
                }
            })
            .await;
        }

        self.set_up_worker(backend).await;
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
        r.po2 = size;
        r.execute_secs = Some(m.duration_secs);
        r.peak_host_bytes = Some(m.peak_host_bytes);
        if let Some(why) = over_cycle_cap(m.cycles, self.max_cycles) {
            return r.end(Outcome::TooHeavy, why);
        }
        r.cycles = Some(m.cycles.to_string());
        r.journal_bytes = Some(m.journal_len);
        r.journal_hash = m.journal.as_ref().map(keccak256);
        let journal = m.journal.as_deref();
        r.proven = Some(proven_label(journal, req.public_values.as_deref()));
        r.host_input_reads = m.host_entropy_reads;
        // Uncounted reads as read: a count is evidence only when the guest provably read none.
        r.host_input = Some(m.host_entropy_reads != Some(0));
        // On this descriptor's input (after its prefix, for a journal-prefix job, which the binding
        // check expects the journal to begin with).
        r.binding = Some(binding_label(&d, journal, job_id, view.prover));
        r.end(Outcome::Measured, "")
    }

    /// The report for a derivation that did not produce an id, and the memory of it when it says
    /// something about the program: the worker's refusal, the derivation's own bound, or the worker
    /// dying on it (a pure function of the bytes: an ELF that balloons the SDK kills it every time).
    #[allow(clippy::too_many_arguments)]
    async fn derivation_failed(
        &self,
        r: Report,
        backend: &'static str,
        sdk: &str,
        program_id: B256,
        elf_hash: B256,
        registry: B256,
        e: anyhow::Error,
    ) -> Report {
        let refused = is_program_id_refusal(&e);
        let died = e
            .downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerDied>()
            .is_some();
        // Only a risc0 refusal can be final, and only of bytes the registry vouches for: read again.
        let (vouched, registry) = if refused && backend == BACKEND_RISC0 {
            match self.registry_info(program_id).await {
                Ok(info) => (info_vouches(&info, &elf_hash), registry_fingerprint(&info)),
                Err(why) => {
                    return r.end(
                        Outcome::Unavailable,
                        format!(
                            "program id: {e:#}; and {why}, to tell whether it declares these bytes"
                        ),
                    )
                }
            }
        } else {
            (false, registry)
        };
        let outcome = classify_program_id_error(backend, &e, vouched);
        let reason = format!(
            "program id: {e:#}{}",
            if refused && backend == BACKEND_RISC0 && !vouched {
                UNVERIFIED_DOWNLOAD
            } else {
                ""
            }
        );
        if refused || died || is_measure_wall_clock_timeout(&e) {
            self.failures.put(
                backend,
                sdk,
                &program_id,
                &RememberedFailure::new(
                    outcome,
                    &reason,
                    self.failures.ttl,
                    registry,
                    Some(elf_hash),
                ),
            );
        }
        r.end(outcome, reason)
    }
}

/// The risc0 guests' `sys_rand` seed key for one `simulate` run: fresh, never this host's lasting key
/// (`~/.zkminer/risc0-sys-rand.key`, which is neither read nor created). No key simulate could hold
/// is the job's prover's, and a miner on this host must not have its guests' randomness served back
/// by simulation output (a guest's count, time and journal follow its seed). Passed as NOT ephemeral,
/// so the workers return the journal: in this measure-only pool it backs no proof, it is advice a
/// reader compares with the journal that was proven (`proven`).
fn per_run_sys_rand_key() -> [u8; 32] {
    rand::random()
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
        "reason": clean_reason(reason),
    });
    serde_json::to_writer(&mut *out, &v)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// The `--stdin` READY line: the measure workers run (`backends`, sorted) and requests are read from
/// now on. A reader sends nothing before it, so a process that dies starting up never takes a request
/// with it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Ready<'a> {
    schema: u32,
    ready: bool,
    backends: &'a [&'a str],
    zkminer_version: &'static str,
    protocol_version: u32,
}

fn emit_ready(out: &mut impl Write, backends: &[&str]) -> Result<()> {
    serde_json::to_writer(
        &mut *out,
        &Ready {
            schema: REPORT_SCHEMA,
            ready: true,
            backends,
            zkminer_version: env!("CARGO_PKG_VERSION"),
            protocol_version: zkminer_prover_protocol::PROTOCOL_VERSION,
        },
    )?;
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
    anyhow::ensure!(opts.max_cycles > 0, "--max-cycles must be at least 1");
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
    // The risc0 guests' `sys_rand` seed key: this run's own (see `per_run_sys_rand_key`).
    zkminer_prover::worker::set_risc0_sys_rand_key(per_run_sys_rand_key(), false);
    let pool = tokio::task::spawn_blocking(move || {
        pool.discover_and_spawn();
        pool
    })
    .await
    .map_err(|e| anyhow::anyhow!("worker discovery task panicked: {e}"))?;
    init_worker_pool(pool);
    let pool = zkminer_prover::engine::worker_pool().context("worker pool not initialised")?;
    // SP1's measure worker builds its CPU prover on first use (~15 s): before READY, and outside
    // any request's bound, so a request's bound is the request's alone.
    if pool.measure_workers_live(BACKEND_SP1) > 0 {
        let ok = tokio::task::spawn_blocking(move || {
            pool.warm_measure_worker(BACKEND_SP1, SP1_SETUP_BOUND)
        })
        .await
        .unwrap_or(false);
        if !ok {
            tracing::warn!(
                "simulate: the SP1 measure worker could not be set up now; each SP1 request tries again"
            );
        }
    }
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
        pool,
        served,
        ids: ProgramIdCache {
            dir: root.join("program-ids"),
        },
        failures: ProgramFailureMemo {
            dir: root.join("program-failures"),
            ttl: opts.program_failure_ttl,
            build: memo_build_identity(),
        },
        po2: opts.po2,
        execute_timeout: opts.execute_timeout,
        program_id_timeout: opts.program_id_timeout,
        max_cycles: opts.max_cycles,
    };
    let mut out = std::io::stdout().lock();
    if opts.stdin {
        // Before any report (a `--job` one included) and before reading a request.
        emit_ready(&mut out, &names)?;
    }
    for job_id in &opts.jobs {
        let report = sim
            .simulate(&Request {
                job_id: *job_id,
                submit_tx: None,
                public_values: None,
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
        // `close` shuts every worker down itself.
        p.close();
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
                submit_tx: None,
                public_values: None,
            }
        );
        let json = format!(r#"{{"jobId":"{}","submitTx":"{}"}}"#, id(1), id(2));
        assert_eq!(
            parse_request(&json).unwrap(),
            Request {
                job_id: id(1),
                submit_tx: Some(id(2)),
                public_values: None,
            }
        );
        let no_tx = format!(r#"{{"jobId":"{}"}}"#, id(3));
        assert_eq!(parse_request(&no_tx).unwrap().submit_tx, None);
        // The fulfil's public values: 0x hex, `0x` alone an empty journal, null none.
        let pv = format!(r#"{{"jobId":"{}","publicValues":"0x37000aFF"}}"#, id(4));
        assert_eq!(
            parse_request(&pv).unwrap().public_values,
            Some(vec![0x37, 0x00, 0x0a, 0xff])
        );
        let empty = format!(r#"{{"jobId":"{}","publicValues":"0x"}}"#, id(4));
        assert_eq!(parse_request(&empty).unwrap().public_values, Some(vec![]));
        let null = format!(r#"{{"jobId":"{}","publicValues":null}}"#, id(4));
        assert_eq!(parse_request(&null).unwrap().public_values, None);
        // The longest allowed, with a hint, fits a line.
        let longest = format!(
            r#"{{"jobId":"{}","submitTx":"{}","publicValues":"0x{}"}}"#,
            id(5),
            id(6),
            "ab".repeat(MAX_PUBLIC_VALUES_BYTES)
        );
        assert!(longest.len() <= MAX_REQUEST_LINE);
        assert_eq!(
            parse_request(&longest).unwrap().public_values.map(|v| v.len()),
            Some(MAX_PUBLIC_VALUES_BYTES)
        );
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
        for pv in [
            "37",
            "0x3",
            "0xzz",
            "0X37",
            &format!("0x{}", "00".repeat(MAX_PUBLIC_VALUES_BYTES + 1)),
        ] {
            let line = format!(r#"{{"jobId":"{}","publicValues":"{pv}"}}"#, id(1));
            if line.len() <= MAX_REQUEST_LINE {
                assert!(parse_request(&line).is_err(), "publicValues {pv:.12}");
            }
        }
        let too_long = format!("0x{}", "00".repeat(MAX_PUBLIC_VALUES_BYTES + 1));
        assert!(parse_public_values(&too_long).is_err(), "one byte past the bound");
        assert!(
            parse_request(&format!(r#"{{"jobId":"{}","publicValues":7}}"#, id(1))).is_err(),
            "not a string"
        );
        // Over the length bound: a request that would parse but for its length (padded inside the
        // JSON, where `trim` does not reach) is refused for its length alone.
        let valid = format!(r#"{{"jobId":"{}"}}"#, id(1));
        assert!(parse_request(&valid).is_ok());
        let padded = format!(r#"{{"jobId":"{}"{}}}"#, id(1), " ".repeat(MAX_REQUEST_LINE));
        let err = parse_request(&padded).expect_err("over the bound");
        assert!(format!("{err:#}").contains("too long"), "{err:#}");
        let at_bound = format!(
            r#"{{"jobId":"{}"{}}}"#,
            id(1),
            " ".repeat(MAX_REQUEST_LINE - valid.len())
        );
        assert_eq!(at_bound.len(), MAX_REQUEST_LINE);
        assert!(
            parse_request(&at_bound).is_ok(),
            "the bound itself is allowed"
        );
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
        // A worker found dead when the request was sent: nothing ran.
        let gone = anyhow::Error::new(zkminer_prover_protocol::types::MeasureWorkerGone {
            slot_key: "risc0:measure:0".into(),
            message: "Send error: Broken pipe (os error 32)".into(),
        });
        assert_eq!(classify_execute_error(&gone), Outcome::Unavailable);
        // Its text is not the type.
        let forged = anyhow::anyhow!(
            "cycle measurement failed: measure worker risc0:measure:0 was gone when the request was sent"
        );
        assert_eq!(classify_execute_error(&forged), Outcome::Failed);
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
    fn only_a_risc0_refusal_of_vouched_bytes_is_a_mismatch() {
        use zkminer_prover_protocol::types::{
            MeasureSlotsBusy, MeasureWallClockTimeout, MeasureWorkerGone, ProgramIdRefused,
        };
        let refused = || {
            anyhow::Error::new(ProgramIdRefused {
                message: "not an ELF".into(),
            })
        };
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &refused(), true),
            Outcome::ProgramMismatch
        );
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &refused(), false),
            Outcome::Failed,
            "bytes the registry does not vouch for may be a mirror's error page"
        );
        for vouched in [true, false] {
            assert_eq!(
                classify_program_id_error(BACKEND_SP1, &refused(), vouched),
                Outcome::Failed,
                "SP1 setup can fail for the host"
            );
        }
        // Anything not the worker's verdict says nothing about the program.
        let dead = anyhow::anyhow!("Worker sp1 died");
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &dead, true),
            Outcome::Failed
        );
        let no_worker = anyhow::anyhow!("no worker registered for backend 'sp1'");
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &no_worker, true),
            Outcome::Failed
        );
        let busy = anyhow::Error::new(MeasureSlotsBusy {
            backend: "sp1".into(),
            slots: 2,
        });
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &busy, true),
            Outcome::Unavailable
        );
        let gone = anyhow::Error::new(MeasureWorkerGone {
            slot_key: "sp1:measure:0".into(),
            message: "Send error: Broken pipe".into(),
        });
        assert_eq!(
            classify_program_id_error(BACKEND_SP1, &gone, true),
            Outcome::Unavailable,
            "a worker that died while idle ran nothing"
        );
        let slow = anyhow::Error::new(MeasureWallClockTimeout {
            slot_key: "sp1:measure:0".into(),
        });
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &slow, true),
            Outcome::Timeout
        );
        // A worker that died deriving: a failure (remembered for the program), never a verdict.
        let died = anyhow::Error::new(zkminer_prover_protocol::types::MeasureWorkerDied {
            slot_key: "risc0:measure:0".into(),
            message: "Worker risc0 process died (EOF)".into(),
        });
        for backend in [BACKEND_RISC0, BACKEND_SP1] {
            assert_eq!(
                classify_program_id_error(backend, &died, true),
                Outcome::Failed
            );
        }
        // A forged refusal text is not the typed refusal.
        let forged = anyhow::anyhow!("the worker refused to derive a program id: x");
        assert_eq!(
            classify_program_id_error(BACKEND_RISC0, &forged, true),
            Outcome::Failed
        );
    }

    #[test]
    fn bytes_are_vouched_for_by_the_registry_elf_hash_or_a_content_hash() {
        let (h, other) = (id(0x11), id(0x22));
        assert!(bytes_vouched(Some(h), [], &h));
        assert!(bytes_vouched(None, [B256::ZERO, h], &h));
        assert!(!bytes_vouched(Some(other), [other], &h));
        assert!(
            !bytes_vouched(None, [], &h),
            "no hash at all vouches for nothing"
        );
        assert!(
            !bytes_vouched(None, [B256::ZERO], &B256::ZERO),
            "a zero content hash is no hash"
        );
    }

    #[test]
    fn only_risc0_and_both_sp1_ids_are_measured_here() {
        use super::super::run::resolve_backend;
        use zkminer_chain::auction::ProofSystem;
        assert_eq!(
            simulate_backend(ProofSystem::Sp1Plonk.id()),
            Some(BACKEND_SP1)
        );
        assert_eq!(
            simulate_backend(ProofSystem::Sp1Groth16.id()),
            Some(BACKEND_SP1)
        );
        assert_eq!(
            simulate_backend(ProofSystem::Risc0Groth16.id()),
            Some(BACKEND_RISC0)
        );
        assert_eq!(simulate_backend(id(0x99)), None);
        // The miner still does not serve PLONK: it cannot prove it.
        assert_eq!(resolve_backend(ProofSystem::Sp1Plonk.id()), None);
        // OpenVM is never measured here, even where the miner is told to serve it: its worker
        // measures nothing, so its jobs would wait on a worker for ever.
        std::env::set_var("ZKMINER_ENABLE_OPENVM", "1");
        let openvm = simulate_backend(ProofSystem::OpenVmHalo2.id());
        std::env::remove_var("ZKMINER_ENABLE_OPENVM");
        assert_eq!(openvm, None);
    }

    #[test]
    fn a_binding_is_judged_as_the_router_judges_it() {
        let journal = b"zkpool e2e test";
        let (job, prover) = (id(0x22), Address::repeat_byte(0x33));
        let full = |j: &[u8]| {
            let d = descriptor(B256::ZERO);
            zkminer_chain::binding::full_hash(d.proofSystemId, d.programId, j)
        };
        // No binding at all.
        assert_eq!(binding_label(&descriptor(B256::ZERO), Some(journal), job, prover), "none");
        assert_eq!(binding_label(&descriptor(B256::ZERO), None, job, prover), "none");
        // FULL.
        let mut d = descriptor(B256::ZERO);
        d.expectedJournalHash = full(journal);
        assert_eq!(binding_label(&d, Some(journal), job, prover), "satisfied");
        assert_eq!(binding_label(&d, Some(b"another"), job, prover), "fails");
        assert_eq!(binding_label(&d, None, job, prover), "unchecked", "no whole journal");

        // The SP1 proof nonce binds the seal; the router still checks the statement over the whole
        // journal, with slot 0 cleared. So does this.
        let mut nonce = B256::ZERO;
        nonce.0[..4].copy_from_slice(&zkminer_chain::binding::PROOF_NONCE_MARKER.to_be_bytes());
        let mut d = descriptor(nonce);
        d.expectedJournalHash = full(journal);
        assert_eq!(binding_label(&d, Some(journal), job, prover), "satisfied");
        assert_eq!(
            binding_label(&d, Some(b"j"), job, prover),
            "fails",
            "a nonce job whose journal fails its FULL hash fails"
        );
        assert_eq!(binding_label(&d, None, job, prover), "unchecked");
        // Nonce + FIELDS: the journal's first 8 bytes as slot 1.
        let mut fields = nonce;
        fields.0[4..8].copy_from_slice(&8u32.to_be_bytes());
        let mut d = descriptor(fields);
        d.expectedJournalHash = keccak256(&journal[..8]);
        assert_eq!(binding_label(&d, Some(journal), job, prover), "satisfied");
        assert_eq!(binding_label(&d, Some(b"zkpool!! other"), job, prover), "fails");
        // A nonce and no statement: the journal is bound by nothing.
        assert_eq!(binding_label(&descriptor(nonce), Some(journal), job, prover), "none");

        // The journal prefix: checked, with the statement after it.
        let mut prefix = B256::ZERO;
        prefix.0[..4].copy_from_slice(&JOURNAL_PREFIX_MARKER.to_be_bytes());
        let mut prefixed = job.to_vec();
        prefixed.extend_from_slice(B256::left_padding_from(prover.as_slice()).as_slice());
        prefixed.extend_from_slice(journal);
        let mut d = descriptor(prefix);
        assert_eq!(binding_label(&d, Some(&prefixed), job, prover), "satisfied");
        assert_eq!(binding_label(&d, Some(journal), job, prover), "fails");
        d.expectedJournalHash = full(journal);
        assert_eq!(binding_label(&d, Some(&prefixed), job, prover), "satisfied");
        assert_eq!(
            binding_label(&d, Some(&prefixed), job, Address::repeat_byte(0x44)),
            "fails",
            "another prover's prefix"
        );
    }

    #[test]
    fn proven_is_the_exact_bytes_of_the_fulfil() {
        assert_eq!(proven_label(Some(b"55"), Some(b"55")), "matches");
        assert_eq!(proven_label(Some(b""), Some(b"")), "matches", "both empty");
        assert_eq!(proven_label(Some(b"55"), Some(b"56")), "differs");
        assert_eq!(proven_label(Some(b"55"), Some(b"55\0")), "differs", "a trailing byte");
        assert_eq!(proven_label(Some(b""), Some(b"x")), "differs");
        assert_eq!(proven_label(Some(b"55"), None), "unknown", "nothing to compare with");
        assert_eq!(proven_label(None, Some(b"55")), "unknown", "no whole journal");
        assert_eq!(proven_label(None, None), "unknown");
        // An SP1 nonce job too: its public values are the guest's journal, compared whole (the first
        // 32 bytes included).
        let mut a = vec![1u8; 40];
        let b = a.clone();
        a[0] = 2;
        assert_eq!(proven_label(Some(&a), Some(&b)), "differs");
    }

    fn descriptor(fields: B256) -> JobDescriptor {
        JobDescriptor {
            programId: id(0xaa),
            proofSystemId: zkminer_chain::auction::ProofSystem::Risc0Groth16.id(),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: vec![1u8, 2, 3].into(),
            callbackExtraData: Default::default(),
            extraVerifierData: Default::default(),
            expectedJournalHash: B256::ZERO,
            journalFields: fields,
        }
    }

    #[test]
    fn a_journal_prefix_job_runs_on_its_provers_input() {
        let mut prefix_fields = B256::ZERO;
        prefix_fields.0[..4].copy_from_slice(&JOURNAL_PREFIX_MARKER.to_be_bytes());
        let job = id(0x22);
        let prover = Address::repeat_byte(0x33);

        // No marker, or the SP1 nonce (it binds the seal): the job's input, as it is.
        let plain = descriptor(B256::ZERO);
        assert_eq!(
            guest_input(&plain, job, prover, BACKEND_SP1).unwrap(),
            vec![1, 2, 3]
        );
        let mut nonce = B256::ZERO;
        nonce.0[..4].copy_from_slice(&zkminer_chain::binding::PROOF_NONCE_MARKER.to_be_bytes());
        assert_eq!(
            guest_input(&descriptor(nonce), job, prover, BACKEND_SP1).unwrap(),
            vec![1, 2, 3]
        );

        // risc0: abi.encode(jobId, prover), then the input.
        let d = descriptor(prefix_fields);
        let input = guest_input(&d, job, prover, BACKEND_RISC0).unwrap();
        assert_eq!(input.len(), JOURNAL_PREFIX_BYTES + 3);
        assert_eq!(&input[..32], job.as_slice());
        assert_eq!(&input[32..44], &[0u8; 12]);
        assert_eq!(&input[44..64], prover.as_slice());
        assert_eq!(&input[64..], &[1, 2, 3]);
        // A guest that commits its input's first 64 bytes then its output satisfies the prefix check
        // against the same (job, prover): the measured run is the one the binding names.
        let mut journal = input[..64].to_vec();
        journal.extend_from_slice(b"out");
        assert_eq!(
            zkminer_chain::binding::check_journal_binding(&d, &journal, job, prover),
            Ok(())
        );

        // No one to name: nothing to run.
        let (outcome, _) = guest_input(&d, job, Address::ZERO, BACKEND_RISC0).unwrap_err();
        assert_eq!(outcome, Outcome::Unavailable);
        // SP1 reads the prefix as a stdin buffer of its own: not reproducible by one Execute input,
        // ever, so final.
        let (outcome, why) = guest_input(&d, job, prover, BACKEND_SP1).unwrap_err();
        assert_eq!(outcome, Outcome::NotServed);
        assert!(!outcome.retryable());
        assert!(why.contains("journal-prefix"), "{why}");
    }

    #[test]
    fn a_count_above_the_cap_is_never_measured() {
        assert_eq!(over_cycle_cap(DEFAULT_MAX_CYCLES, DEFAULT_MAX_CYCLES), None);
        let why = over_cycle_cap(1_000_000_000_000, DEFAULT_MAX_CYCLES).unwrap();
        assert!(
            why.contains("1000000000000"),
            "the count is in the reason: {why}"
        );
        let r = Report::new(id(1)).end(Outcome::TooHeavy, &why);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["outcome"], "too_heavy");
        assert_eq!(v["retryable"], false);
        assert!(v.get("cycles").is_none());
    }

    #[test]
    fn the_ready_line_is_exact() {
        let mut out = Vec::new();
        emit_ready(&mut out, &["risc0", "sp1"]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "{{\"schema\":1,\"ready\":true,\"backends\":[\"risc0\",\"sp1\"],\
                 \"zkminerVersion\":\"{}\",\"protocolVersion\":{}}}\n",
                env!("CARGO_PKG_VERSION"),
                zkminer_prover_protocol::PROTOCOL_VERSION
            )
        );
    }

    fn memo_at(dir: &Path, ttl: Duration) -> ProgramFailureMemo {
        ProgramFailureMemo {
            dir: dir.to_path_buf(),
            ttl,
            build: "test build".into(),
        }
    }

    fn remembered(outcome: Outcome, ttl: Duration, registry: B256) -> RememberedFailure {
        RememberedFailure::new(outcome, "the reason", ttl, registry, Some(id(0xee)))
    }

    #[test]
    fn a_failure_is_remembered_per_build_backend_sdk_and_program_for_its_ttl() {
        let dir = std::env::temp_dir().join(format!("zkminer-sim-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let memo = memo_at(&dir, Duration::from_secs(3600));
        let (p, q, sdk, reg) = (id(1), id(2), "sp1-sdk 6.8.1", id(0x77));
        assert!(memo.get(BACKEND_SP1, sdk, &p).is_none());
        memo.put(
            BACKEND_SP1,
            sdk,
            &p,
            &RememberedFailure::new(
                Outcome::Failed,
                "the ELF served derives to 0x12 (see https://h/KEY)",
                Duration::from_secs(3600),
                reg,
                Some(id(0xee)),
            ),
        );
        let (m, age) = memo.get(BACKEND_SP1, sdk, &p).expect("remembered");
        assert!(age < 5);
        assert_eq!(m.outcome, Outcome::Failed);
        assert_eq!((m.registry, m.elf_hash), (reg, Some(id(0xee))));
        assert!(!m.reason.contains("KEY"), "stored redacted: {}", m.reason);
        assert!(memo.get(BACKEND_SP1, sdk, &q).is_none(), "per program");
        assert!(memo.get(BACKEND_RISC0, sdk, &p).is_none(), "per backend");
        assert!(
            memo.get(BACKEND_SP1, "sp1-sdk 6.9.0", &p).is_none(),
            "per SDK"
        );
        let other_build = ProgramFailureMemo {
            build: "another build".into(),
            ..memo_at(&dir, Duration::from_secs(3600))
        };
        assert!(
            other_build.get(BACKEND_SP1, sdk, &p).is_none(),
            "per zkminer build: an upgrade answers nothing from its predecessor's memory"
        );
        memo.clear(BACKEND_SP1, sdk, &p);
        assert!(memo.get(BACKEND_SP1, sdk, &p).is_none(), "bytes that bound clear it");

        // Each entry lives its own TTL, at most the memo's: a fetch failure briefly.
        memo.put(
            BACKEND_SP1,
            sdk,
            &q,
            &remembered(Outcome::Unavailable, FETCH_FAILURE_TTL, reg),
        );
        let (m, _) = memo.get(BACKEND_SP1, sdk, &q).unwrap();
        assert_eq!(memo.ttl_of(&m), FETCH_FAILURE_TTL.as_secs());
        let short = memo_at(&dir, Duration::from_secs(60));
        assert_eq!(short.ttl_of(&m), 60, "never longer than --program-failure-ttl-secs");

        // Expired: forgotten (and removed).
        let mut old = remembered(Outcome::Unavailable, FETCH_FAILURE_TTL, reg);
        old.at = unix_now() - FETCH_FAILURE_TTL.as_secs();
        std::fs::write(
            memo.path(BACKEND_SP1, sdk, &q),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        assert!(memo.get(BACKEND_SP1, sdk, &q).is_none());
        assert!(!memo.path(BACKEND_SP1, sdk, &q).exists());
        // Dated ahead of the clock (written under a wrong one): forgotten, not kept until then.
        for (ahead, kept) in [(MEMO_FUTURE_SLACK_SECS, true), (MEMO_FUTURE_SLACK_SECS + 5, false), (365 * 86_400, false)] {
            let mut future = remembered(Outcome::Failed, Duration::from_secs(3600), reg);
            future.at = unix_now() + ahead;
            std::fs::write(
                memo.path(BACKEND_SP1, sdk, &p),
                serde_json::to_vec(&future).unwrap(),
            )
            .unwrap();
            assert_eq!(memo.get(BACKEND_SP1, sdk, &p).is_some(), kept, "{ahead} s ahead");
            assert_eq!(memo.path(BACKEND_SP1, sdk, &p).exists(), kept);
        }
        // Garbage, or the previous format: ignored and removed.
        for text in ["not json", r#"{"outcome":"failed","reason":"x","at":1}"#] {
            std::fs::write(memo.path(BACKEND_SP1, sdk, &p), text).unwrap();
            assert!(memo.get(BACKEND_SP1, sdk, &p).is_none());
            assert!(!memo.path(BACKEND_SP1, sdk, &p).exists());
        }

        // A zero TTL remembers nothing.
        let off = memo_at(&dir.join("off"), Duration::ZERO);
        off.put(BACKEND_SP1, sdk, &p, &remembered(Outcome::Failed, Duration::from_secs(9), reg));
        assert!(off.get(BACKEND_SP1, sdk, &p).is_none());
        assert!(!off.dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_remembered_failure_answers_only_while_the_registry_reads_the_same() {
        let reg = id(0x77);
        let h = id(0xee);
        let vouched = |x: &B256| *x == h;
        let never = |_: &B256| false;
        // Not final: `unavailable` (no new strike), whatever the bytes.
        for o in [Outcome::Failed, Outcome::Timeout, Outcome::Unavailable] {
            let m = remembered(o, Duration::from_secs(60), reg);
            assert_eq!(recall(&m, reg, never), Recall::Answer(Outcome::Unavailable), "{o:?}");
            assert_eq!(recall(&m, id(0x78), never), Recall::Forget, "{o:?}: entry changed");
        }
        // A final verdict stays final while the registry still vouches for its bytes.
        let m = remembered(Outcome::ProgramMismatch, Duration::from_secs(60), reg);
        assert_eq!(recall(&m, reg, vouched), Recall::Answer(Outcome::ProgramMismatch));
        assert_eq!(recall(&m, reg, never), Recall::Forget, "no longer vouched");
        assert_eq!(recall(&m, id(0x78), vouched), Recall::Forget, "the entry changed");
        let mut no_bytes = m.clone();
        no_bytes.elf_hash = None;
        assert_eq!(recall(&no_bytes, reg, vouched), Recall::Forget);
    }

    #[test]
    fn the_registry_fingerprint_covers_the_hash_and_every_uri() {
        use zkminer_chain::programs::{ResolvedURI, StorageKind};
        let uri = |kind, text: &str, hash| ResolvedURI {
            storage_type: kind,
            uri: text.into(),
            content_hash: hash,
        };
        let info = |elf_hash, uris| ProgramInfo {
            program_id: id(1),
            proof_system_id: id(2),
            name: "p".into(),
            status: 0,
            estimated_cycles: 0,
            storage_uris: uris,
            elf_hash,
        };
        let base = info(Some(id(3)), vec![uri(StorageKind::HTTP, "https://a/x", B256::ZERO)]);
        let fp = registry_fingerprint(&base);
        assert_eq!(fp, registry_fingerprint(&base.clone()));
        let mut renamed = base.clone();
        renamed.name = "q".into();
        assert_eq!(registry_fingerprint(&renamed), fp, "the name is not what a verdict rests on");
        for changed in [
            info(None, base.storage_uris.clone()),
            info(Some(id(4)), base.storage_uris.clone()),
            info(Some(id(3)), vec![]),
            info(Some(id(3)), vec![uri(StorageKind::HTTP, "https://b/x", B256::ZERO)]),
            info(Some(id(3)), vec![uri(StorageKind::IPFS, "https://a/x", B256::ZERO)]),
            info(Some(id(3)), vec![uri(StorageKind::HTTP, "https://a/x", id(5))]),
            info(
                Some(id(3)),
                vec![
                    uri(StorageKind::HTTP, "https://a/x", B256::ZERO),
                    uri(StorageKind::HTTP, "https://b/x", B256::ZERO),
                ],
            ),
        ] {
            assert_ne!(registry_fingerprint(&changed), fp);
        }
        // URI boundaries count: ["ab", "c"] is not ["a", "bc"].
        let two = |a: &str, b: &str| {
            info(None, vec![uri(StorageKind::HTTP, a, B256::ZERO), uri(StorageKind::HTTP, b, B256::ZERO)])
        };
        assert_ne!(registry_fingerprint(&two("ab", "c")), registry_fingerprint(&two("a", "bc")));
    }

    #[test]
    fn each_run_seeds_with_its_own_key() {
        let (a, b) = (per_run_sys_rand_key(), per_run_sys_rand_key());
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn a_measured_report_says_whether_it_is_evidence() {
        let mut r = Report::new(id(7));
        r.cycles = Some("32768".into());
        r.proven = Some("matches");
        r.host_input = Some(false);
        r.host_input_reads = Some(0);
        r.sdk_version = Some(bounded_sdk_version("risc0-zkvm 3.0.6\u{1b}[2J"));
        let v: serde_json::Value = serde_json::to_value(r.end(Outcome::Measured, "")).unwrap();
        assert_eq!(v["proven"], "matches");
        assert_eq!(v["hostInput"], false);
        assert_eq!(v["hostInputReads"], 0);
        assert_eq!(v["sdkVersion"], "risc0-zkvm 3.0.6[2J", "sanitized");
        assert_eq!(bounded_sdk_version(&"x".repeat(1000)).chars().count(), MAX_SDK_VERSION_CHARS);
        // An unmeasured report carries none of the evidence fields.
        let v: serde_json::Value =
            serde_json::to_value(Report::new(id(7)).end(Outcome::Failed, "no")).unwrap();
        for f in ["proven", "hostInput", "hostInputReads", "sdkVersion"] {
            assert!(v.get(f).is_none(), "{f}");
        }
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
        // A key in the query of a URL with no path, or in its fragment.
        assert_eq!(
            redact_urls("https://host?apikey=SECRET"),
            "https://host/…"
        );
        assert_eq!(
            redact_urls("at (https://host:8545?apikey=SECRET) down"),
            "at (https://host:8545/…) down"
        );
        assert_eq!(redact_urls("https://host#SECRET"), "https://host/…");
        let r = Report::new(id(1)).end(
            Outcome::Unavailable,
            "status view unreadable: https://rpc.example.com/KEY123",
        );
        assert!(!r.reason.unwrap().contains("KEY123"));
    }

    /// Sanitized before redacted: a control char inside a URL (between its scheme and `://`, or in
    /// its host) cannot hide it from the redaction and then be stripped to rejoin it.
    #[test]
    fn a_control_char_cannot_smuggle_a_url_past_the_redaction() {
        for text in [
            "https\u{1b}://host/SECRET",
            "https:\u{7}//host/SECRET",
            "ht\u{0}tps://host?apikey=SECRET",
            "https://ho\u{202e}st/SECRET",
            "https\u{2028}://host/SECRET",
        ] {
            let r = Report::new(id(1)).end(Outcome::Failed, text);
            let reason = r.reason.unwrap();
            assert!(!reason.contains("SECRET"), "{text:?} -> {reason:?}");
            assert!(clean_reason(text).contains("://"), "{text:?}");
            let invalid = {
                let mut out = Vec::new();
                emit_invalid(&mut out, text).unwrap();
                String::from_utf8(out).unwrap()
            };
            assert!(!invalid.contains("SECRET"), "invalid_request: {invalid}");
        }
    }

    #[test]
    fn a_multibyte_char_before_a_scheme_is_kept_whole() {
        assert_eq!(redact_urls("é://x"), "é://x");
        assert_eq!(redact_urls("see “https://h/x”"), "see “https://h/…");
        assert_eq!(redact_urls("详见https://h/x"), "详见https://h/…");
        assert_eq!(
            redact_urls("Guest panicked: →ws://a"),
            "Guest panicked: →ws://a"
        );
        assert_eq!(redact_urls("→https://host/KEY"), "→https://host/…");
        assert_eq!(redact_urls("😀http://u:p@h/k"), "😀http://h/…");
        // Through a report, as a guest's panic text reaches one.
        let r = Report::new(id(1)).end(
            Outcome::Failed,
            "execute: cycle measurement failed: Guest panicked: é://x “https://h/SECRET”",
        );
        assert!(!r.reason.unwrap().contains("SECRET"));
    }

    #[test]
    fn redacting_never_panics_on_any_text() {
        // Every mix of multi-byte, scheme and separator pieces, up to four long: no panic, and no
        // URL path survives.
        const PIECES: [&str; 19] = [
            "é",
            "“",
            "”",
            "详",
            "→",
            "😀",
            "\u{301}",
            "a",
            "Z9",
            "+",
            "-.",
            " ",
            "/",
            "@",
            "://",
            "https://h/SECRET",
            "x://",
            "\u{feff}",
            "https://h?apikey=SECRET",
        ];
        let n = PIECES.len();
        let mut checked = 0;
        for len in 1..=4u32 {
            for mut k in 0..n.pow(len) {
                let mut text = String::new();
                for _ in 0..len {
                    text.push_str(PIECES[k % n]);
                    k /= n;
                }
                let out = redact_urls(&text);
                assert!(!out.contains("SECRET"), "{text:?} -> {out:?}");
                let out = clean_reason(&text);
                assert!(!out.contains("SECRET"), "{text:?} -> {out:?}");
                checked += 1;
            }
        }
        assert_eq!(checked, n + n.pow(2) + n.pow(3) + n.pow(4));
        // And a long pseudo-random walk over a wider alphabet (a fixed LCG: reproducible).
        let alphabet: Vec<char> = "a:/é“详→😀@?#.+- \u{301}\u{10ffff}".chars().collect();
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..2_000 {
            let mut text = String::new();
            for _ in 0..24 {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                text.push(alphabet[(seed >> 33) as usize % alphabet.len()]);
            }
            let _ = redact_urls(&text);
        }
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
