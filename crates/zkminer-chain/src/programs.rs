//! Program registry operations — query ELF metadata and download URIs.
//!
//! The ProgramRegistry is an on-chain advisory registry where program authors
//! register their compiled ELF binaries with metadata and download locations.
//! Provers use this to discover where to obtain the ELF for a given programId.

use std::time::Duration;

use alloy::primitives::B256;
use anyhow::{bail, Context, Result};

use crate::client::ChainClient;
use zkminer_contracts::bindings::IProgramRegistry;
use zkminer_netguard::{ContentIdDenied, GuardedClient, NetMode, NetPolicy};

/// Strip control/escape bytes (keep tab) and cap length before logging a submitter-controlled string
/// (storage URIs, program names). Otherwise a crafted URI/name with ANSI escapes
/// could inject into the operator's terminal or forge log lines (via carriage returns) when the log
/// is viewed.
pub fn sanitize_log(s: &str) -> String {
    const MAX: usize = 512;
    // `char::is_control()` is Unicode category Cc only — it strips ESC/CR/LF/C1 (the ANSI/OSC/CRLF
    // injection vectors), but NOT the bidirectional-override/isolate format chars (Cf) or the
    // line/paragraph separators U+2028/U+2029 (Zl/Zp). Those enable Trojan-Source visual reordering
    // (CVE-2021-42574) and apparent-newline forging in log viewers — the same "forge log lines"
    // outcome, from a submitter-controlled URI / CID / program name. Strip them too. Keep TAB.
    let mut out: String = s
        .chars()
        .filter(|&c| c == '\t' || (!c.is_control() && !is_log_unsafe_format(c)))
        .take(MAX)
        .collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// Bidi controls / explicit directional format chars and the line/paragraph separators that
/// `char::is_control()` (Cc-only) does not catch but that can still reorder or forge log lines.
fn is_log_unsafe_format(c: char) -> bool {
    matches!(
        c,
        '\u{2028}' | '\u{2029}'               // line / paragraph separator (Zl, Zp)
        | '\u{200E}' | '\u{200F}' | '\u{061C}' // LRM / RLM / ALM
        | '\u{202A}'..='\u{202E}'             // LRE / RLE / PDF / LRO / RLO
        | '\u{2066}'..='\u{2069}'             // LRI / RLI / FSI / PDI (isolates)
    )
}

/// Per-request connect + total timeout for an ELF download. A submitter endpoint that trickles bytes
/// or never closes must not pin a socket — and, on the pre-claim measurement path, a worker slot —
/// indefinitely. Overridable with `ZKMINER_ELF_FETCH_TIMEOUT_SECS`.
fn elf_fetch_timeout() -> Duration {
    let secs = std::env::var("ZKMINER_ELF_FETCH_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(60);
    // Bounded: this is added to an `Instant`, which panics past what it can hold.
    Duration::from_secs(secs.min(24 * 60 * 60))
}

/// How many redirects one ELF fetch follows.
const MAX_ELF_REDIRECTS: usize = 5;

/// The gateway an IPFS storage URI (a CID) is fetched through. Fixed: the requester names only the
/// content, never the host (see [`zkminer_netguard::ipfs_gateway_url`]).
const IPFS_GATEWAY: &str = "https://ipfs.io";

/// The gateway an Arweave storage URI (a transaction id) is fetched through.
const ARWEAVE_GATEWAY: &str = "https://arweave.net";

/// Downloads programs' ELFs from their registered storage URIs, through the network guard.
///
/// Every storage URI is submitter-controlled, so every hop of every fetch (the URI and each
/// redirect, up to [`MAX_ELF_REDIRECTS`]) passes [`zkminer_netguard::check_url`], and every
/// connection goes only to an address the guarded resolver admitted from its one lookup: in the
/// default [`NetMode::Public`], a globally routable address that is not this host's (public NAT
/// addresses included), not on a network it is connected to or in its IPv6 site, not a DNS server
/// it uses, reached by its default route, and not in `[egress] deny_cidrs`. No proxy is used. The
/// only way to reach a private address is `[dev] private_network = true`
/// ([`NetMode::DevPrivate`]), which is refused on mainnet; there is no environment-variable bypass.
#[derive(Debug, Clone)]
pub struct ElfFetcher {
    client: GuardedClient,
}

impl ElfFetcher {
    /// A fetcher under `config`'s network mode, deny CIDRs and `[egress]` facts options, over this
    /// host's facts (own and public addresses, connected and site prefixes, DNS servers, routing
    /// table). Says [`zkminer_config::DEV_MODE_BANNER`] when developer mode is on.
    pub fn from_config(config: &zkminer_config::ZkMinerConfig) -> Result<Self> {
        let mode = config.net_mode();
        let policy =
            NetPolicy::with_options(mode, config.egress_deny()?, config.egress_facts_options()?)
                .context(
                    "reading this host's network interfaces and routes (the ELF fetch refuses \
                     this host's own addresses and networks, so it cannot run without knowing \
                     them)",
                )?;
        Self::new(&policy)
    }

    /// A fetcher under `policy`.
    pub fn new(policy: &NetPolicy) -> Result<Self> {
        if policy.mode() == NetMode::DevPrivate {
            tracing::warn!(
                "{}: ELF downloads may reach loopback and the local network",
                zkminer_config::DEV_MODE_BANNER
            );
        }
        let client = zkminer_netguard::guarded_client(policy)
            .context("building the guarded ELF download client")?;
        Ok(Self::from_client(client))
    }

    /// A fetcher over a guarded client of the caller's (tests: a staged lookup).
    pub fn from_client(client: GuardedClient) -> Self {
        ElfFetcher { client }
    }

    /// The network mode its fetches run under.
    pub fn mode(&self) -> NetMode {
        self.client.policy().mode()
    }
}

/// The URL a storage URI is fetched from: an HTTP URI as given (the guard checks it), an IPFS CID or
/// an Arweave id on its fixed gateway (syntax-checked, so it cannot leave the gateway), `None` for
/// a Custom one, which zkminer does not fetch.
fn storage_url(uri: &ResolvedURI) -> std::result::Result<Option<String>, ContentIdDenied> {
    match uri.storage_type {
        StorageKind::HTTP => Ok(Some(uri.uri.clone())),
        StorageKind::IPFS => zkminer_netguard::ipfs_gateway_url(IPFS_GATEWAY, &uri.uri).map(Some),
        StorageKind::Arweave => {
            zkminer_netguard::arweave_gateway_url(ARWEAVE_GATEWAY, &uri.uri).map(Some)
        }
        StorageKind::Custom => Ok(None),
    }
}

/// Hard cap on a downloaded ELF. Real guest ELFs are single-digit MB; this bounds a
/// submitter-controlled storage URI so an accidentally- or maliciously-huge response
/// can't OOM the miner (the outer timeout bounds TIME, not bytes).
///
/// Kept strictly BELOW the worker-IPC frame cap (MAX_FRAME_SIZE = 256 MiB in zkminer-prover-protocol):
/// the Execute/Prove command serializes the ELF plus its input and a small envelope, so an ELF AT a
/// 256 MiB cap would be un-sendable over the pipe (FrameTooLarge) after a full download + disk write +
/// triple allocation — a pointless bounded griefing lever and an over-block of any ~256 MiB program.
/// 248 MiB leaves ample headroom for the command envelope and bounded input. No real guest is near it.
const MAX_ELF_BYTES: u64 = 248 * 1024 * 1024;

/// Resolved program info with download URIs.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    pub program_id: B256,
    pub proof_system_id: B256,
    pub name: String,
    pub status: u8,
    pub estimated_cycles: u64,
    pub storage_uris: Vec<ResolvedURI>,
    pub elf_hash: Option<B256>,
}

/// A resolved storage URI with type information.
#[derive(Debug, Clone)]
pub struct ResolvedURI {
    pub storage_type: StorageKind,
    pub uri: String,
    pub content_hash: B256,
}

/// Storage type enum matching the contract's StorageType.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    IPFS,
    Arweave,
    HTTP,
    Custom,
}

impl From<u8> for StorageKind {
    fn from(v: u8) -> Self {
        match v {
            0 => StorageKind::IPFS,
            1 => StorageKind::Arweave,
            2 => StorageKind::HTTP,
            3 => StorageKind::Custom,
            _ => StorageKind::Custom,
        }
    }
}

impl ChainClient {
    /// Query the ProgramRegistry for a program's metadata. Cached per programId for a short TTL:
    /// registered metadata is MUTABLE (`addStorageURI`, `removeStorageURI`, `setBuildInfo`), and an
    /// unregistered or URI-less read — which succeeds with empty values — is never cached at all, so
    /// a job seen before its program's registration cannot block that program for the process's life.
    pub async fn get_program_info(&self, program_id: B256) -> Result<ProgramInfo> {
        if let Some(hit) = self.program_info_cache.lock().unwrap().get(&program_id) {
            return Ok(hit);
        }

        let registry_addr = self
            .program_registry
            .ok_or_else(|| anyhow::anyhow!("program_registry address not configured"))?;

        let registry = IProgramRegistry::new(registry_addr, &*self.provider);

        // Fetch program metadata
        let version = registry
            .getProgram(program_id)
            .call()
            .await
            .context("Failed to query ProgramRegistry.getProgram")?;

        // Fetch storage URIs
        let uris = registry
            .getStorageURIs(program_id)
            .call()
            .await
            .context("Failed to query ProgramRegistry.getStorageURIs")?;

        // Fetch ELF hash for verification. Distinguish an AUTHORITATIVE "no elf_hash registered yet"
        // (Ok + elfHash == ZERO) from a NON-AUTHORITATIVE transient RPC failure (a 429/timeout on a
        // hosted or load-balanced node). The two sibling reads above propagate their errors via `?`;
        // this one MUST too, because for SP1 a false `elf_hash = None` becomes a session-long over-block
        // of a legit program (the SP1 measure gate refuses a program with no elf_hash, and this info is
        // cached). Swallowing `Err` into `None` conflated a transient blip — which the attacker's job
        // flood can drive the operator RPC into, and which most plausibly hits THIS call as the last of
        // the three sequential reads — with a genuine no-hash verdict. Propagate instead: a transient
        // failure then leaves nothing cached and is retried next tick; only a real ZERO read yields None.
        let build_hashes = registry
            .getBuildHashes(program_id)
            .call()
            .await
            .context("Failed to query ProgramRegistry.getBuildHashes")?;
        let elf_hash = if build_hashes.elfHash == B256::ZERO {
            None
        } else {
            Some(build_hashes.elfHash)
        };

        let storage_uris: Vec<ResolvedURI> = uris
            .iter()
            .map(|u| ResolvedURI {
                storage_type: StorageKind::from(u.storageType),
                uri: u.uri.clone(),
                content_hash: u.contentHash,
            })
            .collect();

        let info = ProgramInfo {
            program_id,
            proof_system_id: version.proofSystemId,
            name: version.name.clone(),
            status: version.status,
            estimated_cycles: version.resources.estimatedCycles,
            storage_uris,
            elf_hash,
        };
        // `elf_hash` is the ONE field that is NOT immutable at registration: `registerProgram` takes no
        // elfHash argument (the chain cannot keccak an off-chain ELF), so the hash is set by a LATER
        // call. A brand-new legit SP1 program therefore reads `elfHash == ZERO` in the window between
        // registration and the hash being set. SP1 REQUIRES the hash to size/claim, and this cache has
        // no TTL/invalidation, so caching a None for an SP1 program would pin that transient absence for
        // the whole process lifetime and permanently over-block the program even after its hash appears.
        // So do NOT cache a None elf_hash for an SP1 program — re-read it until the hash is set, then
        // cache normally. (The SP1 measure gate re-checks on a self-healing TTL, so this re-read is
        // bounded, not per-tick.) risc0 legitimately has no registry elf_hash — it is bound by its
        // image-id — so its None is immutable and cached as before, with no re-read cost. "An SP1
        // program" means EITHER SP1 id: a program entry is served under both `sp1.groth16.v1` and
        // `sp1.plonk.v1` (same vkey), so testing one id would re-open the permanent pin for the other.
        let cacheable = !info.storage_uris.is_empty()
            && (info.elf_hash.is_some() || !crate::auction::is_sp1_id(info.proof_system_id));
        if cacheable {
            self.program_info_cache
                .lock()
                .unwrap()
                .insert(program_id, info.clone());
        }
        Ok(info)
    }

    /// Check if a program is registered in the ProgramRegistry.
    pub async fn is_program_registered(&self, program_id: B256) -> Result<bool> {
        let registry_addr = self
            .program_registry
            .ok_or_else(|| anyhow::anyhow!("program_registry address not configured"))?;

        let registry = IProgramRegistry::new(registry_addr, &*self.provider);
        let registered = registry
            .isRegistered(program_id)
            .call()
            .await
            .context("Failed to query ProgramRegistry.isRegistered")?;

        Ok(registered)
    }
}

/// Program ids whose on-disk ELF must NOT be LRU-evicted right now, as a refcount (several in-flight
/// jobs can share a program). A lifecycle task pins its program from claim through prove: the on-disk
/// LRU is small (default 4 GiB) relative to the 256 MiB-ish ELF size, so a submitter flooding distinct
/// decoy programs during the claim->prove window could otherwise evict a just-claimed program's cached
/// ELF (mtime unchanged since measurement), turning the claim into a prove-time fetch miss -> penalized
/// release. Pinned bytes stay bounded by max_concurrent in-flight lifecycles.
static ELF_PIN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<B256, usize>>> =
    std::sync::OnceLock::new();

fn elf_pin_map() -> &'static std::sync::Mutex<std::collections::HashMap<B256, usize>> {
    ELF_PIN.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn elf_is_pinned(program_id: &B256) -> bool {
    elf_pin_map()
        .lock()
        .map(|m| m.contains_key(program_id))
        .unwrap_or(false)
}

/// RAII pin: increments the refcount for `program_id` and decrements it on drop. Hold one for the
/// lifetime of a lifecycle task so the program's ELF survives in the on-disk cache until prove.
#[must_use]
pub struct ElfPin(B256);

impl ElfPin {
    pub fn new(program_id: B256) -> Self {
        if let Ok(mut m) = elf_pin_map().lock() {
            *m.entry(program_id).or_insert(0) += 1;
        }
        ElfPin(program_id)
    }
}

impl Drop for ElfPin {
    fn drop(&mut self) {
        if let Ok(mut m) = elf_pin_map().lock() {
            if let Some(n) = m.get_mut(&self.0) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&self.0);
                }
            }
        }
    }
}

/// Local ELF cache manager — stores downloaded ELF binaries at ~/.zkminer/elfs/.
#[derive(Clone)]
pub struct ElfCache {
    cache_dir: std::path::PathBuf,
}

impl Default for ElfCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Where [`ElfCache::new`] keeps ELFs instead of `~/.zkminer/elfs`, when set (once, at startup).
static ELF_CACHE_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Keep this process's ELF cache in `dir`, apart from `~/.zkminer/elfs` (a watch-only run, which
/// must not prune or purge the cache a miner on the same host relies on). Call before any cache is
/// used; a second call is ignored.
pub fn set_elf_cache_dir(dir: std::path::PathBuf) {
    let _ = ELF_CACHE_DIR.set(dir);
}

impl ElfCache {
    pub fn new() -> Self {
        let cache_dir = ELF_CACHE_DIR.get().cloned().unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".zkminer")
                .join("elfs")
        });
        Self { cache_dir }
    }

    /// Get the cached ELF for a programId.
    ///
    /// `expected_content_hash`, when provided, is compared to `keccak256(elf)`
    /// and the cache entry is purged on mismatch. When `None`, the bytes are
    /// returned without integrity verification — appropriate when the caller
    /// does not have a trusted content hash (e.g., a backend where `programId`
    /// is a verifying key rather than the ELF hash, and the registry URI was
    /// not consulted yet).
    pub fn get(&self, program_id: &B256, expected_content_hash: Option<B256>) -> Option<Vec<u8>> {
        let path = self.cache_dir.join(format!("{}.elf", program_id));
        let bytes = std::fs::read(&path).ok()?;
        // Nothing caches an empty ELF: an empty entry is a torn write (a crash before writes were
        // atomic), and keeping it would fail every proof of the program, every session.
        if bytes.is_empty() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        if let Some(expected) = expected_content_hash {
            let actual_hash = alloy::primitives::keccak256(&bytes);
            if actual_hash != expected {
                tracing::warn!(
                    "ELF cache miss for {}: hash mismatch (got {}, expected {}) — deleting corrupt entry",
                    program_id, actual_hash, expected,
                );
                let _ = std::fs::remove_file(&path);
                return None;
            }
        }
        Some(bytes)
    }

    /// Whether an entry for `program_id` is on disk (no read, no hash).
    pub fn contains(&self, program_id: &B256) -> bool {
        self.cache_dir.join(format!("{}.elf", program_id)).is_file()
    }

    /// Store an ELF in the cache: written in full to a temporary file, synced, then renamed into
    /// place, so a crash or a concurrent reader never sees a partial entry (a read without an
    /// expected hash — a recovered lock's, a measurement's — takes the bytes as they are).
    pub fn put(&self, program_id: &B256, elf: &[u8]) -> Result<()> {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        std::fs::create_dir_all(&self.cache_dir).context("Failed to create ELF cache directory")?;
        let path = self.cache_dir.join(format!("{}.elf", program_id));
        static TMP: AtomicU64 = AtomicU64::new(0);
        let tmp = self.cache_dir.join(format!(
            ".{}.{}.{}.tmp",
            program_id,
            std::process::id(),
            TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let written = std::fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(elf)?;
                f.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).context("Failed to write ELF to cache");
        }
        tracing::info!("Cached ELF for {} ({} bytes)", program_id, elf.len());
        // Bound total on-disk cache size. Without this, a submitter who registers many distinct
        // programs (each served from a URI near the 256 MiB cap) could fill the operator's disk —
        // and this cache is written even on the PRE-CLAIM measurement path, for jobs never claimed.
        self.prune_to_budget();
        Ok(())
    }

    /// Maximum total bytes kept in the on-disk ELF cache. Override with
    /// `ZKMINER_ELF_CACHE_MAX_BYTES` (0 = unbounded, the old behaviour).
    fn cache_budget_bytes() -> u64 {
        std::env::var("ZKMINER_ELF_CACHE_MAX_BYTES")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(4 * 1024 * 1024 * 1024) // 4 GiB
    }

    /// Evict the least-recently-modified cached ELFs until the directory is under budget.
    fn prune_to_budget(&self) {
        self.prune_with_budget(Self::cache_budget_bytes());
    }

    fn prune_with_budget(&self, budget: u64) {
        if budget == 0 {
            return;
        }
        let read = match std::fs::read_dir(&self.cache_dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        // (path, size, mtime) for each cached ELF.
        let mut entries: Vec<(std::path::PathBuf, u64, std::time::SystemTime)> = Vec::new();
        for ent in read.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("elf") {
                continue;
            }
            if let Ok(md) = ent.metadata() {
                let mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
                entries.push((path, md.len(), mtime));
            }
        }
        let mut total: u64 = entries.iter().map(|(_, sz, _)| *sz).sum();
        if total <= budget {
            return;
        }
        // Oldest first.
        entries.sort_by_key(|(_, _, mtime)| *mtime);
        for (path, sz, _) in entries {
            if total <= budget {
                break;
            }
            // Never evict an ELF whose program is pinned (a lifecycle task holds locked collateral on
            // it and will read the ELF at prove time). The filename is "<programId>.elf"; parse the
            // stem back to a B256 and skip if pinned. Pinned bytes are bounded by in-flight count, so
            // the cache may briefly exceed budget rather than evict a program we are about to prove.
            let pinned = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<B256>().ok())
                .map(|pid| elf_is_pinned(&pid))
                .unwrap_or(false);
            if pinned {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    total = total.saturating_sub(sz);
                    tracing::info!("Evicted cached ELF {} ({sz} bytes) to stay under cache budget", path.display());
                }
                Err(e) => tracing::warn!("Failed to evict cached ELF {}: {e}", path.display()),
            }
        }
    }

    /// Check if an ELF is cached.
    pub fn has(&self, program_id: &B256) -> bool {
        self.cache_dir.join(format!("{}.elf", program_id)).exists()
    }
}

/// The registry lists no storage URIs for a program: unregistered, or registered and not yet given a
/// URI. Says nothing about the program's future, unlike a URI that fails.
#[derive(Debug, Clone, Copy)]
pub struct NoStorageUris;

impl std::fmt::Display for NoStorageUris {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("No storage URIs available for this program")
    }
}
impl std::error::Error for NoStorageUris {}

/// Download an ELF binary from a list of storage URIs, through `fetcher`'s network guard.
/// Tries each URI in order until one succeeds.
pub async fn download_elf(
    fetcher: &ElfFetcher,
    uris: &[ResolvedURI],
    expected_hash: Option<B256>,
) -> Result<Vec<u8>> {
    if uris.is_empty() {
        return Err(NoStorageUris.into());
    }

    // Cap the number of submitter-listed URIs actually tried. download_elf is on the
    // pre-claim MEASURE path (bounded by a measure-fetch timeout at the caller) and the prove path;
    // without a cap a program advertising dozens of stalling URIs burns timeout × count, pinning a
    // scarce measure-budget slot (or a prove deadline). Real programs list one or a few mirrors.
    const MAX_ELF_URIS: usize = 8;
    if uris.len() > MAX_ELF_URIS {
        tracing::warn!(
            "program lists {} storage URIs; trying only the first {} (flood protection)",
            uris.len(),
            MAX_ELF_URIS
        );
    }

    // Why the last URI tried failed, for the final error (the per-URI warnings say more).
    let mut last_failure: Option<String> = None;
    for uri_info in uris.iter().take(MAX_ELF_URIS) {
        let url = match storage_url(uri_info) {
            Ok(Some(url)) => url,
            Ok(None) => {
                tracing::debug!("Skipping Custom storage URI: {}", sanitize_log(&uri_info.uri));
                continue;
            }
            Err(e) => {
                tracing::warn!("Skipping storage URI {}: {e}", sanitize_log(&uri_info.uri));
                last_failure = Some(e.to_string());
                continue;
            }
        };

        // The URL string is submitter-controlled (built from a registered URI); sanitize it in
        // every log line so embedded ANSI/OSC/CRLF cannot forge or corrupt operator console output.
        let url_log = sanitize_log(&url);
        tracing::info!("Downloading ELF from {}...", url_log);
        // Every hop is checked by the network guard, and connects only to an address it admitted.
        let fetched = fetcher
            .client
            .get_following_redirects(&url, MAX_ELF_REDIRECTS, elf_fetch_timeout())
            .await;
        match fetched {
            Ok(mut response) => {
                if !response.status().is_success() {
                    tracing::warn!("HTTP {} from {}", response.status(), url_log);
                    last_failure = Some(format!("HTTP {}", response.status()));
                    continue;
                }
                // Reject an over-cap body up front when the server declares its size.
                if let Some(len) = response.content_length() {
                    if len > MAX_ELF_BYTES {
                        tracing::warn!(
                            "ELF at {} declares {} bytes (> {} cap) — skipping",
                            url_log,
                            len,
                            MAX_ELF_BYTES
                        );
                        last_failure = Some("over the ELF size cap".into());
                        continue;
                    }
                }
                // Stream the body chunk-by-chunk, enforcing the cap as we go. A
                // server that omits Content-Length (or lies about it) can't force
                // an unbounded buffer: we bail the moment the running total crosses
                // the cap, so peak memory is bounded regardless of the declared size.
                let mut elf: Vec<u8> = Vec::new();
                let mut over_cap = false;
                let mut read_err: Option<String> = None;
                loop {
                    match response.chunk().await {
                        Ok(Some(chunk)) => {
                            if elf.len() as u64 + chunk.len() as u64 > MAX_ELF_BYTES {
                                over_cap = true;
                                break;
                            }
                            elf.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            read_err = Some(e.to_string());
                            break;
                        }
                    }
                }
                if over_cap {
                    tracing::warn!(
                        "ELF from {} exceeds {} cap mid-stream — skipping",
                        url_log,
                        MAX_ELF_BYTES
                    );
                    last_failure = Some("over the ELF size cap".into());
                    continue;
                }
                if let Some(e) = read_err {
                    tracing::warn!("Failed to read response from {}: {}", url_log, sanitize_log(&e));
                    last_failure = Some(format!("reading the body: {}", sanitize_log(&e)));
                    continue;
                }

                // Verify the whole-ELF keccak digest against the registry `elf_hash` and the
                // per-URI content_hash. keccak256 over up to MAX_ELF_BYTES is ~1-2s of non-yielding
                // CPU, so offload it to a blocking thread (the on-disk cache read/write paths already
                // do): a large-ELF or hash-mismatch flood on this download path must not pin the async
                // runtime's worker threads. Both checks hash the SAME bytes, so compute the digest once.
                if expected_hash.is_some() || uri_info.content_hash != B256::ZERO {
                    let elf_arc = std::sync::Arc::new(std::mem::take(&mut elf));
                    let for_hash = elf_arc.clone();
                    let actual = match tokio::task::spawn_blocking(move || {
                        alloy::primitives::keccak256(for_hash.as_slice())
                    })
                    .await
                    {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!("ELF hashing task failed for {}: {e}", url_log);
                            continue;
                        }
                    };
                    // The closure dropped its clone, so this Arc is now sole-owner: no 256 MiB copy.
                    elf = std::sync::Arc::try_unwrap(elf_arc).unwrap_or_else(|a| (*a).clone());
                    if let Some(expected) = expected_hash {
                        if actual != expected {
                            tracing::warn!(
                                "ELF hash mismatch from {}: expected {}, got {}",
                                url_log,
                                expected,
                                actual
                            );
                            last_failure = Some("ELF hash mismatch".into());
                            continue;
                        }
                    }
                    if uri_info.content_hash != B256::ZERO && actual != uri_info.content_hash {
                        tracing::warn!(
                            "Content hash mismatch from {}: expected {}, got {}",
                            url_log,
                            uri_info.content_hash,
                            actual
                        );
                        last_failure = Some("content hash mismatch".into());
                        continue;
                    }
                }

                tracing::info!("Downloaded ELF: {} bytes", elf.len());
                return Ok(elf);
            }
            Err(e) => {
                let why = sanitize_log(&e.to_string());
                tracing::warn!("Failed to download from {}: {}", url_log, why);
                last_failure = Some(why);
                continue;
            }
        }
    }

    match last_failure {
        Some(why) => bail!(
            "Failed to download ELF from any of {} URIs (last: {why})",
            uris.len()
        ),
        None => bail!("Failed to download ELF from any of {} URIs", uris.len()),
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn pinned_elfs_are_not_evicted_by_prune() {
        use std::io::Write;
        // Unique temp cache dir for this test.
        let dir = std::env::temp_dir().join(format!("zkminer-elf-pin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = ElfCache { cache_dir: dir.clone() };

        // Three 2 MiB ELFs (6 MiB total); pin two of them.
        let ids = [B256::repeat_byte(0x11), B256::repeat_byte(0x22), B256::repeat_byte(0x33)];
        for id in &ids {
            let mut f = std::fs::File::create(dir.join(format!("{id}.elf"))).unwrap();
            f.write_all(&vec![0u8; 2 * 1024 * 1024]).unwrap();
        }
        let _p1 = ElfPin::new(ids[0]);
        let _p2 = ElfPin::new(ids[1]);
        assert!(elf_is_pinned(&ids[0]) && elf_is_pinned(&ids[1]) && !elf_is_pinned(&ids[2]));

        // Budget 3 MiB: prune must shed down toward it, but can only evict the single UNPINNED entry.
        cache.prune_with_budget(3 * 1024 * 1024);

        assert!(dir.join(format!("{}.elf", ids[0])).exists(), "pinned ELF #1 must survive");
        assert!(dir.join(format!("{}.elf", ids[1])).exists(), "pinned ELF #2 must survive");
        assert!(!dir.join(format!("{}.elf", ids[2])).exists(), "unpinned ELF must be evicted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn elf_pin_refcount_releases_on_drop() {
        let id = B256::repeat_byte(0xab);
        assert!(!elf_is_pinned(&id));
        {
            let _a = ElfPin::new(id);
            let _b = ElfPin::new(id);
            assert!(elf_is_pinned(&id), "pinned while a guard is held");
        }
        assert!(!elf_is_pinned(&id), "unpinned once all guards drop");
    }

    // The integrity-hash purge the risc0 ELF-swap binding depends on: `fetch_or_download_elf` reads
    // the cache with the (co-resolved) verified keccak, so a cached entry whose bytes do NOT match the
    // expected hash must be dropped and reported as a miss (forcing a hash-enforced re-download), while
    // a matching entry is returned. keccak256 over the genuine bytes is deterministic from the program,
    // so this never purges a correct entry.
    #[test]
    fn a_cached_elf_is_written_whole_and_an_empty_one_is_a_miss() {
        let dir = std::env::temp_dir().join(format!(
            "zkminer-elf-atomic-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ElfCache {
            cache_dir: dir.clone(),
        };
        let id = B256::repeat_byte(0x5a);
        cache.put(&id, b"elf-bytes").unwrap();
        assert_eq!(cache.get(&id, None).as_deref(), Some(&b"elf-bytes"[..]));
        // Only the entry is left: no temporary file.
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(format!("{id}.elf"))]);
        // A torn (empty) entry is a miss, and goes.
        std::fs::write(dir.join(format!("{id}.elf")), b"").unwrap();
        assert_eq!(cache.get(&id, None), None);
        assert!(!cache.contains(&id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_get_purges_on_hash_mismatch_and_returns_on_match() {
        let dir = std::env::temp_dir().join(format!(
            "zkminer-elf-hash-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ElfCache { cache_dir: dir.clone() };

        let id = B256::repeat_byte(0x7e);
        let bytes = b"the-genuine-risc0-elf-bytes".to_vec();
        let good = alloy::primitives::keccak256(&bytes);
        cache.put(&id, &bytes).unwrap();

        // No expected hash -> returned unverified.
        assert_eq!(cache.get(&id, None).as_deref(), Some(bytes.as_slice()));
        // Correct hash -> returned, entry kept.
        assert_eq!(cache.get(&id, Some(good)).as_deref(), Some(bytes.as_slice()));
        assert!(dir.join(format!("{id}.elf")).exists());

        // Wrong hash (a swapped ELF would land here) -> miss AND the corrupt/stale entry is purged,
        // so the next fetch cannot serve the mismatching bytes and must re-download under the hash.
        let wrong = B256::repeat_byte(0xff);
        assert_eq!(cache.get(&id, Some(wrong)), None, "mismatch must be a miss");
        assert!(
            !dir.join(format!("{id}.elf")).exists(),
            "mismatching entry must be purged"
        );
        assert_eq!(cache.get(&id, None), None, "entry is gone after the purge");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_log_strips_terminal_and_bidi_and_separators() {
        // CRLF / ESC (Cc) stripped, TAB and the printable ANSI payload kept.
        assert_eq!(super::sanitize_log("a\r\nb\x1b[31mc\td"), "ab[31mc\td");
        // Bidi overrides/isolates (Cf) and line/paragraph separators (Zl/Zp) stripped.
        for bad in ['\u{202E}', '\u{2066}', '\u{200F}', '\u{061C}', '\u{2028}', '\u{2029}'] {
            let input = format!("safe{bad}text");
            let out = super::sanitize_log(&input);
            assert_eq!(out, "safetext", "{:?} must be stripped", bad);
        }
        // Ordinary unicode (non-format) is preserved.
        assert_eq!(super::sanitize_log("café-π"), "café-π");
    }

    #[test]
    fn cache_prune_enforces_byte_budget() {
        let dir = std::env::temp_dir().join(format!("zkminer-elfcache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = ElfCache {
            cache_dir: dir.clone(),
        };

        // Three 1000-byte ELFs = 3000 bytes total.
        for name in ["a", "b", "c"] {
            std::fs::write(dir.join(format!("{name}.elf")), vec![0u8; 1000]).unwrap();
        }

        // A budget of 2500 must leave the directory at or under budget (one file evicted).
        cache.prune_with_budget(2500);
        let remaining: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("elf"))
            .collect();
        let total: u64 = remaining.iter().map(|e| e.metadata().unwrap().len()).sum();
        assert!(total <= 2500, "cache not pruned under budget: {total} bytes");
        assert_eq!(remaining.len(), 2, "exactly one oldest ELF should be evicted");

        // Budget 0 = unbounded: nothing is evicted.
        for name in ["a", "b", "c"] {
            std::fs::write(dir.join(format!("{name}.elf")), vec![0u8; 1000]).unwrap();
        }
        cache.prune_with_budget(0);
        let count = std::fs::read_dir(&dir).unwrap().flatten().count();
        assert_eq!(count, 3, "budget 0 must not evict");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The ELF fetch through the network guard, against servers on 127.0.0.1: refused in public mode
/// however the local address is named or reached, served in developer mode. A public-mode fetch that
/// is served needs a public address, so those tests stage a lookup whose public answers then connect
/// to loopback (zkminer-netguard's `test-util` seam, which only test builds have).
#[cfg(test)]
mod fetch_tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use zkminer_netguard::{ClientOptions, Lookup, LookupFuture};

    const ELF: &[u8] = b"\x7fELF-guest-bytes";

    /// A server on 127.0.0.1 that answers every request with `reply(port)` and counts requests.
    struct Server {
        port: u16,
        hits: Arc<AtomicUsize>,
    }

    fn serve(reply: impl Fn(u16) -> Vec<u8> + Send + 'static) -> Server {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&reply(port));
            }
        });
        Server { port, hits }
    }

    fn elf_server() -> Server {
        serve(|_| {
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ELF.len()
            )
            .into_bytes();
            r.extend_from_slice(ELF);
            r
        })
    }

    fn redirect_server(to: String) -> Server {
        serve(move |_| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes()
        })
    }

    fn http(uri: String) -> ResolvedURI {
        ResolvedURI {
            storage_type: StorageKind::HTTP,
            uri,
            content_hash: B256::ZERO,
        }
    }

    fn hits(s: &Server) -> usize {
        s.hits.load(Ordering::SeqCst)
    }

    /// This host's real policy and the system resolver, as the miner runs.
    fn real(mode: NetMode) -> ElfFetcher {
        ElfFetcher::new(&NetPolicy::new(mode, Vec::new()).unwrap()).unwrap()
    }

    /// A lookup that answers from a table.
    struct Staged(HashMap<&'static str, Vec<IpAddr>>);

    impl Lookup for Staged {
        fn lookup(&self, host: &str) -> LookupFuture {
            let r =
                self.0.get(host).cloned().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no such name")
                });
            Box::pin(async move { r })
        }
    }

    fn staged() -> Arc<Staged> {
        Arc::new(Staged(HashMap::from([
            ("elfs.example.com", vec!["93.184.216.34".parse().unwrap()]),
            ("rebind.example.com", vec!["127.0.0.1".parse().unwrap()]),
        ])))
    }

    /// Public mode over this host's real facts, names from [`staged`], and every admitted (public)
    /// address connected to on loopback.
    fn public_via_loopback() -> ElfFetcher {
        let policy = NetPolicy::new(NetMode::Public, Vec::new()).unwrap();
        let map: zkminer_netguard::ConnectMap = Arc::new(|_| IpAddr::from([127, 0, 0, 1]));
        let client = zkminer_netguard::guarded_client_for_test(
            &policy,
            staged(),
            map,
            ClientOptions::default(),
        )
        .unwrap();
        ElfFetcher::from_client(client)
    }

    #[tokio::test]
    async fn public_mode_refuses_local_storage_uris_without_connecting() {
        let server = elf_server();
        let fetcher = real(NetMode::Public);
        assert_eq!(fetcher.mode(), NetMode::Public);
        let p = server.port;
        for uri in [
            format!("http://127.0.0.1:{p}/guest.elf"),
            format!("http://localhost:{p}/guest.elf"),
            format!("http://LocalHost:{p}/guest.elf"),
            format!("http://localhost.:{p}/guest.elf"),
            format!("http://foo.localhost:{p}/guest.elf"),
            format!("http://[::1]:{p}/guest.elf"),
            format!("http://[::ffff:127.0.0.1]:{p}/guest.elf"),
            format!("http://2130706433:{p}/guest.elf"),
            format!("http://0x7f.0.0.1:{p}/guest.elf"),
            format!("http://127.1:{p}/guest.elf"),
            format!("http://user@127.0.0.1:{p}/guest.elf"),
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/".to_string(),
        ] {
            let e = download_elf(&fetcher, &[http(uri.clone())], None)
                .await
                .expect_err(&uri);
            assert!(
                format!("{e:#}").contains("refused by the network guard"),
                "{uri}: {e:#}"
            );
        }
        assert_eq!(hits(&server), 0, "a refused URI was connected to");
    }

    /// A redirect from one local URL to another: refused at the first hop when that is local, and at
    /// the redirect when the first hop is public, with the local target never connected to.
    #[tokio::test]
    async fn a_redirect_to_a_local_url_is_refused_in_public_mode() {
        let target = elf_server();
        let t = target.port;
        for to in [
            format!("http://127.0.0.1:{t}/guest.elf"),
            format!("http://localhost:{t}/guest.elf"),
            format!("http://[::1]:{t}/guest.elf"),
            format!("http://rebind.example.com:{t}/guest.elf"),
        ] {
            let first = redirect_server(to.clone());
            // A local first hop: nothing is connected to at all.
            let local = format!("http://127.0.0.1:{}/start", first.port);
            let e = download_elf(&real(NetMode::Public), &[http(local)], None)
                .await
                .unwrap_err();
            assert!(
                format!("{e:#}").contains("refused by the network guard"),
                "{e:#}"
            );
            assert_eq!(hits(&first), 0);
            // A public first hop that redirects to the local URL: the redirect is refused.
            let public = format!("http://elfs.example.com:{}/start", first.port);
            let e = download_elf(&public_via_loopback(), &[http(public)], None)
                .await
                .unwrap_err();
            assert!(
                format!("{e:#}").contains("refused by the network guard"),
                "{to}: {e:#}"
            );
            assert_eq!(hits(&first), 1, "{to}: the public hop was reached");
        }
        assert_eq!(hits(&target), 0, "a local redirect target was connected to");
    }

    /// DNS rebinding: a public-looking name whose answer is loopback.
    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused() {
        let server = elf_server();
        let uri = format!("http://rebind.example.com:{}/guest.elf", server.port);
        let e = download_elf(&public_via_loopback(), &[http(uri)], None)
            .await
            .unwrap_err();
        assert!(
            format!("{e:#}").contains("resolves to no admitted address"),
            "{e:#}"
        );
        assert_eq!(hits(&server), 0);
    }

    /// The allowed case: a public store is fetched, and its bytes still checked against the hashes.
    #[tokio::test]
    async fn a_public_store_is_served_in_public_mode_and_hash_checked() {
        let server = elf_server();
        let uri = http(format!("http://elfs.example.com:{}/guest.elf", server.port));
        let fetcher = public_via_loopback();
        let good = alloy::primitives::keccak256(ELF);
        assert_eq!(
            download_elf(&fetcher, std::slice::from_ref(&uri), Some(good))
                .await
                .unwrap(),
            ELF
        );
        let e = download_elf(
            &fetcher,
            std::slice::from_ref(&uri),
            Some(B256::repeat_byte(1)),
        )
        .await
        .unwrap_err();
        assert!(format!("{e:#}").contains("ELF hash mismatch"), "{e:#}");
        let mut wrong_content = uri.clone();
        wrong_content.content_hash = B256::repeat_byte(2);
        let e = download_elf(&fetcher, &[wrong_content], None)
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("content hash mismatch"), "{e:#}");
        assert_eq!(hits(&server), 3);
    }

    #[tokio::test]
    async fn dev_mode_serves_local_storage_uris_and_their_redirects() {
        let server = elf_server();
        let fetcher = real(NetMode::DevPrivate);
        assert_eq!(fetcher.mode(), NetMode::DevPrivate);
        let p = server.port;
        for uri in [
            format!("http://127.0.0.1:{p}/guest.elf"),
            format!("http://localhost:{p}/guest.elf"),
        ] {
            assert_eq!(
                download_elf(&fetcher, &[http(uri.clone())], None)
                    .await
                    .unwrap_or_else(|e| panic!("{uri}: {e:#}")),
                ELF
            );
        }
        let first = redirect_server(format!("http://127.0.0.1:{p}/guest.elf"));
        let start = format!("http://127.0.0.1:{}/start", first.port);
        assert_eq!(
            download_elf(&fetcher, &[http(start)], None).await.unwrap(),
            ELF
        );
        assert_eq!((hits(&first), hits(&server)), (1, 3));
        // Developer mode turns off the destination checks only: other schemes stay refused.
        let e = download_elf(&fetcher, &[http("file:///etc/passwd".into())], None)
            .await
            .unwrap_err();
        assert!(
            format!("{e:#}").contains("refused by the network guard"),
            "{e:#}"
        );
    }

    #[test]
    fn content_ids_name_only_content_on_a_fixed_gateway() {
        let uri = |kind, s: &str| ResolvedURI {
            storage_type: kind,
            uri: s.into(),
            content_hash: B256::ZERO,
        };
        let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        assert_eq!(
            storage_url(&uri(StorageKind::IPFS, cid)).unwrap().unwrap(),
            format!("https://ipfs.io/ipfs/{cid}")
        );
        assert_eq!(
            storage_url(&uri(StorageKind::IPFS, &format!("ipfs://{cid}/guest.elf")))
                .unwrap()
                .unwrap(),
            format!("https://ipfs.io/ipfs/{cid}/guest.elf")
        );
        let ar = "bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U";
        assert_eq!(
            storage_url(&uri(StorageKind::Arweave, ar))
                .unwrap()
                .unwrap(),
            format!("https://arweave.net/{ar}")
        );
        for bad in [
            "@127.0.0.1/x",
            "x@localhost",
            "../../admin",
            "QmNotACid",
            "bafy?x=1",
            &format!("{cid}/../../x"),
            &format!("{cid}#x"),
            &format!("{cid}/a%2f.."),
        ] {
            assert!(
                storage_url(&uri(StorageKind::IPFS, bad)).is_err(),
                "ipfs {bad}"
            );
            assert!(
                storage_url(&uri(StorageKind::Arweave, bad)).is_err(),
                "arweave {bad}"
            );
        }
        assert_eq!(
            storage_url(&uri(StorageKind::Custom, "anything")).unwrap(),
            None
        );
        assert_eq!(
            storage_url(&uri(StorageKind::HTTP, "http://x/"))
                .unwrap()
                .as_deref(),
            Some("http://x/")
        );
    }

    #[tokio::test]
    async fn a_malformed_content_id_is_skipped_without_a_request() {
        let uri = ResolvedURI {
            storage_type: StorageKind::IPFS,
            uri: "@127.0.0.1:8080/x".into(),
            content_hash: B256::ZERO,
        };
        let e = download_elf(&real(NetMode::DevPrivate), &[uri], None)
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("not an IPFS CID"), "{e:#}");
    }

    /// The stores the redirect handling was written for, for real, in public mode: neither redirect
    /// stays on the host asked for (Arweave to a subdomain of its own, GitHub to its asset host).
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn real_stores_that_redirect_across_hosts_are_followed() {
        let fetcher = real(NetMode::Public);
        for url in [
            "https://arweave.net/bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U",
            "https://github.com/risc0/risc0/releases/download/v1.0.0/cargo-risczero-x86_64-unknown-linux-gnu.tgz",
        ] {
            let response = fetcher
                .client
                .get_following_redirects(url, MAX_ELF_REDIRECTS, Duration::from_secs(60))
                .await
                .unwrap_or_else(|e| panic!("{url}: {e}"));
            assert!(response.status().is_success(), "{url}: {}", response.status());
            assert_ne!(
                response.url().host_str(),
                reqwest::Url::parse(url).unwrap().host_str(),
                "{url} no longer redirects"
            );
        }
    }
}
