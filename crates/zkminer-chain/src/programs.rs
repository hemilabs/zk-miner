//! Program registry operations — query ELF metadata and download URIs.
//!
//! The ProgramRegistry is an on-chain advisory registry where program authors
//! register their compiled ELF binaries with metadata and download locations.
//! Provers use this to discover where to obtain the ELF for a given programId.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use alloy::primitives::B256;
use anyhow::{bail, Context, Result};

use crate::client::ChainClient;
use zkminer_contracts::bindings::IProgramRegistry;

/// Strip control/escape bytes (keep tab) and cap length before logging a submitter-controlled string
/// (storage URIs, program names). Otherwise a crafted URI/name with ANSI escapes
/// could inject into the operator's terminal or forge log lines (via carriage returns) when the log
/// is viewed.
pub fn sanitize_log(s: &str) -> String {
    const MAX: usize = 512;
    let mut out: String = s
        .chars()
        .filter(|&c| c == '\t' || !c.is_control())
        .take(MAX)
        .collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    out
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
    Duration::from_secs(secs)
}

/// Allow fetching an ELF from a private/loopback/link-local host — only for an operator who
/// deliberately self-hosts the program store on a private network. OFF by default: a
/// submitter-controlled storage URI that resolves to 169.254.169.254 (cloud metadata), 127.0.0.1,
/// 10/8, etc. is a server-side request forgery vector (the miner fetches it pre-claim, unauthenticated).
fn allow_private_elf_hosts() -> bool {
    matches!(
        std::env::var("ZKMINER_ELF_ALLOW_PRIVATE_URLS")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// True for an address a submitter must not be able to make the miner reach: loopback, RFC1918
/// private, link-local (incl. the 169.254.169.254 metadata endpoint), CGNAT, unspecified, broadcast,
/// documentation, multicast, IPv6 ULA/link-local, and IPv4-mapped forms of all the above.
fn ip_is_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_blocked(&IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}


/// Async wrapper around [`validate_fetch_url`] that runs the BLOCKING DNS resolution off the tokio
/// runtime, bounded by a timeout. `validate_fetch_url` calls `to_socket_addrs`, which
/// blocks the calling thread; invoked directly from the async `download_elf` it would stall a
/// runtime worker (a submitter hostname with slow/hanging DNS could wedge the executor, and the
/// reqwest download timeout does not cover resolution, which happens before the request). The scheme
/// check stays inline (cheap); only the resolution is offloaded.
/// Validate a (submitter-controlled) ELF URL and return the VETTED socket addresses its host
/// resolves to. The caller PINS the connection to exactly these addresses (reqwest
/// `resolve_to_addrs`), so the host is resolved ONCE here (off-runtime, IP-checked) and never
/// re-resolved at connect time — closing the DNS-rebinding window where a TTL-0 host answers public
/// to this validation lookup and internal to reqwest's own connect lookup. An empty Vec means "do not
/// pin" (private hosts are allowed by config, so there is nothing to guard).
async fn validate_fetch_url_async(url: &reqwest::Url) -> Result<Vec<std::net::SocketAddr>> {
    match url.scheme() {
        "http" | "https" => {}
        other => bail!("refusing ELF fetch with non-http(s) scheme '{other}': {url}"),
    }
    if allow_private_elf_hosts() {
        return Ok(Vec::new());
    }
    let host_raw = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("ELF URL has no host: {url}"))?;
    // host_str() brackets an IPv6 literal ("[::1]"); strip so to_socket_addrs treats it as an IP.
    let host = host_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_raw)
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let host_for_dns = host.clone();
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            (host_for_dns.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>())
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("DNS resolution for ELF host '{host}' timed out"))?
    .map_err(|e| anyhow::anyhow!("DNS resolution task failed for '{host}': {e}"))?
    .with_context(|| format!("resolving ELF host '{host}'"))?;
    reject_blocked_addrs(&host, &addrs)?;
    Ok(addrs)
}

/// Shared IP-range check used by both the sync and async URL validators.
fn reject_blocked_addrs(host: &str, addrs: &[std::net::SocketAddr]) -> Result<()> {
    if addrs.is_empty() {
        bail!("ELF host '{host}' did not resolve");
    }
    for a in addrs {
        if ip_is_blocked(&a.ip()) {
            bail!(
                "refusing ELF fetch to private/reserved address {} (host '{host}') — set \
                 ZKMINER_ELF_ALLOW_PRIVATE_URLS=1 only if you self-host the program store",
                a.ip()
            );
        }
    }
    Ok(())
}

/// Non-blocking redirect-hop validation (no DNS). reqwest runs the redirect policy
/// synchronously on its connection task, so it must NOT resolve DNS (that would stall a runtime worker) —
/// but that is exactly why a redirect to an unvalidated HOSTNAME must now be REFUSED rather than
/// followed: we cannot IP-check it here, and only the ORIGINAL host was resolved+vetted+pinned
/// off-runtime. The previous policy followed hostname redirects, so a `302 Location:
/// http://name.attacker.com/` whose A record is 169.254.169.254 / 127.0.0.1 / RFC1918 defeated the
/// whole SSRF guard. Now: reject a non-http(s) scheme; allow a redirect back to the SAME (pinned)
/// host — reqwest connects it to the pinned address, so http→https and path redirects still work;
/// IP-check an IP-literal target; and refuse any OTHER hostname.
fn validate_redirect_target(url: &reqwest::Url, pinned_host: &str) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        other => bail!("non-http(s) redirect scheme '{other}'"),
    }
    if allow_private_elf_hosts() {
        return Ok(());
    }
    let Some(host) = url.host_str() else {
        bail!("redirect target has no host");
    };
    // Same host as the vetted+pinned original: safe to follow — the client's resolve override pins
    // this host to the addresses we already IP-checked, so no fresh (rebindable) lookup happens.
    if host.eq_ignore_ascii_case(pinned_host) {
        return Ok(());
    }
    // host_str() returns an IPv6 literal bracketed ("[::1]"); strip for IpAddr parsing.
    let h = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    match h.parse::<IpAddr>() {
        Ok(ip) => {
            if ip_is_blocked(&ip) {
                bail!("redirect to private/reserved address {ip}");
            }
            Ok(())
        }
        // A different hostname we cannot resolve+check on the runtime task: refuse.
        Err(_) => bail!(
            "redirect to unvalidated host '{host}' (differs from the vetted ELF host); refusing \
             to follow a redirect whose address cannot be re-checked"
        ),
    }
}

/// Build a download client pinned to `host` → `addrs` (the addresses `validate_fetch_url_async`
/// already IP-checked), with bounded connect/total timeouts and an SSRF-checked redirect policy.
/// Pinning resolves the host ONCE (here) and connects to those exact addresses,
/// closing DNS rebinding; the policy refuses redirects to any other hostname (see
/// `validate_redirect_target`). An empty `addrs` (private hosts allowed by config) builds an
/// unpinned client — there is nothing to guard in that mode.
fn build_elf_client(host: &str, addrs: &[std::net::SocketAddr]) -> Result<reqwest::Client> {
    let pinned_host = host.to_string();
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects while fetching ELF");
        }
        match validate_redirect_target(attempt.url(), &pinned_host) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(format!("blocked redirect target: {e}")),
        }
    });
    let mut builder = reqwest::Client::builder()
        .connect_timeout(elf_fetch_timeout())
        .timeout(elf_fetch_timeout())
        .redirect(policy);
    if !addrs.is_empty() {
        // Pin only the vetted IP, NOT the port. The connector (hyper-util `set_port`)
        // fills a resolved addr's port iff it is 0 OR the URI carries an explicit port, so a pinned
        // port-0 addr gets the correct scheme-default PER HOP — 80 on http, 443 on an https upgrade —
        // while the IP still blocks DNS rebinding. Baking the original scheme's default port in (80
        // for an http:// URL) instead breaks a legitimate same-host http->https redirect: the
        // connector keeps 80 and attempts TLS against the plaintext port. See `pin_addrs`.
        let pinned = pin_addrs(addrs);
        builder = builder.resolve_to_addrs(host, &pinned);
    }
    builder
        .build()
        .context("building hardened ELF download client")
}

/// Strip the port from each vetted address so the pin binds the IP only. The connector
/// supplies the correct per-hop scheme-default port (see `build_elf_client`); pinning a concrete port
/// would break a same-host cross-scheme (http<->https) redirect, whose default port differs from the
/// original URL's. The SSRF guarantee rests on the IP (already `reject_blocked_addrs`-checked), which
/// is preserved.
fn pin_addrs(addrs: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    addrs
        .iter()
        .map(|a| {
            let mut a = *a;
            a.set_port(0);
            a
        })
        .collect()
}

/// Hard cap on a downloaded ELF. Real guest ELFs are single-digit MB; this bounds a
/// submitter-controlled storage URI so an accidentally- or maliciously-huge response
/// can't OOM the miner (the outer timeout bounds TIME, not bytes).
const MAX_ELF_BYTES: u64 = 256 * 1024 * 1024;

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
    /// Query the ProgramRegistry for a program's metadata. Cached per programId
    /// (registered metadata is immutable), so repeated jobs for the same program
    /// hit the registry only once.
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

        // Fetch ELF hash for verification
        let elf_hash = match registry.getBuildHashes(program_id).call().await {
            Ok(result) => {
                if result.elfHash == B256::ZERO {
                    None
                } else {
                    Some(result.elfHash)
                }
            }
            Err(_) => None,
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
        self.program_info_cache
            .lock()
            .unwrap()
            .insert(program_id, info.clone());
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

impl ElfCache {
    pub fn new() -> Self {
        let cache_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zkminer")
            .join("elfs");
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

    /// Store an ELF in the cache.
    pub fn put(&self, program_id: &B256, elf: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.cache_dir).context("Failed to create ELF cache directory")?;
        let path = self.cache_dir.join(format!("{}.elf", program_id));
        std::fs::write(&path, elf).context("Failed to write ELF to cache")?;
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

/// Download an ELF binary from a list of storage URIs.
/// Tries each URI in order until one succeeds.
pub async fn download_elf(uris: &[ResolvedURI], expected_hash: Option<B256>) -> Result<Vec<u8>> {
    if uris.is_empty() {
        bail!("No storage URIs available for this program");
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

    for uri_info in uris.iter().take(MAX_ELF_URIS) {
        let url = match uri_info.storage_type {
            StorageKind::IPFS => {
                // Convert IPFS CID to a gateway URL
                let cid = &uri_info.uri;
                format!("https://ipfs.io/ipfs/{cid}")
            }
            StorageKind::HTTP => uri_info.uri.clone(),
            StorageKind::Arweave => {
                let tx_id = &uri_info.uri;
                format!("https://arweave.net/{tx_id}")
            }
            StorageKind::Custom => {
                tracing::debug!("Skipping Custom storage URI: {}", uri_info.uri);
                continue;
            }
        };

        // SSRF guard: parse + validate the (submitter-controlled) URL before touching the network.
        let parsed = match reqwest::Url::parse(&url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("Skipping unparseable storage URI {}: {e}", sanitize_log(&url));
                continue;
            }
        };
        let vetted_addrs = match validate_fetch_url_async(&parsed).await {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!("Skipping storage URI {}: {e:#}", sanitize_log(&url));
                continue;
            }
        };
        // Build the client pinned to the host we just resolved+IP-checked, so the
        // connection uses those exact addresses (no rebindable re-resolution) and redirects to any
        // other hostname are refused. Per-URI because each may target a different host.
        let host = parsed.host_str().unwrap_or("").to_string();
        let client = match build_elf_client(&host, &vetted_addrs) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Skipping storage URI {}: client build failed: {e:#}", sanitize_log(&url));
                continue;
            }
        };

        tracing::info!("Downloading ELF from {}...", url);
        match client.get(parsed).send().await {
            Ok(mut response) => {
                if !response.status().is_success() {
                    tracing::warn!("HTTP {} from {}", response.status(), url);
                    continue;
                }
                // Reject an over-cap body up front when the server declares its size.
                if let Some(len) = response.content_length() {
                    if len > MAX_ELF_BYTES {
                        tracing::warn!(
                            "ELF at {} declares {} bytes (> {} cap) — skipping",
                            url,
                            len,
                            MAX_ELF_BYTES
                        );
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
                        url,
                        MAX_ELF_BYTES
                    );
                    continue;
                }
                if let Some(e) = read_err {
                    tracing::warn!("Failed to read response from {}: {}", url, e);
                    continue;
                }

                // Verify content hash if provided
                if let Some(expected) = expected_hash {
                    let actual = alloy::primitives::keccak256(&elf);
                    if actual != expected {
                        tracing::warn!(
                            "ELF hash mismatch from {}: expected {}, got {}",
                            url,
                            expected,
                            actual
                        );
                        continue;
                    }
                }

                // Also verify against URI-level content hash
                if uri_info.content_hash != B256::ZERO {
                    let actual = alloy::primitives::keccak256(&elf);
                    if actual != uri_info.content_hash {
                        tracing::warn!(
                            "Content hash mismatch from {}: expected {}, got {}",
                            url,
                            uri_info.content_hash,
                            actual
                        );
                        continue;
                    }
                }

                tracing::info!("Downloaded ELF: {} bytes", elf.len());
                return Ok(elf);
            }
            Err(e) => {
                tracing::warn!("Failed to download from {}: {}", url, e);
                continue;
            }
        }
    }

    bail!("Failed to download ELF from any of {} URIs", uris.len())
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_private_reserved_and_metadata_addresses() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ] {
            assert!(ip_is_blocked(&ip(s)), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!ip_is_blocked(&ip(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn validate_rejects_bad_scheme_and_private_ip_literals() {
        // The redirect-hop validator (non-blocking) rejects bad schemes and private IP LITERALS. The
        // pinned host here is "elf.example.com" — the vetted ELF host the download started from.
        let pin = "elf.example.com";
        let v = |u: &str| validate_redirect_target(&reqwest::Url::parse(u).unwrap(), pin);
        assert!(v("ftp://example.com/x").is_err());
        assert!(v("file:///etc/passwd").is_err());
        assert!(v("http://127.0.0.1/x").is_err());
        assert!(v("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(v("http://[::1]:8545/").is_err());
        // Public IP literal is allowed.
        assert!(v("https://1.1.1.1/elf").is_ok());
        // A redirect back to the SAME (pinned) host is allowed — the client pins it to
        // the already-vetted address, so http→https and path redirects still work.
        assert!(v("https://elf.example.com/elf").is_ok());
        assert!(v("https://ELF.EXAMPLE.COM/elf").is_ok()); // case-insensitive
        // A redirect to a DIFFERENT hostname is refused: it cannot be resolved+checked
        // on reqwest's runtime task, and only the original host was vetted+pinned. This closes
        // the redirect-to-internal-hostname / DNS-rebind SSRF bypass.
        assert!(v("http://name.attacker.com/").is_err());
        assert!(v("https://metadata.google.internal/").is_err());
    }

    #[test]
    fn pinning_binds_the_ip_but_not_the_port() {
        // The pin must carry port 0 so the connector fills the
        // correct scheme-default per hop; baking a concrete port (80 for http) in breaks a legitimate
        // same-host http->https redirect (connector keeps 80, attempts TLS on it). The IP — the thing
        // the SSRF guard actually rests on — is preserved exactly.
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let pinned = pin_addrs(&[v4, v6]);
        assert_eq!(pinned.len(), 2);
        assert_eq!(pinned[0].ip(), v4.ip(), "IP preserved");
        assert_eq!(pinned[0].port(), 0, "port zeroed so the connector picks the per-hop default");
        assert_eq!(pinned[1].ip(), v6.ip(), "IPv6 preserved");
        assert_eq!(pinned[1].port(), 0);
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
