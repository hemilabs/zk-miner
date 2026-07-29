//! Program registry operations — query ELF metadata and download URIs.
//!
//! The ProgramRegistry is an on-chain advisory registry where program authors
//! register their compiled ELF binaries with metadata and download locations.
//! Provers use this to discover where to obtain the ELF for a given programId.

use alloy::primitives::B256;
use anyhow::{Context, Result, bail};

use crate::client::ChainClient;
use zkminer_contracts::bindings::{IProgramRegistry, ProgramVersion, StorageURI};

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
        if let Some(hit) = self
            .program_info_cache
            .lock()
            .unwrap()
            .get(&program_id)
            .cloned()
        {
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
pub struct ElfCache {
    cache_dir: std::path::PathBuf,
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
        std::fs::create_dir_all(&self.cache_dir)
            .context("Failed to create ELF cache directory")?;
        let path = self.cache_dir.join(format!("{}.elf", program_id));
        std::fs::write(&path, elf).context("Failed to write ELF to cache")?;
        tracing::info!("Cached ELF for {} ({} bytes)", program_id, elf.len());
        Ok(())
    }

    /// Check if an ELF is cached.
    pub fn has(&self, program_id: &B256) -> bool {
        self.cache_dir
            .join(format!("{}.elf", program_id))
            .exists()
    }
}

/// Download an ELF binary from a list of storage URIs.
/// Tries each URI in order until one succeeds.
pub async fn download_elf(
    uris: &[ResolvedURI],
    expected_hash: Option<B256>,
) -> Result<Vec<u8>> {
    if uris.is_empty() {
        bail!("No storage URIs available for this program");
    }

    for uri_info in uris {
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

        tracing::info!("Downloading ELF from {}...", url);
        match reqwest::get(&url).await {
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
                            url, len, MAX_ELF_BYTES
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
                        url, MAX_ELF_BYTES
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
                            url, expected, actual
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
                            url, uri_info.content_hash, actual
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
