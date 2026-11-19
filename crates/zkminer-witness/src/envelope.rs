//! The witness-job envelope carried in `JobDescriptor.inputData` (plan §7.1).
//!
//! `inputData = WITNESS_JOB_TAG_V1 ‖ abi.encode(WitnessJobV1)`. Decoding is strict: the body is
//! decoded, re-encoded, and must equal the original bytes exactly, which rejects trailing bytes,
//! dirty high bits, non-canonical offsets and nonzero padding.

use alloy_primitives::{b256, B256};
use alloy_sol_types::{sol, SolValue};

use crate::locator::{HemiCodeLocator, LocatorError};

/// `keccak256("hemiprove.witness-job.v1")`.
pub const WITNESS_JOB_TAG_V1: B256 =
    b256!("8cc8a382a07bfd380a010bc7dc5a6c2d7ee7a1984ec0555baba41a6fb40f4df3");

/// `keccak256("evm-rpc/v1")`.
pub const CLASS_EVM_RPC_V1: B256 =
    b256!("74d47797fc541e361442d98a5b45ff3d5e54bfb28cbbbc97f128ed9b98308d91");
/// `keccak256("blob/v1")`.
pub const CLASS_BLOB_V1: B256 =
    b256!("6b2b59f84c5ad9614227bf40d627bbae33351c7888e565b81c40a3fe7a3d1aff");
/// `keccak256("state-read")`.
pub const METHOD_SET_STATE_READ: B256 =
    b256!("443f50d27406b101b4b4af812d91df11e0ebaaf1d24dae2f29b85a5324437205");
/// `keccak256("state-trace")` (Phase 2).
pub const METHOD_SET_STATE_TRACE: B256 =
    b256!("e20d5a4ab94fea975651a18213a677ad5bc44ff7db79b6351f2865e885ff641c");

/// Envelope field ranges (plan §7.1).
pub const MAX_BUILDER_URIS: usize = 4;
pub const MAX_BUILDER_URI_BYTES: usize = 512;
pub const MAX_BUILDER_PARAMS_BYTES: usize = 16 * 1024;
pub const MIN_SOURCES: usize = 1;
pub const MAX_SOURCES: usize = 8;
pub const MAX_CONFIG_BYTES: usize = 1024;
pub const MAX_REQUEST_BYTES: u32 = 65_536;

sol! {
    /// A declared capability: a class id and a config decoded by that class's schema.
    #[derive(Debug, PartialEq, Eq)]
    struct Capability {
        bytes32 class;
        bytes config;
    }

    /// Requester-declared upper bounds the miner enforces during simulation.
    #[derive(Debug, PartialEq, Eq)]
    struct Limits {
        uint32 maxFetches;
        uint64 maxFetchBytes;
        uint32 maxRequestBytes;
        uint32 maxResponseBytes;
        uint64 maxBuilderFuel;
        uint64 maxBuilderMemoryBytes;
        uint32 maxBuilderSeconds;
        uint64 maxWitnessBytes;
        uint64 maxGuestCycles;
    }

    /// The envelope body.
    #[derive(Debug, PartialEq, Eq)]
    struct WitnessJobV1 {
        uint8 builderType;
        bytes32 builderId;
        string[] builderURIs;
        bytes builderParams;
        Capability[] sources;
        Limits limits;
    }

    /// The builder's input (plan §9.2), as `abi.encode(ctx)` with its `0x20` head word. `limits`
    /// carries the envelope's declared values, never the host's clamps.
    #[derive(Debug, PartialEq, Eq)]
    struct BuilderContextV1 {
        uint64 hemiChainId;
        address router;
        bytes32 programId;
        bytes32 proofSystemId;
        bytes32 expectedJournalHash;
        bytes32 journalFields;
        Capability[] sources;
        Limits limits;
        bytes builderParams;
    }

    /// `evm-rpc/v1` config: `abi.encode(uint64 chainId, bool archive, bytes32 methodSet, uint64 maxProofAge)`.
    #[derive(Debug, PartialEq, Eq)]
    struct EvmRpcConfigV1 {
        uint64 chainId;
        bool archive;
        bytes32 methodSet;
        uint64 maxProofAge;
    }

    /// `blob/v1` config: `abi.encode(uint64 maxBytes)`.
    #[derive(Debug, PartialEq, Eq)]
    struct BlobConfigV1 {
        uint64 maxBytes;
    }
}

/// Builder runtime types (plan §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuilderType {
    /// WASM module run by wasmtime (Phase 1).
    Wasm,
    /// RISC-V program in the risc0 executor's builder mode (Phase 2+).
    RiscV,
    /// Declarative manifest (Phase 2+).
    Declarative,
}

impl BuilderType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Wasm),
            2 => Some(Self::RiscV),
            3 => Some(Self::Declarative),
            _ => None,
        }
    }
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Wasm => 1,
            Self::RiscV => 2,
            Self::Declarative => 3,
        }
    }
}

/// A capability class this build understands, with its decoded config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityKind {
    EvmRpcV1 { chain_id: u64, archive: bool, method_set: MethodSet, max_proof_age: u64 },
    BlobV1 { max_bytes: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodSet {
    StateRead,
    /// Phase 2.
    StateTrace,
}

/// Why an envelope is malformed or out of range. Fixed set: no attacker-controlled strings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("inputData does not start with WITNESS_JOB_TAG_V1")]
    NotWitnessJob,
    #[error("envelope body does not ABI-decode")]
    Undecodable,
    #[error("envelope body longer than {MAX_ENVELOPE_BODY_BYTES} bytes")]
    BodyTooLarge,
    #[error("envelope body is not the canonical encoding of what it decodes to")]
    NonCanonical,
    #[error("unknown builder type")]
    UnknownBuilderType,
    #[error("more than {MAX_BUILDER_URIS} builder URIs")]
    TooManyUris,
    #[error("a builder URI is longer than {MAX_BUILDER_URI_BYTES} bytes")]
    UriTooLong,
    #[error("builderParams longer than {MAX_BUILDER_PARAMS_BYTES} bytes")]
    ParamsTooLong,
    #[error("sources count outside {MIN_SOURCES}..={MAX_SOURCES}")]
    SourcesCount,
    #[error("a capability config is longer than {MAX_CONFIG_BYTES} bytes")]
    ConfigTooLong,
    #[error("unknown capability class")]
    UnknownClass,
    #[error("a capability config does not decode canonically under its class schema")]
    BadConfig,
    #[error("unknown method set")]
    UnknownMethodSet,
    #[error("maxRequestBytes above {MAX_REQUEST_BYTES}")]
    RequestBytesOutOfRange,
}

/// A decoded, range-checked envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub job: WitnessJobV1,
    pub builder_type: BuilderType,
    pub capabilities: Vec<CapabilityKind>,
}

/// Returns the envelope body if `input_data` carries the witness-job tag.
pub fn classify(input_data: &[u8]) -> Option<&[u8]> {
    if input_data.len() >= 32 && input_data[..32] == WITNESS_JOB_TAG_V1[..] {
        Some(&input_data[32..])
    } else {
        None
    }
}

/// `WITNESS_JOB_TAG_V1 ‖ abi.encode(job)`.
pub fn encode_envelope(job: &WitnessJobV1) -> Vec<u8> {
    let mut out = WITNESS_JOB_TAG_V1.to_vec();
    out.extend_from_slice(&job.abi_encode());
    out
}

/// The longest canonical body whose every field is at its maximum (asserted by a test): 480 head
/// bytes, 4 URIs of 512 bytes (2,336), 16 KiB of params (16,416) and 8 sources with 1 KiB configs
/// (9,248). A longer body must fail a range check, so it is refused before decoding.
pub const MAX_ENVELOPE_BODY_BYTES: usize = 28_480;

/// A head word read as a `usize`, `None` if it is out of bounds or above `u64`.
fn word_usize(b: &[u8], at: usize) -> Option<usize> {
    let w = b.get(at..at.checked_add(32)?)?;
    if w[..24].iter().any(|&x| x != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(w[24..].try_into().ok()?)).ok()
}

/// Bounds the decoder's work before alloy runs: the body size, the outer head word, and the two
/// array lengths. Without this, offsets that alias one long string make the decoder copy it once per
/// array element (about 60 MB from 64 KB of `inputData`).
fn precheck(body: &[u8]) -> Result<(), EnvelopeError> {
    if body.len() > MAX_ENVELOPE_BODY_BYTES {
        return Err(EnvelopeError::BodyTooLarge);
    }
    if word_usize(body, 0) != Some(0x20) {
        return Err(EnvelopeError::NonCanonical);
    }
    // The tuple starts at 32; builderURIs' offset is its third head word, sources' its fifth.
    let tuple = 32usize;
    let uris = tuple
        .checked_add(word_usize(body, tuple + 64).ok_or(EnvelopeError::Undecodable)?)
        .ok_or(EnvelopeError::Undecodable)?;
    let sources = tuple
        .checked_add(word_usize(body, tuple + 128).ok_or(EnvelopeError::Undecodable)?)
        .ok_or(EnvelopeError::Undecodable)?;
    if word_usize(body, uris).ok_or(EnvelopeError::Undecodable)? > MAX_BUILDER_URIS {
        return Err(EnvelopeError::TooManyUris);
    }
    let n_sources = word_usize(body, sources).ok_or(EnvelopeError::Undecodable)?;
    if !(MIN_SOURCES..=MAX_SOURCES).contains(&n_sources) {
        return Err(EnvelopeError::SourcesCount);
    }
    Ok(())
}

/// Strictly decodes and range-checks an envelope from `inputData`. A string that is not valid UTF-8
/// is reported as `NonCanonical` (the decoder replaces invalid sequences, so it does not re-encode).
pub fn decode(input_data: &[u8]) -> Result<Envelope, EnvelopeError> {
    let body = classify(input_data).ok_or(EnvelopeError::NotWitnessJob)?;
    precheck(body)?;
    let job = WitnessJobV1::abi_decode(body).map_err(|_| EnvelopeError::Undecodable)?;
    if job.abi_encode() != body {
        return Err(EnvelopeError::NonCanonical);
    }
    let builder_type =
        BuilderType::from_u8(job.builderType).ok_or(EnvelopeError::UnknownBuilderType)?;
    if job.builderURIs.len() > MAX_BUILDER_URIS {
        return Err(EnvelopeError::TooManyUris);
    }
    if job.builderURIs.iter().any(|u| u.len() > MAX_BUILDER_URI_BYTES) {
        return Err(EnvelopeError::UriTooLong);
    }
    if job.builderParams.len() > MAX_BUILDER_PARAMS_BYTES {
        return Err(EnvelopeError::ParamsTooLong);
    }
    if !(MIN_SOURCES..=MAX_SOURCES).contains(&job.sources.len()) {
        return Err(EnvelopeError::SourcesCount);
    }
    if job.limits.maxRequestBytes > MAX_REQUEST_BYTES {
        return Err(EnvelopeError::RequestBytesOutOfRange);
    }
    let mut capabilities = Vec::with_capacity(job.sources.len());
    for cap in &job.sources {
        capabilities.push(decode_capability(cap)?);
    }
    Ok(Envelope { job, builder_type, capabilities })
}

/// Decodes one capability's config under its class schema (canonical encoding required).
pub fn decode_capability(cap: &Capability) -> Result<CapabilityKind, EnvelopeError> {
    if cap.config.len() > MAX_CONFIG_BYTES {
        return Err(EnvelopeError::ConfigTooLong);
    }
    let cfg = &cap.config[..];
    if cap.class == CLASS_EVM_RPC_V1 {
        let c = EvmRpcConfigV1::abi_decode(cfg).map_err(|_| EnvelopeError::BadConfig)?;
        if c.abi_encode() != cfg {
            return Err(EnvelopeError::BadConfig);
        }
        let method_set = if c.methodSet == METHOD_SET_STATE_READ {
            MethodSet::StateRead
        } else if c.methodSet == METHOD_SET_STATE_TRACE {
            MethodSet::StateTrace
        } else {
            return Err(EnvelopeError::UnknownMethodSet);
        };
        Ok(CapabilityKind::EvmRpcV1 {
            chain_id: c.chainId,
            archive: c.archive,
            method_set,
            max_proof_age: c.maxProofAge,
        })
    } else if cap.class == CLASS_BLOB_V1 {
        let c = BlobConfigV1::abi_decode(cfg).map_err(|_| EnvelopeError::BadConfig)?;
        if c.abi_encode() != cfg {
            return Err(EnvelopeError::BadConfig);
        }
        Ok(CapabilityKind::BlobV1 { max_bytes: c.maxBytes })
    } else {
        Err(EnvelopeError::UnknownClass)
    }
}

/// Encodes an `evm-rpc/v1` config.
pub fn encode_evm_rpc_config(chain_id: u64, archive: bool, method_set: B256, max_proof_age: u64) -> Vec<u8> {
    EvmRpcConfigV1 { chainId: chain_id, archive, methodSet: method_set, maxProofAge: max_proof_age }
        .abi_encode()
}

/// Encodes a `blob/v1` config.
pub fn encode_blob_config(max_bytes: u64) -> Vec<u8> {
    BlobConfigV1 { maxBytes: max_bytes }.abi_encode()
}

/// A usable source for the builder artifact (plan §13.4 fetch order uses these after the cache and
/// the operator mirror).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderSource {
    HemiCode(HemiCodeLocator),
}

/// Why a `builderURIs` entry is ignored (not fatal for the job, plan §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoredUri {
    UnknownScheme,
    RefusedScheme,
    Malformed(LocatorError),
    OtherChain,
    /// `https`/`ipfs` entries: served from Phase 2 through the artifact egress.
    NotInThisPhase,
    /// The same locator appeared earlier in the list.
    Duplicate,
}

/// Classifies `builderURIs` for a job on `job_chain_id`, in envelope order.
pub fn usable_builder_sources(job: &WitnessJobV1, job_chain_id: u64) -> (Vec<BuilderSource>, Vec<IgnoredUri>) {
    let mut usable = Vec::new();
    let mut ignored = Vec::new();
    for uri in &job.builderURIs {
        let bytes = uri.as_bytes();
        let scheme_end = bytes.windows(3).position(|w| w == b"://");
        let scheme = match scheme_end {
            Some(i) => &bytes[..i],
            None => {
                ignored.push(IgnoredUri::UnknownScheme);
                continue;
            }
        };
        match scheme {
            b"hemi-code" => match HemiCodeLocator::parse(uri) {
                Ok(loc) if loc.chain_id == job_chain_id => {
                    let src = BuilderSource::HemiCode(loc);
                    if usable.contains(&src) {
                        ignored.push(IgnoredUri::Duplicate);
                    } else {
                        usable.push(src);
                    }
                }
                Ok(_) => ignored.push(IgnoredUri::OtherChain),
                Err(e) => ignored.push(IgnoredUri::Malformed(e)),
            },
            b"https" | b"ipfs" => ignored.push(IgnoredUri::NotInThisPhase),
            b"http" => ignored.push(IgnoredUri::RefusedScheme),
            _ => ignored.push(IgnoredUri::UnknownScheme),
        }
    }
    (usable, ignored)
}

/// Host maxima and clamps (plan §7.1, §9.1 hard ceilings, §19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMaxima {
    pub max_witness_bytes: u64,
    pub max_guest_cycles: u64,
    pub max_fetches: u32,
    pub max_fetch_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_builder_fuel: u64,
    pub max_builder_memory_bytes: u64,
    pub max_builder_seconds: u32,
}

/// Hard ceilings in code, whatever the configuration (plan §9.1). The operator's
/// `[witness] max_witness_bytes` (default 32 MiB, §15.4) can be raised only up to the W ceiling.
pub const HARD_MAX_BUILDER_MEMORY_BYTES: u64 = 1 << 30;
pub const HARD_MAX_BUILDER_SECONDS: u32 = 300;
pub const HARD_MAX_WITNESS_BYTES: u64 = 1 << 30;
/// The Phase-1 default for `[witness] max_witness_bytes`.
pub const DEFAULT_MAX_WITNESS_BYTES: u64 = 32 << 20;

impl HostMaxima {
    /// Applies the hard ceilings to an operator configuration.
    pub fn with_hard_ceilings(mut self) -> Self {
        self.max_builder_memory_bytes = self.max_builder_memory_bytes.min(HARD_MAX_BUILDER_MEMORY_BYTES);
        self.max_builder_seconds = self.max_builder_seconds.min(HARD_MAX_BUILDER_SECONDS);
        self.max_request_bytes = self.max_request_bytes.min(MAX_REQUEST_BYTES);
        self.max_witness_bytes = self.max_witness_bytes.min(HARD_MAX_WITNESS_BYTES);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsRejected {
    #[error("maxWitnessBytes above this host's maximum")]
    WitnessBytes,
    #[error("maxGuestCycles above this host's maximum")]
    GuestCycles,
}

/// Effective limits: `maxWitnessBytes`/`maxGuestCycles` above the host's maxima reject the job;
/// the builder-side limits are clamped (a builder that needed more fails).
pub fn effective_limits(declared: &Limits, host: &HostMaxima) -> Result<Limits, LimitsRejected> {
    let host = host.with_hard_ceilings();
    if declared.maxWitnessBytes > host.max_witness_bytes {
        return Err(LimitsRejected::WitnessBytes);
    }
    if declared.maxGuestCycles > host.max_guest_cycles {
        return Err(LimitsRejected::GuestCycles);
    }
    Ok(Limits {
        maxFetches: declared.maxFetches.min(host.max_fetches),
        maxFetchBytes: declared.maxFetchBytes.min(host.max_fetch_bytes),
        maxRequestBytes: declared.maxRequestBytes.min(host.max_request_bytes),
        maxResponseBytes: declared.maxResponseBytes.min(host.max_response_bytes),
        maxBuilderFuel: declared.maxBuilderFuel.min(host.max_builder_fuel),
        maxBuilderMemoryBytes: declared.maxBuilderMemoryBytes.min(host.max_builder_memory_bytes),
        maxBuilderSeconds: declared.maxBuilderSeconds.min(host.max_builder_seconds),
        maxWitnessBytes: declared.maxWitnessBytes,
        maxGuestCycles: declared.maxGuestCycles,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    pub(crate) fn sample_job() -> WitnessJobV1 {
        WitnessJobV1 {
            builderType: 1,
            builderId: B256::repeat_byte(0x11),
            builderURIs: vec![format!("hemi-code://743111/0x{}", "ab".repeat(20))],
            builderParams: vec![1, 2, 3].into(),
            sources: vec![Capability {
                class: CLASS_EVM_RPC_V1,
                config: encode_evm_rpc_config(8453, true, METHOD_SET_STATE_READ, 300).into(),
            }],
            limits: Limits {
                maxFetches: 100,
                maxFetchBytes: 1 << 24,
                maxRequestBytes: 65_536,
                maxResponseBytes: 1 << 22,
                maxBuilderFuel: 1 << 32,
                maxBuilderMemoryBytes: 1 << 28,
                maxBuilderSeconds: 60,
                maxWitnessBytes: 1 << 24,
                maxGuestCycles: 1 << 28,
            },
        }
    }

    #[test]
    fn tags_are_the_keccak_of_their_names() {
        assert_eq!(WITNESS_JOB_TAG_V1, keccak256("hemiprove.witness-job.v1"));
        assert_eq!(CLASS_EVM_RPC_V1, keccak256("evm-rpc/v1"));
        assert_eq!(CLASS_BLOB_V1, keccak256("blob/v1"));
        assert_eq!(METHOD_SET_STATE_READ, keccak256("state-read"));
        assert_eq!(METHOD_SET_STATE_TRACE, keccak256("state-trace"));
    }

    #[test]
    fn round_trips_and_starts_with_the_head_offset() {
        let job = sample_job();
        let bytes = encode_envelope(&job);
        assert_eq!(&bytes[32..64], &B256::left_padding_from(&[0x20])[..], "abi.encode(struct) head word");
        let env = decode(&bytes).unwrap();
        assert_eq!(env.job, job);
        assert_eq!(env.builder_type, BuilderType::Wasm);
        assert_eq!(
            env.capabilities,
            vec![CapabilityKind::EvmRpcV1 { chain_id: 8453, archive: true, method_set: MethodSet::StateRead, max_proof_age: 300 }]
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_dirty_bits() {
        let mut bytes = encode_envelope(&sample_job());
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(EnvelopeError::NonCanonical | EnvelopeError::Undecodable)));
        let mut bytes = encode_envelope(&sample_job());
        // builderType is the first head word of the struct (after the 0x20 offset): dirty a high byte.
        bytes[32 + 32] = 0x01;
        assert!(matches!(decode(&bytes), Err(EnvelopeError::NonCanonical | EnvelopeError::Undecodable)));
        assert_eq!(decode(&[0u8; 10]), Err(EnvelopeError::NotWitnessJob));
    }

    #[test]
    fn range_checks() {
        let mut j = sample_job();
        j.builderType = 9;
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::UnknownBuilderType));
        let mut j = sample_job();
        j.builderURIs = vec!["a".into(); 5];
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::TooManyUris));
        let mut j = sample_job();
        j.builderURIs = vec!["a".repeat(513)];
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::UriTooLong));
        let mut j = sample_job();
        j.builderParams = vec![0u8; MAX_BUILDER_PARAMS_BYTES + 1].into();
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::ParamsTooLong));
        let mut j = sample_job();
        j.sources = vec![];
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::SourcesCount));
        let mut j = sample_job();
        j.sources[0].class = B256::repeat_byte(7);
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::UnknownClass));
        let mut j = sample_job();
        j.sources[0].config = encode_evm_rpc_config(1, false, B256::repeat_byte(9), 0).into();
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::UnknownMethodSet));
        let mut j = sample_job();
        let mut cfg = j.sources[0].config.to_vec();
        cfg.push(0);
        j.sources[0].config = cfg.into();
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::BadConfig));
        let mut j = sample_job();
        j.limits.maxRequestBytes = 65_537;
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::RequestBytesOutOfRange));
    }

    #[test]
    fn builder_uris_are_classified_not_fatal() {
        let mut j = sample_job();
        j.builderURIs = vec![
            "https://example.com/b.wasm".into(),
            "http://example.com/b.wasm".into(),
            "ftp://x".into(),
            format!("hemi-code://43111/0x{}", "cd".repeat(20)),
        ];
        let (usable, ignored) = usable_builder_sources(&j, 743111);
        assert!(usable.is_empty());
        assert_eq!(
            ignored,
            vec![IgnoredUri::NotInThisPhase, IgnoredUri::RefusedScheme, IgnoredUri::UnknownScheme, IgnoredUri::OtherChain]
        );
        let (usable, _) = usable_builder_sources(&sample_job(), 743111);
        assert_eq!(usable.len(), 1);
    }

    #[test]
    fn host_maxima_reject_and_clamp() {
        let host = HostMaxima {
            max_witness_bytes: 1 << 25,
            max_guest_cycles: 1 << 30,
            max_fetches: 10,
            max_fetch_bytes: 1 << 20,
            max_request_bytes: 70_000,
            max_response_bytes: 1 << 20,
            max_builder_fuel: 1 << 20,
            max_builder_memory_bytes: 1 << 40,
            max_builder_seconds: 10_000,
        };
        let eff = effective_limits(&sample_job().limits, &host).unwrap();
        assert_eq!(eff.maxFetches, 10);
        assert_eq!(eff.maxBuilderMemoryBytes, 1 << 28, "declared below the hard ceiling");
        assert_eq!(eff.maxBuilderSeconds, 60);
        assert_eq!(eff.maxRequestBytes, 65_536);
        let mut l = sample_job().limits;
        l.maxBuilderMemoryBytes = u64::MAX;
        l.maxBuilderSeconds = u32::MAX;
        let eff = effective_limits(&l, &host).unwrap();
        assert_eq!(eff.maxBuilderMemoryBytes, HARD_MAX_BUILDER_MEMORY_BYTES);
        assert_eq!(eff.maxBuilderSeconds, HARD_MAX_BUILDER_SECONDS);
        let mut l = sample_job().limits;
        l.maxWitnessBytes = 1 << 26;
        assert_eq!(effective_limits(&l, &host), Err(LimitsRejected::WitnessBytes));
        let mut l = sample_job().limits;
        l.maxGuestCycles = 1 << 31;
        assert_eq!(effective_limits(&l, &host), Err(LimitsRejected::GuestCycles));
    }

    #[test]
    fn matches_solidity_abi_encode() {
        // `cast abi-encode "f((uint8,bytes32,string[],bytes,(bytes32,bytes)[],(uint32,…,uint64)))"` of
        // `sample_job()`, hashed.
        let body = sample_job().abi_encode();
        assert_eq!(body.len(), 992);
        assert_eq!(keccak256(&body), b256!("3c00157f164915e258db1a464fad085e0a6e77306ba7dfd1730e2c8c1b53a114"));
        let d = crate::context::DescriptorFields {
            program_id: B256::repeat_byte(1),
            proof_system_id: B256::repeat_byte(2),
            expected_journal_hash: B256::repeat_byte(3),
            journal_fields: B256::repeat_byte(4),
        };
        let ctx = crate::context::build_context(743111, alloy_primitives::Address::repeat_byte(5), &d, &sample_job());
        let enc = crate::context::encode_context(&ctx);
        assert_eq!(enc.len(), 928);
        assert_eq!(keccak256(&enc), b256!("0d9043a9b52dbd3d89f7445c374f9a5e7b858ccc9884fbfdb95e13bcea3a45b8"));
    }

    fn maximal_job() -> WitnessJobV1 {
        let mut j = sample_job();
        j.builderURIs = vec!["u".repeat(MAX_BUILDER_URI_BYTES); MAX_BUILDER_URIS];
        j.builderParams = vec![7u8; MAX_BUILDER_PARAMS_BYTES].into();
        j.sources = vec![Capability { class: CLASS_BLOB_V1, config: vec![0u8; MAX_CONFIG_BYTES].into() }; MAX_SOURCES];
        j
    }

    #[test]
    fn maximal_body_is_exactly_the_precheck_bound() {
        assert_eq!(maximal_job().abi_encode().len(), MAX_ENVELOPE_BODY_BYTES);
        // Every field at its maximum passes the ranges (the 1 KiB configs fail only their schema).
        let mut j = maximal_job();
        j.sources = vec![j.sources[0].clone(); MAX_SOURCES];
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::BadConfig));
        let mut j = sample_job();
        j.builderURIs = vec!["u".repeat(MAX_BUILDER_URI_BYTES); MAX_BUILDER_URIS];
        j.builderParams = vec![7u8; MAX_BUILDER_PARAMS_BYTES].into();
        j.sources = vec![j.sources[0].clone(); MAX_SOURCES];
        j.limits.maxRequestBytes = MAX_REQUEST_BYTES;
        assert!(decode(&encode_envelope(&j)).is_ok());
        let mut input = encode_envelope(&maximal_job());
        input.extend_from_slice(&[0u8; 32]);
        assert_eq!(decode(&input), Err(EnvelopeError::BodyTooLarge));
    }

    #[test]
    fn aliased_offsets_are_refused_before_decoding() {
        // 1,000 builderURIs whose offsets all point at one long string: alloy would copy it 1,000
        // times. The precheck rejects the count first.
        let mut body = Vec::new();
        let word = |v: u64| B256::left_padding_from(&v.to_be_bytes()).0;
        body.extend_from_slice(&word(0x20));
        let tuple_head = 5 * 32 + 9 * 32;
        body.extend_from_slice(&word(1)); // builderType
        body.extend_from_slice(&[0x11; 32]); // builderId
        body.extend_from_slice(&word(tuple_head as u64)); // builderURIs offset
        body.extend_from_slice(&word(0)); // builderParams offset (unused here)
        body.extend_from_slice(&word(0)); // sources offset
        body.extend_from_slice(&[0u8; 9 * 32]); // limits
        body.extend_from_slice(&word(1000)); // builderURIs length
        assert_eq!(decode(&[WITNESS_JOB_TAG_V1.as_slice(), &body].concat()), Err(EnvelopeError::TooManyUris));
        // The same through sources.
        let mut j = sample_job();
        j.sources = vec![j.sources[0].clone(); 9];
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::SourcesCount));
        // A head offset that is not 0x20.
        let mut input = encode_envelope(&sample_job());
        input[63] = 0x40;
        assert_eq!(decode(&input), Err(EnvelopeError::NonCanonical));
    }

    #[test]
    fn dirty_config_encodings_are_refused() {
        let cfg = encode_evm_rpc_config(1, true, METHOD_SET_STATE_READ, 0);
        let check = |cfg: Vec<u8>| {
            let mut j = sample_job();
            j.sources[0].config = cfg.into();
            decode(&encode_envelope(&j))
        };
        assert!(check(cfg.clone()).is_ok());
        let mut c = cfg.clone();
        c[63] = 2; // bool = 2
        assert_eq!(check(c), Err(EnvelopeError::BadConfig));
        let mut c = cfg.clone();
        c[0] = 1; // high bits of the uint64 chainId
        assert_eq!(check(c), Err(EnvelopeError::BadConfig));
        let mut j = sample_job();
        let mut b = encode_blob_config(5);
        b.push(0);
        j.sources[0] = Capability { class: CLASS_BLOB_V1, config: b.into() };
        assert_eq!(decode(&encode_envelope(&j)), Err(EnvelopeError::BadConfig));
        let mut j = sample_job();
        j.sources[0] = Capability { class: CLASS_BLOB_V1, config: encode_blob_config(5).into() };
        assert_eq!(decode(&encode_envelope(&j)).unwrap().capabilities, vec![CapabilityKind::BlobV1 { max_bytes: 5 }]);
    }

    #[test]
    fn non_utf8_uri_is_refused() {
        let mut input = encode_envelope(&sample_job());
        let at = input.windows(9).position(|w| w == b"hemi-code").unwrap();
        input[at] = 0xff;
        assert_eq!(decode(&input), Err(EnvelopeError::NonCanonical));
    }

    #[test]
    fn duplicate_locators_are_read_once() {
        let mut j = sample_job();
        j.builderURIs = vec![j.builderURIs[0].clone(), j.builderURIs[0].clone()];
        let (usable, ignored) = usable_builder_sources(&j, 743111);
        assert_eq!(usable.len(), 1);
        assert_eq!(ignored, vec![IgnoredUri::Duplicate]);
    }

    #[test]
    fn witness_ceiling_applies_whatever_the_host_says() {
        let host = HostMaxima {
            max_witness_bytes: u64::MAX,
            max_guest_cycles: u64::MAX,
            max_fetches: 1,
            max_fetch_bytes: 1,
            max_request_bytes: 1,
            max_response_bytes: 1,
            max_builder_fuel: 1,
            max_builder_memory_bytes: 1,
            max_builder_seconds: 1,
        };
        let mut l = sample_job().limits;
        l.maxWitnessBytes = HARD_MAX_WITNESS_BYTES + 1;
        assert_eq!(effective_limits(&l, &host), Err(LimitsRejected::WitnessBytes));
        l.maxWitnessBytes = HARD_MAX_WITNESS_BYTES;
        assert!(effective_limits(&l, &host).is_ok());
    }

    proptest::proptest! {
        /// Structured mutation: change one byte of a valid envelope. Never panics, and anything that
        /// still decodes re-encodes to exactly the input.
        #[test]
        fn mutated_envelopes_decode_strictly(at in 0usize..1024, v in proptest::prelude::any::<u8>()) {
            let mut input = encode_envelope(&sample_job());
            let at = 32 + at % (input.len() - 32);
            input[at] = v;
            if let Ok(env) = decode(&input) {
                proptest::prop_assert_eq!(encode_envelope(&env.job), input);
            }
        }

        /// Offsets and lengths nudged by small amounts.
        #[test]
        fn nudged_words_never_panic(word in 0usize..31, delta in -64i64..64) {
            let mut input = encode_envelope(&sample_job());
            let at = 32 + word * 32 + 24;
            let mut v = u64::from_be_bytes(input[at..at + 8].try_into().unwrap()) as i64;
            v = v.wrapping_add(delta);
            input[at..at + 8].copy_from_slice(&(v as u64).to_be_bytes());
            let _ = decode(&input);
        }
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let mut input = WITNESS_JOB_TAG_V1.to_vec();
            input.extend_from_slice(&data);
            let _ = decode(&input);
        }
    }
}
