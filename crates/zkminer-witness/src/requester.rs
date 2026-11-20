//! Requester tooling (plan §7, §21.1 item 3): the envelope written from a human-friendly spec, an
//! existing envelope explained, and typed 32-byte words for `builderParams` and journal headers.
//!
//! Everything here encodes with [`encode_envelope`] and then decodes the result with [`decode`], the
//! miner's own strict decoder, so a spec the miner would skip is refused here with the miner's own
//! reason. Nothing here talks to a network.

use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::envelope::{
    decode, decode_capability, encode_blob_config, encode_envelope, encode_evm_rpc_config, usable_builder_sources,
    Capability, CapabilityKind, EnvelopeError, IgnoredUri, Limits, MethodSet, WitnessJobV1, CLASS_BLOB_V1,
    CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ, METHOD_SET_STATE_TRACE, WITNESS_JOB_TAG_V1,
};

/// Keep the whole envelope under about this size (plan §7.1): the submit transaction meets the same
/// DA throttle as a fulfil.
pub const ENVELOPE_SIZE_ADVICE_BYTES: usize = 8_000;

/// A requester's envelope, as TOML or JSON. Every limit is required: zero means "none allowed",
/// never "unlimited" (plan §7.1), so no default could be right for every job.
///
/// ```toml
/// builder_type = 1
/// builder_id = "0x…"                       # or `--builder <wasm>`: its sha256
/// builder_uris = ["hemi-code://743111/0x…"]
/// builder_params_abi = ["uint64:8453", "bytes32:0x…", "address:0x…"]   # or builder_params = "0x…"
///
/// [[sources]]
/// class = "evm-rpc/v1"
/// chain_id = 8453
/// archive = true
/// method_set = "state-read"
/// max_proof_age = 300
///
/// [limits]
/// max_fetches = 64
/// max_fetch_bytes = 16777216
/// max_request_bytes = 65536
/// max_response_bytes = 4194304
/// max_builder_fuel = 10000000000
/// max_builder_memory_bytes = 268435456
/// max_builder_seconds = 60
/// max_witness_bytes = 1048576
/// max_guest_cycles = 67108864
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSpec {
    #[serde(default = "default_builder_type")]
    pub builder_type: u8,
    /// sha256 of the artifact (types 1 and 3). Optional here when the tool is given the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<B256>,
    #[serde(default)]
    pub builder_uris: Vec<String>,
    /// Raw `builderParams`, `0x` hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_params: Option<String>,
    /// `builderParams` as `abi.encode` of static values, each `type:value` ([`parse_word`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_params_abi: Option<Vec<String>>,
    pub sources: Vec<SourceSpec>,
    pub limits: LimitsSpec,
}

fn default_builder_type() -> u8 {
    1
}

/// One capability (plan §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", deny_unknown_fields)]
pub enum SourceSpec {
    #[serde(rename = "evm-rpc/v1")]
    EvmRpc { chain_id: u64, archive: bool, method_set: String, max_proof_age: u64 },
    #[serde(rename = "blob/v1")]
    Blob { max_bytes: u64 },
}

/// [`Limits`] with snake-case names, every field required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSpec {
    pub max_fetches: u32,
    pub max_fetch_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_builder_fuel: u64,
    pub max_builder_memory_bytes: u64,
    pub max_builder_seconds: u32,
    pub max_witness_bytes: u64,
    pub max_guest_cycles: u64,
}

impl From<&LimitsSpec> for Limits {
    fn from(l: &LimitsSpec) -> Self {
        Limits {
            maxFetches: l.max_fetches,
            maxFetchBytes: l.max_fetch_bytes,
            maxRequestBytes: l.max_request_bytes,
            maxResponseBytes: l.max_response_bytes,
            maxBuilderFuel: l.max_builder_fuel,
            maxBuilderMemoryBytes: l.max_builder_memory_bytes,
            maxBuilderSeconds: l.max_builder_seconds,
            maxWitnessBytes: l.max_witness_bytes,
            maxGuestCycles: l.max_guest_cycles,
        }
    }
}

impl From<&Limits> for LimitsSpec {
    fn from(l: &Limits) -> Self {
        LimitsSpec {
            max_fetches: l.maxFetches,
            max_fetch_bytes: l.maxFetchBytes,
            max_request_bytes: l.maxRequestBytes,
            max_response_bytes: l.maxResponseBytes,
            max_builder_fuel: l.maxBuilderFuel,
            max_builder_memory_bytes: l.maxBuilderMemoryBytes,
            max_builder_seconds: l.maxBuilderSeconds,
            max_witness_bytes: l.maxWitnessBytes,
            max_guest_cycles: l.maxGuestCycles,
        }
    }
}

/// Why a spec does not make an envelope the miner accepts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("no builder_id: give it, or the builder artifact to hash")]
    NoBuilderId,
    #[error("builder_id {spec} is not the artifact's sha256 {artifact}")]
    BuilderIdMismatch { spec: B256, artifact: B256 },
    #[error("give builder_params or builder_params_abi, not both")]
    BothParams,
    #[error("builder_params: {0}")]
    Params(String),
    #[error("unknown method set {0:?} (state-read, or state-trace in Phase 2)")]
    MethodSet(String),
    /// The miner's own decoder refuses the result.
    #[error("the miner would skip this envelope: {0}")]
    Refused(EnvelopeError),
}

/// A 32-byte word from `type:value`: `uintN:<decimal or 0x hex>` (N a multiple of 8 up to 256, the
/// value range-checked), `bool:true|false`, `address:0x…` (20 bytes, left-padded), `bytes32:0x…`
/// (exactly 32 bytes), `bytesN:0x…` (exactly N bytes, right-padded as Solidity's `bytesN`),
/// `keccak:<text>` (keccak256 of the UTF-8 text) and `word:0x…` (a raw 32-byte word). These are
/// `abi.encode`'s words for static values, so a list of them is `abi.encode(v1, v2, …)`.
pub fn parse_word(s: &str) -> Result<B256, String> {
    let (ty, value) = s.split_once(':').ok_or_else(|| format!("{s:?}: expected type:value"))?;
    let hex_exact = |v: &str, n: usize| -> Result<Vec<u8>, String> {
        let h = v.strip_prefix("0x").ok_or_else(|| format!("{s:?}: the value must be 0x-prefixed hex"))?;
        let b = hex::decode(h).map_err(|e| format!("{s:?}: {e}"))?;
        if b.len() != n {
            return Err(format!("{s:?}: expected {n} bytes, got {}", b.len()));
        }
        Ok(b)
    };
    match ty {
        "bool" => match value {
            "true" => Ok(B256::with_last_byte(1)),
            "false" => Ok(B256::ZERO),
            _ => Err(format!("{s:?}: a bool is true or false")),
        },
        "address" => {
            let a: Address = value.parse().map_err(|e| format!("{s:?}: {e}"))?;
            Ok(B256::left_padding_from(a.as_slice()))
        }
        "word" | "bytes32" => Ok(B256::from_slice(&hex_exact(value, 32)?)),
        "keccak" => Ok(keccak256(value.as_bytes())),
        t if t.starts_with("bytes") => {
            let n: usize = t[5..].parse().map_err(|_| format!("{s:?}: unknown type {t}"))?;
            if !(1..=32).contains(&n) {
                return Err(format!("{s:?}: bytesN takes N in 1..=32"));
            }
            let mut w = [0u8; 32];
            w[..n].copy_from_slice(&hex_exact(value, n)?);
            Ok(B256::from(w))
        }
        t if t.starts_with("uint") => {
            let bits: usize = if t == "uint" { 256 } else { t[4..].parse().map_err(|_| format!("{s:?}: unknown type {t}"))? };
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(format!("{s:?}: uintN takes N a multiple of 8 in 8..=256"));
            }
            let v = match value.strip_prefix("0x") {
                Some(h) => U256::from_str_radix(h, 16),
                None => U256::from_str_radix(value, 10),
            }
            .map_err(|e| format!("{s:?}: {e}"))?;
            if bits < 256 && v >> bits != U256::ZERO {
                return Err(format!("{s:?}: does not fit in uint{bits}"));
            }
            Ok(B256::from(v.to_be_bytes::<32>()))
        }
        _ => Err(format!("{s:?}: unknown type {ty} (uintN, bool, address, bytesN, bytes32, keccak, word)")),
    }
}

/// `abi.encode` of static values given as [`parse_word`] strings: their words concatenated.
pub fn encode_words(items: &[String]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(32 * items.len());
    for i in items {
        out.extend_from_slice(parse_word(i)?.as_slice());
    }
    Ok(out)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let h = s.strip_prefix("0x").ok_or("must be 0x-prefixed hex")?;
    hex::decode(h).map_err(|e| e.to_string())
}

impl EnvelopeSpec {
    /// The envelope body, checked by the miner's decoder. `artifact_sha256` is the sha256 of the
    /// builder artifact when the tool has it: it fills a missing `builder_id` and must equal a given
    /// one.
    pub fn to_job(&self, artifact_sha256: Option<B256>) -> Result<WitnessJobV1, SpecError> {
        let builder_id = match (self.builder_id, artifact_sha256) {
            (Some(spec), Some(artifact)) if spec != artifact => return Err(SpecError::BuilderIdMismatch { spec, artifact }),
            (Some(id), _) | (None, Some(id)) => id,
            (None, None) => return Err(SpecError::NoBuilderId),
        };
        let params = match (&self.builder_params, &self.builder_params_abi) {
            (Some(_), Some(_)) => return Err(SpecError::BothParams),
            (Some(h), None) => parse_hex_bytes(h).map_err(SpecError::Params)?,
            (None, Some(words)) => encode_words(words).map_err(SpecError::Params)?,
            (None, None) => Vec::new(),
        };
        let mut sources = Vec::with_capacity(self.sources.len());
        for s in &self.sources {
            sources.push(match s {
                SourceSpec::EvmRpc { chain_id, archive, method_set, max_proof_age } => {
                    let set = match method_set.as_str() {
                        "state-read" => METHOD_SET_STATE_READ,
                        "state-trace" => METHOD_SET_STATE_TRACE,
                        other => return Err(SpecError::MethodSet(other.to_string())),
                    };
                    Capability {
                        class: CLASS_EVM_RPC_V1,
                        config: encode_evm_rpc_config(*chain_id, *archive, set, *max_proof_age).into(),
                    }
                }
                SourceSpec::Blob { max_bytes } => Capability { class: CLASS_BLOB_V1, config: encode_blob_config(*max_bytes).into() },
            });
        }
        let job = WitnessJobV1 {
            builderType: self.builder_type,
            builderId: builder_id,
            builderURIs: self.builder_uris.clone(),
            builderParams: params.into(),
            sources,
            limits: (&self.limits).into(),
        };
        decode(&encode_envelope(&job)).map_err(SpecError::Refused)?;
        Ok(job)
    }

    /// `inputData`: `WITNESS_JOB_TAG_V1 ‖ abi.encode(job)`, checked as [`Self::to_job`] says.
    pub fn encode(&self, artifact_sha256: Option<B256>) -> Result<Vec<u8>, SpecError> {
        Ok(encode_envelope(&self.to_job(artifact_sha256)?))
    }

    /// The spec of a decoded job (raw `builder_params`), so an existing envelope can be edited and
    /// encoded again. Capabilities of a class this build does not know are dropped (the decoder
    /// refuses them anyway).
    pub fn from_job(job: &WitnessJobV1) -> Self {
        EnvelopeSpec {
            builder_type: job.builderType,
            builder_id: Some(job.builderId),
            builder_uris: job.builderURIs.clone(),
            builder_params: Some(format!("0x{}", hex::encode(&job.builderParams))),
            builder_params_abi: None,
            sources: job
                .sources
                .iter()
                .filter_map(|c| match decode_capability(c).ok()? {
                    CapabilityKind::EvmRpcV1 { chain_id, archive, method_set, max_proof_age } => Some(SourceSpec::EvmRpc {
                        chain_id,
                        archive,
                        method_set: match method_set {
                            MethodSet::StateRead => "state-read",
                            MethodSet::StateTrace => "state-trace",
                        }
                        .to_string(),
                        max_proof_age,
                    }),
                    CapabilityKind::BlobV1 { max_bytes } => Some(SourceSpec::Blob { max_bytes }),
                })
                .collect(),
            limits: (&job.limits).into(),
        }
    }
}

/// One `builderURIs` entry as a miner on `chain_id` reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UriReport {
    pub uri: String,
    /// `usable` or why it is ignored (never fatal, plan §7.1).
    pub status: String,
}

/// An existing `inputData`, explained: what the miner's decoder makes of it and what it would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvelopeReport {
    pub input_bytes: usize,
    /// keccak256(inputData), the descriptor's input hash.
    pub input_keccak256: B256,
    /// Starts with `WITNESS_JOB_TAG_V1`.
    pub witness_job: bool,
    /// The decoder's refusal (the miner skips the job: plan §16, envelope rows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<EnvelopeSpec>,
    pub uris: Vec<UriReport>,
    /// What a requester should look at (size, unusable URIs, Phase-2 features).
    pub warnings: Vec<String>,
}

fn ignored_text(i: &IgnoredUri) -> String {
    match i {
        IgnoredUri::UnknownScheme => "ignored: unknown scheme".into(),
        IgnoredUri::RefusedScheme => "ignored: refused scheme (http)".into(),
        IgnoredUri::Malformed(e) => format!("ignored: malformed hemi-code locator ({e})"),
        IgnoredUri::OtherChain => "ignored: hemi-code locator for another chain".into(),
        IgnoredUri::NotInThisPhase => "ignored: https/ipfs builder URIs are served from Phase 2".into(),
        IgnoredUri::Duplicate => "ignored: the same locator appears earlier".into(),
    }
}

/// Explains `input_data` for a job on the HemiProve chain `chain_id`.
pub fn explain(input_data: &[u8], chain_id: u64) -> EnvelopeReport {
    let mut r = EnvelopeReport {
        input_bytes: input_data.len(),
        input_keccak256: keccak256(input_data),
        witness_job: input_data.len() >= 32 && input_data[..32] == WITNESS_JOB_TAG_V1[..],
        error: None,
        spec: None,
        uris: Vec::new(),
        warnings: Vec::new(),
    };
    if input_data.len() > ENVELOPE_SIZE_ADVICE_BYTES {
        r.warnings.push(format!(
            "inputData is {} bytes: keep the envelope under about {ENVELOPE_SIZE_ADVICE_BYTES} (the submit \
             transaction meets the DA throttle, plan §7.1)",
            input_data.len()
        ));
    }
    let env = match decode(input_data) {
        Ok(e) => e,
        Err(e) => {
            r.error = Some(e.to_string());
            return r;
        }
    };
    // Each URI in envelope order, with what the classifier made of it. Every entry lands in exactly
    // one of its two lists, each in envelope order: an entry is usable when it is a locator for this
    // chain not seen before, and otherwise takes the next ignored reason.
    let (usable, ignored) = usable_builder_sources(&env.job, chain_id);
    let mut ignored = ignored.iter();
    let mut seen = Vec::new();
    for uri in &env.job.builderURIs {
        let status = match crate::locator::HemiCodeLocator::parse(uri) {
            Ok(l) if l.chain_id == chain_id && !seen.contains(&l) => {
                seen.push(l);
                "usable".to_string()
            }
            _ => ignored.next().map(ignored_text).unwrap_or_else(|| "ignored".into()),
        };
        r.uris.push(UriReport { uri: uri.clone(), status });
    }
    debug_assert_eq!(seen.len(), usable.len());
    if usable.is_empty() {
        r.warnings.push(format!(
            "no builderURIs entry is usable on chain {chain_id}: only miners with the artifact cached or in \
             an operator mirror can serve this job"
        ));
    }
    for c in &env.capabilities {
        if let CapabilityKind::EvmRpcV1 { method_set: MethodSet::StateTrace, .. } = c {
            r.warnings.push("the state-trace method set is served from Phase 2".into());
        }
    }
    if env.builder_type.as_u8() != 1 {
        r.warnings.push("only builder type 1 (WASM) is served in Phase 1".into());
    }
    r.spec = Some(EnvelopeSpec::from_job(&env.job));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> EnvelopeSpec {
        toml_spec(
            r#"
            builder_uris = ["hemi-code://743111/0x00112233445566778899aabbccddeeff00112233"]
            builder_params_abi = ["uint64:8453", "bytes32:0x1111111111111111111111111111111111111111111111111111111111111111", "address:0x00000000000000000000000000000000000000c0"]
            [[sources]]
            class = "evm-rpc/v1"
            chain_id = 8453
            archive = true
            method_set = "state-read"
            max_proof_age = 300
            [limits]
            max_fetches = 64
            max_fetch_bytes = 16777216
            max_request_bytes = 65536
            max_response_bytes = 4194304
            max_builder_fuel = 10000000000
            max_builder_memory_bytes = 268435456
            max_builder_seconds = 60
            max_witness_bytes = 1048576
            max_guest_cycles = 67108864
            "#,
        )
    }

    fn toml_spec(s: &str) -> EnvelopeSpec {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn words_are_abi_encode_words() {
        assert_eq!(parse_word("uint64:8453").unwrap(), B256::from(U256::from(8453u64).to_be_bytes::<32>()));
        assert_eq!(parse_word("uint:0xff").unwrap(), B256::with_last_byte(0xff));
        assert_eq!(parse_word("bool:true").unwrap(), B256::with_last_byte(1));
        let a = parse_word("address:0x00000000000000000000000000000000000000c0").unwrap();
        assert_eq!(a, B256::with_last_byte(0xc0));
        let b4 = parse_word("bytes4:0xdeadbeef").unwrap();
        assert_eq!(&b4.0[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&b4.0[4..], &[0u8; 28]);
        assert_eq!(parse_word("keccak:state-read").unwrap(), METHOD_SET_STATE_READ);
        for bad in ["uint8:256", "uint7:1", "uint264:1", "bytes33:0x00", "bytes2:0x00", "bool:1", "address:0x12", "int:1", "x"] {
            assert!(parse_word(bad).is_err(), "{bad}");
        }
        // abi.encode(uint64, bytes32, address) is three static words.
        let w = encode_words(&["uint64:1".into(), "bool:false".into()]).unwrap();
        assert_eq!(w.len(), 64);
    }

    #[test]
    fn a_spec_encodes_to_what_the_miner_decodes() {
        let s = spec();
        let id = B256::repeat_byte(0x42);
        let input = s.encode(Some(id)).unwrap();
        let env = decode(&input).unwrap();
        assert_eq!(env.job.builderId, id);
        assert_eq!(env.job.builderParams.len(), 96);
        assert_eq!(env.job.limits.maxGuestCycles, 67_108_864);
        // Round trip through the explained form.
        let r = explain(&input, 743111);
        assert!(r.witness_job && r.error.is_none());
        assert_eq!(r.uris[0].status, "usable");
        let back = r.spec.unwrap();
        assert_eq!(back.encode(None).unwrap(), input);
    }

    #[test]
    fn the_builder_id_comes_from_the_spec_or_the_artifact_and_must_agree() {
        let mut s = spec();
        assert_eq!(s.encode(None), Err(SpecError::NoBuilderId));
        s.builder_id = Some(B256::repeat_byte(1));
        assert!(s.encode(None).is_ok());
        assert!(matches!(s.encode(Some(B256::repeat_byte(2))), Err(SpecError::BuilderIdMismatch { .. })));
        assert!(s.encode(Some(B256::repeat_byte(1))).is_ok());
        s.builder_params = Some("0x00".into());
        assert_eq!(s.encode(None), Err(SpecError::BothParams));
    }

    #[test]
    fn out_of_range_specs_are_refused_with_the_miners_reason() {
        let mut s = spec();
        s.builder_id = Some(B256::ZERO);
        s.limits.max_request_bytes = 65_537;
        assert_eq!(s.encode(None), Err(SpecError::Refused(EnvelopeError::RequestBytesOutOfRange)));
        let mut s = spec();
        s.builder_id = Some(B256::ZERO);
        s.sources.clear();
        assert_eq!(s.encode(None), Err(SpecError::Refused(EnvelopeError::SourcesCount)));
        let mut s = spec();
        s.builder_id = Some(B256::ZERO);
        s.builder_type = 9;
        assert_eq!(s.encode(None), Err(SpecError::Refused(EnvelopeError::UnknownBuilderType)));
        let mut s = spec();
        s.builder_id = Some(B256::ZERO);
        s.sources[0] = SourceSpec::EvmRpc { chain_id: 1, archive: false, method_set: "everything".into(), max_proof_age: 0 };
        assert_eq!(s.encode(None), Err(SpecError::MethodSet("everything".into())));
    }

    #[test]
    fn explaining_reports_uris_and_refusals() {
        let mut s = spec();
        s.builder_id = Some(B256::ZERO);
        s.builder_uris = vec![
            "https://example.com/b.wasm".into(),
            "hemi-code://743111/0x00112233445566778899aabbccddeeff00112233".into(),
            "hemi-code://1/0x00112233445566778899aabbccddeeff00112233".into(),
            "hemi-code://743111/0x00112233445566778899aabbccddeeff00112233".into(),
        ];
        let r = explain(&s.encode(None).unwrap(), 743111);
        let st: Vec<&str> = r.uris.iter().map(|u| u.status.as_str()).collect();
        assert_eq!(st[1], "usable");
        assert!(st[0].contains("Phase 2"), "{st:?}");
        assert!(st[2].contains("another chain"), "{st:?}");
        assert!(st[3].contains("earlier"), "{st:?}");
        // On another chain nothing is usable, and that is said.
        let r = explain(&s.encode(None).unwrap(), 43111);
        assert!(r.uris.iter().all(|u| u.status != "usable"));
        assert!(r.warnings.iter().any(|w| w.contains("no builderURIs entry is usable")));
        // Not an envelope at all.
        let r = explain(b"\x01\x02", 743111);
        assert!(!r.witness_job && r.error.is_some() && r.spec.is_none());
        // Trailing bytes: the strict decode refuses them.
        let mut input = s.encode(None).unwrap();
        input.push(0);
        assert!(explain(&input, 743111).error.is_some());
    }
}
