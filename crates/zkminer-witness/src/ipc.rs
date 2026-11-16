//! Frames between the miner, the broker and builder runners (plan §10.1, §11.4).
//!
//! Every frame is `kind (u8) ‖ length (u32 BE) ‖ payload`. A reader is given a per-channel maximum
//! and rejects a larger length *before* allocating. The builder is treated as hostile: its frames
//! are fixed-layout binary; control frames between the miner and the broker carry capped JSON.

use std::io::{self, Read, Write};

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

pub const FRAME_HEADER_BYTES: usize = 5;

/// Builder → broker: `cap (u32 BE) ‖ request bytes`.
pub const KIND_FETCH: u8 = 0x01;
/// Broker → builder: `status (u8) ‖ body`.
pub const KIND_FETCH_RESULT: u8 = 0x02;
/// Miner ↔ broker control frames (JSON payloads, at most `MAX_CONTROL_BYTES`).
pub const KIND_CONTROL: u8 = 0x10;
pub const MAX_CONTROL_BYTES: u32 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FetchStatus {
    Ok = 0,
    Denied = 1,
    Failed = 2,
    Exhausted = 3,
}

impl FetchStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Ok,
            1 => Self::Denied,
            2 => Self::Failed,
            3 => Self::Exhausted,
            _ => return None,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("frame of {len} bytes exceeds the channel maximum {max}")]
    TooLarge { len: u32, max: u32 },
    #[error("unexpected frame kind {0:#x}")]
    UnexpectedKind(u8),
    #[error("malformed frame payload")]
    Malformed,
}

pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::other("frame too large"))?;
    let mut header = [0u8; FRAME_HEADER_BYTES];
    header[0] = kind;
    header[1..].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header)?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads one frame, refusing a length above `max` before allocating.
pub fn read_frame(r: &mut impl Read, max: u32) -> Result<(u8, Vec<u8>), FrameError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    r.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header[1..].try_into().unwrap());
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

/// The largest `KIND_FETCH` payload a reader accepts for a job whose effective `maxRequestBytes` is
/// `max_request_bytes`: the 4-byte cap index plus the request (plan §11.4 caps the request bytes).
pub fn fetch_frame_max(max_request_bytes: u32) -> u32 {
    max_request_bytes.max(64 * 1024).saturating_add(4)
}

/// The largest `KIND_FETCH_RESULT` payload: the status byte plus the response.
pub fn fetch_result_frame_max(max_response_bytes: u32) -> u32 {
    max_response_bytes.saturating_add(1)
}

pub fn encode_fetch(cap: u32, request: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + request.len());
    p.extend_from_slice(&cap.to_be_bytes());
    p.extend_from_slice(request);
    p
}

pub fn decode_fetch(payload: &[u8]) -> Result<(u32, &[u8]), FrameError> {
    if payload.len() < 4 {
        return Err(FrameError::Malformed);
    }
    Ok((u32::from_be_bytes(payload[..4].try_into().unwrap()), &payload[4..]))
}

pub fn encode_fetch_result(status: FetchStatus, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + body.len());
    p.push(status as u8);
    p.extend_from_slice(body);
    p
}

pub fn decode_fetch_result(payload: &[u8]) -> Result<(FetchStatus, &[u8]), FrameError> {
    let (&s, body) = payload.split_first().ok_or(FrameError::Malformed)?;
    Ok((FetchStatus::from_u8(s).ok_or(FrameError::Malformed)?, body))
}

/// Builder runner exit codes (the runner's process exit status).
pub mod exit {
    pub const OK: i32 = 0;
    pub const INVALID_MODULE: i32 = 10;
    pub const UNKNOWN_IMPORT: i32 = 11;
    pub const TRAP: i32 = 12;
    pub const FUEL: i32 = 13;
    pub const MEMORY: i32 = 14;
    pub const NONZERO_RETURN: i32 = 15;
    pub const WITNESS_TOO_LARGE: i32 = 16;
    pub const WALL_CLOCK: i32 = 17;
    pub const INTERNAL: i32 = 20;
}

/// The fixed-layout summary a builder runner writes to its summary fd before exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BuilderSummary {
    pub exit_code: i32,
    /// Some fetch returned status 2 (failed). Informational: verdicts take this from the broker.
    pub transient: bool,
    pub fetches: u32,
    pub fetch_bytes: u64,
    pub fuel_used: u64,
    pub witness_bytes: u64,
    pub compile_ms: u32,
    pub run_ms: u32,
}

pub const BUILDER_SUMMARY_MAGIC: [u8; 4] = *b"WBS1";
pub const BUILDER_SUMMARY_BYTES: usize = 48;

impl BuilderSummary {
    pub fn encode(&self) -> [u8; BUILDER_SUMMARY_BYTES] {
        let mut b = [0u8; BUILDER_SUMMARY_BYTES];
        b[0..4].copy_from_slice(&BUILDER_SUMMARY_MAGIC);
        b[4..8].copy_from_slice(&self.exit_code.to_be_bytes());
        b[8] = u8::from(self.transient);
        b[12..16].copy_from_slice(&self.fetches.to_be_bytes());
        b[16..24].copy_from_slice(&self.fetch_bytes.to_be_bytes());
        b[24..32].copy_from_slice(&self.fuel_used.to_be_bytes());
        b[32..40].copy_from_slice(&self.witness_bytes.to_be_bytes());
        b[40..44].copy_from_slice(&self.compile_ms.to_be_bytes());
        b[44..48].copy_from_slice(&self.run_ms.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != BUILDER_SUMMARY_BYTES || b[0..4] != BUILDER_SUMMARY_MAGIC || b[8] > 1 || b[9..12] != [0; 3] {
            return None;
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        Some(Self {
            exit_code: i32::from_be_bytes(b[4..8].try_into().unwrap()),
            transient: b[8] == 1,
            fetches: u32_at(12),
            fetch_bytes: u64_at(16),
            fuel_used: u64_at(24),
            witness_bytes: u64_at(32),
            compile_ms: u32_at(40),
            run_ms: u32_at(44),
        })
    }
}

/// Builder-visible budgets the broker enforces for one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobBudget {
    pub max_fetches: u32,
    pub max_fetch_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
}

/// Miner → broker control messages. The builder end of the job's socketpair travels with
/// `RegisterJob` as an `SCM_RIGHTS` fd; artifacts come back as a sealed memfd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlRequest {
    RegisterJob {
        job_key: B256,
        caller: Address,
        /// (class, config) pairs exactly as in the envelope, in envelope order (fetch `cap` indexes them).
        sources: Vec<(B256, Vec<u8>)>,
        budget: JobBudget,
        /// Held-lock work draws on the reserved lane.
        held_lock: bool,
    },
    EndJob {
        job_key: B256,
    },
    FetchArtifact {
        job_key: B256,
        caller: Address,
        source: ArtifactSource,
        builder_type: u8,
        /// `Some(builderId)` for builder types whose id is the sha256 (1 and 3).
        expected_sha256: Option<B256>,
        max_bytes: u64,
        held_lock: bool,
    },
    SelfTest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactSource {
    HemiCode { chain_id: u64, manifest: Address },
    Mirror { builder_type: u8, builder_id: B256 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFailure {
    NotConfigured,
    EmptyManifest,
    /// Structural failure, permanent for the manifest address when read at or below the safe head.
    ManifestInvalid { at_or_below_safe: bool },
    IdMismatch,
    ChunkInvalid { at_or_below_safe: bool },
    /// The chunks assembled to bytes that do not hash to the manifest's own sha256.
    HashMismatch { at_or_below_safe: bool },
    TooLarge,
    Endpoint,
    Budget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Registered { job_key: B256 },
    /// The broker's account of a job, sent in answer to `EndJob`. `transient` = some fetch returned
    /// status 2; `fetch_in_flight_at_end` = a fetch was still being served when the job ended.
    JobStats {
        job_key: B256,
        fetches: u32,
        fetch_bytes: u64,
        transient: bool,
        fetch_in_flight_at_end: bool,
        denied: u32,
    },
    /// The artifact is in the memfd sent with this frame.
    Artifact { len: u64, sha256: B256 },
    ArtifactFailed { failure: ArtifactFailure },
    SelfTest { ok: bool, checks: Vec<(SelfTestCheck, bool)> },
    Error { code: ControlErrorCode },
}

/// The broker's self-test checks (plan §10.3): a fixed set, no broker-supplied strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestCheck {
    SeccompActive,
    NoNewPrivs,
    LandlockActive,
    SecretUnreadable,
    GpuNodeUnopenable,
    LoopbackDenied,
    MetadataDenied,
    Rfc1918Denied,
    OwnAddressDenied,
    ConnectedPrefixDenied,
    EndpointsReachable,
    ArtifactEndpointChainId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    Malformed,
    UnknownJob,
    Busy,
    Internal,
}

pub fn encode_control<T: Serialize>(msg: &T) -> Vec<u8> {
    serde_json::to_vec(msg).expect("control messages serialize")
}

pub fn decode_control<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, FrameError> {
    if payload.len() > MAX_CONTROL_BYTES as usize {
        return Err(FrameError::TooLarge { len: payload.len() as u32, max: MAX_CONTROL_BYTES });
    }
    serde_json::from_slice(payload).map_err(|_| FrameError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_cap_before_allocating() {
        let mut buf = Vec::new();
        write_frame(&mut buf, KIND_FETCH, &encode_fetch(3, b"{}")).unwrap();
        let (k, p) = read_frame(&mut &buf[..], 1024).unwrap();
        assert_eq!(k, KIND_FETCH);
        assert_eq!(decode_fetch(&p).unwrap(), (3, &b"{}"[..]));
        let mut huge = vec![KIND_FETCH];
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(read_frame(&mut &huge[..], 1024), Err(FrameError::TooLarge { .. })));
        // EOF inside the payload is an error, not a short frame.
        let mut cut = Vec::new();
        write_frame(&mut cut, KIND_FETCH, &[1, 2, 3, 4, 5]).unwrap();
        cut.truncate(cut.len() - 2);
        assert!(matches!(read_frame(&mut &cut[..], 1024), Err(FrameError::Io(_))));
    }

    #[test]
    fn a_maximal_legal_request_fits_its_frame() {
        let req = vec![b'x'; 65_536];
        let mut buf = Vec::new();
        write_frame(&mut buf, KIND_FETCH, &encode_fetch(0, &req)).unwrap();
        let (_, p) = read_frame(&mut &buf[..], fetch_frame_max(65_536)).unwrap();
        assert_eq!(decode_fetch(&p).unwrap().1.len(), 65_536);
        assert_eq!(fetch_frame_max(100), 65_540, "small limits still allow the 64 KiB floor");
        assert_eq!(fetch_result_frame_max(10), 11);
        assert!(matches!(decode_fetch_result(&[4]), Err(FrameError::Malformed)), "unknown status");
        assert!(matches!(decode_fetch_result(&[]), Err(FrameError::Malformed)));
    }

    #[test]
    fn summary_round_trip() {
        let s = BuilderSummary { exit_code: exit::FUEL, transient: true, fetches: 7, fetch_bytes: 99, fuel_used: 5, witness_bytes: 3, compile_ms: 1, run_ms: 2 };
        assert_eq!(BuilderSummary::decode(&s.encode()), Some(s));
        let mut b = s.encode();
        b[8] = 7;
        assert_eq!(BuilderSummary::decode(&b), None);
        let mut b = s.encode();
        b[10] = 1;
        assert_eq!(BuilderSummary::decode(&b), None, "reserved bytes must be zero");
        let neg = BuilderSummary { exit_code: -9, ..s };
        assert_eq!(BuilderSummary::decode(&neg.encode()), Some(neg));
    }

    #[test]
    fn control_round_trip() {
        let m = ControlRequest::FetchArtifact {
            job_key: B256::repeat_byte(1),
            caller: Address::repeat_byte(2),
            source: ArtifactSource::HemiCode { chain_id: 743111, manifest: Address::repeat_byte(3) },
            builder_type: 1,
            expected_sha256: Some(B256::repeat_byte(4)),
            max_bytes: 1 << 22,
            held_lock: false,
        };
        let bytes = encode_control(&m);
        assert_eq!(decode_control::<ControlRequest>(&bytes).unwrap(), m);
        assert!(decode_control::<ControlRequest>(b"not json").is_err());
        let big = vec![b' '; MAX_CONTROL_BYTES as usize + 1];
        assert!(matches!(decode_control::<ControlRequest>(&big), Err(FrameError::TooLarge { .. })));
        let st = ControlResponse::SelfTest { ok: false, checks: vec![(SelfTestCheck::LoopbackDenied, false)] };
        assert_eq!(decode_control::<ControlResponse>(&encode_control(&st)).unwrap(), st);
        assert!(decode_control::<ControlResponse>(br#"{"type":"self_test","ok":true,"checks":[["made_up",true]]}"#).is_err());
    }
}
