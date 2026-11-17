//! The pure parts of publishing (§13.5, Appendix B): the input check, the transactions' encodings,
//! the pacing gate, fees and replacements, and the cost preview.

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::primitives::{Bytes, TxKind, U256};
use anyhow::{bail, Result};
use zkminer_witness::manifest::{
    chunk_runtime_code, creation_code, ArtifactBudget, MAX_CHUNK_BODY, MAX_MANIFEST_CHUNKS, MIN_PLANNED_CHUNK_BODY,
};

/// What is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A type-1 witness builder (a WASM module).
    Builder,
    /// A guest ELF (risc0, RV32IM): a risc0 3.x `R0BF` program binary (user and kernel ELF), as
    /// the ProgramRegistry hashes it and miners derive its image id, or a bare RV32 ELF.
    Elf,
}

/// The cap on each chunk transaction's `GasPriceOracle.getL1GasUsed / 16` (§13.5): below the first
/// throttled level's 20,000.
pub const MAX_CHUNK_DA_BYTES: u64 = 19_500;
/// The chunk body tried first, shrunk in proportion until the oracle's estimate fits
/// [`MAX_CHUNK_DA_BYTES`]: a bare creation of 23,000 incompressible bytes estimates at about 19,900
/// under Fjord, so such a chunk ends near 22,500 bytes.
pub const DEFAULT_CHUNK_BYTES: usize = 23_000;
/// Send only while the DA backlog plus this publisher's own unmined estimates is under this (a
/// tenth of the backlog page level).
pub const MAX_BACKLOG_BYTES: u64 = 250_000;
/// Send only while the safe head lags the head by at most this.
pub const MAX_SAFE_LAG_SECS: u64 = 300;
/// Send only while the head is at most this old.
pub const MAX_HEAD_AGE_SECS: u64 = 60;
/// The published default `[artifacts] max_builder_bytes`: a larger builder is warned about.
pub const DEFAULT_MAX_BUILDER_BYTES: u64 = 4 << 20;

/// `--kind` must match the bytes (§13.5 "Input check"): publication is permanent.
pub fn check_input(bytes: &[u8], kind: Kind) -> Result<()> {
    if bytes.is_empty() {
        bail!("the file is empty");
    }
    match kind {
        Kind::Builder => {
            if bytes.len() < 8 || &bytes[..4] != b"\0asm" || bytes[4..8] != [1, 0, 0, 0] {
                bail!("--kind builder, but the file is not a WASM module (no \\0asm version-1 header)");
            }
            for payload in wasmparser::Parser::new(0).parse_all(bytes) {
                if let Err(e) = payload {
                    bail!("--kind builder, but the file does not parse as a WASM module: {e}");
                }
            }
            Ok(())
        }
        Kind::Elf if bytes.starts_with(b"R0BF") => {
            let p = risc0_binfmt::ProgramBinary::decode(bytes)
                .map_err(|e| anyhow::anyhow!("--kind elf, but the risc0 program binary does not parse: {e}"))?;
            check_rv32_elf(p.user_elf, "its user ELF")?;
            check_rv32_elf(p.kernel_elf, "its kernel ELF")?;
            // Load both as the executor does: what a miner derives the image id from.
            p.compute_image_id()
                .map_err(|e| anyhow::anyhow!("--kind elf, but the risc0 program binary does not load: {e:#}"))?;
            Ok(())
        }
        Kind::Elf => check_rv32_elf(bytes, "the file"),
    }
}

fn check_rv32_elf(bytes: &[u8], what: &str) -> Result<()> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        bail!("--kind elf, but {what} is not an ELF (nor a risc0 R0BF program binary)");
    }
    if bytes[4] != 1 || bytes[5] != 1 {
        bail!("--kind elf, but {what} is not 32-bit little-endian (a risc0 guest is RV32IM)");
    }
    if u16::from_le_bytes([bytes[18], bytes[19]]) != 0xf3 {
        bail!("--kind elf, but {what} is not for RISC-V");
    }
    Ok(())
}

/// The creation input that deploys one chunk: `creation_code(0x00 ‖ body)`.
pub fn chunk_creation(body: &[u8]) -> Vec<u8> {
    creation_code(&chunk_runtime_code(body))
}

/// The unsigned EIP-1559 contract creation, as `GasPriceOracle.getL1GasUsed` takes it.
pub fn unsigned_creation(chain_id: u64, nonce: u64, gas_limit: u64, max_fee: u128, tip: u128, input: Vec<u8>) -> TxEip1559 {
    TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        to: TxKind::Create,
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::from(input),
    }
}

/// A creation with every field the publisher may still change at a value at least as long in RLP
/// as any it sends, so a chunk sized against it is never larger when sent.
pub fn conservative_creation(chain_id: u64, input: Vec<u8>) -> Vec<u8> {
    unsigned_creation(chain_id, u64::from(u32::MAX), u64::from(u32::MAX), u128::from(u64::MAX), u128::from(u64::MAX), input)
        .encoded_for_signing()
}

/// The next size to try for a chunk of `size` bytes whose transaction estimated `estimate` DA bytes
/// (above the cap): scaled down to the cap, with a margin, never below one byte.
pub fn shrink(size: usize, estimate: u64) -> usize {
    let scaled = (size as u128 * u128::from(MAX_CHUNK_DA_BYTES) / u128::from(estimate.max(1))) as usize;
    scaled.saturating_sub(64).clamp(1, size.saturating_sub(1).max(1))
}

/// The chunk sizes are a plan the manifest can hold, and one every miner whose artifact cap admits
/// the bytes also admits: its per-job budget counts chunk reads from [`MIN_PLANNED_CHUNK_BODY`]
/// (`ArtifactBudget`), and a manifest over it is `NotAdmitted`, deferred for ever, never served.
/// Only an oracle pricing chunks far above their bytes makes such a plan.
pub fn check_plan(chunks: usize, length: usize) -> Result<()> {
    if chunks == 0 || chunks > MAX_MANIFEST_CHUNKS as usize {
        bail!("{chunks} chunks: one manifest holds 1..={MAX_MANIFEST_CHUNKS}");
    }
    if chunks < length.div_ceil(MAX_CHUNK_BODY) || chunks > length {
        bail!("{chunks} chunks cannot hold {length} bytes");
    }
    let budget = ArtifactBudget::for_max_bytes((length as u64).max(DEFAULT_MAX_BUILDER_BYTES));
    if !budget.admits(length as u64, chunks as u32) {
        bail!(
            "{length} bytes in {chunks} chunks: a miner's per-job budget admits at most {} chunk reads for an artifact \
             up to {} bytes (chunks of at least {MIN_PLANNED_CHUNK_BODY} bytes but the last); this chain's \
             GasPriceOracle priced the chunks too high to publish one miners serve",
            budget.max_chunks,
            budget.max_bytes
        );
    }
    Ok(())
}

/// What the pacing gate reads before each send (§13.5 "Pacing"); `None` is unknown, and unknown
/// never sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PaceInputs {
    /// `Σ l1GasUsed/16` over user transactions in (safe, head].
    pub backlog_bytes: Option<u64>,
    /// This publisher's own unmined estimates.
    pub own_unmined_bytes: u64,
    pub safe_lag_secs: Option<u64>,
    pub router_paused: Option<bool>,
    pub head_age_secs: Option<u64>,
}

/// `Ok` to send now, or why to wait.
pub fn pace(i: &PaceInputs) -> Result<(), String> {
    match i.router_paused {
        Some(false) => {}
        Some(true) => return Err("the HemiProve router is paused".into()),
        None => return Err("the router's pause state is unknown".into()),
    }
    match i.head_age_secs {
        Some(a) if a <= MAX_HEAD_AGE_SECS => {}
        Some(a) => return Err(format!("the head is {a} s old (at most {MAX_HEAD_AGE_SECS})")),
        None => return Err("the head's age is unknown".into()),
    }
    match i.safe_lag_secs {
        Some(l) if l <= MAX_SAFE_LAG_SECS => {}
        Some(l) => return Err(format!("the safe head lags {l} s (at most {MAX_SAFE_LAG_SECS})")),
        None => return Err("the safe-head lag is unknown".into()),
    }
    match i.backlog_bytes {
        Some(b) if b.saturating_add(i.own_unmined_bytes) < MAX_BACKLOG_BYTES => Ok(()),
        Some(b) => Err(format!(
            "the DA backlog is {} bytes with this publisher's unmined ones (under {MAX_BACKLOG_BYTES} to send)",
            b.saturating_add(i.own_unmined_bytes)
        )),
        None => Err("the DA backlog cannot be read".into()),
    }
}

/// Both fee fields for a send: `maxFee = 2 × baseFee + tip`.
pub fn fees(base_fee: u128, tip: u128) -> (u128, u128) {
    (tip, base_fee.saturating_mul(2).saturating_add(tip))
}

/// A replacement's fees at the same nonce: each field raised by at least an eighth (nodes refuse a
/// replacement below +10%) and to at least what a fresh send would carry now.
pub fn bump(prev_tip: u128, prev_max_fee: u128, base_fee: u128, floor_tip: u128) -> (u128, u128) {
    let tip = (prev_tip.saturating_mul(9) / 8).saturating_add(1).max(floor_tip);
    let max_fee = (prev_max_fee.saturating_mul(9) / 8).saturating_add(1).max(fees(base_fee, tip).1);
    (tip, max_fee)
}

/// The inclusion floor from recent blocks' included user tips: the lowest seen, at least 1 wei.
pub fn tip_floor(observed: impl IntoIterator<Item = u128>) -> Option<u128> {
    observed.into_iter().min().map(|t| t.max(1))
}

/// A transaction's effective tip in a block of `base_fee` (type 2: `min(tip, maxFee − base)`;
/// legacy: `gasPrice − base`).
pub fn effective_tip(base_fee: u128, max_fee: Option<u128>, tip: Option<u128>, gas_price: Option<u128>) -> Option<u128> {
    match (max_fee, tip, gas_price) {
        (Some(m), Some(t), _) => Some(t.min(m.saturating_sub(base_fee))),
        (_, _, Some(p)) => Some(p.saturating_sub(base_fee)),
        _ => None,
    }
}

/// The cost preview (§13.5): L2 gas at the chosen tip, the L1 data fee, and the balance an
/// in-flight chunk needs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostPreview {
    pub length: usize,
    pub chunks: usize,
    pub largest_chunk: usize,
    pub base_fee_wei: String,
    pub tip_wei: String,
    pub max_fee_wei: String,
    /// Gas for every deployment, the manifest's included.
    pub l2_gas: u64,
    /// `l2_gas × (base fee + tip)`.
    pub l2_fee_wei: String,
    /// `Σ GasPriceOracle.getL1Fee`, when the chain has the oracle.
    pub l1_fee_wei: Option<String>,
    /// What the pool needs for one chunk in flight: `gas limit × max fee + its L1 fee`.
    pub in_flight_balance_wei: String,
    pub balance_wei: String,
}

impl std::fmt::Display for CostPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Publishing {} bytes in {} chunk(s) of at most {} bytes, then a manifest.", self.length, self.chunks, self.largest_chunk)?;
        writeln!(f, "  fees:       base {} wei, tip {} wei, max fee {} wei", self.base_fee_wei, self.tip_wei, self.max_fee_wei)?;
        writeln!(f, "  L2 gas:     {} (about {} wei at base + tip)", self.l2_gas, self.l2_fee_wei)?;
        match &self.l1_fee_wei {
            Some(l1) => writeln!(f, "  L1 fee:     about {l1} wei (GasPriceOracle)")?,
            None => writeln!(f, "  L1 fee:     unknown (no GasPriceOracle on this chain)")?,
        }
        writeln!(f, "  in flight:  {} wei needed for one chunk (gas limit × max fee + its L1 fee)", self.in_flight_balance_wei)?;
        write!(f, "  balance:    {} wei", self.balance_wei)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_must_match_the_bytes() {
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0))"#).unwrap();
        assert!(check_input(&wasm, Kind::Builder).is_ok());
        assert!(check_input(&wasm, Kind::Elf).is_err());
        let mut truncated = wasm.clone();
        truncated.truncate(wasm.len() - 3);
        assert!(check_input(&truncated, Kind::Builder).is_err());
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1;
        elf[5] = 1;
        elf[18..20].copy_from_slice(&0xf3u16.to_le_bytes());
        assert!(check_input(&elf, Kind::Elf).is_ok());
        assert!(check_input(&elf, Kind::Builder).is_err());
        elf[4] = 2;
        assert!(check_input(&elf, Kind::Elf).is_err(), "64-bit");
        elf[4] = 1;
        elf[18] = 0x3e;
        assert!(check_input(&elf, Kind::Elf).is_err(), "x86-64");
        assert!(check_input(&[], Kind::Builder).is_err());
        // A risc0 program binary: its parts are checked too.
        elf[18] = 0xf3;
        let r0bf = risc0_binfmt::ProgramBinary::new(&elf, &[1, 2, 3, 4]).encode();
        let e = check_input(&r0bf, Kind::Elf).unwrap_err().to_string();
        assert!(e.contains("its kernel ELF is not an ELF"), "{e}");
        let mut bad = r0bf.clone();
        bad[4] ^= 0xff;
        assert!(check_input(&bad, Kind::Elf).unwrap_err().to_string().contains("does not parse"));
        assert!(check_input(&r0bf, Kind::Builder).is_err());
    }

    #[test]
    fn pacing_sends_only_when_everything_is_known_and_low() {
        let ok = PaceInputs {
            backlog_bytes: Some(10_000),
            own_unmined_bytes: 0,
            safe_lag_secs: Some(120),
            router_paused: Some(false),
            head_age_secs: Some(3),
        };
        assert!(pace(&ok).is_ok());
        assert!(pace(&PaceInputs { backlog_bytes: Some(240_000), own_unmined_bytes: 10_000, ..ok }).is_err());
        assert!(pace(&PaceInputs { backlog_bytes: Some(249_999), ..ok }).is_ok());
        assert!(pace(&PaceInputs { backlog_bytes: None, ..ok }).is_err());
        assert!(pace(&PaceInputs { safe_lag_secs: Some(301), ..ok }).is_err());
        assert!(pace(&PaceInputs { safe_lag_secs: None, ..ok }).is_err());
        assert!(pace(&PaceInputs { router_paused: Some(true), ..ok }).is_err());
        assert!(pace(&PaceInputs { router_paused: None, ..ok }).is_err());
        assert!(pace(&PaceInputs { head_age_secs: Some(61), ..ok }).is_err());
        assert!(pace(&PaceInputs::default()).is_err());
    }

    #[test]
    fn replacements_raise_both_fields_past_the_nodes_minimum() {
        let (t, m) = fees(1_000, 10);
        assert_eq!((t, m), (10, 2_010));
        let (t2, m2) = bump(t, m, 1_000, 10);
        assert!(t2 * 10 >= t * 11 && m2 * 10 >= m * 11, "{t2} {m2}");
        // The base fee rose: the max fee follows it.
        let (_, m3) = bump(t2, m2, 50_000, 10);
        assert!(m3 >= 100_000 + t2);
        assert_eq!(tip_floor([7u128, 3, 9]), Some(3));
        assert_eq!(tip_floor([0u128]), Some(1));
        assert_eq!(tip_floor(Vec::<u128>::new()), None);
        assert_eq!(effective_tip(100, Some(150), Some(80), None), Some(50));
        assert_eq!(effective_tip(100, Some(500), Some(80), None), Some(80));
        assert_eq!(effective_tip(100, None, None, Some(130)), Some(30));
    }

    #[test]
    fn chunks_shrink_to_the_cap_and_plans_fit_a_manifest() {
        assert!(shrink(23_000, 20_000) < 23_000 * 19_500 / 20_000);
        assert_eq!(shrink(10, 1_000_000), 1);
        assert!(shrink(23_000, 19_600) >= 22_000);
        assert!(check_plan(1, 100).is_ok());
        assert!(check_plan(2, 30_000).is_ok());
        assert!(check_plan(1, 30_000).is_err(), "too few for the body cap");
        assert!(check_plan(5, 3).is_err(), "more chunks than bytes");
        assert!(check_plan(1_225, 1 << 30).is_err());
        // Within a miner's artifact budget: 4 MiB in 23,000-byte chunks, or shrunk to 19,400, fits;
        // chunks of 10,000 bytes need more reads than a miner admits for the bytes.
        let four = 4usize << 20;
        assert!(check_plan(four.div_ceil(23_000), four).is_ok());
        assert!(check_plan(four.div_ceil(19_400), four).is_ok());
        assert!(check_plan(3_956_001usize.div_ceil(23_000), 3_956_001).is_ok());
        let e = check_plan(four.div_ceil(10_000), four).unwrap_err().to_string();
        assert!(e.contains("at most 257 chunk reads"), "{e}");
        // The conservative transaction is never shorter than a real one.
        let input = chunk_creation(&[7u8; 100]);
        let real = unsigned_creation(743111, 5, 5_000_000, 3_000_000_000, 10, input.clone()).encoded_for_signing();
        assert!(conservative_creation(743111, input).len() >= real.len());
    }
}
