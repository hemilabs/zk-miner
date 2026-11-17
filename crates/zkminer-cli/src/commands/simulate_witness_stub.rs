//! `zkminer simulate --descriptor` needs the witness sandbox, which exists on Linux only.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_ADVERSARIAL_SECS: u64 = 600;
pub const DEFAULT_FLIPS: usize = 32;
pub const MAX_MUTATIONS: usize = 256;
pub const DEFAULT_ADVERSARIAL_MAX_W_BYTES: u64 = 8 << 20;

#[derive(Debug, Clone)]
pub struct AdversarialOptions {
    pub budget: Duration,
    pub flips: usize,
    pub max_mutations: usize,
    pub scheme: Option<u64>,
    pub providers: Option<Vec<String>>,
    pub max_w_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct WitnessSimOptions {
    pub descriptor: PathBuf,
    pub builder: Option<PathBuf>,
    pub elf: Option<PathBuf>,
    pub prover: Option<alloy::primitives::Address>,
    pub po2s: Vec<u8>,
    pub keccak_po2: u8,
    pub broker_config: Option<PathBuf>,
    pub execute_worker: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub execute_timeout: Duration,
    pub out: Option<PathBuf>,
    pub max_guest_cycles: Option<u64>,
    pub header_bytes: Option<usize>,
    pub adversarial: Option<AdversarialOptions>,
}

pub async fn run(_: Option<&Path>, _: WitnessSimOptions) -> anyhow::Result<()> {
    anyhow::bail!("witness-construction jobs are simulated on Linux only")
}
