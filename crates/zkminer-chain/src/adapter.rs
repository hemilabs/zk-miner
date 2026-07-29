//! HemiProveRegistry adapter metadata queries.
//!
//! Adapter entries carry proof-system–specific parameters the miner needs to
//! correctly compute collateral requirements and expected fees for a job.

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use zkminer_contracts::bindings::IHemiProveRegistry;

use crate::client::ChainClient;

/// Subset of `AdapterEntry` the evaluator needs.
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub adapter: Address,
    pub status: u8,
    /// Default collateral ratio in basis points (e.g. 15000 = 150%).
    pub default_collateral_bps: u128,
    pub min_stake: u128,
    pub fee_rate_bps: u16,
    pub cycle_attestation_mode: u8,
}

impl ChainClient {
    /// Query the registry for an adapter's metadata (collateral ratio, fee, etc.).
    ///
    /// Returns an error if the proof system is not registered (adapter address
    /// is zero), ensuring the caller's fallback logic is triggered rather than
    /// silently accepting all-zero parameters.
    pub async fn get_adapter_info(&self, proof_system_id: B256) -> Result<AdapterInfo> {
        let registry = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        let entry = registry
            .getAdapter(proof_system_id)
            .call()
            .await
            .context("Failed to query HemiProveRegistry.getAdapter")?;
        if entry.adapter == Address::ZERO {
            anyhow::bail!(
                "Proof system 0x{} is not registered (adapter address is zero)",
                alloy::hex::encode(proof_system_id),
            );
        }
        Ok(AdapterInfo {
            adapter: entry.adapter,
            status: entry.status,
            default_collateral_bps: entry.defaultCollateralRatio.to::<u128>(),
            min_stake: entry.minStake,
            fee_rate_bps: entry.feeRateBps,
            cycle_attestation_mode: entry.cycleAttestationMode,
        })
    }
}
