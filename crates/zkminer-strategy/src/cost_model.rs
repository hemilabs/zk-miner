//! Cost modeling for electricity and hardware amortization.

use std::time::Duration;

/// Cost parameters for the proving operation.
#[derive(Debug, Clone)]
pub struct CostParams {
    /// Electricity cost in USD per kWh.
    pub electricity_cost_kwh: f64,
    /// System power draw in watts during proving.
    pub system_power_watts: f64,
    /// Hardware amortization cost in USD per hour.
    pub hardware_cost_per_hour: f64,
    /// Estimated gas cost in USD for the on-chain transactions (claim + fulfill).
    pub gas_cost_usd: f64,
}

impl Default for CostParams {
    fn default() -> Self {
        Self {
            electricity_cost_kwh: 0.12,
            system_power_watts: 200.0,
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.01, // ~0.0005 ETH at ~$20/ETH (Hemi gas is cheap)
        }
    }
}

/// Estimate the cost of proving for a given duration.
pub fn estimate_proving_cost(params: &CostParams, duration: Duration) -> f64 {
    let hours = duration.as_secs_f64() / 3600.0;

    // Electricity cost: watts * hours / 1000 * $/kWh
    let electricity = params.system_power_watts * hours / 1000.0 * params.electricity_cost_kwh;

    // Hardware amortization
    let hardware = params.hardware_cost_per_hour * hours;

    // Gas cost is fixed per job (claim + fulfill transactions)
    electricity + hardware + params.gas_cost_usd
}
