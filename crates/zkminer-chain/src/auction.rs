//! Rust mirror of `AuctionMath.sol` and `SlashLib.sol` — matching Solidity exactly.

use alloy::primitives::U256;

/// Curve types matching the Solidity `CurveType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    Linear = 0,
    Quadratic = 1,
}

impl CurveType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Linear),
            1 => Some(Self::Quadratic),
            _ => None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Constants (matching Constants.sol)
// ──────────────────────────────────────────────────────────────────────────────

pub const MIN_STAKING_AGE: u64 = 3600; // 1 hour
pub const GLOBAL_DEFAULT_COLLATERAL_BPS: u64 = 15000; // 150%
pub const RELEASE_PENALTY_BPS: u64 = 2000; // 20% max
pub const SLASH_BURN_BPS: u64 = 6500; // 65%
pub const SLASH_BONUS_BPS: u64 = 3300; // 33%
pub const SLASH_KEEPER_BPS: u64 = 200; // 2%
pub const MIN_KEEPER_REWARD: u128 = 500_000_000_000_000_000; // 0.5e18
pub const TIMESTAMP_SLACK: u64 = 30;
pub const RELEASE_PENALTY_FLOOR_BPS: u64 = 500; // 5%

/// RISC_ZERO_V1 = keccak256("risczero.v1")
pub const RISC_ZERO_V1: [u8; 32] = [0u8; 32]; // Placeholder — use risc_zero_v1_id() at runtime

/// Compute keccak256("risczero.v1") at runtime.
pub fn risc_zero_v1_id() -> alloy::primitives::B256 {
    alloy::primitives::keccak256("risczero.v1")
}

/// Compute keccak256("sp1.v1") at runtime.
pub fn sp1_v1_id() -> alloy::primitives::B256 {
    alloy::primitives::keccak256("sp1.v1")
}

/// Compute keccak256("openvm.v1") at runtime.
pub fn openvm_v1_id() -> alloy::primitives::B256 {
    alloy::primitives::keccak256("openvm.v1")
}

/// Compute keccak256("custom") at runtime.
pub fn custom_verifier_id() -> alloy::primitives::B256 {
    alloy::primitives::keccak256("custom")
}

// ──────────────────────────────────────────────────────────────────────────────
// Auction Price Computation (mirrors AuctionMath.computePrice)
// ──────────────────────────────────────────────────────────────────────────────

/// Computes the current Dutch auction price.
/// Exact mirror of `AuctionMath.computePrice` in Solidity.
pub fn compute_price(
    min_price: u128,
    max_price: u128,
    ramp_up_period: u64,
    curve_type: CurveType,
    elapsed: u64,
) -> u128 {
    // Fixed price
    if min_price == max_price {
        return max_price;
    }
    // Past ramp period → max price
    if elapsed >= ramp_up_period {
        return max_price;
    }

    let range = max_price - min_price;
    let elapsed = elapsed as u128;
    let period = ramp_up_period as u128;

    match curve_type {
        CurveType::Linear => {
            // price = min + (max - min) * elapsed / period
            // Use U256 to avoid u128 overflow (uint96 * uint40 = 2^136 > 2^128)
            let r = U256::from(range);
            let e = U256::from(elapsed);
            let p = U256::from(period);
            min_price + (r * e / p).to::<u128>()
        }
        CurveType::Quadratic => {
            // price = min + (max - min) * elapsed^2 / period^2
            // Use U256 to avoid u128 overflow on large ranges
            let r = U256::from(range);
            let e = U256::from(elapsed);
            let p = U256::from(period);
            let result = r * e * e / (p * p);
            min_price + result.to::<u128>()
        }
    }
}

/// Computes the speed premium bonus.
/// Exact mirror of `AuctionMath.computeSpeedBonus`.
pub fn compute_speed_bonus(
    speed_premium: u128,
    effective_time_remaining: u64,
    fulfillment_timeout: u64,
) -> u128 {
    if speed_premium == 0 || fulfillment_timeout == 0 {
        return 0;
    }
    // Use U256 to avoid u128 overflow for large speed_premium * time
    let product = U256::from(speed_premium) * U256::from(effective_time_remaining as u128);
    (product / U256::from(fulfillment_timeout as u128)).to::<u128>()
}

/// Computes collateral using ceiling division.
/// Exact mirror of `AuctionMath.computeCollateral`.
pub fn compute_collateral(
    settled_price: u128,
    effective_collateral_bps: u64,
    min_collateral_amount: u128,
) -> u128 {
    // Compute entirely in U256 to avoid overflow, then convert final result
    let product = U256::from(settled_price) * U256::from(effective_collateral_bps as u128);
    // Ceiling division in U256: (n == 0) ? 0 : (n - 1) / d + 1
    let raw = if product.is_zero() {
        0u128
    } else {
        ((product - U256::from(1u128)) / U256::from(10000u128) + U256::from(1u128)).to::<u128>()
    };
    // Apply the min-collateral floor FIRST, then the overflow check — mirroring the
    // contract's computeCollateral order (it maxes the floor in, then require()s the
    // result <= uint96::max, reverting "CollateralOverflow"). Doing the floor first
    // means a min_collateral_amount that itself exceeds the u96 ceiling is correctly
    // reported as unaffordable (the contract would revert), instead of slipping
    // through as a finite "affordable" value and triggering a guaranteed-revert claim.
    let floored = raw.max(min_collateral_amount);
    // Return an effectively-unaffordable amount so the evaluator SKIPS the job instead
    // of paying gas for a guaranteed-revert claim. (This value is never summed once
    // skipped — the evaluator gates on availability before reserving collateral.)
    const U96_MAX: u128 = (1u128 << 96) - 1;
    if floored > U96_MAX {
        return u128::MAX;
    }
    floored
}

/// Ceiling division. Returns 0 for n == 0.
pub fn ceil_div(n: u128, d: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    (n - 1) / d + 1
}

// ──────────────────────────────────────────────────────────────────────────────
// Slash / Release Penalty (mirrors SlashLib)
// ──────────────────────────────────────────────────────────────────────────────

/// Computes the slash split using the residual method with keeper floor.
/// Returns (keeper_reward, burn_amount, bonus_portion).
pub fn compute_slash_split(locked_collateral: u128) -> (u128, u128, u128) {
    let total = locked_collateral;

    // Keeper floor: max(MIN_KEEPER_REWARD, collateral * 2%)
    let mut keeper_reward = (U256::from(total) * U256::from(SLASH_KEEPER_BPS as u128)
        / U256::from(10000u128))
    .to::<u128>();
    if keeper_reward < MIN_KEEPER_REWARD {
        keeper_reward = MIN_KEEPER_REWARD;
    }
    // Cap at total
    if keeper_reward > total {
        keeper_reward = total;
    }

    // Remaining split proportionally between burn and bonus
    let remaining = total - keeper_reward;
    let burn_amount =
        remaining * SLASH_BURN_BPS as u128 / (SLASH_BURN_BPS + SLASH_BONUS_BPS) as u128;
    let bonus_portion = remaining - burn_amount;

    (keeper_reward, burn_amount, bonus_portion)
}

/// Computes the time-scaled voluntary release penalty.
/// Note: Uses `current_timestamp` instead of `block.timestamp` since we're off-chain.
pub fn compute_release_penalty(
    locked_collateral: u128,
    fulfillment_timeout: u64,
    lock_deadline: u64,
    current_timestamp: u64,
) -> u128 {
    let total = locked_collateral;

    if fulfillment_timeout == 0 {
        // Avoid division by zero; return floor penalty
        let min_penalty = (U256::from(total) * U256::from(RELEASE_PENALTY_FLOOR_BPS as u128)
            / U256::from(10000u128))
        .to::<u128>();
        return std::cmp::min(min_penalty, total);
    }

    // Time remaining until deadline
    let time_remaining = if lock_deadline > current_timestamp {
        let remaining = lock_deadline - current_timestamp;
        std::cmp::min(remaining as u128, fulfillment_timeout as u128)
    } else {
        0u128
    };

    // Scale penalty by time remaining (use U256 to avoid overflow)
    let scaled_penalty =
        (U256::from(total) * U256::from(RELEASE_PENALTY_BPS as u128) * U256::from(time_remaining)
            / (U256::from(fulfillment_timeout as u128) * U256::from(10000u128)))
        .to::<u128>();

    // 5% floor
    let min_penalty = (U256::from(total) * U256::from(RELEASE_PENALTY_FLOOR_BPS as u128)
        / U256::from(10000u128))
    .to::<u128>();

    let penalty = std::cmp::max(scaled_penalty, min_penalty);
    std::cmp::min(penalty, total)
}

/// Estimate the total prover reward for a job.
pub fn estimate_prover_reward(
    settled_price: u128,
    bonus_amount: u128,
    speed_premium: u128,
    time_remaining: u64,
    fulfillment_timeout: u64,
    fee_rate_bps: u16,
) -> (u128, u128, u128) {
    let speed_bonus = compute_speed_bonus(speed_premium, time_remaining, fulfillment_timeout);

    let gross = settled_price + bonus_amount + speed_bonus;
    // Protocol fee is on settled_price only (matching Solidity contract)
    let protocol_fee = (U256::from(settled_price) * U256::from(fee_rate_bps as u128)
        / U256::from(10000u128))
    .to::<u128>();
    let net_payout = gross.saturating_sub(protocol_fee);

    (net_payout, protocol_fee, speed_bonus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_price_linear() {
        // min=1e18, max=10e18, period=3600s
        let min = 1_000_000_000_000_000_000u128;
        let max = 10_000_000_000_000_000_000u128;
        let period = 3600u64;

        // At 0s: min
        assert_eq!(compute_price(min, max, period, CurveType::Linear, 0), min);
        // At 3600s: max
        assert_eq!(
            compute_price(min, max, period, CurveType::Linear, 3600),
            max
        );
        // At 1800s: midpoint
        let mid = compute_price(min, max, period, CurveType::Linear, 1800);
        assert_eq!(mid, 5_500_000_000_000_000_000u128);
    }

    #[test]
    fn test_compute_price_quadratic() {
        let min = 1_000_000_000_000_000_000u128;
        let max = 10_000_000_000_000_000_000u128;
        let period = 3600u64;

        // At 1800s (half): min + range * 0.25 = 1 + 9*0.25 = 3.25e18
        let price = compute_price(min, max, period, CurveType::Quadratic, 1800);
        assert_eq!(price, 3_250_000_000_000_000_000u128);
    }

    #[test]
    fn test_compute_price_fixed() {
        let price = 5_000_000_000_000_000_000u128;
        assert_eq!(
            compute_price(price, price, 3600, CurveType::Linear, 100),
            price
        );
    }

    #[test]
    fn test_ceil_div() {
        assert_eq!(ceil_div(0, 10), 0);
        assert_eq!(ceil_div(10, 3), 4);
        assert_eq!(ceil_div(9, 3), 3);
        assert_eq!(ceil_div(1, 1), 1);
    }

    #[test]
    fn test_compute_collateral_basic_and_floor() {
        // bps=10000 (100%) → raw == settled_price.
        assert_eq!(compute_collateral(1_000, 10_000, 0), 1_000);
        // Ceiling division: 100 * 15000 / 10000 = 150.
        assert_eq!(compute_collateral(100, 15_000, 0), 150);
        // Floor applies when raw < min_collateral_amount.
        assert_eq!(compute_collateral(100, 10_000, 500), 500);
        // Zero price → zero (no floor) .
        assert_eq!(compute_collateral(0, 15_000, 0), 0);
    }

    #[test]
    fn test_compute_collateral_uint96_overflow_guard() {
        const U96_MAX: u128 = (1u128 << 96) - 1;
        // Exactly u96max (bps=10000) is representable on-chain → returned as-is, NOT MAX.
        assert_eq!(compute_collateral(U96_MAX, 10_000, 0), U96_MAX);
        // Just over the ceiling → contract would revert CollateralOverflow, so we return
        // an unaffordable u128::MAX to make the evaluator skip the guaranteed-revert claim.
        assert_eq!(compute_collateral(U96_MAX, 10_001, 0), u128::MAX);
    }

    #[test]
    fn test_compute_collateral_floor_before_overflow() {
        const U96_MAX: u128 = (1u128 << 96) - 1;
        // A min-collateral floor that itself exceeds the u96 ceiling: the contract maxes
        // the floor in THEN require()s <= u96max, so it reverts. We must mirror that and
        // return u128::MAX (unaffordable), not the finite floor value — this is the
        // floor-before-overflow ordering fix.
        assert_eq!(compute_collateral(1, 1, U96_MAX + 1), u128::MAX);
    }

    #[test]
    fn test_slash_split() {
        let collateral = 10_000_000_000_000_000_000u128; // 10e18
        let (keeper, burn, bonus) = compute_slash_split(collateral);

        // Keeper: max(0.5e18, 10e18 * 200/10000) = max(0.5e18, 0.2e18) = 0.5e18
        assert_eq!(keeper, 500_000_000_000_000_000u128);
        // Remaining: 9.5e18
        // Burn: 9.5e18 * 6500 / (6500 + 3300) = 9.5e18 * 6500/9800
        let remaining = collateral - keeper;
        let expected_burn = remaining * 6500 / 9800;
        assert_eq!(burn, expected_burn);
        assert_eq!(bonus, remaining - expected_burn);
        assert_eq!(keeper + burn + bonus, collateral);
    }
}
