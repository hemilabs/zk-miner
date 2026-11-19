//! Token and DEX events in the block's logs, decoded with alloy-sol-types and aggregated per
//! contract: what a "token flows in this block" builder puts next to its receipt proofs.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Log as PrimLog, LogData, B256, I256, U256};
use alloy_sol_types::{sol, SolEvent};
use serde::Serialize;

use crate::types::Log;

sol! {
    // ERC-20 / ERC-721 (the 721 Transfer has its token id indexed, so it is a different event shape).
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    // WETH.
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    // ERC-1155.
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);
    // Uniswap V2 pairs.
    event Sync(uint112 reserve0, uint112 reserve1);
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);
    event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, address indexed to);
    // Uniswap V3 pools (namespaced: the names clash with V2's).
    interface IUniswapV3Pool {
        event Swap(address indexed sender, address indexed recipient, int256 amount0, int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick);
        event Mint(address sender, address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount, uint256 amount0, uint256 amount1);
        event Burn(address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount, uint256 amount0, uint256 amount1);
        event Collect(address indexed owner, address recipient, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount0, uint128 amount1);
        event Flash(address indexed sender, address indexed recipient, uint256 amount0, uint256 amount1, uint256 paid0, uint256 paid1);
    }
    // ERC-4626 vaults.
    interface IERC4626 {
        event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
        event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    }
}

/// What one contract's events add up to.
#[derive(Serialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Flows {
    pub transfers: u32,
    pub transferred: U256,
    pub approvals: u32,
    pub wrapped: U256,
    pub unwrapped: U256,
    pub multi_token_transfers: u32,
    pub v2_swaps: u32,
    pub v2_reserves: Option<(U256, U256)>,
    pub v2_liquidity_events: u32,
    pub v3_swaps: u32,
    pub v3_net0: I256,
    pub v3_net1: I256,
    pub v3_last_tick: Option<i32>,
    pub v3_last_sqrt_price: Option<U256>,
    pub v3_liquidity_events: u32,
    pub vault_assets_in: U256,
    pub vault_assets_out: U256,
    pub undecoded: u32,
}

/// Every contract with at least one recognized event, in address order.
#[derive(Serialize, Default, Debug)]
pub struct Report {
    pub contracts: BTreeMap<Address, Flows>,
    pub logs: u32,
    pub unrecognized: u32,
}

fn prim(l: &Log) -> Option<PrimLog> {
    let topics: Vec<B256> = l.topics.iter().map(|t| B256::from(t.0)).collect();
    let data = LogData::new(topics, l.data.0.clone().into())?;
    Some(PrimLog { address: Address::from(l.address.0), data })
}

impl Report {
    pub fn add(&mut self, l: &Log) {
        self.logs += 1;
        let Some(log) = prim(l) else {
            self.unrecognized += 1;
            return;
        };
        let Some(&topic0) = log.topics().first() else {
            self.unrecognized += 1;
            return;
        };
        let f = self.contracts.entry(log.address).or_default();
        let ok = match topic0 {
            t if t == Transfer::SIGNATURE_HASH => match Transfer::decode_log_data(&log.data) {
                Ok(e) => {
                    f.transfers += 1;
                    f.transferred = f.transferred.saturating_add(e.value);
                    true
                }
                // ERC-721 Transfer: the same signature with the id indexed and no data.
                Err(_) => {
                    f.transfers += 1;
                    log.topics().len() == 4
                }
            },
            t if t == Approval::SIGNATURE_HASH => {
                f.approvals += 1;
                true
            }
            t if t == Deposit::SIGNATURE_HASH => {
                Deposit::decode_log_data(&log.data).map(|e| f.wrapped = f.wrapped.saturating_add(e.wad)).is_ok()
            }
            t if t == Withdrawal::SIGNATURE_HASH => {
                Withdrawal::decode_log_data(&log.data).map(|e| f.unwrapped = f.unwrapped.saturating_add(e.wad)).is_ok()
            }
            t if t == TransferSingle::SIGNATURE_HASH => {
                TransferSingle::decode_log_data(&log.data).map(|_| f.multi_token_transfers += 1).is_ok()
            }
            t if t == TransferBatch::SIGNATURE_HASH => TransferBatch::decode_log_data(&log.data)
                .map(|e| f.multi_token_transfers += e.ids.len().min(e.values.len()) as u32)
                .is_ok(),
            t if t == Sync::SIGNATURE_HASH => Sync::decode_log_data(&log.data)
                .map(|e| f.v2_reserves = Some((U256::from(e.reserve0), U256::from(e.reserve1))))
                .is_ok(),
            t if t == Mint::SIGNATURE_HASH || t == Burn::SIGNATURE_HASH => {
                f.v2_liquidity_events += 1;
                Mint::decode_log_data(&log.data).is_ok() || Burn::decode_log_data(&log.data).is_ok()
            }
            t if t == Swap::SIGNATURE_HASH => Swap::decode_log_data(&log.data).map(|_| f.v2_swaps += 1).is_ok(),
            t if t == IUniswapV3Pool::Swap::SIGNATURE_HASH => IUniswapV3Pool::Swap::decode_log_data(&log.data)
                .map(|e| {
                    f.v3_swaps += 1;
                    f.v3_net0 = f.v3_net0.saturating_add(e.amount0);
                    f.v3_net1 = f.v3_net1.saturating_add(e.amount1);
                    f.v3_last_tick = Some(e.tick.as_i32());
                    f.v3_last_sqrt_price = Some(U256::from(e.sqrtPriceX96));
                })
                .is_ok(),
            t if t == IUniswapV3Pool::Mint::SIGNATURE_HASH
                || t == IUniswapV3Pool::Burn::SIGNATURE_HASH
                || t == IUniswapV3Pool::Collect::SIGNATURE_HASH
                || t == IUniswapV3Pool::Flash::SIGNATURE_HASH =>
            {
                f.v3_liquidity_events += 1;
                IUniswapV3Pool::Mint::decode_log_data(&log.data).is_ok()
                    || IUniswapV3Pool::Burn::decode_log_data(&log.data).is_ok()
                    || IUniswapV3Pool::Collect::decode_log_data(&log.data).is_ok()
                    || IUniswapV3Pool::Flash::decode_log_data(&log.data).is_ok()
            }
            t if t == IERC4626::Deposit::SIGNATURE_HASH => IERC4626::Deposit::decode_log_data(&log.data)
                .map(|e| f.vault_assets_in = f.vault_assets_in.saturating_add(e.assets))
                .is_ok(),
            t if t == IERC4626::Withdraw::SIGNATURE_HASH => IERC4626::Withdraw::decode_log_data(&log.data)
                .map(|e| f.vault_assets_out = f.vault_assets_out.saturating_add(e.assets))
                .is_ok(),
            _ => {
                self.unrecognized += 1;
                return;
            }
        };
        if !ok {
            f.undecoded += 1;
        }
    }
}
