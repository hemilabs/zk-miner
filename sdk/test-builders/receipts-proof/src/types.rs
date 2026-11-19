//! The JSON-RPC shapes the builder reads: a block with full transactions, and its receipts.

use serde::Deserialize;

use crate::hex::{Address, Bloom, Bytes, Nonce8, Quantity, H256};

/// A JSON-RPC response envelope.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Response<T> {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(default = "Option::default")]
    pub result: Option<T>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct Block {
    pub hash: H256,
    pub parent_hash: H256,
    pub sha3_uncles: H256,
    pub miner: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: Quantity,
    pub number: Quantity,
    pub gas_limit: Quantity,
    pub gas_used: Quantity,
    pub timestamp: Quantity,
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: Nonce8,
    #[serde(default)]
    pub base_fee_per_gas: Option<Quantity>,
    #[serde(default)]
    pub withdrawals_root: Option<H256>,
    #[serde(default)]
    pub blob_gas_used: Option<Quantity>,
    #[serde(default)]
    pub excess_blob_gas: Option<Quantity>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<H256>,
    #[serde(default)]
    pub requests_hash: Option<H256>,
    #[serde(default)]
    pub size: Option<Quantity>,
    #[serde(default)]
    pub total_difficulty: Option<Quantity>,
    #[serde(default)]
    pub uncles: Vec<H256>,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub withdrawals: Option<Vec<Withdrawal>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: H256,
    pub nonce: Quantity,
    pub block_hash: Option<H256>,
    pub block_number: Option<Quantity>,
    pub transaction_index: Option<Quantity>,
    pub from: Address,
    pub to: Option<Address>,
    pub value: Quantity,
    #[serde(default)]
    pub gas_price: Option<Quantity>,
    pub gas: Quantity,
    #[serde(default)]
    pub max_fee_per_gas: Option<Quantity>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<Quantity>,
    #[serde(default)]
    pub max_fee_per_blob_gas: Option<Quantity>,
    pub input: Bytes,
    #[serde(default)]
    pub v: Option<Quantity>,
    pub r: Quantity,
    pub s: Quantity,
    #[serde(default)]
    pub y_parity: Option<Quantity>,
    #[serde(default)]
    pub chain_id: Option<Quantity>,
    #[serde(default)]
    pub access_list: Option<Vec<AccessListItem>>,
    #[serde(default)]
    pub blob_versioned_hashes: Option<Vec<H256>>,
    #[serde(default)]
    pub authorization_list: Option<Vec<Authorization>>,
    #[serde(rename = "type")]
    pub tx_type: Quantity,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub chain_id: Quantity,
    pub address: Address,
    pub nonce: Quantity,
    pub y_parity: Quantity,
    pub r: Quantity,
    pub s: Quantity,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub index: Quantity,
    pub validator_index: Quantity,
    pub address: Address,
    pub amount: Quantity,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub transaction_hash: H256,
    pub transaction_index: Quantity,
    pub block_hash: H256,
    pub block_number: Quantity,
    pub from: Address,
    pub to: Option<Address>,
    pub cumulative_gas_used: Quantity,
    pub gas_used: Quantity,
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
    pub logs_bloom: Bloom,
    #[serde(rename = "type")]
    pub tx_type: Quantity,
    #[serde(default)]
    pub status: Option<Quantity>,
    #[serde(default)]
    pub root: Option<H256>,
    pub effective_gas_price: Quantity,
    #[serde(default)]
    pub blob_gas_used: Option<Quantity>,
    #[serde(default)]
    pub blob_gas_price: Option<Quantity>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
    #[serde(default)]
    pub block_number: Option<Quantity>,
    #[serde(default)]
    pub transaction_hash: Option<H256>,
    #[serde(default)]
    pub transaction_index: Option<Quantity>,
    #[serde(default)]
    pub block_hash: Option<H256>,
    #[serde(default)]
    pub log_index: Option<Quantity>,
    #[serde(default)]
    pub removed: bool,
}
