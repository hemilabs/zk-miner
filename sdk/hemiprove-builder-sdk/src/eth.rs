//! Ethereum JSON-RPC results as the reference prelude's types (feature `eth`): block headers from
//! `eth_getBlockBy*`, proofs from `eth_getProof`, receipts from `eth_getTransactionReceipt` and
//! `eth_getBlockReceipts`. With [`hemiprove_eth_prelude`]'s encoders these are the RLP header and
//! receipt encoders a builder needs (zkminer docs/witness-construction-jobs.md §21.1 item 2):
//! `header(json)?.encode()` hashes to the block hash, `receipt(json)?.encode()` is the
//! receipts-trie leaf.
//!
//! Parsing is strict about shape (every field present and well-formed) but trusts nothing: a node
//! can still answer with any values, and only the guest's checks make them count.

pub use hemiprove_eth_prelude as prelude;
use prelude::header::Header;
use prelude::receipt::{Log, Outcome, Receipt};

use crate::json::{self, JsonError};
use crate::Error;

fn str_of<'a>(obj: &'a [u8], key: &str) -> Result<&'a str, Error> {
    Ok(json::str_member(obj, key)?)
}

fn fixed<const N: usize>(obj: &[u8], key: &str) -> Result<[u8; N], Error> {
    json::hex_bytes(str_of(obj, key)?)?.try_into().map_err(|_| Error::Json(JsonError::NotHex))
}

fn u64_of(obj: &[u8], key: &str) -> Result<u64, Error> {
    Ok(json::quantity_u64(str_of(obj, key)?)?)
}

fn u256_of(obj: &[u8], key: &str) -> Result<[u8; 32], Error> {
    Ok(json::quantity_u256(str_of(obj, key)?)?)
}

/// `Some` when `key` is present and not `null`.
fn optional<T>(obj: &[u8], key: &str, f: impl Fn(&[u8], &str) -> Result<T, Error>) -> Result<Option<T>, Error> {
    match json::get(obj, key)? {
        Some(v) if v != b"null" => f(obj, key).map(Some),
        _ => Ok(None),
    }
}

/// A block header from an `eth_getBlockByHash` / `eth_getBlockByNumber` result. The fork's
/// optional fields are taken as the node reports them; [`Header::encode`] refuses a set that is
/// not one fork's layout.
pub fn header(block: &[u8]) -> Result<Header, Error> {
    Ok(Header {
        parent_hash: fixed(block, "parentHash")?,
        ommers_hash: fixed(block, "sha3Uncles")?,
        beneficiary: fixed(block, "miner")?,
        state_root: fixed(block, "stateRoot")?,
        transactions_root: fixed(block, "transactionsRoot")?,
        receipts_root: fixed(block, "receiptsRoot")?,
        logs_bloom: fixed(block, "logsBloom")?,
        difficulty: u256_of(block, "difficulty")?,
        number: u64_of(block, "number")?,
        gas_limit: u64_of(block, "gasLimit")?,
        gas_used: u64_of(block, "gasUsed")?,
        timestamp: u64_of(block, "timestamp")?,
        extra_data: json::hex_bytes(str_of(block, "extraData")?)?,
        mix_hash: fixed(block, "mixHash")?,
        nonce: fixed(block, "nonce")?,
        base_fee_per_gas: optional(block, "baseFeePerGas", u256_of)?,
        withdrawals_root: optional(block, "withdrawalsRoot", fixed)?,
        blob_gas_used: optional(block, "blobGasUsed", u64_of)?,
        excess_blob_gas: optional(block, "excessBlobGas", u64_of)?,
        parent_beacon_block_root: optional(block, "parentBeaconBlockRoot", fixed)?,
        requests_hash: optional(block, "requestsHash", fixed)?,
    })
}

/// One `storageProof` entry of `eth_getProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProof {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub proof: Vec<Vec<u8>>,
}

/// An `eth_getProof` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProof {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Vec<StorageProof>,
}

fn nodes(arr: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    json::elements(arr)?.into_iter().map(|n| Ok(json::hex_bytes(json::as_str(n)?)?)).collect()
}

/// An `eth_getProof` result.
pub fn account_proof(result: &[u8]) -> Result<AccountProof, Error> {
    let storage_proof = json::elements(json::required(result, "storageProof")?)?
        .into_iter()
        .map(|s| {
            Ok(StorageProof {
                key: u256_of(s, "key")?,
                value: u256_of(s, "value")?,
                proof: nodes(json::required(s, "proof")?)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(AccountProof {
        address: fixed(result, "address")?,
        nonce: u64_of(result, "nonce")?,
        balance: u256_of(result, "balance")?,
        storage_hash: fixed(result, "storageHash")?,
        code_hash: fixed(result, "codeHash")?,
        account_proof: nodes(json::required(result, "accountProof")?)?,
        storage_proof,
    })
}

/// A receipt from `eth_getTransactionReceipt` or an element of `eth_getBlockReceipts`: the fields
/// its consensus encoding has (`type`, `status` or `root`, `cumulativeGasUsed`, `logsBloom`, `logs`,
/// and a deposit's `depositNonce` and `depositReceiptVersion`).
pub fn receipt(r: &[u8]) -> Result<Receipt, Error> {
    let tx_type = u8::try_from(u64_of(r, "type")?).map_err(|_| Error::Json(JsonError::NotHex))?;
    let outcome = match optional(r, "status", u64_of)? {
        Some(s) => Outcome::Status(s == 1),
        None => Outcome::PostState(fixed(r, "root")?),
    };
    let logs = json::elements(json::required(r, "logs")?)?
        .into_iter()
        .map(|l| {
            Ok(Log {
                address: fixed(l, "address")?,
                topics: json::elements(json::required(l, "topics")?)?
                    .into_iter()
                    .map(|t| json::bytes32(json::as_str(t)?).map_err(Error::from))
                    .collect::<Result<_, Error>>()?,
                data: json::hex_bytes(str_of(l, "data")?)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Receipt {
        tx_type,
        outcome,
        cumulative_gas_used: u64_of(r, "cumulativeGasUsed")?,
        logs_bloom: fixed(r, "logsBloom")?,
        logs,
        deposit_nonce: optional(r, "depositNonce", u64_of)?,
        deposit_receipt_version: optional(r, "depositReceiptVersion", u64_of)?,
    })
}

/// Every receipt of an `eth_getBlockReceipts` result, in transaction order.
pub fn receipts(result: &[u8]) -> Result<Vec<Receipt>, Error> {
    json::elements(result)?.into_iter().map(receipt).collect()
}

#[cfg(test)]
mod tests {
    //! The real-chain fixtures of hemiprove-eth-prelude, read through this crate's JSON scanner and
    //! checked against each block's own hashes: an independent parse of the same answers.
    use super::*;
    use prelude::keccak::keccak256;
    use prelude::state;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../reference/eth-prelude/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn real_headers_proofs_and_receipts() {
        for name in ["ethereum", "base", "hemi"] {
            let f = fixture(name);
            let block = json::required(&f, "block").unwrap();
            let h = header(block).unwrap();
            let hash = json::bytes32(json::str_member(block, "hash").unwrap()).unwrap();
            assert_eq!(keccak256(&h.encode().unwrap()), hash, "{name}");

            for entry in json::elements(json::required(&f, "proofs").unwrap()).unwrap() {
                let p = account_proof(json::required(entry, "proof").unwrap()).unwrap();
                let account = state::verify_account(&h.state_root, &p.address, &p.account_proof).unwrap();
                if let Some(a) = account {
                    assert_eq!((a.nonce, a.balance, a.storage_root, a.code_hash), (p.nonce, p.balance, p.storage_hash, p.code_hash));
                }
                for s in &p.storage_proof {
                    assert_eq!(state::verify_storage(&state::storage_root(&account), &s.key, &s.proof).unwrap(), s.value);
                }
            }

            // Every receipt encodes, decodes back and carries its logs' bloom. (The receipts root
            // these encodings rebuild is checked in hemiprove-eth-prelude's real-chain tests.)
            let rs = receipts(json::required(&f, "receipts").unwrap()).unwrap();
            assert!(!rs.is_empty());
            for r in &rs {
                let enc = r.encode().unwrap();
                assert_eq!(&prelude::receipt::Receipt::decode(&enc).unwrap(), r);
                assert!(r.bloom_matches(), "{name}");
            }
        }
    }
}
