//! A realistic test builder, for the runner's compile-cost calibration and tests: one block's
//! receipts, with Merkle-Patricia proofs.
//!
//! It fetches `eth_getBlockByNumber(n, true)` and `eth_getBlockReceipts(n)` through capability 0
//! (`evm-rpc/v1`), deserializes both into typed structs (serde_json), checks them against each
//! other, RLP-encodes the header, every receipt, transaction and withdrawal (alloy-rlp), hashes them
//! (tiny-keccak), recomputes the receipts, transactions and withdrawals roots with a hand-rolled MPT
//! and every logs bloom, proves the selected receipts and verifies every proof, and decodes the
//! block's token and DEX events (alloy-sol-types) into a per-contract JSON report (serde).
//!
//! `builderParams` = `flags (u8) ‖ block number (u64 BE) ‖ receipt indices (u16 BE each)`; empty
//! means "latest" and receipt 0. Flag bit 0 (strict): fail unless every recomputed hash, root and
//! bloom matches the block's.
//!
//! ```text
//! W = rlp(header) ‖ blockHash ‖ receiptsRoot ‖ checks (u8: bits 0–4 = header hash, receipts root,
//!     transactions (hashes and root), withdrawals root, logs blooms)
//!     ‖ count (u32) ‖ per index: index (u32) ‖ receipt ‖ node count (u32) ‖ nodes
//!     ‖ the token and DEX events of the block, per contract, as JSON
//! ```
//! with every byte string as `len (u32 BE) ‖ bytes`.

mod events;
mod hex;
mod mpt;
mod rlp;
mod summary;
mod txs;
mod types;

use hemiprove_builder_sdk::{self as sdk, Error};

use crate::types::{Block, Receipt, Response};

sdk::entry!(build);

struct Params {
    strict: bool,
    block: Option<u64>,
    indices: Vec<u16>,
}

fn params(raw: &[u8]) -> Result<Params, Error> {
    if raw.is_empty() {
        return Ok(Params { strict: false, block: None, indices: vec![0] });
    }
    if raw.len() < 9 || !(raw.len() - 9).is_multiple_of(2) {
        return Err(Error::Other("builderParams: flags, block, indices"));
    }
    let block = u64::from_be_bytes(raw[1..9].try_into().unwrap());
    let indices = raw[9..].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    Ok(Params { strict: raw[0] & 1 == 1, block: Some(block), indices })
}

fn rpc<T: serde::de::DeserializeOwned>(method: &str, params: &str) -> Result<T, Error> {
    let request = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let response = sdk::fetch(0, request.as_bytes())?;
    let parsed: Response<T> = serde_json::from_slice(&response).map_err(|e| {
        sdk::log(&format!("receipts-proof: {method}: {e}\n"));
        Error::Other("malformed JSON-RPC response")
    })?;
    if parsed.jsonrpc != "2.0" {
        return Err(Error::Other("not a JSON-RPC 2.0 response"));
    }
    if let Some(e) = parsed.error {
        sdk::log(&format!("receipts-proof: {method}: error {} {}\n", e.code, e.message));
        return Err(Error::Other("JSON-RPC error"));
    }
    parsed.result.ok_or(Error::Other("JSON-RPC response without a result"))
}

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    let source = ctx.sources.first().ok_or(Error::Other("no capability 0"))?;
    if source.class != sdk::CLASS_EVM_RPC_V1 {
        return Err(Error::Other("capability 0 is not evm-rpc/v1"));
    }
    let p = params(&ctx.builder_params)?;
    let tag = match p.block {
        Some(n) => format!("\"0x{n:x}\""),
        None => "\"latest\"".into(),
    };

    let block: Block = rpc("eth_getBlockByNumber", &format!("[{tag},true]"))?;
    let receipts: Vec<Receipt> = rpc("eth_getBlockReceipts", &format!("[{tag}]"))?;
    if receipts.len() != block.transactions.len() {
        return Err(Error::Other("receipt count differs from the transaction count"));
    }
    for (i, (r, t)) in receipts.iter().zip(&block.transactions).enumerate() {
        if r.transaction_hash != t.hash || r.transaction_index.as_u64() != Some(i as u64) {
            return Err(Error::Other("receipts out of order"));
        }
    }

    let summary = summary::check(&block, &receipts).map_err(Error::Other)?;
    sdk::log(&format!("receipts-proof: {summary}\n"));

    let header = rlp::header(&block).map_err(|_| Error::Other("header fields out of fork order"))?;
    let hash = mpt::keccak(&header);
    let encoded = receipts
        .iter()
        .map(rlp::receipt)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Other("unencodable receipt"))?;
    let (trie, root) = mpt::ordered_root(&encoded);
    let hash_ok = hash == block.hash.0;
    let root_ok = root == block.receipts_root.0;

    // The transactions root, every transaction's hash, the withdrawals root and the blooms.
    let txs = block.transactions.iter().map(txs::encode).collect::<Result<Vec<_>, _>>().map_err(|e| {
        sdk::log(&format!("receipts-proof: transaction: {e:?}\n"));
        Error::Other("unencodable transaction")
    })?;
    let tx_hashes_ok = txs.iter().zip(&block.transactions).all(|(enc, tx)| mpt::keccak(enc) == tx.hash.0);
    let tx_root_ok = mpt::ordered_root(&txs).1 == block.transactions_root.0;
    let withdrawals_ok = match (&block.withdrawals, &block.withdrawals_root) {
        (Some(ws), Some(r)) => mpt::ordered_root(&ws.iter().map(txs::withdrawal).collect::<Vec<_>>()).1 == r.0,
        (None, None) => true,
        _ => false,
    };
    let mut block_bloom = txs::Bloom::new();
    let mut blooms_ok = true;
    for r in &receipts {
        let mut bloom = txs::Bloom::new();
        for l in &r.logs {
            bloom.add_log(l);
        }
        blooms_ok &= bloom.0[..] == r.logs_bloom.0[..];
        block_bloom.or(&r.logs_bloom.0);
    }
    blooms_ok &= block_bloom.0[..] == block.logs_bloom.0[..];
    let checks = [hash_ok, root_ok, tx_hashes_ok && tx_root_ok, withdrawals_ok, blooms_ok];
    let verdict = |ok: bool| if ok { "ok" } else { "MISMATCH" };
    sdk::log(&format!(
        "receipts-proof: block {} ({} txs, {} withdrawals): hash {} receipts {} transactions {} withdrawals {} blooms {}\n",
        block.number.as_u64().unwrap_or(u64::MAX),
        block.transactions.len(),
        block.withdrawals.as_ref().map_or(0, Vec::len),
        verdict(checks[0]),
        verdict(checks[1]),
        verdict(checks[2]),
        verdict(checks[3]),
        verdict(checks[4]),
    ));
    if p.strict && !checks.iter().all(|&c| c) {
        return Err(Error::Other("block does not match its header"));
    }

    let mut w = Vec::new();
    rlp::put(&mut w, &header);
    w.extend_from_slice(&hash);
    w.extend_from_slice(&root);
    w.push(checks.iter().enumerate().fold(0u8, |acc, (i, &ok)| acc | (u8::from(ok) << i)));
    w.extend_from_slice(&(p.indices.len() as u32).to_be_bytes());
    for &i in &p.indices {
        let value = encoded.get(usize::from(i)).ok_or(Error::Other("receipt index out of range"))?;
        let key = rlp::index_key(u64::from(i));
        let mut proof = Vec::new();
        trie.prove(&mpt::nibbles(&key), &mut proof, true);
        match mpt::verify(root, &key, &proof) {
            Ok(Some(v)) if &v == value => {}
            other => {
                sdk::log(&format!("receipts-proof: proof of receipt {i}: {other:?}\n"));
                return Err(Error::Other("a receipt proof does not verify"));
            }
        }
        w.extend_from_slice(&u32::from(i).to_be_bytes());
        rlp::put(&mut w, value);
        w.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        for node in &proof {
            rlp::put(&mut w, node);
        }
    }
    // Absent keys prove absent too.
    let missing = rlp::index_key(encoded.len() as u64);
    let mut proof = Vec::new();
    trie.prove(&mpt::nibbles(&missing), &mut proof, true);
    if !matches!(mpt::verify(root, &missing, &proof), Ok(None)) {
        return Err(Error::Other("an exclusion proof does not verify"));
    }
    // The token flows of the block, as JSON after the proofs.
    let mut report = events::Report::default();
    for l in receipts.iter().flat_map(|r| &r.logs) {
        report.add(l);
    }
    let json = serde_json::to_vec(&report).map_err(|_| Error::Other("unserializable report"))?;
    sdk::log(&format!(
        "receipts-proof: {} logs, {} contracts with token or DEX events, {} unrecognized\n",
        report.logs,
        report.contracts.len(),
        report.unrecognized
    ));
    rlp::put(&mut w, &json);
    sdk::write_witness(&w)?;
    Ok(())
}
