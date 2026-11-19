//! The reference builder of plan §12 (builder type 1): it discovers through the job's `evm-rpc/v1`
//! capability exactly what §12.2 shows, and writes the scheme-1 witness the `proxy-slots` guest
//! consumes (`hemiprove-proxy-slots` documents the statement, its journal and its `W`).
//!
//! `builderParams` = `abi.encode(uint64 chainId, bytes32 B, address C, bytes32 R, uint64 k)`.
//!
//! 1. The header of `B`: `eth_getBlockByHash(B, false)`, RLP-encoded here (the guest checks that it
//!    hashes to `B`).
//! 2. Adaptively, the implementation: `eth_getStorageAt(C, EIP-1967 slot, {blockHash: B})`, then the
//!    slot set of rule `R` for that implementation, with the guest's own code.
//! 3. The proofs: `eth_getProof(C, [EIP-1967 slot, slots…], {blockHash: B})` and
//!    `eth_getProof(I, [], {blockHash: B})`.
//! 4. `W`: the header words, the header, C's account proof with its storage proofs, I's account
//!    proof; each proof's kind (inclusion or exclusion) as the proof itself shows it.
//!
//! Every answer is a hint: a lying node yields a `W` the guest refuses (or that answers a different
//! header, which the binding refuses). The builder runs the statement over its own `W` before
//! writing it, so a bad answer fails here, with a reason in the log, instead of in the guest.

use hemiprove_builder_sdk::eth::{self, AccountProof};
use hemiprove_builder_sdk::{self as sdk, json, rpc, Error, EvmRpcConfig};
use hemiprove_eth_prelude::keccak::{keccak256, EMPTY_ROOT};
use hemiprove_eth_prelude::scheme1::{AccountProof as WAccount, ProofKind, TrieProof, Witness};
use hemiprove_eth_prelude::{mpt, state};
use hemiprove_proxy_slots::{Statement, EIP1967_IMPLEMENTATION_SLOT};
use std::borrow::Cow;

sdk::entry!(build);

/// The kind a proof has, as the proof itself shows it, and its nodes as `W` carries them. A node
/// that serves the empty trie's proof as `["0x80"]` is normalised to the one accepted form, `[]`.
/// `path` is the trie key: `keccak256(address)` or `keccak256(slot)`.
fn trie_proof(root: &[u8; 32], path: &[u8; 32], nodes: Vec<Vec<u8>>) -> Result<TrieProof<'static>, Error> {
    let nodes = if *root == EMPTY_ROOT && nodes == [vec![0x80]] { Vec::new() } else { nodes };
    let found = mpt::verify(root, path, &nodes).map_err(|e| {
        sdk::log(&format!("proxy-slots: a proof does not verify: {e}\n"));
        Error::Other("the node returned a proof that does not verify")
    })?;
    let kind = if found.is_some() { ProofKind::Inclusion } else { ProofKind::Exclusion };
    Ok(TrieProof { kind, nodes: nodes.into_iter().map(Cow::Owned).collect() })
}

/// `eth_getProof(address, slots, block)`, checked to answer the question asked.
fn get_proof(address: &[u8; 20], slots: &[[u8; 32]], at: &str) -> Result<AccountProof, Error> {
    let keys: Vec<String> = slots.iter().map(|s| format!("\"{}\"", json::to_hex(s))).collect();
    let params = format!("[\"{}\",[{}],{at}]", json::to_hex(address), keys.join(","));
    let p = eth::account_proof(&rpc::call(0, "eth_getProof", &params)?)?;
    if p.address != *address || p.storage_proof.len() != slots.len() || p.storage_proof.iter().zip(slots).any(|(s, k)| s.key != *k) {
        return Err(Error::Other("eth_getProof answered another question"));
    }
    Ok(p)
}

/// An account's proof and its storage proofs, as `W` carries them.
fn account(state_root: &[u8; 32], p: AccountProof) -> Result<WAccount<'static>, Error> {
    let account = state::verify_account(state_root, &p.address, &p.account_proof).map_err(|e| {
        sdk::log(&format!("proxy-slots: account proof of {}: {e}\n", json::to_hex(&p.address)));
        Error::Other("the node returned an account proof that does not verify")
    })?;
    let storage_root = state::storage_root(&account);
    let proof = trie_proof(state_root, &keccak256(&p.address), p.account_proof)?;
    let storage = p
        .storage_proof
        .into_iter()
        .map(|s| trie_proof(&storage_root, &keccak256(&s.key), s.proof))
        .collect::<Result<_, _>>()?;
    Ok(WAccount { proof, storage })
}

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    let source = ctx.sources.first().ok_or(Error::Other("the job declares no capability 0"))?;
    if source.class != sdk::CLASS_EVM_RPC_V1 {
        return Err(Error::Other("capability 0 is not evm-rpc/v1"));
    }
    let config = EvmRpcConfig::decode(&source.config)?;
    let (chain_id, statement) = Statement::from_builder_params(&ctx.builder_params)
        .map_err(|_| Error::Other("builderParams: abi.encode(uint64, bytes32, address, bytes32, uint64)"))?;
    if config.chain_id != chain_id {
        return Err(Error::Other("capability 0 serves another chain than builderParams names"));
    }
    let at = rpc::at_block_hash(&statement.block_hash);

    // 1. The header of B.
    let block = rpc::call(0, "eth_getBlockByHash", &format!("[\"{}\",false]", json::to_hex(&statement.block_hash)))?;
    let header = eth::header(&block)?.encode().map_err(|_| Error::Other("the block's header fields are no known fork's"))?;
    if keccak256(&header) != statement.block_hash {
        return Err(Error::Other("the node's header for B does not hash to B"));
    }
    let state_root = eth::header(&block)?.state_root;

    // 2. The implementation (a hint the guest re-derives), then the rule's slots for it.
    let word = rpc::call(0, "eth_getStorageAt", &format!(
        "[\"{}\",\"{}\",{at}]",
        json::to_hex(&statement.proxy),
        json::to_hex(&EIP1967_IMPLEMENTATION_SLOT)
    ))?;
    let word = json::bytes32(json::as_str(&word)?)?;
    let implementation: [u8; 20] = word[12..].try_into().expect("20 bytes");
    let mut slots = vec![EIP1967_IMPLEMENTATION_SLOT];
    slots.extend(statement.rule.slots(&implementation, statement.k));

    // 3. Proofs for everything the guest will read.
    let proxy = get_proof(&statement.proxy, &slots, &at)?;
    let imp = get_proof(&implementation, &[], &at)?;

    // 4. W, in the order the guest reads it.
    let w = Witness {
        header_words: statement.header_words().to_vec(),
        headers: vec![Cow::Owned(header)],
        accounts: vec![account(&state_root, proxy)?, account(&state_root, imp)?],
        receipts: vec![],
        transactions: vec![],
    }
    .encode()
    .map_err(|_| Error::Other("W does not encode"))?;

    // The guest's statement over this W, with a placeholder prefix (the miner adds the real one).
    let mut input = vec![0u8; 64];
    input.extend_from_slice(&w);
    match hemiprove_proxy_slots::run(&input) {
        Ok(journal) => {
            let j = hemiprove_proxy_slots::decode_journal(&journal).expect("the statement's own journal");
            sdk::log(&format!(
                "proxy-slots: chain {chain_id} block {} proxy {} implementation {} ({} slots), W {} bytes\n",
                json::to_hex(&statement.block_hash),
                json::to_hex(&statement.proxy),
                json::to_hex(&j.outputs.implementation),
                j.outputs.slots.len(),
                w.len()
            ));
        }
        Err(e) => {
            sdk::log(&format!("proxy-slots: the guest would refuse this witness: {e}\n"));
            return Err(Error::Other("the witness fails the statement"));
        }
    }
    sdk::write_witness(&w)?;
    Ok(())
}
