//! A realistic test builder, for the runner's compile-cost calibration and tests: an account and
//! some of its storage slots, with EIP-1186 proofs checked against the block's state root.
//!
//! It fetches `eth_getBlockByNumber(n, false)` and `eth_getProof(address, slots, n)` through
//! capability 0 (`evm-rpc/v1`), deserializes both with serde_json into alloy-primitives types,
//! RLP-encodes the header with alloy-rlp's derive, verifies the account proof against the header's
//! state root and every storage proof against the account's storage root with alloy-trie, optionally
//! reads the account's ERC-20 metadata with `eth_call`s (alloy-sol-types), and commits to the result
//! with an ABI-encoded struct and sha256.
//!
//! `builderParams` = `address (20) ‖ block number (u64 BE) ‖ flags (u8) ‖ [oracle (20)] ‖ slots (32
//! bytes each)`.
//! Flag bit 0 (strict): fail unless the header hashes to the block's `hash`. Bit 1: the account is
//! an ERC-20; read its name, symbol, decimals, total supply and its own balance. Bit 2: the account
//! is a Uniswap V3 pool and `oracle` (20 bytes after the flags) a Chainlink-style aggregator; read the
//! pool's spot and 30-minute TWAP ticks and the oracle's latest answer.
//!
//! ```text
//! W = rlp(header) ‖ address ‖ rlp(account) ‖ count (u32) ‖ per slot: key ‖ value (32, BE)
//!     ‖ node count (u32) ‖ nodes ‖ account node count (u32) ‖ account nodes
//!     ‖ abi.encode(Commitment) ‖ [abi.encode(Prices)] ‖ sha256(everything before)
//! ```
//! with every byte string as `len (u32 BE) ‖ bytes`.

use alloy_primitives::{hex, keccak256, Address, Bloom, Bytes, B256, B64, U256, U64};
use alloy_rlp::RlpEncodable;
use alloy_sol_types::{sol, SolCall, SolValue};
use alloy_trie::proof::verify_proof;
use alloy_trie::{Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use hemiprove_builder_sdk::{self as sdk, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

sdk::entry!(build);

sol! {
    interface IERC20 {
        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
    }

    /// What the builder commits to besides the proofs, ABI-encoded into W.
    struct Commitment {
        address account;
        uint64 blockNumber;
        bytes32 stateRoot;
        bytes32 storageRoot;
        uint256[] slots;
        uint256[] values;
        Token token;
    }

    struct Token {
        string name;
        string symbol;
        uint8 decimals;
        uint256 totalSupply;
        uint256 heldByItself;
    }

    interface IUniswapV3Pool {
        function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked);
        function liquidity() external view returns (uint128);
        function token0() external view returns (address);
        function token1() external view returns (address);
        function fee() external view returns (uint24);
        function observe(uint32[] secondsAgos) external view returns (int56[] tickCumulatives, uint160[] secondsPerLiquidityCumulativeX128s);
    }

    interface IAggregatorV3 {
        function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        function decimals() external view returns (uint8);
        function description() external view returns (string);
    }

    /// A pool's spot and time-weighted prices next to an oracle's answer (flag bit 2).
    struct Prices {
        address token0;
        address token1;
        uint24 fee;
        uint160 sqrtPriceX96;
        int24 spotTick;
        int24 twapTick;
        uint128 liquidity;
        int256 oracleAnswer;
        uint8 oracleDecimals;
        string oracleDescription;
        uint256 oracleUpdatedAt;
    }
}

/// The TWAP window, in seconds.
const TWAP_SECONDS: u32 = 1_800;

/// Flag bit 2: the account is a Uniswap V3 pool, and `oracle` a Chainlink-style aggregator.
fn prices(pool: Address, oracle: Address, tag: &str) -> Result<Prices, Error> {
    let slot0 = call(pool, &IUniswapV3Pool::slot0Call {}, tag)?;
    let observed = call(pool, &IUniswapV3Pool::observeCall { secondsAgos: vec![TWAP_SECONDS, 0] }, tag)?;
    let [then, now] = observed.tickCumulatives[..] else {
        return Err(Error::Other("observe returned the wrong number of points"));
    };
    let delta = now.as_i64() - then.as_i64();
    let mut twap = delta / i64::from(TWAP_SECONDS);
    if delta < 0 && delta % i64::from(TWAP_SECONDS) != 0 {
        twap -= 1; // round towards negative infinity, as the Uniswap oracle library does
    }
    let twap_tick =
        alloy_primitives::aliases::I24::try_from(twap).map_err(|_| Error::Other("TWAP tick out of range"))?;
    let round = call(oracle, &IAggregatorV3::latestRoundDataCall {}, tag)?;
    if round.answeredInRound < round.roundId || round.answer.is_negative() {
        return Err(Error::Other("stale or negative oracle answer"));
    }
    Ok(Prices {
        token0: call(pool, &IUniswapV3Pool::token0Call {}, tag)?,
        token1: call(pool, &IUniswapV3Pool::token1Call {}, tag)?,
        fee: call(pool, &IUniswapV3Pool::feeCall {}, tag)?,
        sqrtPriceX96: slot0.sqrtPriceX96,
        spotTick: slot0.tick,
        twapTick: twap_tick,
        liquidity: call(pool, &IUniswapV3Pool::liquidityCall {}, tag)?,
        oracleAnswer: round.answer,
        oracleDecimals: call(oracle, &IAggregatorV3::decimalsCall {}, tag)?,
        oracleDescription: call(oracle, &IAggregatorV3::descriptionCall {}, tag)?,
        oracleUpdatedAt: round.updatedAt,
    })
}

#[derive(Serialize)]
struct CallRequest {
    to: Address,
    data: Bytes,
}

/// `eth_call` of `call` on `to` at `tag`, decoded.
fn call<C: SolCall>(to: Address, call: &C, tag: &str) -> Result<C::Return, Error> {
    let data: Bytes = rpc("eth_call", (CallRequest { to, data: call.abi_encode().into() }, tag))?;
    C::abi_decode_returns(&data).map_err(|e| {
        sdk::log(&format!("storage-proof: {}: {e}\n", C::SIGNATURE));
        Error::Other("undecodable eth_call result")
    })
}

/// The ERC-20 metadata of `token` (flag bit 1).
fn token(token: Address, tag: &str) -> Result<Token, Error> {
    Ok(Token {
        name: call(token, &IERC20::nameCall {}, tag)?,
        symbol: call(token, &IERC20::symbolCall {}, tag)?,
        decimals: call(token, &IERC20::decimalsCall {}, tag)?,
        totalSupply: call(token, &IERC20::totalSupplyCall {}, tag)?,
        heldByItself: call(token, &IERC20::balanceOfCall { owner: token }, tag)?,
    })
}

#[derive(Serialize)]
struct Request<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
struct Response<T> {
    jsonrpc: String,
    #[allow(dead_code)]
    id: serde_json::Value,
    #[serde(default = "Option::default")]
    result: Option<T>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Block {
    hash: B256,
    parent_hash: B256,
    sha3_uncles: B256,
    miner: Address,
    state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    difficulty: U256,
    number: U64,
    gas_limit: U64,
    gas_used: U64,
    timestamp: U64,
    extra_data: Bytes,
    mix_hash: B256,
    nonce: B64,
    #[serde(default)]
    base_fee_per_gas: Option<U256>,
    #[serde(default)]
    withdrawals_root: Option<B256>,
    #[serde(default)]
    blob_gas_used: Option<U64>,
    #[serde(default)]
    excess_blob_gas: Option<U64>,
    #[serde(default)]
    parent_beacon_block_root: Option<B256>,
    #[serde(default)]
    requests_hash: Option<B256>,
}

/// The consensus header, in RLP field order, with the fork tail as trailing options.
#[derive(RlpEncodable)]
#[rlp(trailing)]
struct Header {
    parent_hash: B256,
    ommers_hash: B256,
    beneficiary: Address,
    state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    difficulty: U256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: Bytes,
    mix_hash: B256,
    nonce: B64,
    base_fee_per_gas: Option<U256>,
    withdrawals_root: Option<B256>,
    blob_gas_used: Option<u64>,
    excess_blob_gas: Option<u64>,
    parent_beacon_block_root: Option<B256>,
    requests_hash: Option<B256>,
}

impl From<&Block> for Header {
    fn from(b: &Block) -> Self {
        Self {
            parent_hash: b.parent_hash,
            ommers_hash: b.sha3_uncles,
            beneficiary: b.miner,
            state_root: b.state_root,
            transactions_root: b.transactions_root,
            receipts_root: b.receipts_root,
            logs_bloom: b.logs_bloom,
            difficulty: b.difficulty,
            number: b.number.to(),
            gas_limit: b.gas_limit.to(),
            gas_used: b.gas_used.to(),
            timestamp: b.timestamp.to(),
            extra_data: b.extra_data.clone(),
            mix_hash: b.mix_hash,
            nonce: b.nonce,
            base_fee_per_gas: b.base_fee_per_gas,
            withdrawals_root: b.withdrawals_root,
            blob_gas_used: b.blob_gas_used.map(|v| v.to()),
            excess_blob_gas: b.excess_blob_gas.map(|v| v.to()),
            parent_beacon_block_root: b.parent_beacon_block_root,
            requests_hash: b.requests_hash,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AccountProof {
    address: Address,
    balance: U256,
    code_hash: B256,
    nonce: U64,
    storage_hash: B256,
    account_proof: Vec<Bytes>,
    storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize, Debug)]
struct StorageProof {
    key: U256,
    value: U256,
    proof: Vec<Bytes>,
}

struct Params {
    address: Address,
    block: u64,
    strict: bool,
    erc20: bool,
    oracle: Option<Address>,
    slots: Vec<B256>,
}

fn params(raw: &[u8]) -> Result<Params, Error> {
    let bad = Error::Other("builderParams: address, block, flags, [oracle], slots");
    if raw.len() < 29 {
        return Err(bad);
    }
    let flags = raw[28];
    let (oracle, rest) = if flags & 4 == 4 {
        let o = raw.get(29..49).ok_or(bad.clone())?;
        (Some(Address::from_slice(o)), &raw[49..])
    } else {
        (None, &raw[29..])
    };
    if rest.len() % 32 != 0 {
        return Err(bad);
    }
    Ok(Params {
        address: Address::from_slice(&raw[..20]),
        block: u64::from_be_bytes(raw[20..28].try_into().unwrap()),
        strict: flags & 1 == 1,
        erc20: flags & 2 == 2,
        oracle,
        slots: rest.chunks(32).map(B256::from_slice).collect(),
    })
}

fn rpc<P: Serialize, T: serde::de::DeserializeOwned>(method: &str, params: P) -> Result<T, Error> {
    let request = serde_json::to_vec(&Request { jsonrpc: "2.0", id: 1, method, params })
        .map_err(|_| Error::Other("unserializable request"))?;
    let response = sdk::fetch(0, &request)?;
    let parsed: Response<T> = serde_json::from_slice(&response).map_err(|e| {
        sdk::log(&format!("storage-proof: {method}: {e}\n"));
        Error::Other("malformed JSON-RPC response")
    })?;
    if parsed.jsonrpc != "2.0" {
        return Err(Error::Other("not a JSON-RPC 2.0 response"));
    }
    if let Some(e) = parsed.error {
        sdk::log(&format!("storage-proof: {method}: error {} {}\n", e.code, e.message));
        return Err(Error::Other("JSON-RPC error"));
    }
    parsed.result.ok_or(Error::Other("JSON-RPC response without a result"))
}

fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_be_bytes());
    w.extend_from_slice(b);
}

fn put_nodes(w: &mut Vec<u8>, nodes: &[Bytes]) {
    w.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
    for n in nodes {
        put(w, n);
    }
}

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    let source = ctx.sources.first().ok_or(Error::Other("no capability 0"))?;
    if source.class != sdk::CLASS_EVM_RPC_V1 {
        return Err(Error::Other("capability 0 is not evm-rpc/v1"));
    }
    let p = params(&ctx.builder_params)?;
    let tag = format!("0x{:x}", p.block);

    let block: Block = rpc("eth_getBlockByNumber", (&tag, false))?;
    let header = alloy_rlp::encode(Header::from(&block));
    let hash_ok = keccak256(&header) == block.hash;
    if p.strict && !hash_ok {
        return Err(Error::Other("the header does not hash to the block hash"));
    }
    let proof: AccountProof = rpc("eth_getProof", (p.address, &p.slots, &tag))?;
    if proof.address != p.address || proof.storage_proof.len() != p.slots.len() {
        return Err(Error::Other("eth_getProof answered another question"));
    }

    let account = TrieAccount {
        nonce: proof.nonce.to(),
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    let empty = account.nonce == 0
        && account.balance.is_zero()
        && account.storage_root == EMPTY_ROOT_HASH
        && account.code_hash == KECCAK_EMPTY;
    let account_rlp = alloy_rlp::encode(account);
    verify_proof(
        block.state_root,
        Nibbles::unpack(keccak256(p.address)),
        (!empty).then(|| account_rlp.clone()),
        &proof.account_proof,
    )
    .map_err(|e| {
        sdk::log(&format!("storage-proof: account proof: {e}\n"));
        Error::Other("the account proof does not verify")
    })?;

    let mut w = Vec::new();
    put(&mut w, &header);
    w.extend_from_slice(p.address.as_slice());
    put(&mut w, &account_rlp);
    w.extend_from_slice(&(p.slots.len() as u32).to_be_bytes());
    for (slot, sp) in p.slots.iter().zip(&proof.storage_proof) {
        if B256::from(sp.key) != *slot {
            return Err(Error::Other("storage proofs out of order"));
        }
        let expected = (!sp.value.is_zero()).then(|| alloy_rlp::encode(sp.value));
        verify_proof(proof.storage_hash, Nibbles::unpack(keccak256(slot)), expected, &sp.proof).map_err(|e| {
            sdk::log(&format!("storage-proof: slot {slot}: {e}\n"));
            Error::Other("a storage proof does not verify")
        })?;
        w.extend_from_slice(slot.as_slice());
        w.extend_from_slice(&sp.value.to_be_bytes::<32>());
        put_nodes(&mut w, &sp.proof);
    }
    put_nodes(&mut w, &proof.account_proof);
    let token = if p.erc20 {
        token(p.address, &tag)?
    } else {
        Token {
            name: String::new(),
            symbol: String::new(),
            decimals: 0,
            totalSupply: U256::ZERO,
            heldByItself: U256::ZERO,
        }
    };
    let commitment = Commitment {
        account: p.address,
        blockNumber: block.number.to(),
        stateRoot: block.state_root,
        storageRoot: proof.storage_hash,
        slots: p.slots.iter().map(|s| U256::from_be_bytes(s.0)).collect(),
        values: proof.storage_proof.iter().map(|sp| sp.value).collect(),
        token,
    };
    put(&mut w, &commitment.abi_encode());
    if let Some(oracle) = p.oracle {
        let prices = prices(p.address, oracle, &tag)?;
        sdk::log(&format!(
            "storage-proof: pool {} spot tick {} TWAP tick {}, oracle {:?} answer {}\n",
            p.address, prices.spotTick, prices.twapTick, prices.oracleDescription, prices.oracleAnswer
        ));
        put(&mut w, &prices.abi_encode());
    }
    let digest = Sha256::digest(&w);
    w.extend_from_slice(&digest);
    sdk::log(&format!(
        "storage-proof: block {} account {} nonce {} balance {}, {} slots, header hash {}, digest {}\n",
        block.number,
        p.address,
        account.nonce,
        account.balance,
        p.slots.len(),
        if hash_ok { "ok" } else { "MISMATCH" },
        hex::encode(digest),
    ));
    sdk::write_witness(&w)?;
    Ok(())
}
