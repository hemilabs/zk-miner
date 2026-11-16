//! `evm-rpc/v1` (plan §11.2): the strict request parser, the broker-built outgoing request, and the
//! canonical response. Pure functions: no I/O. The broker process (`job.rs`, `endpoints.rs`) owns the
//! network, failover, budgets and caches and calls into this module.
//!
//! INTERFACE CONTRACT (fixed for milestone 2; the bodies are implemented on max/witness-broker-rpc).
//!
//! # Requests ([`parse_request`])
//!
//! One JSON-RPC 2.0 object, or a batch array of 1..=[`MAX_BATCH`]. The JSON grammar is narrowed so
//! that every accepted text means the same thing to every parser (`req_json`): whitespace between
//! tokens only; no BOM or trailing bytes; strings of printable ASCII with **no escape sequences**
//! anywhere (`method` spelled with its `m` as a `\u` escape is a malformed key, not `method`); numbers
//! only as canonical
//! non-negative decimal integers; no duplicate keys at any level; depth at most [`MAX_JSON_DEPTH`]
//! (the top-level value is depth 1; deeper is [`Denied::TooDeep`]).
//!
//! Each call object has exactly the keys `jsonrpc`, `id`, `method`, `params` (any order, compared as
//! raw bytes, so `Method` or `METHOD` is an unknown key and malformed). `jsonrpc` is the string `2.0`.
//! `id` is an integer in `0..=2^53-1`, or a string of 0..=64 bytes of printable ASCII without `"` or
//! `\` (so it never needs an escape; it is echoed byte for byte by [`render`]). `null`, other numbers
//! and other strings are malformed. `params` is an array.
//!
//! Encodings: a *quantity* is `0x` plus lowercase hex without leading zeros (`0x0` for zero), at most
//! 64 digits, and at most 16 where it must fit `u64` (block numbers; more is
//! [`Denied::ParamOutOfRange`]). *Data* is `0x` plus an even number of hex digits of either case,
//! re-emitted lowercase; an address is 20 bytes of data, a hash 32. A *storage key* (`eth_getStorageAt`,
//! `eth_getProof`) is 32 bytes of data or a quantity, re-emitted as 32 bytes of data.
//!
//! Methods ([`Method`]; anything else, including the Phase-2 `state-trace` additions for now, is
//! [`Denied::MethodNotAllowed`]) and their params, of exactly this arity:
//!
//! | method | params |
//! |---|---|
//! | `eth_chainId`, `eth_blockNumber` | `[]` |
//! | `eth_getBlockByHash` | `[hash, bool]` |
//! | `eth_getBlockByNumber` | `[quantity \| tag, bool]` |
//! | `eth_getBlockReceipts` | `[quantity \| tag \| hash \| EIP-1898]` |
//! | `eth_getTransactionByHash`, `eth_getTransactionReceipt` | `[hash]` |
//! | `eth_getBalance`, `eth_getCode`, `eth_getTransactionCount` | `[address, block]` |
//! | `eth_getStorageAt` | `[address, storage key, block]` |
//! | `eth_getProof` | `[address, [storage key; 0..=256], block]` |
//! | `eth_call`, `eth_createAccessList` | `[call]` or `[call, block]` (missing = `latest`) |
//! | `eth_getLogs` | `[filter]` |
//!
//! A *block* is a quantity, `latest`, `safe`, `finalized`, or an EIP-1898 object: `{"blockHash":h}`,
//! `{"blockHash":h,"requireCanonical":bool}` or `{"blockNumber":quantity}`. `pending` and `earliest`
//! are out of range. `requireCanonical: true` is kept (the node then refuses a non-canonical block);
//! `false` is the default and dropped; `{"blockNumber":n}` is re-emitted as the quantity `n`. A plain
//! 32-byte hash string is accepted only by `eth_getBlockReceipts` (as in the execution-apis spec).
//! Tags are resolved by the broker ([`ParsedRequest::tags`], then [`ParsedRequest::outgoing`]).
//!
//! A *call* object has only the keys `from`, `to` (addresses), `gas`, `gasPrice`, `maxFeePerGas`,
//! `maxPriorityFeePerGas`, `value` (quantities), and one of `data` / `input` (data); both `data` and
//! `input` is malformed (not normalised), and so is `gasPrice` with either EIP-1559 fee. The input is
//! always re-emitted as `input`. `gas` is always emitted, as `min(requested or 30M, 30M)`. A third or
//! fourth param (state / block overrides) is out of range.
//!
//! A *filter* has only `fromBlock`, `toBlock`, `blockHash`, `address`, `topics`. Either `blockHash`
//! alone, or both `fromBlock` and `toBlock` (quantities or tags; a missing bound is out of range)
//! spanning at most [`MAX_LOG_RANGE`] blocks counted inclusively (`to - from <= 9_999`, `from <= to`):
//! checked at parse time when both are numbers and by [`ParsedRequest::check_after_resolution`] once
//! tags are resolved. `address` is one address (re-emitted as a list of one) or a list of
//! 1..=[`MAX_LOG_ADDRESSES`]. `topics` has 1..=4 positions; position 0 is not null; each position is
//! `null`, one hash, or a list of 1..=[`MAX_TOPIC_VALUES`] hashes.
//!
//! # Outgoing requests
//!
//! The broker never forwards builder bytes: [`ParsedRequest::outgoing`] serialises the typed form
//! with fixed key order (`jsonrpc`, `id`, `method`, `params`), the broker's ids and framing. A
//! case-insensitive parser on the node (geth's `encoding/json`) can therefore never see a second
//! `method`.
//!
//! # Answers ([`parse_answers`])
//!
//! See `canon` for the canonical form. Each result is re-emitted as is; an error object becomes
//! `{"code":<int>}` or `{"code":<int>,"data":"0x…"}` (data only when it is a string of `0x` plus an
//! even number of hex digits, lowercased; the message is dropped). `max_bytes` bounds the bytes
//! [`render`] will produce for these answers (envelopes and ids included), enforced while streaming.
//! The mempool rule turns an `eth_getTransactionByHash` object whose top-level `blockHash` is `null`
//! or absent into `null`.
//!
//! **Lagging heuristics** ([`ResponseError::Lagging`], retry on another endpoint):
//!
//! - an error whose message contains, case-insensitively, one of [`LAGGING_MESSAGES`] (`header not
//!   found`, `missing trie node`, `unknown block`, `block not found`, `historical state`, `state not
//!   available`, `state is not available`, `state unavailable`, `is pruned`, `pruned history`,
//!   `node is syncing`), unless its code is 3 or its message contains `revert`: a reverted call's
//!   reason is chosen by the contract and must not be able to fake a lagging node;
//! - a `null` result for a call whose answer is never legitimately null when the node has the block:
//!   everything except `eth_getTransactionByHash` / `eth_getTransactionReceipt` (unknown or pending
//!   transaction), and `eth_getBlockByNumber` / `eth_getBlockReceipts` with an explicit number (a
//!   future block). A tag the broker resolved, a block hash, or any state query answered with `null`
//!   means the node lacks a block that should exist. (A builder asking for a hash that exists nowhere
//!   therefore fails over and ends as status 2, like any unanswerable query.)
//!
//! A mempool result rewritten to `null` is charged at its full size while streaming (the cap may
//! refuse it although the final answer is 4 bytes).

mod canon;
mod req_json;
#[cfg(test)]
mod tests;

use canon::{top_level_field, Body, Budget, Kind, Scanner};
use req_json::V;
use zkminer_witness::envelope::MethodSet;

pub const MAX_BATCH: usize = 32;
pub const MAX_JSON_DEPTH: usize = 32;
pub const CALL_GAS_CAP: u64 = 30_000_000;
pub const MAX_LOG_RANGE: u64 = 10_000;
pub const MAX_LOG_ADDRESSES: usize = 8;
pub const MAX_TOPIC_VALUES: usize = 8;
pub const MAX_PROOF_KEYS: usize = 256;

/// The longest builder string id, in bytes.
pub const MAX_ID_STRING: usize = 64;
/// The largest builder integer id (`2^53 - 1`, exact in every JSON implementation).
pub const MAX_ID_NUMBER: u64 = (1 << 53) - 1;
/// The most `topics` positions in an `eth_getLogs` filter.
pub const MAX_TOPIC_POSITIONS: usize = 4;

/// Symbolic block tags the broker resolves to a number before sending (`pending`/`earliest` are
/// rejected at parse time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockTag {
    Latest,
    Safe,
    Finalized,
}

impl BlockTag {
    /// The JSON-RPC spelling (`latest`, `safe`, `finalized`).
    pub fn as_str(self) -> &'static str {
        match self {
            BlockTag::Latest => "latest",
            BlockTag::Safe => "safe",
            BlockTag::Finalized => "finalized",
        }
    }
}

/// The builder's request id, re-emitted in canonical form in the response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RpcId {
    Num(u64),
    Str(String),
}

/// The methods of `state-read` (and, in Phase 2, `state-trace`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    EthChainId,
    EthBlockNumber,
    EthGetBlockByHash,
    EthGetBlockByNumber,
    EthGetBlockReceipts,
    EthGetTransactionByHash,
    EthGetTransactionReceipt,
    EthGetBalance,
    EthGetCode,
    EthGetStorageAt,
    EthGetTransactionCount,
    EthGetProof,
    EthCall,
    EthCreateAccessList,
    EthGetLogs,
}

/// `state-read`, exactly (§11.2).
const STATE_READ: &[(&str, Method)] = &[
    ("eth_chainId", Method::EthChainId),
    ("eth_blockNumber", Method::EthBlockNumber),
    ("eth_getBlockByHash", Method::EthGetBlockByHash),
    ("eth_getBlockByNumber", Method::EthGetBlockByNumber),
    ("eth_getBlockReceipts", Method::EthGetBlockReceipts),
    ("eth_getTransactionByHash", Method::EthGetTransactionByHash),
    (
        "eth_getTransactionReceipt",
        Method::EthGetTransactionReceipt,
    ),
    ("eth_getBalance", Method::EthGetBalance),
    ("eth_getCode", Method::EthGetCode),
    ("eth_getStorageAt", Method::EthGetStorageAt),
    ("eth_getTransactionCount", Method::EthGetTransactionCount),
    ("eth_getProof", Method::EthGetProof),
    ("eth_call", Method::EthCall),
    ("eth_createAccessList", Method::EthCreateAccessList),
    ("eth_getLogs", Method::EthGetLogs),
];

/// What `state-trace` adds to `state-read` (Phase 2). Recognised, but refused until the broker
/// rewrites `TraceConfig` (§11.2); enabling one means a `Method` variant, its params and caps here.
const STATE_TRACE_EXTRA: &[&str] = &[
    "debug_traceCall",
    "debug_traceTransaction",
    "debug_traceBlockByHash",
    "debug_executionWitness",
];

impl Method {
    /// The JSON-RPC method name.
    pub fn name(self) -> &'static str {
        STATE_READ
            .iter()
            .find(|(_, m)| *m == self)
            .map_or("", |(n, _)| n)
    }

    fn from_name(name: &[u8], set: MethodSet) -> Result<Method, Denied> {
        if let Some((_, m)) = STATE_READ.iter().find(|(n, _)| n.as_bytes() == name) {
            // Both sets contain state-read.
            return Ok(*m);
        }
        if set == MethodSet::StateTrace && Self::is_state_trace_extra(name) {
            // Phase 2: map these to their own variants here once the TraceConfig rewrite exists.
            return Err(Denied::MethodNotAllowed);
        }
        Err(Denied::MethodNotAllowed)
    }

    fn is_state_trace_extra(name: &[u8]) -> bool {
        STATE_TRACE_EXTRA.iter().any(|n| n.as_bytes() == name)
    }
}

/// One validated call in the broker's own representation (never the builder's bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub id: RpcId,
    pub method: Method,
    /// Typed, validated params with symbolic tags; private representation.
    params: Params,
}

/// A validated request: one call (`batch == false`) or a batch of 1..=32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub calls: Vec<Call>,
    pub batch: bool,
}

/// Why a builder request is refused (fetch status 1). A fixed set: no builder strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("malformed JSON-RPC request")]
    Malformed,
    #[error("method not in the capability's method set")]
    MethodNotAllowed,
    #[error("a parameter is out of range")]
    ParamOutOfRange,
    #[error("batch empty or larger than {MAX_BATCH}")]
    BatchSize,
    #[error("JSON nested deeper than {MAX_JSON_DEPTH}")]
    TooDeep,
}

/// Why an endpoint's answer is unusable. `Lagging` asks the caller to retry on another endpoint
/// ("header not found", "missing trie node"); the others are status 2 after failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    #[error("malformed response body")]
    Malformed,
    #[error("response larger than the cap")]
    TooLarge,
    #[error("the node lags or lacks the state")]
    Lagging,
    #[error("response ids or count do not match the request")]
    Mismatch,
}

/// One call's answer, canonical: `result` JSON, or an error object `{"code":…,"data":"0x…"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallAnswer {
    pub canonical: Vec<u8>,
    pub is_error: bool,
}

// ------------------------------------------------------------------------------------------------
// The typed form.

type Address = [u8; 20];
type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Block {
    Num(u64),
    Tag(BlockTag),
    Hash { hash: Hash, require_canonical: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallObject {
    from: Option<Address>,
    to: Option<Address>,
    /// Already capped.
    gas: u64,
    /// Canonical quantities, `0x…`.
    gas_price: Option<String>,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
    value: Option<String>,
    input: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LogRange {
    Blocks { from: Block, to: Block },
    Hash(Hash),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Topic {
    Any,
    One(Hash),
    AnyOf(Vec<Hash>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Filter {
    range: LogRange,
    addresses: Vec<Address>,
    topics: Vec<Topic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Params {
    None,
    BlockByHash {
        hash: Hash,
        full: bool,
    },
    BlockByNumber {
        block: Block,
        full: bool,
    },
    BlockReceipts(Block),
    TxHash(Hash),
    Account {
        addr: Address,
        block: Block,
    },
    StorageAt {
        addr: Address,
        slot: Hash,
        block: Block,
    },
    Proof {
        addr: Address,
        keys: Vec<Hash>,
        block: Block,
    },
    Call {
        call: CallObject,
        block: Block,
    },
    Logs(Filter),
}

// ------------------------------------------------------------------------------------------------
// Parsing.

/// Parses and validates builder request bytes under `set` (exact keys, canonical numbers, hex data,
/// per-method caps). See the module doc for the accepted grammar.
pub fn parse_request(bytes: &[u8], set: MethodSet) -> Result<ParsedRequest, Denied> {
    match req_json::parse(bytes)? {
        V::Arr(items) => {
            if items.is_empty() || items.len() > MAX_BATCH {
                return Err(Denied::BatchSize);
            }
            let calls = items
                .iter()
                .map(|v| parse_call(v, set))
                .collect::<Result<_, _>>()?;
            Ok(ParsedRequest { calls, batch: true })
        }
        v @ V::Obj(_) => Ok(ParsedRequest {
            calls: vec![parse_call(&v, set)?],
            batch: false,
        }),
        _ => Err(Denied::Malformed),
    }
}

fn parse_call(v: &V<'_>, set: MethodSet) -> Result<Call, Denied> {
    let fields = v.obj()?;
    let get = |key: &[u8]| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
    // Duplicates are already refused, so four fields with these four names is exactly these keys.
    let (Some(version), Some(id), Some(method), Some(params), 4) = (
        get(b"jsonrpc"),
        get(b"id"),
        get(b"method"),
        get(b"params"),
        fields.len(),
    ) else {
        return Err(Denied::Malformed);
    };
    if version.str()? != b"2.0" {
        return Err(Denied::Malformed);
    }
    let id = match id {
        V::Num(n) if *n <= MAX_ID_NUMBER => RpcId::Num(*n),
        // req_json admits only printable ASCII without `"` or `\` in strings.
        V::Str(s) if s.len() <= MAX_ID_STRING => {
            RpcId::Str(String::from_utf8_lossy(s).into_owned())
        }
        _ => return Err(Denied::Malformed),
    };
    let method = Method::from_name(method.str()?, set)?;
    let params = parse_params(method, params.arr()?)?;
    Ok(Call { id, method, params })
}

fn arity(p: &[V<'_>], n: usize) -> Result<(), Denied> {
    if p.len() == n {
        Ok(())
    } else {
        Err(Denied::Malformed)
    }
}

fn parse_params(method: Method, p: &[V<'_>]) -> Result<Params, Denied> {
    use Method::*;
    Ok(match method {
        EthChainId | EthBlockNumber => {
            arity(p, 0)?;
            Params::None
        }
        EthGetBlockByHash => {
            arity(p, 2)?;
            Params::BlockByHash {
                hash: fixed(p[0].str()?)?,
                full: p[1].boolean()?,
            }
        }
        EthGetBlockByNumber => {
            arity(p, 2)?;
            Params::BlockByNumber {
                block: tag_or_quantity(p[0].str()?)?,
                full: p[1].boolean()?,
            }
        }
        EthGetBlockReceipts => {
            arity(p, 1)?;
            Params::BlockReceipts(block_receipts_param(&p[0])?)
        }
        EthGetTransactionByHash | EthGetTransactionReceipt => {
            arity(p, 1)?;
            Params::TxHash(fixed(p[0].str()?)?)
        }
        EthGetBalance | EthGetCode | EthGetTransactionCount => {
            arity(p, 2)?;
            Params::Account {
                addr: fixed(p[0].str()?)?,
                block: block_state_param(&p[1])?,
            }
        }
        EthGetStorageAt => {
            arity(p, 3)?;
            Params::StorageAt {
                addr: fixed(p[0].str()?)?,
                slot: storage_key(&p[1])?,
                block: block_state_param(&p[2])?,
            }
        }
        EthGetProof => {
            arity(p, 3)?;
            let addr = fixed(p[0].str()?)?;
            let keys = p[1].arr()?;
            if keys.len() > MAX_PROOF_KEYS {
                return Err(Denied::ParamOutOfRange);
            }
            let keys = keys.iter().map(storage_key).collect::<Result<_, _>>()?;
            Params::Proof {
                addr,
                keys,
                block: block_state_param(&p[2])?,
            }
        }
        EthCall | EthCreateAccessList => {
            match p.len() {
                1 | 2 => {}
                // State overrides, then block overrides: never.
                3 | 4 => return Err(Denied::ParamOutOfRange),
                _ => return Err(Denied::Malformed),
            }
            let call = call_object(&p[0])?;
            let block = match p.get(1) {
                Some(b) => block_state_param(b)?,
                None => Block::Tag(BlockTag::Latest),
            };
            Params::Call { call, block }
        }
        EthGetLogs => {
            arity(p, 1)?;
            Params::Logs(filter(&p[0])?)
        }
    })
}

/// `0x0` or `0x[1-9a-f][0-9a-f]*`, at most 64 digits: the digits.
fn quantity_digits(s: &[u8]) -> Result<&[u8], Denied> {
    let d = s.strip_prefix(b"0x").ok_or(Denied::Malformed)?;
    let ok = !d.is_empty()
        && d.len() <= 64
        && d.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && !(d.len() > 1 && d[0] == b'0');
    if ok {
        Ok(d)
    } else {
        Err(Denied::Malformed)
    }
}

fn digits_u64(d: &[u8]) -> u64 {
    d.iter().fold(0u64, |n, &c| {
        (n << 4) | u64::from(canon::hex_val(c).unwrap_or(0))
    })
}

/// A quantity that must fit `u64`.
fn quantity_u64(s: &[u8]) -> Result<u64, Denied> {
    let d = quantity_digits(s)?;
    if d.len() > 16 {
        return Err(Denied::ParamOutOfRange);
    }
    Ok(digits_u64(d))
}

/// A quantity kept as its canonical spelling.
fn quantity_string(s: &[u8]) -> Result<String, Denied> {
    quantity_digits(s)?;
    Ok(String::from_utf8_lossy(s).into_owned())
}

/// `0x` plus an even number of hex digits of either case.
fn data(s: &[u8]) -> Result<Vec<u8>, Denied> {
    let d = s.strip_prefix(b"0x").ok_or(Denied::Malformed)?;
    if d.len() % 2 != 0 {
        return Err(Denied::Malformed);
    }
    d.chunks_exact(2)
        .map(
            |pair| match (canon::hex_val(pair[0]), canon::hex_val(pair[1])) {
                (Some(h), Some(l)) => Ok((h << 4) | l),
                _ => Err(Denied::Malformed),
            },
        )
        .collect()
}

/// Data of exactly `N` bytes.
fn fixed<const N: usize>(s: &[u8]) -> Result<[u8; N], Denied> {
    if s.len() != 2 + 2 * N {
        return Err(Denied::Malformed);
    }
    data(s)?.try_into().map_err(|_| Denied::Malformed)
}

/// 32 bytes of data, or a quantity left-padded to 32 bytes.
fn storage_key(v: &V<'_>) -> Result<Hash, Denied> {
    let s = v.str()?;
    if s.len() == 66 {
        return fixed(s);
    }
    let d = quantity_digits(s)?;
    let mut out = [0u8; 32];
    for (i, &c) in d.iter().rev().enumerate() {
        out[31 - i / 2] |= canon::hex_val(c).unwrap_or(0) << (4 * (i % 2));
    }
    Ok(out)
}

fn tag_or_quantity(s: &[u8]) -> Result<Block, Denied> {
    match s {
        b"latest" => Ok(Block::Tag(BlockTag::Latest)),
        b"safe" => Ok(Block::Tag(BlockTag::Safe)),
        b"finalized" => Ok(Block::Tag(BlockTag::Finalized)),
        b"pending" | b"earliest" => Err(Denied::ParamOutOfRange),
        _ => Ok(Block::Num(quantity_u64(s)?)),
    }
}

/// A state method's block: a quantity, a tag, or an EIP-1898 object.
fn block_state_param(v: &V<'_>) -> Result<Block, Denied> {
    match v {
        // A bare hash is the EIP-1898 object's job here.
        V::Str(s) if s.len() == 66 => Err(Denied::Malformed),
        V::Str(s) => tag_or_quantity(s),
        V::Obj(fields) => {
            let (mut hash, mut number, mut canonical) = (None, None, None);
            for (k, v) in fields {
                match *k {
                    b"blockHash" => hash = Some(fixed(v.str()?)?),
                    b"blockNumber" => number = Some(quantity_u64(v.str()?)?),
                    b"requireCanonical" => canonical = Some(v.boolean()?),
                    _ => return Err(Denied::Malformed),
                }
            }
            match (hash, number, canonical) {
                (Some(hash), None, rc) => Ok(Block::Hash {
                    hash,
                    require_canonical: rc.unwrap_or(false),
                }),
                (None, Some(n), None) => Ok(Block::Num(n)),
                _ => Err(Denied::Malformed),
            }
        }
        _ => Err(Denied::Malformed),
    }
}

/// `eth_getBlockReceipts`' block: as a state method's, plus a bare 32-byte hash.
fn block_receipts_param(v: &V<'_>) -> Result<Block, Denied> {
    match v {
        V::Str(s) if s.len() == 66 => Ok(Block::Hash {
            hash: fixed(s)?,
            require_canonical: false,
        }),
        _ => block_state_param(v),
    }
}

fn call_object(v: &V<'_>) -> Result<CallObject, Denied> {
    let mut c = CallObject {
        from: None,
        to: None,
        gas: CALL_GAS_CAP,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        input: None,
    };
    for (k, v) in v.obj()? {
        let s = v.str()?;
        match *k {
            b"from" => c.from = Some(fixed(s)?),
            b"to" => c.to = Some(fixed(s)?),
            b"gas" => {
                let d = quantity_digits(s)?;
                c.gas = if d.len() > 16 {
                    CALL_GAS_CAP
                } else {
                    digits_u64(d).min(CALL_GAS_CAP)
                };
            }
            b"gasPrice" => c.gas_price = Some(quantity_string(s)?),
            b"maxFeePerGas" => c.max_fee_per_gas = Some(quantity_string(s)?),
            b"maxPriorityFeePerGas" => c.max_priority_fee_per_gas = Some(quantity_string(s)?),
            b"value" => c.value = Some(quantity_string(s)?),
            b"data" | b"input" => {
                if c.input.is_some() {
                    return Err(Denied::Malformed);
                }
                c.input = Some(data(s)?);
            }
            _ => return Err(Denied::Malformed),
        }
    }
    if c.gas_price.is_some()
        && (c.max_fee_per_gas.is_some() || c.max_priority_fee_per_gas.is_some())
    {
        return Err(Denied::Malformed);
    }
    Ok(c)
}

fn log_range_ok(from: u64, to: u64) -> Result<(), Denied> {
    if from <= to && to - from < MAX_LOG_RANGE {
        Ok(())
    } else {
        Err(Denied::ParamOutOfRange)
    }
}

fn filter(v: &V<'_>) -> Result<Filter, Denied> {
    let (mut from, mut to, mut hash, mut address, mut topics) = (None, None, None, None, None);
    for (k, v) in v.obj()? {
        match *k {
            b"fromBlock" => from = Some(v),
            b"toBlock" => to = Some(v),
            b"blockHash" => hash = Some(v),
            b"address" => address = Some(v),
            b"topics" => topics = Some(v),
            _ => return Err(Denied::Malformed),
        }
    }
    let range = match (hash, from, to) {
        (Some(h), None, None) => LogRange::Hash(fixed(h.str()?)?),
        (Some(_), _, _) => return Err(Denied::Malformed),
        (None, Some(f), Some(t)) => {
            let (from, to) = (tag_or_quantity(f.str()?)?, tag_or_quantity(t.str()?)?);
            if let (Block::Num(a), Block::Num(b)) = (&from, &to) {
                log_range_ok(*a, *b)?;
            }
            LogRange::Blocks { from, to }
        }
        // Not a concrete range.
        (None, _, _) => return Err(Denied::ParamOutOfRange),
    };
    let addresses = match address {
        Some(V::Str(s)) => vec![fixed(s)?],
        Some(V::Arr(items)) => {
            if items.is_empty() || items.len() > MAX_LOG_ADDRESSES {
                return Err(Denied::ParamOutOfRange);
            }
            items
                .iter()
                .map(|a| fixed(a.str()?))
                .collect::<Result<_, _>>()?
        }
        None | Some(V::Null) => return Err(Denied::ParamOutOfRange),
        Some(_) => return Err(Denied::Malformed),
    };
    let topics = match topics {
        Some(V::Arr(positions)) => {
            if positions.is_empty() || positions.len() > MAX_TOPIC_POSITIONS {
                return Err(Denied::ParamOutOfRange);
            }
            positions
                .iter()
                .enumerate()
                .map(|(i, t)| topic(t, i == 0))
                .collect::<Result<_, _>>()?
        }
        None | Some(V::Null) => return Err(Denied::ParamOutOfRange),
        Some(_) => return Err(Denied::Malformed),
    };
    Ok(Filter {
        range,
        addresses,
        topics,
    })
}

fn topic(v: &V<'_>, first: bool) -> Result<Topic, Denied> {
    match v {
        V::Null if first => Err(Denied::ParamOutOfRange),
        V::Null => Ok(Topic::Any),
        V::Str(s) => Ok(Topic::One(fixed(s)?)),
        V::Arr(items) => {
            if items.is_empty() || items.len() > MAX_TOPIC_VALUES {
                return Err(Denied::ParamOutOfRange);
            }
            Ok(Topic::AnyOf(
                items
                    .iter()
                    .map(|t| fixed(t.str()?))
                    .collect::<Result<_, _>>()?,
            ))
        }
        _ => Err(Denied::Malformed),
    }
}

// ------------------------------------------------------------------------------------------------
// Emitting.

const HEX: &[u8; 16] = b"0123456789abcdef";

fn put_quantity(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(b"\"0x");
    let digits = (64 - n.leading_zeros()).div_ceil(4).max(1);
    for i in (0..digits).rev() {
        out.push(HEX[((n >> (4 * i)) & 15) as usize]);
    }
    out.push(b'"');
}

fn put_data(out: &mut Vec<u8>, bytes: &[u8]) {
    out.reserve(4 + 2 * bytes.len());
    out.extend_from_slice(b"\"0x");
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)]);
        out.push(HEX[usize::from(b & 15)]);
    }
    out.push(b'"');
}

fn put_bool(out: &mut Vec<u8>, b: bool) {
    out.extend_from_slice(if b { b"true" } else { b"false" });
}

fn put_list<T>(out: &mut Vec<u8>, items: &[T], mut each: impl FnMut(&mut Vec<u8>, &T)) {
    out.push(b'[');
    for (i, t) in items.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        each(out, t);
    }
    out.push(b']');
}

type Resolve<'r> = &'r dyn Fn(BlockTag) -> u64;

impl Block {
    fn number(&self, resolve: Resolve<'_>) -> Option<u64> {
        match self {
            Block::Num(n) => Some(*n),
            Block::Tag(t) => Some(resolve(*t)),
            Block::Hash { .. } => None,
        }
    }

    /// As a quantity, or an EIP-1898 hash object.
    fn put(&self, out: &mut Vec<u8>, resolve: Resolve<'_>) {
        match self {
            Block::Num(n) => put_quantity(out, *n),
            Block::Tag(t) => put_quantity(out, resolve(*t)),
            Block::Hash {
                hash,
                require_canonical,
            } => {
                out.extend_from_slice(b"{\"blockHash\":");
                put_data(out, hash);
                if *require_canonical {
                    out.extend_from_slice(b",\"requireCanonical\":true");
                }
                out.push(b'}');
            }
        }
    }

    /// `eth_getBlockReceipts`' form: a bare hash unless `requireCanonical` needs the object.
    fn put_receipts(&self, out: &mut Vec<u8>, resolve: Resolve<'_>) {
        match self {
            Block::Hash {
                hash,
                require_canonical: false,
            } => put_data(out, hash),
            _ => self.put(out, resolve),
        }
    }

    fn pinned_to_hash(&self) -> bool {
        matches!(
            self,
            Block::Hash {
                require_canonical: false,
                ..
            }
        )
    }
}

/// Writes `,"key":` (or `"key":` first).
fn put_key(out: &mut Vec<u8>, first: &mut bool, key: &str) {
    if !*first {
        out.push(b',');
    }
    *first = false;
    out.push(b'"');
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"\":");
}

impl CallObject {
    fn put(&self, out: &mut Vec<u8>) {
        let first = &mut true;
        out.push(b'{');
        if let Some(a) = &self.from {
            put_key(out, first, "from");
            put_data(out, a);
        }
        if let Some(a) = &self.to {
            put_key(out, first, "to");
            put_data(out, a);
        }
        put_key(out, first, "gas");
        put_quantity(out, self.gas);
        for (key, q) in [
            ("gasPrice", &self.gas_price),
            ("maxFeePerGas", &self.max_fee_per_gas),
            ("maxPriorityFeePerGas", &self.max_priority_fee_per_gas),
            ("value", &self.value),
        ] {
            if let Some(q) = q {
                put_key(out, first, key);
                out.push(b'"');
                out.extend_from_slice(q.as_bytes());
                out.push(b'"');
            }
        }
        if let Some(d) = &self.input {
            put_key(out, first, "input");
            put_data(out, d);
        }
        out.push(b'}');
    }
}

impl Filter {
    fn put(&self, out: &mut Vec<u8>, resolve: Resolve<'_>) {
        out.push(b'{');
        match &self.range {
            LogRange::Blocks { from, to } => {
                out.extend_from_slice(b"\"fromBlock\":");
                from.put(out, resolve);
                out.extend_from_slice(b",\"toBlock\":");
                to.put(out, resolve);
            }
            LogRange::Hash(h) => {
                out.extend_from_slice(b"\"blockHash\":");
                put_data(out, h);
            }
        }
        out.extend_from_slice(b",\"address\":");
        put_list(out, &self.addresses, |o, a| put_data(o, a));
        out.extend_from_slice(b",\"topics\":");
        put_list(out, &self.topics, |o, t| match t {
            Topic::Any => o.extend_from_slice(b"null"),
            Topic::One(h) => put_data(o, h),
            Topic::AnyOf(hs) => put_list(o, hs, |o, h| put_data(o, h)),
        });
        out.push(b'}');
    }
}

impl Params {
    fn put(&self, out: &mut Vec<u8>, resolve: Resolve<'_>) {
        out.push(b'[');
        match self {
            Params::None => {}
            Params::BlockByHash { hash, full } => {
                put_data(out, hash);
                out.push(b',');
                put_bool(out, *full);
            }
            Params::BlockByNumber { block, full } => {
                block.put(out, resolve);
                out.push(b',');
                put_bool(out, *full);
            }
            Params::BlockReceipts(block) => block.put_receipts(out, resolve),
            Params::TxHash(h) => put_data(out, h),
            Params::Account { addr, block } => {
                put_data(out, addr);
                out.push(b',');
                block.put(out, resolve);
            }
            Params::StorageAt { addr, slot, block } => {
                put_data(out, addr);
                out.push(b',');
                put_data(out, slot);
                out.push(b',');
                block.put(out, resolve);
            }
            Params::Proof { addr, keys, block } => {
                put_data(out, addr);
                out.push(b',');
                put_list(out, keys, |o, k| put_data(o, k));
                out.push(b',');
                block.put(out, resolve);
            }
            Params::Call { call, block } => {
                call.put(out);
                out.push(b',');
                block.put(out, resolve);
            }
            Params::Logs(f) => f.put(out, resolve),
        }
        out.push(b']');
    }

    /// The block parameters, for tag collection.
    fn blocks(&self) -> [Option<&Block>; 2] {
        match self {
            Params::BlockByNumber { block, .. }
            | Params::BlockReceipts(block)
            | Params::Account { block, .. }
            | Params::StorageAt { block, .. }
            | Params::Proof { block, .. }
            | Params::Call { block, .. } => [Some(block), None],
            Params::Logs(Filter {
                range: LogRange::Blocks { from, to },
                ..
            }) => [Some(from), Some(to)],
            Params::None | Params::BlockByHash { .. } | Params::TxHash(_) | Params::Logs(_) => {
                [None, None]
            }
        }
    }

    /// Whether the answer is fixed by a block hash (and so cacheable).
    fn pinned_to_hash(&self) -> bool {
        match self {
            Params::BlockByHash { .. } => true,
            Params::BlockReceipts(b)
            | Params::Account { block: b, .. }
            | Params::StorageAt { block: b, .. }
            | Params::Proof { block: b, .. }
            | Params::Call { block: b, .. } => b.pinned_to_hash(),
            // getLogs by blockHash is not: a node without the block may answer `[]`, which is
            // indistinguishable from "no logs" and must not be cached.
            Params::None | Params::BlockByNumber { .. } | Params::TxHash(_) | Params::Logs(_) => {
                false
            }
        }
    }

    /// Whether a `null` result is a real answer (see the module doc's lagging heuristics).
    fn null_is_an_answer(&self) -> bool {
        matches!(
            self,
            Params::TxHash(_)
                | Params::BlockByNumber {
                    block: Block::Num(_),
                    ..
                }
                | Params::BlockReceipts(Block::Num(_))
        )
    }
}

impl Call {
    fn put(&self, out: &mut Vec<u8>, id: Option<u64>, resolve: Resolve<'_>) {
        out.extend_from_slice(b"{\"jsonrpc\":\"2.0\",");
        if let Some(id) = id {
            out.extend_from_slice(b"\"id\":");
            out.extend_from_slice(id.to_string().as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(b"\"method\":\"");
        out.extend_from_slice(self.method.name().as_bytes());
        out.extend_from_slice(b"\",\"params\":");
        self.params.put(out, resolve);
        out.push(b'}');
    }
}

impl ParsedRequest {
    /// The distinct tags that must be resolved before [`ParsedRequest::outgoing`], sorted.
    pub fn tags(&self) -> Vec<BlockTag> {
        let mut tags: Vec<BlockTag> = self
            .calls
            .iter()
            .flat_map(|c| c.params.blocks())
            .flatten()
            .filter_map(|b| match b {
                Block::Tag(t) => Some(*t),
                _ => None,
            })
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }

    /// The `eth_getLogs` range rule once tags are resolved: every range-form filter must span
    /// `from <= to` and at most [`MAX_LOG_RANGE`] blocks. Call it with the same `resolve` as
    /// [`ParsedRequest::outgoing`], before sending.
    pub fn check_after_resolution(&self, resolve: &dyn Fn(BlockTag) -> u64) -> Result<(), Denied> {
        for c in &self.calls {
            if let Params::Logs(Filter {
                range: LogRange::Blocks { from, to },
                ..
            }) = &c.params
            {
                if let (Some(a), Some(b)) = (from.number(resolve), to.number(resolve)) {
                    log_range_ok(a, b)?;
                }
            }
        }
        Ok(())
    }

    /// Whether the request is framed as a JSON array (a batch, or anything but exactly one call).
    fn framed_as_array(&self) -> bool {
        self.batch || self.calls.len() != 1
    }

    /// The outgoing JSON-RPC body: the broker's own ids `first_id..first_id+n`, its own batch
    /// framing (always an array when `self.batch`), params re-encoded from the parsed form, tags
    /// replaced by `resolve(tag)`, `eth_call`/`eth_createAccessList` gas capped.
    ///
    /// Ids wrap around `u64::MAX` (as [`parse_answers`] expects); keep them at most `2^53 - 1` for
    /// nodes whose JSON numbers are doubles.
    pub fn outgoing(&self, resolve: &dyn Fn(BlockTag) -> u64, first_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 * self.calls.len());
        let array = self.framed_as_array();
        if array {
            out.push(b'[');
        }
        for (i, c) in self.calls.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            c.put(&mut out, Some(first_id.wrapping_add(i as u64)), resolve);
        }
        if array {
            out.push(b']');
        }
        out
    }

    /// Calls `indices` only, as a sub-request (for partial cache hits). Keeps `batch`, so a subset of
    /// a batch is still framed as an array. Panics if an index is out of range (a caller bug).
    pub fn subset(&self, indices: &[usize]) -> ParsedRequest {
        ParsedRequest {
            calls: indices.iter().map(|&i| self.calls[i].clone()).collect(),
            batch: self.batch,
        }
    }

    /// The cache key of call `i` — its canonical outgoing form without an id — if its answer is
    /// pinned to a block hash (EIP-1898 `blockHash` or a by-hash block method); `None` otherwise.
    ///
    /// Pinned: `eth_getBlockByHash`; `eth_getBlockReceipts` by hash; the state methods
    /// (`eth_getBalance`, `eth_getCode`, `eth_getTransactionCount`, `eth_getStorageAt`,
    /// `eth_getProof`, `eth_call`, `eth_createAccessList`) with an EIP-1898 `blockHash`. Never a tag,
    /// a number, a by-transaction-hash method, `eth_getLogs` (see `Params::pinned_to_hash`), or
    /// `requireCanonical: true` (its answer turns into an error after a reorg).
    pub fn cache_key(&self, i: usize) -> Option<Vec<u8>> {
        let c = self.calls.get(i)?;
        if !c.params.pinned_to_hash() {
            return None;
        }
        let mut out = Vec::new();
        // A hash-pinned call has no tag left to resolve.
        c.put(&mut out, None, &|_| 0);
        Some(out)
    }
}

// ------------------------------------------------------------------------------------------------
// Answers.

/// Substrings of a lower-cased error message that mean the node lacks the block or its state.
pub const LAGGING_MESSAGES: &[&str] = &[
    "header not found",  // geth, erigon, nethermind: block past the head or unknown
    "missing trie node", // geth, erigon: pruned state
    "unknown block",     // geth
    "block not found",   // reth, besu, erigon; "finalized block not found" before the merge
    "historical state",  // geth path scheme: "historical state … is not available"
    "state not available",
    "state is not available",
    "state unavailable",
    "is pruned",      // reth: "state at block #… is pruned"
    "pruned history", // geth history expiry: "pruned history unavailable"
    "node is syncing",
];

fn is_lagging_error(code: i64, message: &[u8]) -> bool {
    if code == 3 {
        return false;
    }
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.windows(needle.len()).any(|w| w == needle.as_bytes());
    !has("revert") && LAGGING_MESSAGES.iter().any(|p| has(p))
}

const ENVELOPE_HEAD: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":";
const RESULT_KEY: &[u8] = b",\"result\":";
const ERROR_KEY: &[u8] = b",\"error\":";

fn put_id(out: &mut Vec<u8>, id: &RpcId) {
    match id {
        RpcId::Num(n) => out.extend_from_slice(n.to_string().as_bytes()),
        RpcId::Str(s) => canon::put_str(out, s),
    }
}

/// What [`render`] adds around the answers (every answer counted as a result, the longer key).
fn render_overhead(req: &ParsedRequest) -> usize {
    let n = req.calls.len();
    let framing = if req.framed_as_array() {
        2 + n.saturating_sub(1)
    } else {
        0
    };
    let mut id = Vec::new();
    framing
        + req
            .calls
            .iter()
            .map(|c| {
                id.clear();
                put_id(&mut id, &c.id);
                ENVELOPE_HEAD.len() + id.len() + RESULT_KEY.len() + 1
            })
            .sum::<usize>()
}

/// Parses the endpoint's answer to `req.outgoing(_, first_id)` into per-call canonical answers in
/// request order, streaming (no value tree), rejecting more than `max_bytes` of canonical output.
/// Applies the mempool rule (`eth_getTransactionByHash` with a null `blockHash` → null).
///
/// `max_bytes` bounds `render(req, answers).len()`. The answers come back in request order whatever
/// order a batch was answered in; a missing, duplicate or unknown id is [`ResponseError::Mismatch`].
/// See the module doc for the canonical form and the lagging heuristics.
pub fn parse_answers(
    req: &ParsedRequest,
    body: &[u8],
    first_id: u64,
    max_bytes: usize,
) -> Result<Vec<CallAnswer>, ResponseError> {
    let n = req.calls.len();
    let mut budget = Budget {
        used: 0,
        max: max_bytes,
    };
    budget.charge(render_overhead(req))?;
    let mut slots: Vec<Option<CallAnswer>> = vec![None; n];
    let mut sc = Scanner::new(body);
    if req.framed_as_array() {
        sc.expect(b'[')?;
        sc.ws();
        if sc.peek() == Some(b']') {
            sc.bump();
        } else {
            loop {
                let (id, payload) = sc.envelope(2, &mut budget, 0)?;
                place(req, &mut slots, &mut budget, first_id, id, payload)?;
                sc.ws();
                match sc.bump() {
                    Some(b',') => {}
                    Some(b']') => break,
                    _ => return Err(ResponseError::Malformed),
                }
            }
        }
    } else {
        // The canonical answer is never longer than the body: size it once.
        let reserve = body.len().min(budget.max.saturating_sub(budget.used));
        let (id, payload) = sc.envelope(1, &mut budget, reserve)?;
        place(req, &mut slots, &mut budget, first_id, id, payload)?;
    }
    if !sc.at_end() {
        return Err(ResponseError::Malformed);
    }
    slots
        .into_iter()
        .map(|s| s.ok_or(ResponseError::Mismatch))
        .collect()
}

fn place(
    req: &ParsedRequest,
    slots: &mut [Option<CallAnswer>],
    budget: &mut Budget,
    first_id: u64,
    id: Option<u64>,
    payload: Body,
) -> Result<(), ResponseError> {
    let idx = id
        .map(|id| id.wrapping_sub(first_id))
        .filter(|&i| i < slots.len() as u64)
        .ok_or(ResponseError::Mismatch)? as usize;
    if slots[idx].is_some() {
        return Err(ResponseError::Mismatch);
    }
    let call = &req.calls[idx];
    let answer = match payload {
        Body::Error { lagging: true, .. } => return Err(ResponseError::Lagging),
        Body::Error {
            canon,
            lagging: false,
        } => CallAnswer {
            canonical: canon,
            is_error: true,
        },
        Body::Result {
            kind: Kind::Null, ..
        } if !call.params.null_is_an_answer() => return Err(ResponseError::Lagging),
        Body::Result { mut canon, kind } => {
            if call.method == Method::EthGetTransactionByHash
                && kind == Kind::Object
                && matches!(top_level_field(&canon, "blockHash"), None | Some(b"null"))
            {
                budget.refund(canon.len());
                budget.charge(4)?;
                canon = b"null".to_vec();
            }
            CallAnswer {
                canonical: canon,
                is_error: false,
            }
        }
    };
    slots[idx] = Some(answer);
    Ok(())
}

/// The bytes `response_read` returns: `{"jsonrpc":"2.0","id":…,"result":…}` /
/// `{"jsonrpc":"2.0","id":…,"error":{…}}`, or an array of them in request order when `req.batch`.
///
/// `answers` is [`parse_answers`]' output for `req` (one per call, in order; extra or missing ones
/// are a caller bug: the shorter of the two is rendered).
pub fn render(req: &ParsedRequest, answers: &[CallAnswer]) -> Vec<u8> {
    debug_assert_eq!(req.calls.len(), answers.len());
    let array = req.framed_as_array();
    let mut out = Vec::with_capacity(
        render_overhead(req) + answers.iter().map(|a| a.canonical.len()).sum::<usize>(),
    );
    if array {
        out.push(b'[');
    }
    for (i, (c, a)) in req.calls.iter().zip(answers).enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(ENVELOPE_HEAD);
        put_id(&mut out, &c.id);
        out.extend_from_slice(if a.is_error { ERROR_KEY } else { RESULT_KEY });
        out.extend_from_slice(&a.canonical);
        out.push(b'}');
    }
    if array {
        out.push(b']');
    }
    out
}

/// `eth_getBlockByNumber(tag, false)` with id `id`, for tag resolution.
pub fn tag_query(tag: BlockTag, id: u64) -> Vec<u8> {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"eth_getBlockByNumber\",\"params\":[\"{}\",false]}}",
        tag.as_str()
    )
    .into_bytes()
}

/// The block number from a [`tag_query`] answer.
///
/// The block's top-level `number` (`0x` plus 1..=16 hex digits; node output, so case and leading
/// zeros are tolerated). A `null` result, or an error matching the lagging heuristics (e.g. `safe` on
/// a chain without it: "safe block not found"), is `Lagging`; another error or a block without a
/// number is `Malformed`; another id is `Mismatch`.
pub fn parse_tag_answer(body: &[u8], id: u64) -> Result<u64, ResponseError> {
    let mut budget = Budget {
        used: 0,
        max: usize::MAX,
    };
    let mut sc = Scanner::new(body);
    let (rid, payload) = sc.envelope(1, &mut budget, 0)?;
    if !sc.at_end() {
        return Err(ResponseError::Malformed);
    }
    if rid != Some(id) {
        return Err(ResponseError::Mismatch);
    }
    match payload {
        Body::Error { lagging: true, .. }
        | Body::Result {
            kind: Kind::Null, ..
        } => Err(ResponseError::Lagging),
        Body::Result {
            canon,
            kind: Kind::Object,
        } => {
            let v = top_level_field(&canon, "number").ok_or(ResponseError::Malformed)?;
            let digits = v
                .strip_prefix(b"\"0x")
                .and_then(|d| d.strip_suffix(b"\""))
                .filter(|d| !d.is_empty() && d.len() <= 16 && d.iter().all(u8::is_ascii_hexdigit))
                .ok_or(ResponseError::Malformed)?;
            Ok(digits_u64(digits))
        }
        Body::Error { .. } | Body::Result { .. } => Err(ResponseError::Malformed),
    }
}
