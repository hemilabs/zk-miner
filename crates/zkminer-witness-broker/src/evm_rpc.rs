//! `evm-rpc/v1` (plan §11.2): the strict request parser, the broker-built outgoing request, and the
//! canonical response. Pure functions: no I/O. The broker process (`job.rs`, `endpoints.rs`) owns the
//! network, failover, budgets and caches and calls into this module.
//!
//! INTERFACE CONTRACT (fixed for milestone 2; the bodies are implemented on max/witness-broker-rpc).

use zkminer_witness::envelope::MethodSet;

pub const MAX_BATCH: usize = 32;
pub const MAX_JSON_DEPTH: usize = 32;
pub const CALL_GAS_CAP: u64 = 30_000_000;
pub const MAX_LOG_RANGE: u64 = 10_000;
pub const MAX_LOG_ADDRESSES: usize = 8;
pub const MAX_TOPIC_VALUES: usize = 8;
pub const MAX_PROOF_KEYS: usize = 256;

/// Symbolic block tags the broker resolves to a number before sending (`pending`/`earliest` are
/// rejected at parse time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockTag {
    Latest,
    Safe,
    Finalized,
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

/// One validated call in the broker's own representation (never the builder's bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub id: RpcId,
    pub method: Method,
    /// Canonical params with symbolic tags; private representation.
    params: Vec<u8>,
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

/// Parses and validates builder request bytes under `set` (exact keys, canonical numbers, hex data,
/// per-method caps).
pub fn parse_request(bytes: &[u8], set: MethodSet) -> Result<ParsedRequest, Denied> {
    let _ = (bytes, set);
    todo!("max/witness-broker-rpc")
}

impl ParsedRequest {
    /// The distinct tags that must be resolved before [`ParsedRequest::outgoing`].
    pub fn tags(&self) -> Vec<BlockTag> {
        todo!("max/witness-broker-rpc")
    }

    /// The outgoing JSON-RPC body: the broker's own ids `first_id..first_id+n`, its own batch
    /// framing (always an array when `self.batch`), params re-encoded from the parsed form, tags
    /// replaced by `resolve(tag)`, `eth_call`/`eth_createAccessList` gas capped.
    pub fn outgoing(&self, resolve: &dyn Fn(BlockTag) -> u64, first_id: u64) -> Vec<u8> {
        let _ = (resolve, first_id);
        todo!("max/witness-broker-rpc")
    }

    /// Calls `indices` only, as a sub-request (for partial cache hits).
    pub fn subset(&self, indices: &[usize]) -> ParsedRequest {
        let _ = indices;
        todo!("max/witness-broker-rpc")
    }

    /// The cache key of call `i` — its canonical outgoing form without an id — if its answer is
    /// pinned to a block hash (EIP-1898 `blockHash` or a by-hash block method); `None` otherwise.
    pub fn cache_key(&self, i: usize) -> Option<Vec<u8>> {
        let _ = i;
        todo!("max/witness-broker-rpc")
    }
}

/// Parses the endpoint's answer to `req.outgoing(_, first_id)` into per-call canonical answers in
/// request order, streaming (no value tree), rejecting more than `max_bytes` of canonical output.
/// Applies the mempool rule (`eth_getTransactionByHash` with a null `blockHash` → null).
pub fn parse_answers(
    req: &ParsedRequest,
    body: &[u8],
    first_id: u64,
    max_bytes: usize,
) -> Result<Vec<CallAnswer>, ResponseError> {
    let _ = (req, body, first_id, max_bytes);
    todo!("max/witness-broker-rpc")
}

/// The bytes `response_read` returns: `{"jsonrpc":"2.0","id":…,"result":…}` /
/// `{"jsonrpc":"2.0","id":…,"error":{…}}`, or an array of them in request order when `req.batch`.
pub fn render(req: &ParsedRequest, answers: &[CallAnswer]) -> Vec<u8> {
    let _ = (req, answers);
    todo!("max/witness-broker-rpc")
}

/// `eth_getBlockByNumber(tag, false)` with id `id`, for tag resolution.
pub fn tag_query(tag: BlockTag, id: u64) -> Vec<u8> {
    let _ = (tag, id);
    todo!("max/witness-broker-rpc")
}

/// The block number from a [`tag_query`] answer.
pub fn parse_tag_answer(body: &[u8], id: u64) -> Result<u64, ResponseError> {
    let _ = (body, id);
    todo!("max/witness-broker-rpc")
}
