//! The broker's seams over its two pure modules: [`crate::egress`] (the network floor and log
//! redaction) and [`crate::evm_rpc`] (the strict JSON-RPC codec). Production uses [`Hooks::real`],
//! which calls those modules; tests can substitute their own to exercise the broker's logic
//! (failover, budgets, caches, lanes) independently.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use zkminer_witness::envelope::MethodSet;

use crate::egress::{self, Admit, EgressPolicy, Prefix, Role};
use crate::evm_rpc::{self, BlockTag, CallAnswer, Denied, ParsedRequest, ResponseError};

/// Longest log line built from untrusted bytes.
pub const LOG_MAX: usize = 512;

/// The network floor and log redaction.
pub trait EgressHooks: Send + Sync + 'static {
    /// [`EgressPolicy::admit`].
    fn admit(&self, policy: &EgressPolicy, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit;
    /// [`egress::connected_prefixes`] (only callable before the sandbox is applied).
    fn connected_prefixes(&self) -> io::Result<Vec<Prefix>>;
    /// `redact_urls(sanitize_log(…))`: every log line built from an error or untrusted bytes.
    fn redact(&self, s: &str) -> String;
}

/// [`EgressHooks`] over [`crate::egress`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RealEgress;

impl EgressHooks for RealEgress {
    fn admit(&self, policy: &EgressPolicy, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit {
        policy.admit(role, addr)
    }
    fn connected_prefixes(&self) -> io::Result<Vec<Prefix>> {
        egress::connected_prefixes()
    }
    fn redact(&self, s: &str) -> String {
        egress::redact_urls(&egress::sanitize_log(s.as_bytes(), LOG_MAX))
    }
}

/// The `evm-rpc/v1` codec: parses builder bytes into a request.
pub trait RpcCodec: Send + Sync + 'static {
    /// [`evm_rpc::parse_request`].
    fn parse(&self, bytes: &[u8], set: MethodSet) -> Result<Box<dyn RpcReq>, Denied>;
    /// [`evm_rpc::tag_query`].
    fn tag_query(&self, tag: BlockTag, id: u64) -> Vec<u8>;
    /// [`evm_rpc::parse_tag_answer`].
    fn parse_tag_answer(&self, body: &[u8], id: u64) -> Result<u64, ResponseError>;
}

/// A validated request ([`ParsedRequest`] in production).
pub trait RpcReq: Send + Sync {
    /// Calls in the request (the units it is charged).
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn tags(&self) -> Vec<BlockTag>;
    /// Checks that need the resolved tags (the `eth_getLogs` range).
    fn check_after_resolution(&self, resolve: &dyn Fn(BlockTag) -> u64) -> Result<(), Denied>;
    fn outgoing(&self, resolve: &dyn Fn(BlockTag) -> u64, first_id: u64) -> Vec<u8>;
    fn subset(&self, indices: &[usize]) -> Box<dyn RpcReq>;
    fn cache_key(&self, i: usize) -> Option<Vec<u8>>;
    fn parse_answers(&self, body: &[u8], first_id: u64, max_bytes: usize) -> Result<Vec<CallAnswer>, ResponseError>;
    fn render(&self, answers: &[CallAnswer]) -> Vec<u8>;
}

/// [`RpcCodec`] over [`crate::evm_rpc`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RealCodec;

impl RpcCodec for RealCodec {
    fn parse(&self, bytes: &[u8], set: MethodSet) -> Result<Box<dyn RpcReq>, Denied> {
        Ok(Box::new(evm_rpc::parse_request(bytes, set)?))
    }
    fn tag_query(&self, tag: BlockTag, id: u64) -> Vec<u8> {
        evm_rpc::tag_query(tag, id)
    }
    fn parse_tag_answer(&self, body: &[u8], id: u64) -> Result<u64, ResponseError> {
        evm_rpc::parse_tag_answer(body, id)
    }
}

impl RpcReq for ParsedRequest {
    fn len(&self) -> usize {
        self.calls.len()
    }
    fn tags(&self) -> Vec<BlockTag> {
        ParsedRequest::tags(self)
    }
    fn check_after_resolution(&self, resolve: &dyn Fn(BlockTag) -> u64) -> Result<(), Denied> {
        // TODO(merge): `ParsedRequest::check_after_resolution(self, resolve)` (the eth_getLogs range
        // with tags resolved) once evm_rpc.rs gains it; until then parse-time checks are all.
        let _ = resolve;
        Ok(())
    }
    fn outgoing(&self, resolve: &dyn Fn(BlockTag) -> u64, first_id: u64) -> Vec<u8> {
        ParsedRequest::outgoing(self, resolve, first_id)
    }
    fn subset(&self, indices: &[usize]) -> Box<dyn RpcReq> {
        Box::new(ParsedRequest::subset(self, indices))
    }
    fn cache_key(&self, i: usize) -> Option<Vec<u8>> {
        ParsedRequest::cache_key(self, i)
    }
    fn parse_answers(&self, body: &[u8], first_id: u64, max_bytes: usize) -> Result<Vec<CallAnswer>, ResponseError> {
        evm_rpc::parse_answers(self, body, first_id, max_bytes)
    }
    fn render(&self, answers: &[CallAnswer]) -> Vec<u8> {
        evm_rpc::render(self, answers)
    }
}

/// The seams a broker runs with.
#[derive(Clone)]
pub struct Hooks {
    pub egress: Arc<dyn EgressHooks>,
    pub codec: Arc<dyn RpcCodec>,
}

impl Hooks {
    pub fn real() -> Self {
        Self { egress: Arc::new(RealEgress), codec: Arc::new(RealCodec) }
    }
}
