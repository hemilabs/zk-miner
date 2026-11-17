//! The connector (review r2 F5): every TCP connection the broker uses is made by the **miner**, not
//! by the broker.
//!
//! The broker parses untrusted input (builder requests, endpoint answers), so it is the process an
//! attacker is most likely to get code execution in. Its sandbox therefore gives it no network at
//! all: `socket`, `connect`, `bind`, `listen` and `accept*` are denied (and Landlock grants no TCP
//! port), and after its runtime starts not even `socketpair` remains. What it has is one `AF_UNIX`
//! stream socket to the miner's connector, at fd [`zkminer_witness::ipc::BROKER_CONNECTOR_FD`],
//! created by the miner before `exec`.
//!
//! # The protocol (version 1)
//!
//! The broker asks for a connection with a fixed 32-byte [`Request`]: an operator **endpoint
//! index** (the position in [`crate::config::BrokerConfig::endpoints`]: the `evm_rpc` entries, the
//! blob mirrors, the artifact endpoint, its mirror), the role and port it expects there (checked,
//! never used), and a request id. Nothing in it is a host, an address or a name: the broker can only
//! *name* an endpoint the operator configured.
//!
//! The connector ([`server::Connector`], in the miner, trusted, unsandboxed, never parsing job
//! content) answers with a fixed 40-byte [`Response`] carrying the id and a [`Status`]; on
//! [`Status::Connected`] the connected TCP socket travels with it as `SCM_RIGHTS`, attached to the
//! response's first byte, together with the peer address. Before answering it:
//!
//! 1. validates the request against the broker configuration **it loaded itself** from the
//!    operator's file (never anything read back from the broker): the index exists, the role and
//!    port match it;
//! 2. resolves the endpoint's host name itself, with the broker's stub resolver ([`crate::dns`])
//!    aimed at `[dns] servers` (else `/etc/resolv.conf`'s), and keeps only the answers the role
//!    entry admits (its `cidrs`, else the public floor);
//! 3. admits each candidate address: the role entry (explicit `cidrs`, the URL's IP literal, or
//!    the current DNS answer) and, in public mode — and for every DNS-derived address in either
//!    mode — netguard's full public floor with the miner's host facts, its `[egress] deny_cidrs`,
//!    the broker file's deny CIDRs and the DNS servers. Developer mode comes only from the miner's
//!    own `net_mode()`;
//! 4. connects with the configured connect timeout, trying the admitted addresses in order.
//!
//! Host-name resolution lives here, not in the broker: the broker never resolves anything, so it
//! needs no DNS server as a destination either. The connector can only ever produce a connection
//! to a configured endpoint's admitted address, and the broker cannot point a socket it was handed
//! anywhere else: its sandbox denies `connect` (no `connect(AF_UNSPEC)` and reconnect; TCP Fast
//! Open to another address fails on a connected socket) and every `setsockopt` but
//! `IPPROTO_TCP`/`TCP_NODELAY` (no IPv6 routing header, IPv4 source route, interface binding, next
//! hop or mark), TCP ignores IP-level control messages on `sendmsg`, and the sandbox holds no
//! capability (a per-packet `SO_MARK` needs `CAP_NET_ADMIN`).
//!
//! # Limits and cut-off
//!
//! The broker is hostile input. Frames are decoded strictly (magic, version, operation, role, every
//! reserved byte zero); a frame that fails, an fd sent *to* the connector, more than
//! [`MAX_INFLIGHT`] requests in flight, a request id already in flight, more than
//! [`MAX_MISUSE`] requests naming an index or role/port that does not exist within
//! [`MISUSE_WINDOW`] (checked before the refusal is answered), an answer the broker leaves unread
//! for longer than [`request_budget`], or a failed answer write while the broker keeps sending (it
//! shut its reading side) **cuts the broker off**: the connector closes the socket and aborts the
//! requests it is still serving, the miner pages and kills the broker and the builder runners
//! registered with it (`zkminer-witness-host`). An honest broker can produce none of these (its client keeps the same
//! in-flight bound and reads every answer). A request stays in flight until its answer is handed
//! to the socket, so a broker that stops reading cannot make the miner hold more than
//! [`MAX_INFLIGHT`] connected sockets (and the one being written); the socket's send buffer is the
//! kernel's minimum, so the kernel holds only a few written answers it has not read either. A
//! broker that exits ends its session closed (its requests end at end-of-file), and requests still
//! being served are aborted then too. Connection attempts are paced by a token bucket ([`RATE_BURST`] at once,
//! [`RATE_PER_SEC`] a second — a hard budget of `RATE_BURST + RATE_PER_SEC × t` attempts in any
//! interval `t`) and at most the endpoint's `max_concurrency` are in flight per endpoint; past them
//! a request waits, and is answered [`Status::RateLimited`] when its time runs out. A request is
//! always answered within [`request_budget`].

pub mod client;
pub mod server;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::egress::Role;

pub use client::{ConnectError, ConnectorClient};
pub use server::{Connector, CutOff, SessionEnd};

/// Bytes in a request frame.
pub const REQUEST_LEN: usize = 32;
/// Bytes in a response frame.
pub const RESPONSE_LEN: usize = 40;
const REQUEST_MAGIC: [u8; 4] = *b"zkcq";
const RESPONSE_MAGIC: [u8; 4] = *b"zkcr";
/// The protocol version both sides speak.
pub const VERSION: u8 = 1;
const OP_CONNECT: u8 = 1;

/// Requests in flight per broker session, on both sides.
pub const MAX_INFLIGHT: usize = 64;
/// Connection attempts the bucket holds at once.
pub const RATE_BURST: u32 = 64;
/// Connection attempts the bucket refills per second.
pub const RATE_PER_SEC: u32 = 16;
/// Requests naming no endpoint (or the wrong role or port) tolerated within [`MISUSE_WINDOW`].
pub const MAX_MISUSE: usize = 8;
pub const MISUSE_WINDOW: Duration = Duration::from_secs(60);
/// The longest host-name resolution a request may wait for.
pub const RESOLVE_BUDGET: Duration = Duration::from_secs(10);

/// How long the connector may take to answer one request with connect timeout `connect`: the
/// resolution, the connect, and two seconds of queueing. It always answers within it.
pub fn request_budget(connect: Duration) -> Duration {
    connect + RESOLVE_BUDGET + Duration::from_secs(2)
}

/// A frame that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed connector frame: {0}")]
pub struct Malformed(pub &'static str);

/// The wire tag of a role.
pub fn role_tag(r: Role) -> u8 {
    match r {
        Role::EvmRpc => 1,
        Role::Artifact => 2,
        Role::BlobMirror => 3,
        Role::ArtifactMirror => 4,
    }
}

fn role_from_tag(t: u8) -> Option<Role> {
    Some(match t {
        1 => Role::EvmRpc,
        2 => Role::Artifact,
        3 => Role::BlobMirror,
        4 => Role::ArtifactMirror,
        _ => return None,
    })
}

/// Broker → connector: "a connection to endpoint `endpoint`, which I believe is a `role` on
/// `port`". Layout (big-endian): `magic "zkcq" ‖ version u8 ‖ op u8 (1 = connect) ‖ role u8 ‖ 0 ‖
/// endpoint u32 ‖ port u16 ‖ 0 0 ‖ id u64 ‖ 8 × 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    pub endpoint: u32,
    pub role: Role,
    pub port: u16,
}

impl Request {
    pub fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut b = [0u8; REQUEST_LEN];
        b[0..4].copy_from_slice(&REQUEST_MAGIC);
        b[4] = VERSION;
        b[5] = OP_CONNECT;
        b[6] = role_tag(self.role);
        b[8..12].copy_from_slice(&self.endpoint.to_be_bytes());
        b[12..14].copy_from_slice(&self.port.to_be_bytes());
        b[16..24].copy_from_slice(&self.id.to_be_bytes());
        b
    }

    /// Strict: the magic, version 1, operation 1, a known role, and every reserved byte zero.
    pub fn decode(b: &[u8; REQUEST_LEN]) -> Result<Self, Malformed> {
        if b[0..4] != REQUEST_MAGIC {
            return Err(Malformed("magic"));
        }
        if b[4] != VERSION {
            return Err(Malformed("version"));
        }
        if b[5] != OP_CONNECT {
            return Err(Malformed("operation"));
        }
        let role = role_from_tag(b[6]).ok_or(Malformed("role"))?;
        if b[7] != 0 || b[14..16] != [0, 0] || b[24..32] != [0; 8] {
            return Err(Malformed("reserved bytes"));
        }
        Ok(Request {
            role,
            endpoint: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            port: u16::from_be_bytes([b[12], b[13]]),
            id: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        })
    }
}

/// The connector's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// The connected socket is attached; the peer is the address it is connected to.
    Connected = 0,
    /// No endpoint has that index in the miner's configuration.
    NoSuchEndpoint = 1,
    /// The endpoint at that index has another role or port.
    Mismatch = 2,
    /// No address of the endpoint is admitted (the host name does not resolve, or every answer
    /// is refused by the role entry or the floor).
    NotAdmitted = 3,
    /// Admitted addresses exist, but connecting to every one failed or timed out.
    Unreachable = 4,
    /// The rate or concurrency limit held the request until its time ran out.
    RateLimited = 5,
    /// The connector failed locally (no socket, a resolver task panicked).
    Internal = 6,
}

impl Status {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Status::Connected,
            1 => Status::NoSuchEndpoint,
            2 => Status::Mismatch,
            3 => Status::NotAdmitted,
            4 => Status::Unreachable,
            5 => Status::RateLimited,
            6 => Status::Internal,
            _ => return None,
        })
    }
}

/// Connector → broker. Layout (big-endian): `magic "zkcr" ‖ version u8 ‖ status u8 ‖ family u8 (0
/// none, 4, 6) ‖ 0 ‖ id u64 ‖ port u16 ‖ 6 × 0 ‖ address [16]` (IPv4 in the last four bytes, the rest
/// zero). A peer is present exactly when the status is [`Status::Connected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub id: u64,
    pub status: Status,
    pub peer: Option<SocketAddr>,
}

impl Response {
    pub fn refused(id: u64, status: Status) -> Self {
        Response { id, status, peer: None }
    }

    pub fn encode(&self) -> [u8; RESPONSE_LEN] {
        let mut b = [0u8; RESPONSE_LEN];
        b[0..4].copy_from_slice(&RESPONSE_MAGIC);
        b[4] = VERSION;
        b[5] = self.status as u8;
        b[8..16].copy_from_slice(&self.id.to_be_bytes());
        if let Some(p) = self.peer {
            b[16..18].copy_from_slice(&p.port().to_be_bytes());
            match p.ip() {
                IpAddr::V4(v4) => {
                    b[6] = 4;
                    b[36..40].copy_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    b[6] = 6;
                    b[24..40].copy_from_slice(&v6.octets());
                }
            }
        }
        b
    }

    /// Strict, like [`Request::decode`].
    pub fn decode(b: &[u8; RESPONSE_LEN]) -> Result<Self, Malformed> {
        if b[0..4] != RESPONSE_MAGIC {
            return Err(Malformed("magic"));
        }
        if b[4] != VERSION {
            return Err(Malformed("version"));
        }
        let status = Status::from_u8(b[5]).ok_or(Malformed("status"))?;
        if b[7] != 0 || b[18..24] != [0; 6] {
            return Err(Malformed("reserved bytes"));
        }
        let id = u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
        let port = u16::from_be_bytes([b[16], b[17]]);
        let addr: [u8; 16] = b[24..40].try_into().map_err(|_| Malformed("address"))?;
        let peer = match b[6] {
            0 => {
                if port != 0 || addr != [0; 16] {
                    return Err(Malformed("peer without a family"));
                }
                None
            }
            4 => {
                if addr[..12] != [0; 12] {
                    return Err(Malformed("IPv4 address"));
                }
                Some(SocketAddr::new(IpAddr::from([addr[12], addr[13], addr[14], addr[15]]), port))
            }
            6 => Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port)),
            _ => return Err(Malformed("family")),
        };
        if peer.is_some() != (status == Status::Connected) {
            return Err(Malformed("a peer exactly when connected"));
        }
        Ok(Response { id, status, peer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn requests_round_trip_and_reject_every_deviation() {
        for role in [Role::EvmRpc, Role::Artifact, Role::BlobMirror, Role::ArtifactMirror] {
            let r = Request { id: 0x0102_0304_0506_0708, endpoint: 7, role, port: 8545 };
            assert_eq!(Request::decode(&r.encode()), Ok(r));
        }
        let good = Request { id: 1, endpoint: 0, role: Role::EvmRpc, port: 443 }.encode();
        // Every byte outside the id, endpoint and port fields is checked.
        for i in (0..REQUEST_LEN).filter(|i| !(8..14).contains(i) && !(16..24).contains(i)) {
            for v in [1u8, 0x80, 0xff] {
                let mut b = good;
                b[i] ^= v;
                if i == 6 && role_from_tag(b[6]).is_some() {
                    continue;
                }
                assert!(Request::decode(&b).is_err(), "byte {i} ^ {v:#x} accepted");
            }
        }
    }

    #[test]
    fn responses_round_trip_and_reject_every_deviation() {
        let peers = [None, Some("203.0.113.9:443".parse().unwrap()), Some("[2001:db8::1]:8545".parse().unwrap())];
        for peer in peers {
            let status = if peer.is_some() { Status::Connected } else { Status::NotAdmitted };
            let r = Response { id: 9, status, peer };
            assert_eq!(Response::decode(&r.encode()), Ok(r));
        }
        // A peer without Connected, Connected without a peer, an IPv4 with high bytes set.
        let mut b = Response { id: 1, status: Status::Connected, peer: Some("1.2.3.4:5".parse().unwrap()) }.encode();
        b[5] = Status::Unreachable as u8;
        assert!(Response::decode(&b).is_err());
        let b = Response::refused(1, Status::Connected).encode();
        assert!(Response::decode(&b).is_err());
        let mut b = Response { id: 1, status: Status::Connected, peer: Some("1.2.3.4:5".parse().unwrap()) }.encode();
        b[24] = 1;
        assert!(Response::decode(&b).is_err());
        for (i, v) in [(0usize, 1u8), (4, 2), (5, 7), (6, 5), (7, 1), (18, 1), (23, 1)] {
            let mut b = Response::refused(1, Status::NotAdmitted).encode();
            b[i] = v;
            assert!(Response::decode(&b).is_err(), "byte {i} = {v}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]

        /// The decoders never panic, and anything they accept re-encodes to the same bytes.
        #[test]
        fn decoders_never_panic_and_are_canonical(
            req in prop::array::uniform32(any::<u8>()),
            resp in prop::collection::vec(any::<u8>(), RESPONSE_LEN),
            keep_magic in any::<bool>(),
        ) {
            let mut req = req;
            let mut resp: [u8; RESPONSE_LEN] = resp.try_into().unwrap();
            if keep_magic {
                req[0..4].copy_from_slice(&REQUEST_MAGIC);
                req[4] = VERSION;
                req[5] = OP_CONNECT;
                resp[0..4].copy_from_slice(&RESPONSE_MAGIC);
                resp[4] = VERSION;
            }
            if let Ok(r) = Request::decode(&req) {
                prop_assert_eq!(r.encode(), req);
            }
            if let Ok(r) = Response::decode(&resp) {
                prop_assert_eq!(r.encode(), resp);
            }
        }
    }
}
