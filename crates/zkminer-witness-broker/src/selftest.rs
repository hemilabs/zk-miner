//! The broker's self-test (plan §10.3): the network floor refuses loopback, the metadata service, an
//! RFC 1918 address, the host's own addresses and its connected prefixes — on the requester path,
//! and for every operator role except the endpoints explicitly configured at that address — and the
//! artifact and `evm-rpc` endpoints answer with their configured chain ids.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;

use zkminer_witness::ipc::{ControlResponse, SelfTestCheck};

use crate::broker::Broker;
use crate::config::{mask, prefix_contains};
use crate::egress::{Admit, EgressPolicy, Prefix};
use crate::hooks::EgressHooks;
use crate::jsonrpc::RpcClient;

const LOOPBACK: [&str; 2] = ["127.0.0.1", "::1"];
const METADATA: [&str; 2] = ["169.254.169.254", "fd00:ec2::254"];
const RFC1918: [&str; 3] = ["10.0.0.1", "172.16.0.1", "192.168.1.1"];

/// Whether `ip` is refused on the requester path (ports 443 and 80) and for every role entry that
/// was not configured at that address.
fn floor_denies(eg: &dyn EgressHooks, policy: &EgressPolicy, ip: IpAddr) -> bool {
    let denied = |a: Admit| matches!(a, Admit::Denied(_));
    if ![443, 80].into_iter().all(|port| denied(eg.admit(policy, None, SocketAddr::new(ip, port)))) {
        return false;
    }
    policy.roles.iter().all(|e| {
        e.prefixes.iter().any(|p| prefix_contains(p, ip))
            || denied(eg.admit(policy, Some((e.role, &e.alias)), SocketAddr::new(ip, e.port)))
    })
}

/// Addresses to probe inside a connected prefix: the address given and the prefix's first host.
fn probes(p: &Prefix) -> Vec<IpAddr> {
    let net = mask(p.addr, p.len);
    let first = match net {
        IpAddr::V4(v) if p.len < 32 => IpAddr::V4((u32::from(v) + 1).into()),
        IpAddr::V6(v) if p.len < 128 => IpAddr::V6((u128::from(v) + 1).into()),
        other => other,
    };
    let mut v = vec![p.addr];
    if first != p.addr {
        v.push(first);
    }
    v
}

pub(crate) async fn run(b: &Broker) -> ControlResponse {
    let policy = b.policy.read().unwrap_or_else(|p| p.into_inner()).clone();
    let own = b.own_addresses.read().unwrap_or_else(|p| p.into_inner()).clone();
    let eg = &*b.hooks.egress;
    let all = |ips: &[&str]| ips.iter().all(|s| floor_denies(eg, &policy, s.parse().expect("constant address")));
    let mut checks = vec![
        (SelfTestCheck::LoopbackDenied, all(&LOOPBACK)),
        (SelfTestCheck::MetadataDenied, all(&METADATA)),
        (SelfTestCheck::Rfc1918Denied, all(&RFC1918)),
        (SelfTestCheck::OwnAddressDenied, own.iter().all(|ip| floor_denies(eg, &policy, *ip))),
        (
            SelfTestCheck::ConnectedPrefixDenied,
            policy.connected.iter().flat_map(probes).all(|ip| floor_denies(eg, &policy, ip)),
        ),
    ];
    let ids = AtomicU64::new(1);
    if let Some(ep) = b.artifacts.endpoint() {
        let got = RpcClient { ep, held: true, ids: &ids }.chain_id().await;
        checks.push((SelfTestCheck::ArtifactEndpointChainId, got == Ok(b.artifacts.chain_id())));
    }
    if !b.evm.is_empty() {
        let answers = futures::future::join_all(b.evm.iter().map(|e| {
            let ids = &ids;
            async move { RpcClient { ep: &e.ep, held: true, ids }.chain_id().await == Ok(e.info.chain_id) }
        }))
        .await;
        checks.push((SelfTestCheck::EndpointsReachable, answers.into_iter().all(|ok| ok)));
    }
    // TODO(merge): the sandbox's own checks (SeccompActive, NoNewPrivs, LandlockActive,
    // SecretUnreadable, GpuNodeUnopenable) from zkminer_witness_sandbox, run inside this process.
    let ok = checks.iter().all(|(_, passed)| *passed);
    ControlResponse::SelfTest { ok, checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_prefix_probes() {
        let p = Prefix { addr: "192.168.7.0".parse().unwrap(), len: 24 };
        assert_eq!(probes(&p), vec!["192.168.7.0".parse::<IpAddr>().unwrap(), "192.168.7.1".parse().unwrap()]);
        let p = Prefix { addr: "2001:db8::5".parse().unwrap(), len: 64 };
        assert_eq!(probes(&p), vec!["2001:db8::5".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]);
        let h = Prefix { addr: "10.1.1.1".parse().unwrap(), len: 32 };
        assert_eq!(probes(&h), vec!["10.1.1.1".parse::<IpAddr>().unwrap()]);
    }
}
