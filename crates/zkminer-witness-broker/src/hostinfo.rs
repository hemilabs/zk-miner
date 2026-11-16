//! Host facts the broker reads before its sandbox is applied (after it, netlink sockets and files
//! outside the Landlock paths are denied), for its own second-layer floor: the DNS servers
//! (`/etc/resolv.conf` unless `[dns] servers` is set; denied as destinations) and netguard's facts
//! about the host — the prefixes they refuse (connected prefixes and on-link routes, the IPv6
//! site, routes off the default path, the host's DNS servers) and its own addresses (the public NAT
//! ones included), gathered with the config's `[egress]` options. The broker resolves no names
//! (the miner's connector does).
//!
//! The miner sends its own view with `ControlRequest::RefreshPrefixes` ([`refresh_message`]: its
//! facts, gathered with its `[egress]` options, plus its `[egress] deny_cidrs`). The broker keeps
//! the **union** of what it read at startup and the latest refresh (review r2 B2): a refresh adds
//! to its floor and never takes away what its own options found. The authoritative admission is
//! the miner's connector, with the miner's facts and deny CIDRs.

use std::io;
use std::net::IpAddr;

use zkminer_netguard::FactsOptions;
use zkminer_witness::ipc::{ControlRequest, IpPrefix};

use crate::config::{BrokerConfig, HostFacts};
use crate::dns::system_servers;
use crate::hooks::EgressHooks;

impl HostFacts {
    /// Blocking: picks the DNS servers and reads netguard's facts about the host.
    pub fn gather(cfg: &BrokerConfig, egress: &dyn EgressHooks) -> io::Result<Self> {
        let dns_servers = if cfg.dns.servers.is_empty() { system_servers() } else { cfg.dns.servers.clone() };
        let net = egress.host_facts(&cfg.facts_options)?;
        Ok(Self { dns_servers, ..Self::from_netguard(&net) })
    }

    /// The broker's view of netguard's facts `net`: every prefix they refuse, the own addresses
    /// and the host's DNS servers (no resolver servers).
    pub fn from_netguard(net: &zkminer_netguard::HostFacts) -> Self {
        Self {
            connected: net.refused_prefixes(),
            own_addresses: net.own_addresses().to_vec(),
            dns_servers: Vec::new(),
            resolvers: net.resolvers().to_vec(),
        }
    }
}

/// Every address assigned to an interface of this host (netguard's
/// [`zkminer_netguard::HostFacts::gather_with`] without public-address discovery, sorted).
pub fn own_addresses() -> io::Result<Vec<IpAddr>> {
    let opts = FactsOptions { discover_public_addresses: false, ..FactsOptions::default() };
    Ok(zkminer_netguard::HostFacts::gather_with(&opts)?.own_addresses().to_vec())
}

/// Miner side: the `RefreshPrefixes` message for the host's current facts, gathered with `opts`
/// (the miner's `[egress]` options): every prefix they refuse, the miner's `[egress]`
/// `deny_cidrs` (`deny`), and the own addresses.
pub fn refresh_message(egress: &dyn EgressHooks, opts: &FactsOptions, deny: &[zkminer_netguard::Prefix]) -> io::Result<ControlRequest> {
    Ok(refresh_message_for(&egress.host_facts(opts)?, deny))
}

/// The `RefreshPrefixes` message for `facts` and the miner's deny CIDRs `deny` (sent as refused
/// prefixes: the broker's second layer refuses them like a connected network).
pub fn refresh_message_for(facts: &zkminer_netguard::HostFacts, deny: &[zkminer_netguard::Prefix]) -> ControlRequest {
    let mut prefixes: Vec<IpPrefix> = facts.refused_prefixes().into_iter().map(|p| IpPrefix { addr: p.addr, len: p.len }).collect();
    for p in deny {
        let p = IpPrefix { addr: p.addr, len: p.len };
        if !prefixes.contains(&p) {
            prefixes.push(p);
        }
    }
    ControlRequest::RefreshPrefixes { prefixes, own_addresses: facts.own_addresses().to_vec() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_is_an_own_address() {
        let a = super::own_addresses().unwrap();
        assert!(a.contains(&"127.0.0.1".parse().unwrap()), "{a:?}");
    }
}
