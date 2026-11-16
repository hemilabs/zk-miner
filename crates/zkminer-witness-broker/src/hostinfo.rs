//! Host facts the broker reads before its sandbox is applied (after it, netlink sockets and files
//! outside the Landlock paths are denied): the DNS servers (`/etc/resolv.conf` unless `[dns]
//! servers` is set), what each endpoint host resolves to, and netguard's facts about the host —
//! the prefixes they refuse (connected prefixes and on-link routes, the IPv6 site, routes off the
//! default path, the host's DNS servers) and its own addresses (the public NAT ones included),
//! gathered with the config's `[egress]` options. The miner refreshes the last two with
//! `ControlRequest::RefreshPrefixes`, built with [`refresh_message`] (the broker adds its own site
//! prefixes around the own addresses it is sent).

use std::io;
use std::net::IpAddr;

use zkminer_netguard::FactsOptions;
use zkminer_witness::ipc::{ControlRequest, IpPrefix};

use crate::config::{BrokerConfig, HostFacts};
use crate::dns::{system_servers, Resolver, QUERY_TIMEOUT};
use crate::hooks::EgressHooks;
use crate::net::resolve_blocking;

impl HostFacts {
    /// Blocking: picks the DNS servers, resolves every endpoint host name with the broker's own
    /// resolver (never `getaddrinfo`) and reads netguard's facts about the host.
    pub fn gather(cfg: &BrokerConfig, egress: &dyn EgressHooks) -> io::Result<Self> {
        let dns_servers = if cfg.dns.servers.is_empty() { system_servers() } else { cfg.dns.servers.clone() };
        let resolver = Resolver::new(dns_servers.clone(), QUERY_TIMEOUT);
        let resolved = cfg.endpoints().map(|e| (e.alias.clone(), resolve_blocking(e, &resolver))).collect();
        let net = egress.host_facts(&cfg.facts_options)?;
        Ok(Self { resolved, dns_servers, ..Self::from_netguard(&net) })
    }

    /// The broker's view of netguard's facts `net`: every prefix they refuse, the own addresses
    /// and the host's DNS servers (no endpoint resolutions, no resolver servers).
    pub fn from_netguard(net: &zkminer_netguard::HostFacts) -> Self {
        Self {
            resolved: Default::default(),
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
/// (the miner's `[egress]` options): every prefix they refuse, and the own addresses.
pub fn refresh_message(egress: &dyn EgressHooks, opts: &FactsOptions) -> io::Result<ControlRequest> {
    Ok(refresh_message_for(&egress.host_facts(opts)?))
}

/// The `RefreshPrefixes` message for `facts`.
pub fn refresh_message_for(facts: &zkminer_netguard::HostFacts) -> ControlRequest {
    let prefixes = facts.refused_prefixes().into_iter().map(|p| IpPrefix { addr: p.addr, len: p.len }).collect();
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
