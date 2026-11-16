//! Host facts the broker reads before its sandbox is applied (after it, netlink sockets and files
//! outside the Landlock paths are denied): what each endpoint host resolves to, the connected
//! prefixes, and the host's own addresses. The miner refreshes the last two with
//! `ControlRequest::RefreshPrefixes`, built with [`refresh_message`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zkminer_witness::ipc::{ControlRequest, IpPrefix};

use crate::config::{BrokerConfig, HostFacts};
use crate::hooks::EgressHooks;
use crate::net::resolve_blocking;

impl HostFacts {
    /// Blocking: resolves every endpoint host (system resolver) and reads the interfaces.
    pub fn gather(cfg: &BrokerConfig, egress: &dyn EgressHooks) -> io::Result<Self> {
        let resolved = cfg.endpoints().map(|e| (e.alias.clone(), resolve_blocking(e))).collect();
        Ok(Self { resolved, connected: egress.connected_prefixes()?, own_addresses: own_addresses()? })
    }
}

/// Every address assigned to an interface of this host (`getifaddrs`).
pub fn own_addresses() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` walks the list getifaddrs returned; each ifa_addr, when non-null, points at a
        // sockaddr whose family says which struct it is.
        unsafe {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match i32::from((*ifa.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
    }
    // SAFETY: frees the list from getifaddrs exactly once.
    unsafe { libc::freeifaddrs(head) };
    out.sort();
    out.dedup();
    Ok(out)
}

/// Miner side: the `RefreshPrefixes` message for the host's current interfaces.
pub fn refresh_message(egress: &dyn EgressHooks) -> io::Result<ControlRequest> {
    let prefixes = egress.connected_prefixes()?.into_iter().map(|p| IpPrefix { addr: p.addr, len: p.len }).collect();
    Ok(ControlRequest::RefreshPrefixes { prefixes, own_addresses: own_addresses()? })
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_is_an_own_address() {
        let a = super::own_addresses().unwrap();
        assert!(a.contains(&"127.0.0.1".parse().unwrap()), "{a:?}");
    }
}
