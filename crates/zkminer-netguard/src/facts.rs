//! What the host itself is on the network: its own addresses and the prefixes its interfaces are
//! connected to.
//!
//! A global address can still be the host itself (its public address, reached by hairpin through
//! the router) or a neighbour on its own link (a NAS or a BMC with a global IPv6 address in the
//! miner's /64, a server on the same public subnet). A connection a requester causes is refused to
//! all of them ([`crate::admit`]). A public address the host only has behind NAT is not on any
//! interface, so the operator names it in the deny CIDRs instead.

use std::io;
use std::net::IpAddr;
use std::time::Instant;

use crate::ip::Prefix;

/// A snapshot of the host's addresses and connected prefixes.
#[derive(Debug, Clone)]
pub struct HostFacts {
    connected: Vec<Prefix>,
    own: Vec<IpAddr>,
    gathered_at: Instant,
}

impl HostFacts {
    /// Facts given by the caller (tests, or a caller with its own source).
    pub fn new(mut connected: Vec<Prefix>, mut own: Vec<IpAddr>) -> Self {
        connected.sort();
        connected.dedup();
        own.sort();
        own.dedup();
        HostFacts {
            connected,
            own,
            gathered_at: Instant::now(),
        }
    }

    /// No addresses and no prefixes.
    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new())
    }

    /// Reads every interface of the host: each address is one of its own, and its network (the
    /// address under its netmask or on-link prefix length) a connected prefix, plus the peer of a
    /// point-to-point link as a host route. An address without a netmask counts as a host route; a
    /// non-contiguous netmask counts its leading ones, which only widens the prefix.
    pub fn gather() -> io::Result<Self> {
        let (connected, own) = sys::interfaces()?;
        Ok(Self::new(connected, own))
    }

    /// The connected prefixes, sorted.
    pub fn connected(&self) -> &[Prefix] {
        &self.connected
    }

    /// The host's own addresses, sorted.
    pub fn own_addresses(&self) -> &[IpAddr] {
        &self.own
    }

    /// When these facts were read.
    pub fn gathered_at(&self) -> Instant {
        self.gathered_at
    }
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::ip::Prefix;

    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>)> {
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: the pointer came from a successful getifaddrs and is freed exactly
                    // once.
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
        }
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs writes a list head (or null) into `head`; `List` frees it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let list = List(head);
        let mut connected = Vec::new();
        let mut own = Vec::new();
        let mut cur = list.0;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null node of the list getifaddrs returned, alive until `list`
            // drops.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            // SAFETY: the sockaddr pointers of a live ifaddrs node are null or valid for their
            // family.
            let Some(addr) = (unsafe { sockaddr_ip(ifa.ifa_addr) }) else {
                continue;
            };
            let width = if addr.is_ipv4() { 32 } else { 128 };
            // SAFETY: as above; the netmask is read in the address's family.
            let len = unsafe { sockaddr_mask(ifa.ifa_netmask, addr.is_ipv4()) }.unwrap_or(width);
            own.push(addr);
            connected.push(Prefix::new(addr, len));
            if ifa.ifa_flags & (libc::IFF_POINTOPOINT as libc::c_uint) != 0 {
                // SAFETY: on a point-to-point interface the union holds the destination address.
                if let Some(peer) = unsafe { sockaddr_ip(peer_ptr(ifa)) } {
                    connected.push(Prefix::host(peer));
                }
            }
        }
        Ok((connected, own))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
        ifa.ifa_ifu
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
        ifa.ifa_dstaddr
    }

    /// # Safety
    /// `sa` is null or points to a sockaddr valid for its `sa_family`.
    unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    /// The prefix length of a netmask, read in the address's family (some systems leave the
    /// netmask's own `sa_family` zero).
    ///
    /// # Safety
    /// `sa` is null or points to a sockaddr_in (`v4`) or sockaddr_in6.
    unsafe fn sockaddr_mask(sa: *const libc::sockaddr, v4: bool) -> Option<u8> {
        if sa.is_null() {
            return None;
        }
        if v4 {
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(u32::from_be(sin.sin_addr.s_addr).leading_ones() as u8)
        } else {
            let sin6 = &*(sa as *const libc::sockaddr_in6);
            Some(u128::from_be_bytes(sin6.sin6_addr.s6_addr).leading_ones() as u8)
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS};

    use crate::ip::Prefix;

    /// Every unicast address of every adapter, with its on-link prefix length.
    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>)> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // The documented way: start at 15 KB and grow to what the call asks for, a few times
        // (adapters can appear between calls).
        let mut size: u32 = 15 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let mut done = false;
        for _ in 0..4 {
            // u64 elements: the list must be 8-byte aligned.
            buf = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: `buf` holds at least `size` writable bytes, suitably aligned.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            if rc == ERROR_SUCCESS {
                done = true;
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
        }
        if !done {
            return Err(io::Error::other(
                "GetAdaptersAddresses kept asking for a larger buffer",
            ));
        }
        let mut connected = Vec::new();
        let mut own = Vec::new();
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, alive while `buf`
            // is.
            let a = unsafe { &*adapter };
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: as above.
                let u = unsafe { &*unicast };
                // SAFETY: the address of a live unicast node.
                if let Some(ip) = unsafe { socket_address_ip(&u.Address) } {
                    own.push(ip);
                    connected.push(Prefix::new(ip, u.OnLinkPrefixLength));
                }
                unicast = u.Next;
            }
            adapter = a.Next;
        }
        Ok((connected, own))
    }

    /// The IP of a SOCKET_ADDRESS, read from its bytes (family at 0; IPv4 at 4..8; IPv6 at 8..24).
    ///
    /// # Safety
    /// `sa.lpSockaddr` is null or points to `sa.iSockaddrLength` readable bytes.
    unsafe fn socket_address_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if sa.lpSockaddr.is_null() || sa.iSockaddrLength < 2 {
            return None;
        }
        let bytes =
            std::slice::from_raw_parts(sa.lpSockaddr.cast::<u8>(), sa.iSockaddrLength as usize);
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == AF_INET && bytes.len() >= 8 {
            let o: [u8; 4] = bytes[4..8].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        } else if family == AF_INET6 && bytes.len() >= 24 {
            let o: [u8; 16] = bytes[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        } else {
            None
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod sys {
    use std::io;
    use std::net::IpAddr;

    use crate::ip::Prefix;

    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reading the host's interfaces is not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gathered_facts_are_well_formed() {
        let f = HostFacts::gather().expect("read the interfaces");
        for p in f.connected() {
            let w = if p.addr.is_ipv4() { 32 } else { 128 };
            assert!(p.len <= w, "{p:?}");
            assert_eq!(Prefix::new(p.addr, p.len), *p, "{p:?} is a network address");
        }
        // Every own address is inside a connected prefix (its own network).
        for a in f.own_addresses() {
            assert!(f.connected().iter().any(|p| p.contains(*a)), "{a}");
        }
        // Loopback, where the namespace has it up, is both.
        if f.own_addresses().contains(&"127.0.0.1".parse().unwrap()) {
            assert!(f
                .connected()
                .iter()
                .any(|p| p.contains("127.0.0.1".parse().unwrap())));
        }
        let mut sorted = f.connected().to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, f.connected());
    }
}
