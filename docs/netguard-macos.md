# The network guard on macOS

`zkminer-netguard` (PR #37) refused every requester connection on macOS: the per-destination
route query was netlink-only (`could not ask the kernel how … is routed (unsupported)`), and the
near-hop probe's check connection was Linux-only. This note says how macOS now gets the same
decisions, what was measured, and what macOS cannot show.

Code: `crates/zkminer-netguard/src/routes_macos.rs` (routes, the per-destination query,
interfaces), `nearhop.rs` (`confirm_once` for macOS), `facts.rs` (netmasks read up to `sa_len`,
`/etc/resolver`), `macos_tests.rs` (refusals on this host). Linux code is unchanged: the netlink
module, the Linux `confirm_once` and the Linux `sockaddr_mask` are byte-for-byte what PR #37
has; the only lines outside macOS-only code are documentation, `cfg` conditions, and an
`allow(dead_code)` on `RuleMatch::and` off Linux.

## Mechanisms

### Routing table (`dump`)

`sysctl {CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0}`, unprivileged, both families. xnu
writes the whole dump under its routing lock, so the buffer is a consistent snapshot; if the table
grew between the size query and the read (`ENOMEM`), it is read again (5 times, then the facts read
fails and the last good facts stay in force, as on Linux). Each message is an `rt_msghdr`
(<net/route.h>, 92 bytes, `rtm_version` 5, `rtm_type` `RTM_GET`) followed by the sockaddrs its
`rtm_addrs` bits name, each `sa_len` rounded up to 4 bytes (4 bytes for a zero `sa_len`: xnu's
`ROUNDUP32`). Everything is parsed from bytes with every length checked; nothing is cast.

| macOS | read as |
|---|---|
| `RTF_GATEWAY` with an IP gateway of the route's family | `Hop::Via(gateway)` |
| `RTF_GATEWAY` with any other gateway | `Hop::Unknown` (refused) |
| no `RTF_GATEWAY` (gateway is `link#N` or an interface address) | `Hop::OnLink` |
| `RTF_LOCAL` / `RTF_BROADCAST` | `RouteType::Local` / `Broadcast`: delivers to this host |
| not `RTF_UP`, `RTF_REJECT`, `RTF_BLACKHOLE`, `RTF_MULTICAST` | not read (reaches nothing), as Linux skips those types |
| `RTF_WASCLONED` (ARP/NDP entries, per-destination clones) | not read, as Linux skips `RTM_F_CLONED`, unless it delivers locally or a redirect changed it (`RTF_DYNAMIC`, `RTF_MODIFIED`) |
| `RTF_HOST`, or no netmask | a host route (/32, /128) |
| netmask | its bytes at the family's address offset up to `sa_len` (the kernel trims trailing zeros: `sa_len` 7 for 255.255.255.0, 0 for a default route), the rest zero |
| link-local / interface-local IPv6 | the KAME scope id xnu embeds in the second 16-bit word (`fe80:8::…` for `%en0`) cleared |
| `rtm_index` | the interface |
| `RTF_IFSCOPE` | table `SCOPED_TABLE + ifindex` (0x8000_0000 + index) |
| no `RTF_IFSCOPE` | table `main` |

**Policy rules.** macOS has none. The rules `dump` returns are `lookup main` for each family, so
`main` (the unscoped routes) is the one ordinary table. An interface-scoped route is used only by a
socket bound to that interface (and by the kernel's clones on the primary interface), never by
an unbound connection's lookup: that is exactly a Linux table only a selector reaches. So, by the
unchanged `RouteTable` rules: a scoped default (this Mac's four system `utun` interfaces'
`default fe80::%utunN UGcIg`, a second network interface's `default … UGScI`) is no default route,
its gateway no uplink, and it does not make the host need `internal_ranges`; any other scoped route
that does not take the default path still refuses what it holds (a second interface's subnet is
refused as on-link). Nothing Linux refuses is admitted for lack of rules: with no rules there is no
`to`/`from` selector to miss, and the prefix model is the whole table.

### The kernel per destination (`query`)

An `RTM_GET` written to a fresh `PF_ROUTE` socket (`RTA_DST` + an empty `RTA_IFP` `sockaddr_dl`,
as `route -n get` sends it), the reply read with a 2 s timeout. Every routing socket receives a copy
of every routing message (other processes' queries, routing changes), so the reply is the message
of type `RTM_GET`, version 5, whose `rtm_pid` is this process's and whose `rtm_seq` is this query's
(a per-process atomic counter, so another thread's reply is skipped). `rtm_pid` is set by the
kernel, not taken from the request: a request written with `rtm_pid = 1` is answered with the
writer's real pid (measured), so no other process can forge an answer. `ESRCH` (in `write` or
`rtm_errno`) is no route; a route that reaches nothing is no route; any other error, a truncated or
malformed reply, or an answer whose route does not hold the destination is an error (the
destination is refused). The answer is one `Route`, judged by the unchanged
`RouteTable::judge_answer`.

**Network Extension (NECP).** macOS can send a socket into a tunnel by policy, with no route
saying so (a per-app VPN, an include-all-networks VPN, a content filter). The unprivileged view of
that is a real socket: for an answer the judge could admit (through a gateway, or default-like), a
UDP socket is connected to the destination and port (UDP `connect` sends nothing) and the source
address the kernel chose must be an address of the interface the route names; otherwise the answer
is `KernelAnswer::Split` (refused as `PolicyRule`, the Linux answer for a connection whose lookups
disagree). An unreachable UDP connect is no route. On-link and local answers are refused whatever
the socket says, so they are not asked (under Local Network privacy a UDP connect into the LAN can
fail, and the refusal then still names the on-link route).

### Interfaces (`links`)

`getifaddrs`' `AF_LINK` entries: index (`sdl_index`), name, and type (`sdl_type`,
<net/if_types.h>; the libc crate does not define the `IFT_*` constants, so they are defined with
that citation) read as a Linux link kind: `IFT_ETHER` / `IFT_IEEE80211` / `IFT_LOOP` physical (no
kind; `bridgeN`, `vlanN`, `bondN` by name as those physical kinds, `tapN` as `tap`), `IFT_BRIDGE`
`bridge`, `IFT_L2VLAN` `vlan`, `IFT_IEEE8023ADLAG` `bond`, `IFT_PPP` `ppp`, `utunN` (`IFT_OTHER`)
`tun`, `ipsecN` `ipsec`, `IFT_GIF` `gif`, `IFT_STF` `stf`, anything else `iftype-N`. Kinds not in
`PHYSICAL_KINDS` need `[egress] internal_ranges` when a default route uses them, as on Linux.
macOS has no `/proc/net/pppoe`, so a `ppp` uplink always needs it (stricter than Linux). No nexthop
objects.

### Facts (`facts.rs`)

- **Netmasks** on macOS are read up to their `sa_len` (bytes past it are not the mask's:
  `getifaddrs` copies `sa_len` bytes, and on this Mac 255.255.255.0 has `sa_len` 7). The Linux
  reader, unchanged, reads the whole `sockaddr_in`.
- **DNS servers:** `/etc/resolv.conf` (written by configd from the primary resolvers; here it
  lists the same four servers as `scutil --dns` resolver #1) and every `/etc/resolver/*` file.
- Point-to-point peers use `ifa_dstaddr`, as before.

### Near-hop probe and check connection (`nearhop.rs`)

The probe is unchanged and was already correct on macOS: a TCP socket with `IP_TTL` /
`IPV6_UNICAST_HOPS` set, connected for at most 1.5 s. With `net.inet.tcp.icmp_may_rst=1` (the
default) xnu drops a connection in `SYN_SENT` on an ICMP error that quotes its SYN, "time exceeded"
included, with `EHOSTUNREACH`: the same outcome Linux gives. (The ON37 note's 2-hop timeout to
1.1.1.1 was a router rate-limiting its ICMP: 2 of 20 probes to 9.9.9.9 time out, below.)

The check connection now exists on macOS: the same steps as Linux (connect with the default hop
limit, linger 0, lower the hop limit, `shutdown(SHUT_WR)`, wait `4 × RTT + 250 ms` clamped to
0.3–1.5 s), reading the state from `TCP_CONNECTION_INFO` (<netinet/tcp.h>; `tcpi_srtt` /
`tcpi_rttcur` in ms; `TCPS_FIN_WAIT_1` = 6 from <netinet/tcp_fsm.h>). A state other than
`FIN_WAIT_1` (the FIN acknowledged, or a reset) is near; still `FIN_WAIT_1` at the deadline is far.

## Empirical results (this Mac: macOS 27.2, `kern.osversion` 26B131, Wi-Fi behind a home router)

Experiment programs and outputs: `/Users/user/zkminer/scratch/w11/NETGUARD-MAC/exp/` (`rtget.c`,
`ifs.c`, `probe.py`, `confirm.py`, `icmp_tcp.py`, and their `*.txt` outputs).

**Routing table and `route -n get`** (`./rtget dump`, `netstat -rn`): 62 messages. IPv4: the
default via the router on en0 (unscoped), `127/8` and `127.0.0.1` on lo0, the LAN `/24`, the
router's `/32` and the host's `/32` (on-link, `UCS`), multicast. IPv6: the default via the router's
link-local address on en0 (unscoped), **four scoped defaults** on `utun0`–`utun3` (`UGcIg`,
`RTF_IFSCOPE`), the `/64` on en0, every own address as an `RTF_LOCAL` host route on lo0, scoped
link-local `/64`s, multicast. RTM_GET answers (captured in `src/testdata/macos-routing.txt`):

| destination | answer | judged |
|---|---|---|
| 8.8.4.4 | `0.0.0.0/0` via the router, en0, `UGSc` (unscoped default) | admitted |
| 1.1.1.1 | `1.1.1.1/32` via the router, en0, `HOST, WASCLONED, IFSCOPE` (a clone) | admitted (an uplink) |
| 2606:4700:4700::1111 | `::/0` via `fe80::…%en0` | admitted |
| the router (192.168.1.1) | `/32`, no gateway flag, `LLINFO, ROUTER` | refused, on-link |
| a LAN address | the cloning `/24` (netmask `sa_len` 7) | refused, on-link |
| an IPv6 neighbour in the `/64` | the `/64` | refused, on-link |
| fe80::1 | `fe80::/64` scoped to en0 | refused, on-link (and not global) |
| own IPv4 / IPv6, 127.0.0.1, ::1 | host route on lo0, `LOCAL` | refused, delivered to this host |

The test `this_hosts_answers_agree_with_route_get` compares every one of these (and every own
address) with `/sbin/route -n get`: interface, destination, gateway, and the `LOCAL`, `GATEWAY`
and `IFSCOPE` flags agree.

**Probe** (`probe.py`: non-blocking connect + `poll`, as `socket2::connect_timeout`; 20 probes
each, hop limit 2):

| destination | result |
|---|---|
| 1.1.1.1:443, 8.8.8.8:443, 140.82.112.3:443 | 20/20 `EHOSTUNREACH` within 6 ms |
| 9.9.9.9:443 | 18/20 `EHOSTUNREACH`, 2/20 no answer in 1.5 s (ICMP rate limiting) |
| 2606:4700:4700::1111:443, 2001:4860:4860::8888:443 | 20/20 `EHOSTUNREACH` within 6 ms |
| 1.1.1.1:443 at hop limit 64 | connected |
| the ISP's second-hop router (global IPv6), port 179 | refused (RST) in 2.5 ms: near |
| the same router, port 443 | no answer (filtered): the check connection then cannot connect, refused |
| the home router (LAN and its global IPv6 in the `/64`) | `EHOSTUNREACH` **at once**, before any packet: Local Network privacy (see residual risks) |

`icmp_tcp.py` confirms the mechanism: an unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` socket receives
the router's "time exceeded" quoting the probe's SYN at the same instant the TCP socket reports
`EHOSTUNREACH`. (Unprivileged ICMP sockets work on macOS, as `ping -m 2` shows, but are not needed:
the TCP socket reports the error itself.)

**Check connection** (`confirm.py`: `TCP_CONNECTION_INFO` polled every 5 ms, 1.5 s):

| destination | state after `shutdown`, hop limit 2 |
|---|---|
| 1.1.1.1:443, 8.8.8.8:443, [2606:4700:4700::1111]:443, 140.82.112.3:443 | `FIN_WAIT_1` throughout (`SO_ERROR` 0): far |
| a listener on 127.0.0.1 (and on ::1) | `FIN_WAIT_2` after 8 ms: near |
| 1.1.1.1:443 at hop limit 64 | `TIME_WAIT` after 14 ms (control: the FIN does arrive when it may) |

`net.inet.tcp.syncookie=1`: a full accept queue is answered with SYN cookies, so the Linux test's
"listener that drops SYNs" cannot be staged on macOS without root (the probe would just connect);
the macOS test stages the probe's silence and runs the real check connection.

**End to end through the CLI** (`zkminer simulate`, public mode, the default `[egress]`, the mock
worker standing in for risc0; logs `/Users/user/zkminer/scratch/w11/NETGUARD-MAC/e2e/sim-job.log` and `sim-many.log` there): the guard starts (facts
read, both public addresses learned), and 63 real Hemi testnet jobs were asked about. Every risc0
program on testnet is registered with storage URIs on loopback (`http://127.0.0.1:18547/risc0/…`,
`http://127.0.0.1:8746/…`): each is refused end to end, `Failed to download from
http://127.0.0.1:18547/risc0/sha256-chain: refused by the network guard: 127.0.0.1 is not a public
internet address`, the job reported `unavailable`. No deployed chain registers a program on a
public store (mainnet's contracts are not deployed), so the public download was run with the
miner's own fetcher (`ElfFetcher::new(&NetPolicy::new(NetMode::Public, …))`, what the CLI builds):
`zkminer-chain`'s `a_real_elf_downloads_in_public_mode` downloads busybox's 1,131,168-byte ELF from
`https://busybox.net/…`, and `real_stores_that_redirect_across_hosts_are_followed` follows Arweave's
and GitHub's cross-host redirects (`/Users/user/zkminer/scratch/w11/NETGUARD-MAC/chain-real-network.log`). The guard logs nothing when it
admits; the download's own lines are `Downloading ELF from …` / `Downloaded ELF: N bytes`.

## Differences from Linux

1. **No policy rules.** Scoped routes stand in for tables only a selector reaches (above). The
   refusal text for a scoped default or a socket/route disagreement still says "a policy-routing
   rule (ip rule)", the `PolicyRule` kind's Linux wording.
2. **One `RTM_GET`, not two lookups.** macOS has no source rules, so there is no source-dependent
   second lookup to make; the UDP socket's source address check stands in for it (NECP).
3. **Check connection: far only by the deadline.** macOS keeps an ICMP error for an established
   connection's FIN as a soft error it never reports, so "far" is never answered early, as Linux
   can from `SO_ERROR`. Same verdicts; an undecided destination costs up to 1.5 s more.
4. **`ppp` uplinks always need `internal_ranges`** (no PPPoE session list). Stricter.
5. **No `anycast` route type, no nexthop objects.** macOS's own anycast IPv6 addresses are interface
   addresses (`getifaddrs`), refused as own addresses.
6. **Netmasks honour `sa_len`** (a macOS-only reader; what Linux's would read past it is not the
   mask's on macOS).

## Residual risks (macOS)

- **Network Extension policies that treat TCP and UDP differently** (or that apply only after
  `connect`): the UDP source check would not see them. Not testable here (no NE VPN on this Mac).
  List what such a VPN reaches in `[egress] deny_cidrs`, or set `internal_ranges`.
- **`pf`** (`route-to`, `rdr`, NAT in `/etc/pf.conf` or an anchor) can reroute the miner's packets;
  its rules need root to read. The Linux equivalent (netfilter marks) is in SECURITY.md's known
  limits too.
- **Local Network privacy.** A process without the permission gets `EHOSTUNREACH` at once for a
  connection into a directly attached network. The probe reads that as far (as any unreachable);
  this changes nothing, because the real connection fails the same way and such destinations are
  on-link, refused by the address and route checks before any probe. If the permission is granted
  between the probe and the connection, the destination is still on-link and refused before both.
- **`net.inet.tcp.icmp_may_rst=0`** (not the default) makes every 2-hop probe time out; the check
  connection then decides each connection (same verdicts, slower: up to 1.5 s + its connect).
- **Resolvers only configd knows** (`scutil --dns` scoped resolvers, a VPN's split DNS without an
  `/etc/resolver` file) are not read: `dnsinfo.h` is not in the Command Line Tools SDK. Such a
  server behind a VPN is refused by its route, a private one by `is_global`; a public one of a VPN
  that routes it through the default path is not refused as a DNS server.
- **Virtual Ethernet-type interfaces** (`feth`, VM `vmenet`/`vnic` bridges) count as physical, as a
  Linux device without a kind does. A default route through one is not flagged.
- **Clones on the primary interface carry `RTF_IFSCOPE`** and so read as a scoped table; they are
  admitted only through an uplink's gateway and interface (never as default-like), so nothing is
  admitted that the unscoped default would not admit.

## Tests

`cargo test -p zkminer-netguard` on macOS (all pass; logs under
`/Users/user/zkminer/scratch/w11/NETGUARD-MAC/`):

- `routes::sys::tests` (macOS): `the_header_is_the_kernels`, `captured_route_replies_parse` (11
  captured `RTM_GET` replies, v4 and v6), `the_captured_dump_parses_into_the_default_path` (the
  captured 62-message dump: uplinks, scoped utun defaults dropped, on-link, local, the kernel's
  answers judged), `a_scoped_default_is_no_default_path`, `answers_are_matched_and_judged_strictly`
  (other pids/sequence numbers/types skipped; reject, blackhole, down, `ESRCH` are no route; a
  gateway that is no address is `Unknown`; an answer not holding the destination is an error),
  `malformed_and_truncated_input_is_an_error` (every reply cut at every length, bad lengths,
  missing sockaddrs, an address bit past `RTAX_MAX`, a short sockaddr, a dump cut or of another
  version or type: all errors), `netmasks_and_scopes_read_as_the_kernel_means_them`,
  `interface_types_read_as_link_kinds`, `this_hosts_kernel_answers_agree_with_its_table`,
  `this_hosts_answers_agree_with_route_get`.
- `nearhop::tests`: `the_check_connection_finds_a_public_host_far` (now passes for real),
  `the_check_connection_finds_a_local_listener_near` (v4 and v6),
  `a_near_listener_that_gave_the_probe_no_answer_is_near_on_macos`, and the existing
  `a_local_listener_is_near`, `outcomes_are_classified`.
- `macos_tests` (this host's real facts): `loopback_link_local_the_lan_and_the_router_are_refused`,
  `neighbours_own_addresses_site_resolvers_and_deny_cidrs_are_refused` (with the kernel's own
  on-link and local verdicts), `a_public_address_is_admitted_and_vetted`,
  `a_destination_within_the_hop_limit_is_refused` (a loopback listener stands in, real probe:
  accepted, then refused), `this_macs_uplinks_are_its_unscoped_defaults`,
  `a_utun_or_ppp_uplink_needs_internal_ranges`.
- PR #37's tests that failed on macOS and now pass: `nearhop::tests::the_check_connection_finds_a_public_host_far`,
  `policy::tests::this_hosts_site_resolvers_and_public_addresses_are_refused`,
  `real_host::{ordinary_public_hosts_are_admitted_on_this_host, public_hosts_are_far_and_reachable}`,
  `zkminer-chain` `programs::fetch_tests::{a_public_store_is_served_in_public_mode_and_hash_checked,
  a_redirect_to_a_local_url_is_refused_in_public_mode}`. The platform-independent refusal tests
  (`floor_tests`, `policy::tests`, `client::tests` including the DNS-rebinding cases
  `rebind.example.com` → 127.0.0.1) run unchanged on macOS and pass.
- `real_host::a_near_target_is_near` (ignored; `ZKMINER_TEST_NEAR_TARGET`): the ISP's second-hop
  router refused on port 179, timed out on 443.
