# The network guard on macOS

`zkminer-netguard` (PR #37) refused every requester connection on macOS: the per-destination
route query was netlink-only (`could not ask the kernel how … is routed (unsupported)`), and the
near-hop probe's check connection was Linux-only. This note says how macOS now gets the same
decisions, what was measured, and what macOS cannot show.

> **Since the Linux application** ([netguard-hardening.md](netguard-hardening.md)), every
> finding of review rounds 1 to 3 that touched shared decisions applies on Linux and Android too,
> and on Windows where it has the code path; one new check (each connection checked again once
> made) applies everywhere, macOS included. So the statements below that Linux code is
> unchanged, items 10 to 12 and 15 to 18 of "Differences from Linux", and both "Recommended for
> #37" lists describe the branch after round 3 (af17e48), not now. Six shared nearhop tests lost
> their `_on_macos` suffix; they are named here as they are now. The check connection's
> refusal for a FIN no hop limit got acknowledged now reads `the peer acknowledged the check's
> FIN neither within the hop limit nor at the default one (AWS S3 never does)`: the old text was
> cut at 120 characters before it named a cause.

Code: `crates/zkminer-netguard/src/routes_macos.rs` (routes, the per-destination query,
interfaces), `nearhop.rs` (the macOS probe and `confirm_once`), `facts.rs` (interface addresses
and netmasks read within `sa_len`, the DNS servers: `facts::macos_dns`), `macos_tests.rs`
(refusals on this host). Linux code is unchanged: the netlink module, the Linux `confirm_once`,
and the Linux bodies of `probe_once`, `sockaddr_ip`, `sockaddr_mask` and `system_resolvers` are
byte-for-byte what PR #37 has (the last four now behind `cfg(not(target_os = "macos"))`). What
changed outside macOS-only code, all of it:

- documentation (README, SECURITY.md, module docs) and `cfg` conditions;
- an `allow(dead_code)` on `RuleMatch::and` off Linux;
- `nearhop::tests::the_check_connection_finds_a_local_listener_near`, a new test that runs on
  Linux and Android too (`cfg(any(linux, android, macos))`): the existing Linux check connection
  against loopback listeners, v4 and v6;
- `crates/zkminer-cli/Cargo.toml`: `libc` for `cfg(all(unix, not(target_os = "linux")))`, which
  is every non-Linux Unix, the BSDs included, not only macOS (`run::segment_disk::free_bytes`
  calls `statvfs` on every Unix, and the CLI did not build on any of them before);
- `HostFacts::gather_with` reads `read_system_resolvers()?`, which off macOS is
  `Ok(system_resolvers())` (the same servers as before, and it cannot fail);
- `crates/zkminer-netguard/Cargo.toml`: `system-configuration` 0.7 and `core-foundation` 0.9 for
  `cfg(target_os = "macos")` only, the versions already in `Cargo.lock` through reqwest (the lock
  gains two dependency lines and no package);
- review round 2: lines gated `#[cfg(target_os = "macos")]` in shared items (a `Denied::FactsUnreadable`
  variant and its `Display` arm and `depends_on_facts` case, the check at the top of
  `admit_inner`, `FactsCell`'s refresh fields and their initialisers in `NetPolicy::build`, a
  macOS `get_fresher_than` beside the unchanged one, now `cfg(not(target_os = "macos"))`,
  `HostFacts`' `unreadable` field and its initialisers in `new` and `assemble`, and a shadowing
  `uplink_signature` closure in `gather_with`). With those lines removed, each of these items is
  byte-for-byte what PR #37 has (`gather_with` what round 1 left), which
  `/Users/user/zkminer/scratch/w11/NGREV/fix-r2/linux-identity.py` checks alongside the Linux-only
  blocks above;
- review round 3, more lines gated `#[cfg(target_os = "macos")]` in shared items: a
  `Denied::Nat64Unsettled` variant (its `Display` arm, its `depends_on_facts` case, the check in
  `admit_inner`), `RawFacts::nat64_unsettled` and `HostFacts`' field of that name (and their
  initialisers), `gather_with`'s NAT64 step (the shared `nat64::ensure_discovered()` call is now
  `cfg(not(target_os = "macos"))`, the macOS step comes after the routes are read), a macOS match
  arm in `HostFacts::kernel_verdict` beside the unchanged one, `FactsCell::refresh_started` and
  its initialiser, the DNS-server line of `public::discover`, and in the shared test
  `the_kernels_answer_per_destination_is_judged` two asserts now `cfg(not(target_os = "macos"))`
  with macOS asserts beside them;
- review round 3, cfg-free and so compiled on Linux too (requested; neither changes what Linux
  decides): `HostFacts::unreadable_reason()` (always `None` off macOS) and its use in
  `zkminer-chain`'s `ElfFetcher::guard_warnings`; the test helper `skipped` (and `skip_fails`)
  that every SKIPPED path of the netguard tests now calls, which prints the same line and fails
  only under `ZKMINER_CI_STRICT=1`, a copy of it in each of the three integration test files that
  skip, and the test `strict_ci_fails_skips_it_does_not_allow`.
  `RUSTC_BOOTSTRAP=1 cargo rustc -Zunpretty=expanded` of the library and its tests for
  `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`, at `pr/37` and at this branch, differ
  in these and round 1's accepted lines only (`fix-r3/linux-windows-expanded-diff.log`).

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
| `RTF_GATEWAY` with any other gateway | `Hop::Unknown`: refused, unless the route is default-like (`/0` up to `/4`) in an ordinary table, which `judge` admits whatever its hop, as on Linux (the socket check below still applies) |
| no `RTF_GATEWAY` (gateway is `link#N` or an interface address) | `Hop::OnLink`: refused, with the same exception for a default-like route (a VPN's `0/1` on a `utun`, which then needs `internal_ranges`) |
| `RTF_LOCAL` / `RTF_BROADCAST` | `RouteType::Local` / `Broadcast`: delivers to this host |
| not `RTF_UP`, `RTF_REJECT`, `RTF_BLACKHOLE`, `RTF_MULTICAST` | not read (reaches nothing), as Linux skips those types |
| `RTF_WASCLONED` (ARP/NDP entries, per-destination clones) | not read, as Linux skips `RTM_F_CLONED`, unless it delivers locally or a redirect changed it (`RTF_DYNAMIC`, `RTF_MODIFIED`) |
| `RTF_HOST`, or no netmask | a host route (/32, /128) |
| netmask | its bytes at the family's address offset up to `sa_len` (the kernel trims trailing zeros: `sa_len` 7 for 255.255.255.0, 0 for a default route), the rest zero; a non-contiguous mask (`0.255.255.0`) makes the message malformed (the reply is refused, the dump fails) |
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
as `route -n get` sends it), the reply read with a 2 s timeout. Since review round 2 it is sent as
`RTM_GET_SILENT` (0x11, xnu's private <net/route.h>): the kernel sends the answer to the asking
socket alone (as type `RTM_GET`) instead of to every routing socket, so no other process sees
which destinations are asked about, nor the queries' pid and sequence numbers
(`fix-r2/rtm-get-silent.log`). Since round 3 it is the only way a query is asked: a kernel that
refuses the type (`EPERM`, `EOPNOTSUPP`) fails the query with `this kernel refused a route query
sent as RTM_GET_SILENT …`, and the destination is refused; round 2 fell back to `RTM_GET` from
then on, whose answers every routing socket sees (below, round 3 parse-2). Each query's `rtm_seq`
is drawn from `arc4random` on its own.

The socket still receives other routing messages, and also every write the kernel refused, as it
was written: xnu's `route_output` hands a write whose length is not its `rtm_msglen` to every
routing socket raw, with the pid and sequence number the writer put in it, and a write refused
before the kernel sets `rtm_pid` (another version: `EPROTONOSUPPORT`; any type but `RTM_GET`
from an unprivileged writer: `EPERM`) with the writer's pid, its version or type kept. Round 1
said no other process could forge an answer, because a request's `rtm_pid` is overwritten with
the writer's; that holds for every write the kernel accepts, but not for these refused ones, and
the reviewer's forger had 18,529 forged default routes taken (`r2-parse/spoof-run.log`). So the
answer is the one datagram, received whole, that is exactly one message (its length its
`rtm_msglen`), of type `RTM_GET` and version 5, whose `rtm_pid` is this process's and whose
`rtm_seq` is this query's. Received whole (round 3, parse-1): `recvmsg` into 16 KiB, far more than
any routing message (2,140 bytes at most), and a datagram that fills it or carries `MSG_TRUNC` is
not read; with round 2's 4,096-byte `recv`, a forged datagram of 4,097 to 8,191 bytes whose
`rtm_msglen` is 4,096 arrived cut to exactly its `rtm_msglen`, and passed.
every other datagram is skipped without being read further (an 8-byte stub no longer fails the
query). `fix-r3/forge-variants-r3.log` writes 134 kinds of message (round 2's 23 in
`fix-r2/forge-variants.log`) with another process's pid
(oversize, truncated, stubs, `rtm_msglen` 0, other versions and types, `RTM_ADD`/`RTM_CHANGE`/
`RTM_DELETE`/`RTM_LOCK` refused with `EPERM`, bad sockaddrs refused with `EINVAL`, exact-length
forged answers, `RTM_GET_SILENT`; since round 3 also every `rtm_msglen` around the old and the new
buffer sizes and the routing socket's 8,192-byte default receive buffer, written up to 4,096 bytes
longer, with the writer's `SO_SNDBUF` raised to 1 MiB, received by a socket with the default
receive buffer and by one raised to 1 MiB) and records what the other routing sockets receive:
none is delivered in the accepted shape. The reply's `RTA_IFP` must be a `sockaddr_dl` naming the header's
`rtm_index` (xnu fills both from the route's `rt_ifp`), or it is malformed. 0.0.0.0 and `::` are
answered as a local route without asking: `RTM_GET` answers them with the default route, while a
connection to them goes to this host. `ESRCH`, `ENETUNREACH` or `EHOSTUNREACH` (in `write` or
`rtm_errno`) is no route; a route that reaches nothing is no route; any other error, a malformed
answer, no answer within 2 s, or an answer whose route does not hold the destination is an error
(the destination is refused). A local process that floods every routing socket can make queries
time out (their answers lost when the socket's buffer is full): that refuses, a denial of
service that fails closed. The answer is one `Route`, judged by the unchanged
`RouteTable::judge_answer`; since round 3 (bypass-3) a default-like answer must also be one of the
facts' own default-like routes (family, hop, interface), or it is refused as off the default path
(`OtherGateway`, or `OnLink`), which rests on the facts, so the policy reads them again at once
and judges once more: an uplink that came up after the facts were read (a full-tunnel VPN's `0/1`
on a `utun`) is not admitted on facts that do not know it.

Considered and not adopted (round 2, parse-1 (d)): requiring the answered route to appear in the
`NET_RT_DUMP` snapshot as well. It would not have caught the forgery that mattered: the forged
answer was the real default route (via the real router, on the real interface), which the
snapshot holds; and the kernel's real answers are often clones made after the snapshot (the
1.1.1.1 row below), which would be refused or need a dump per query.

**Network Extension (NECP).** macOS can send a socket into a tunnel by policy, with no route
saying so (a per-app VPN, an include-all-networks VPN, a content filter). The unprivileged view of
that is a real socket: for an answer the judge could admit (through a gateway, or default-like), a
UDP socket is connected to the destination and port (UDP `connect` sends nothing) and the source
address the kernel chose must be an address of the interface the route names and of no other
interface; otherwise (the source on another interface, on several, or on none) the answer is
`KernelAnswer::Split` (refused as `PolicyRule`, the Linux answer for a connection whose lookups
disagree). An unreachable UDP connect is no route. On-link and local answers are refused whatever
the socket says, so they are not asked (under Local Network privacy a UDP connect into the LAN can
fail, and the refusal then still names the on-link route). The decision is the pure function
`routes::sys::decide(route, socket)`, unit-tested on the captured answers.

### Interfaces (`links`)

`getifaddrs`' `AF_LINK` entries: index (`sdl_index`), name, and type (`sdl_type`,
<net/if_types.h>; the libc crate does not define the `IFT_*` constants, so they are defined with
that citation) read as a Linux link kind: `IFT_LOOP` physical (no kind); `IFT_ETHER` /
`IFT_IEEE80211` physical only for Apple's own names (`enN`, `apN`, `awdlN`, `llwN`, `nanN`,
`anpiN`), `bridgeN`, `vlanN`, `bondN` by name as those physical kinds, `tapN` as `tap`, and any
other name as kind `ether-<name>`, not physical (ZeroTier's `feth`, a VM's `vmenet`, an unknown
driver: fail closed); `IFT_BRIDGE` `bridge`, `IFT_L2VLAN` `vlan`, `IFT_IEEE8023ADLAG` `bond`,
`IFT_PPP` `ppp`, `utunN` (`IFT_OTHER`) `tun`, `ipsecN` `ipsec`, `IFT_GIF` `gif`, `IFT_STF` `stf`,
anything else `iftype-N`. This Mac's 26 interfaces (`lo0`, `gif0`, `stf0`, `anpi0-3`, `en0-9`,
`bridge0`, `ap1`, `awdl0`, `llw0`, `nan0`, `utun0-3`) classify as before. Kinds not in
`PHYSICAL_KINDS` need `[egress] internal_ranges` when a default route uses them, as on Linux.
macOS has no `/proc/net/pppoe`, so a `ppp` uplink always needs it (stricter than Linux). No nexthop
objects.

### Facts (`facts.rs`)

- **Netmasks and addresses** on macOS are read up to their `sa_len` (bytes past it are not the
  sockaddr's: `getifaddrs` copies `sa_len` bytes, on this Mac 255.255.255.0 has `sa_len` 7, and a
  `utun`'s destination address has `sa_len` 0); an IP sockaddr too short for its address names
  none. The Linux readers, unchanged, read the whole `sockaddr_in`. (An interface netmask that is
  not contiguous still counts its leading ones: that only widens a connected prefix, which
  refuses more.)
- **DNS servers** (`facts::macos_dns`): `/etc/resolv.conf` (written by configd from the primary
  resolvers), every regular file in `/etc/resolver`, and the `ServerAddresses` of every
  `State:/Network/Service/<id>/DNS` key and of `State:/Network/Global/DNS` in configd's dynamic
  store (a secondary interface's DHCP or RDNSS servers, a VPN's supplemental and split-DNS
  resolvers, scoped resolvers: what `scutil --dns` lists), and since round 2 of every
  `Setup:/Network/Service/<id>/DNS` key (servers set by hand for a service: configd's IPMonitor
  merges them into that service's resolver for `scutil --dns` without writing them to a `State:`
  key, so a secondary service's would otherwise be missed; an inactive service's are refused
  needlessly, never fewer). Files are read as bytes (invalid UTF-8 replaced), at most 1 MiB; each
  is opened `O_NONBLOCK` and `fstat`ed, and what is not a regular file is skipped without being
  read (round 1 said "without being opened", which was wrong: it is opened, never read); a
  missing file or directory has none; a symbolic link that loops (`ELOOP`) is skipped with a
  warning (round 2, below); any other error, a store that cannot be read, a value configd would
  not write, or a daemon that does not answer within 2 s fails the facts read, the message naming
  the file or key. Each request to the daemon is made on a thread of its own (SCDynamicStore has
  no timeout) and waited for at most 2 s; requests are not serialised (the facts re-read, public
  address discovery and NAT64 discovery can ask at once, each on its own thread), and only
  timed-out ones are capped: while four of them have not returned, the next request fails at
  once (round 2 said "at most one at a time", which was wrong; round 3 also fixed the count,
  which could wrap below zero for a moment). Since round 3 (12(a)) a `ServerAddresses` string that
  names no address (empty, a host name) is skipped with a warning, as configd skips it.
- **Facts that cannot be read again** (round 2, bypass-1): when a re-read fails, the cached
  kernel verdicts are dropped and the last good facts stay in force for `REFRESH_GRACE` (2 s)
  past `FACTS_TTL` (1 s); after that every requester connection is refused with
  `Denied::FactsUnreadable` ("… this host's network facts (interfaces, routes, DNS servers) could
  not be read again for more than 3s (the DNS resolver file /etc/resolver/x: Permission denied
  …)"), until a re-read, tried again at most every 100 ms, succeeds. `admit` reads the refusal
  from the facts themselves, so a caller that judges with `NetPolicy::facts()` (the witness
  broker's floor) refuses too. One re-read runs at a time; a caller that finds one under way waits
  for it and takes its facts, but since round 3 (12(b)) only until it is 500 ms old
  (`REFRESH_WAIT`; a re-read takes tens of milliseconds): then it gets the facts in force while
  they are within `FACTS_TTL` + `REFRESH_GRACE`, and after that a refusal
  (`Denied::FactsUnreadable`: "a re-read of them has not finished within 3s"), at once. A
  configuration daemon that answers just after its 2 s held every caller for each re-read (24
  calls held for 3 re-reads in `a_slow_refresh_holds_only_the_caller_that_runs_it` before the
  change, 3 for 3 after: `fix-r3/repro-12b-before.log`, `12b-after.log`).
- **NAT64 prefixes** (round 3, bypass-1 and bypass-2): learned per uplink. The facts' uplink
  signature (below) is handed to `nat64::ensure_discovered_on`: the process's first round runs on
  the caller's thread, as before; a changed signature starts a round at once in the background
  (round 2 learned only at startup and every 300 s); while a host with IPv6 and no IPv4 route has
  found nothing (or its round failed), it asks again every 15 s; one round runs at a time, and a
  round that finishes after the uplink changed again starts another. Each round also reads
  configd's per-interface NAT64 state (`State:/Network/Interface/<if>/NAT64`: its PLAT discovery,
  RFC 7050, and the prefixes a router announces, RFC 8781): every string value shaped like an
  IPv6 prefix of an RFC 6052 length is learned (the key name, `kSCPropNetNAT64PrefixList`, is in
  configd's private schema; on this Mac the key holds only `PLATDiscoveryStartTime` and
  `PLATDiscoveryCompletionTime`: no NAT64 here). The RFC 7050 query goes to the active servers
  first (`State:/Network/Global/DNS`, in configd's order), then the rest; servers of a family the
  host does not route are skipped (so IPv6 first, and only, without an IPv4 route), and the list
  is cut to 8 only after that ordering (round 2 cut the sorted list, IPv4 first). Until the round
  for a new signature has finished, a host with IPv6 and no IPv4 route refuses every IPv6
  destination (`Denied::Nat64Unsettled`, "… is on a new network whose NAT64 prefix is still being
  learned"), which rests on the facts; a dual-stack host is never refused for it.
- **The uplink's identity** (round 2, bypass-2): public addresses are confirmed per uplink. On
  macOS the uplink signature (default routes and internet interfaces, as on Linux) also hashes
  configd's `NetworkSignature` of every active service (`State:/Network/Service/<id>/IPv4`:
  `IPv4.Router=…;IPv4.RouterHardwareAddress=…`; `…/IPv6`: the prefix and the router's hardware
  address): two networks whose routers have the same address on the same interface are two
  uplinks. The kernel's neighbour tables cannot stand in: an unprivileged process sees no ARP
  entry and every NDP entry's hardware address as `02:00:00:00:00:00`
  (`fix-r2/llinfo-unprivileged.log`). Each `nameserver` word (any case) counts
  for every address any macOS parser reads in it: `getaddrinfo(AI_NUMERICHOST)` (libresolv,
  configd; reads `203.0.113.053` as decimal 53), `inet_aton` (octal 43, and `3405803829`,
  `0xcb007135`, `10.1`), and the plain form with a zone dropped.
- Point-to-point peers use `ifa_dstaddr`, as before.

### Near-hop probe and check connection (`nearhop.rs`)

The probe is the Linux one, a TCP socket with `IP_TTL` / `IPV6_UNICAST_HOPS` set, connected for
at most 1.5 s, with one difference: macOS runs `socket2::Socket::connect_timeout`'s steps itself
so that an unreachable `connect` returns at once, before the connection is in progress (Local
Network privacy, a Network Extension denial: no packet was sent, let alone answered), is a
failure, refused, rather than far. An ICMP "time exceeded" can only arrive after `connect`
returned `EINPROGRESS`. With `net.inet.tcp.icmp_may_rst=1` (the
default) xnu drops a connection in `SYN_SENT` on an ICMP error that quotes its SYN, "time exceeded"
included, with `EHOSTUNREACH`: the same outcome Linux gives. (The ON37 note's 2-hop timeout to
1.1.1.1 was a router rate-limiting its ICMP: 2 of 20 probes to 9.9.9.9 time out, below.)

The check connection now exists on macOS: the same steps as Linux (connect with the default hop
limit, linger 0, lower the hop limit, `shutdown(SHUT_WR)`, wait `4 × RTT + 250 ms` clamped to
0.3–1.5 s), reading the state from `TCP_CONNECTION_INFO` (<netinet/tcp.h>; `tcpi_srtt` /
`tcpi_rttcur` in ms; states from <netinet/tcp_fsm.h>). Since round 2 (probe-1) only
`FIN_WAIT_2` or `TIME_WAIT` (reached once the FIN is acknowledged) is an answer, near;
`FIN_WAIT_1` and `CLOSING` (the peer's FIN crossed the check's) wait; still `FIN_WAIT_1` at the
deadline is far, but since round 3 (probe-1) only after a positive control: the hop limit the
connection was made with is restored, and the FIN's retransmission (due within `tcpi_rto`) is
waited for, the RTO, two round trips and 250 ms (clamped to 0.5–4 s); acknowledged then (the peer
answers a FIN that reaches it, and the hop-limited one did not reach it): far; not acknowledged,
or closed or reset meanwhile: a failed check, refused (a reset does not count: an S3 front end
resets an idle connection on a timer). And since round 3 the probe is asked twice within its
1.5 s (1 s, then 0.5 s after a timeout), so that a router rate-limiting its ICMP sends the check
connection fewer destinations. A peer that closed or reset the connection on its own (not `ESTABLISHED` before
the FIN, or `CLOSE_WAIT`/`LAST_ACK`/`CLOSED` after it, or `CLOSING` at the deadline) is a failed
check: refused, but not read as near, and never as far. Before, any state but `FIN_WAIT_1` was
near, so a far server that closes at once (NIST's daytime server 129.6.15.28:13, two hops out)
was refused as near (3 of 3, `fix-r2/repro-probe1-probe2-on-HEAD.log`); it is now refused as a
failed check (a far server that always closes first stays refused, by the check's design: it
never lets the FIN be tested). The probe and the check connection connect to an IPv4-mapped
address as its IPv4 address (probe-2: an IPv6 socket's hop limit does not limit the IPv4 packets
of a mapped connection, so the probe of `[::ffff:1.1.1.1]:443` connected).

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

The test `this_hosts_answers_agree_with_route_get` asks the live kernel for the same kinds of
destination on whatever network the test runs on (two public IPv4 and one IPv6 address, the IPv4
router, a neighbour in the router's LAN, one in each global on-link `/64`, `fe80::1`, loopback
and every own address) and compares each answer with `/sbin/route -n get`: interface,
destination, mask (its prefix length; none shown for a host route, `default` for `/0`), gateway,
and the `LOCAL`, `GATEWAY` and `IFSCOPE` flags agree. The captured rows above are checked by
`captured_route_replies_parse`.

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
| the home router (LAN and its global IPv6 in the `/64`) | `EHOSTUNREACH` **at once**, before any packet: Local Network privacy (now refused, see below) |

Review round 1 measured it again with the probe's own steps (`fix-r1/h13-probe-timing.log`, 20
probes each, hop limit 2): 1.1.1.1, 8.8.8.8, 9.9.9.9, 140.82.112.3, 208.67.222.222 and four
public IPv6 hosts gave 177 `EHOSTUNREACH`, every one after `EINPROGRESS`, the fastest in 2.18 ms
(0.98 ms at hop limit 1), and 3 timeouts; 40 probes into the LAN were refused by `connect` itself
in 0.13 to 0.35 ms. With the change, the crate's `TtlProbe` (`fix-r1/h13-ttlprobe-after.log`)
finds all nine public hosts far (`decide`: far, 3 of 3 each) and the LAN probes failed.

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
7. **An unreachable `connect` reports at once is refused**, not far (Local Network privacy, a
   Network Extension denial). Linux reads every unreachable as far. Stricter.
8. **Ethernet-type interfaces are physical only by Apple's names.** Linux reads a device without
   a kind as physical; macOS has no kind to read, so an unknown name is not physical. Stricter.
9. **DNS servers come from configd too**, and each `nameserver` word is read by every macOS
   parser; a configuration that cannot be read fails the facts read. Linux reads its
   `resolv.conf` files as before, and skips a file it cannot read.
10. **A re-read of the facts that keeps failing refuses** every requester connection after 2 s
    of grace; Linux keeps the last good facts for as long as the failure lasts (recommended for
    #37, below).
11. **The check connection reads only an acknowledged FIN as near**; a peer that closed or reset
    first is a failed check. Linux reads any state but `FIN_WAIT1` as near (recommended for #37).
12. **One facts re-read at a time, the configuration daemon bounded by 2 s.** Linux re-reads in
    every caller that finds the facts stale.
13. **The uplink signature includes configd's network signatures.** Linux's has the routes only.
14. **Route answers are read only whole, and only from `RTM_GET_SILENT`** (round 3). Linux's
    netlink answers have no such forgery path.
15. **A default-like kernel answer must be a default route the facts hold** (round 3, bypass-3).
    Linux admits any default-like route of an ordinary table until the facts are read again
    (recommended for #37).
16. **NAT64 prefixes are learned again when the uplink changes**, every 15 s while an IPv6-only
    host has none, and from configd's NAT64 state; an IPv6-only host refuses IPv6 until the new
    network's round ends (round 3, bypass-1 and -2). Linux learns at startup and every 300 s from
    the first 8 sorted servers (recommended for #37).
17. **The check connection's positive control and a second probe attempt** (round 3, probe-1): a
    peer that acknowledges a FIN at no hop limit is refused, not far. Linux reads it as far
    (recommended for #37, with its cost).
18. **A caller waits for a re-read under way at most 500 ms** (round 3, 12(b)). Linux has no
    single flight (each stale caller re-reads).

## Residual risks (macOS)

- **Network Extension policies that treat TCP and UDP differently** (or that apply only after
  `connect`): the UDP source check would not see them. Not testable here (no NE VPN on this Mac).
  List what such a VPN reaches in `[egress] deny_cidrs`, or set `internal_ranges`.
- **Network Extension flow-divert and app-proxy VPNs** (round 2): such a VPN takes TCP flows in
  the kernel and hands them to its own process, with no `utun` route for them. Each probe is
  then expected to connect at once (the proxy accepts it locally), so every requester connection
  is refused as near: the operator sees `refused by the network guard: <addr> is within 2 hops of
  this host … (a probe limited to 2 hops: it accepted a connection)` for every public host while
  the VPN is on. This fails closed; not testable here (no such VPN on this Mac). README's macOS
  troubleshooting names it.
- **Routers that rewrite destinations** (DNAT, hairpin NAT, a port forward on the router's WAN
  address): a public address the router maps back into the LAN is judged by where it is
  addressed, not where it lands. The near-hop probe refuses the router itself (it answers within
  2 hops), and the host's own public addresses are refused; a forward to another public address
  on a far network is not seen. Shared design (Linux the same).
- **The time between the check and the connection** (round 2, bypass-3): the route, socket and
  near-hop checks run just before the real connection, which is a new socket; a route or VPN
  that changes between them is not seen for that connection. Shared design (Linux the same);
  recommended for #37 (below): check the connected socket's `getsockname` and interface again
  after `connect`, or connect through a connector that binds the checked source.
- **A flood of routing messages** from a local process can make route queries time out:
  refused (fail closed).
- **dnsinfo** (`dns_configuration_copy`, what `scutil --dns` prints) is not read: its layout is
  configd's private `dnsinfo.h` (not in the SDK), a tree of raw pointers with no ABI promise, so
  no sound reader can be written against it. Its sources are read (the `State:` and `Setup:` DNS
  keys, `/etc/resolver`), and the real-host test checks every server `scutil --dns` lists is
  among them.
- **`pf`** (`route-to`, `rdr`, NAT in `/etc/pf.conf` or an anchor) can reroute the miner's packets;
  its rules need root to read. The Linux equivalent (netfilter marks) is in SECURITY.md's known
  limits too.
- **Local Network privacy.** A process without the permission gets `EHOSTUNREACH` at once for a
  connection into a directly attached network. The probe now refuses that (it no longer reads it
  as far); such destinations are on-link and refused by the address and route checks before any
  probe anyway.
- **`net.inet.tcp.icmp_may_rst=0`** (not the default) makes every 2-hop probe time out; the check
  connection then decides each connection (same verdicts, slower: up to 1.5 s + its connect).
- **DNS servers that change between facts reads** (a VPN that comes up) are known from the next
  read, as on Linux. Resolvers configd keeps under other keys than `State:/Network/Service/*/DNS`,
  `State:/Network/Global/DNS` and `Setup:/Network/Service/*/DNS` are not read
  (`this_hosts_dns_keys_are_all_read` fails if this host's configd holds another
  `…/Network/…/DNS` key).
- **Bridges** (`bridgeN`, `IFT_BRIDGE`) count as physical, as a Linux bridge does, so a default
  route through a VM's `bridge100` is not flagged. Other Ethernet-type interfaces of names the
  guard does not know (`feth`, `vmenet`) are not physical and are flagged.
- **Clones on the primary interface carry `RTF_IFSCOPE`** and so read as a scoped table; they are
  admitted only through an uplink's gateway and interface (never as default-like), so nothing is
  admitted that the unscoped default would not admit.

## Tests

`cargo test -p zkminer-netguard` on macOS (all pass; logs under
`/Users/user/zkminer/scratch/w11/NETGUARD-MAC/`):

- `routes::sys::tests` (macOS; review round 1 added `the_socket_view_decides_an_admissible_answer`,
  `the_unspecified_addresses_are_this_host`, `the_answers_interface_is_the_headers`,
  `a_non_contiguous_netmask_is_malformed`, `this_hosts_sockets_leave_by_the_routes_interface`,
  `this_hosts_interfaces_read_as_their_kinds`): `the_header_is_the_kernels`, `captured_route_replies_parse` (11
  captured `RTM_GET` replies, v4 and v6), `the_captured_dump_parses_into_the_default_path` (the
  captured 62-message dump: uplinks, scoped utun defaults dropped, on-link, local, the kernel's
  answers judged), `a_scoped_default_is_no_default_path`, `answers_are_matched_and_judged_strictly`
  (other pids/sequence numbers/types skipped; reject, blackhole, down, `ESRCH` are no route; a
  gateway that is no address is `Unknown`; an answer not holding the destination is an error),
  `malformed_and_truncated_input_is_an_error` (every reply cut at every length and every
  length mismatch: no answer, since round 2; missing sockaddrs, an address bit past `RTAX_MAX`,
  a short sockaddr, a dump cut or of another version or type: errors),
  `netmasks_and_scopes_read_as_the_kernel_means_them`,
  `interface_types_read_as_link_kinds`, `this_hosts_kernel_answers_agree_with_its_table`,
  `this_hosts_answers_agree_with_route_get`. Round 2: `forged_and_refused_writes_are_no_answer`,
  `live_forged_answers_are_never_taken` (live, opt-in: `ZKMINER_TEST_LIVE_FORGE=1`, run on its own),
  `queries_are_answered_to_the_asking_socket_alone`,
  `the_destination_port_reaches_the_socket_check`, `plain_clones_in_the_dump_are_not_read`.
- `facts::tests` (macOS, review round 1): `ip_sockaddrs_are_read_within_their_length`,
  `macos_reads_nameservers_as_its_resolvers_do`, `macos_resolver_files_are_read_strictly`,
  `macos_dns_servers_are_the_configuration_daemons` (against `scutil --dns`; round 2 adds
  configd's, the `Setup:` keys' and `/etc/resolver`'s servers ⊆ all). Round 2:
  `macos_dns_servers_come_from_every_source`, `configd_values_are_read_strictly`,
  `this_hosts_dns_keys_are_all_read`, `netmasks_are_read_within_their_length`,
  `the_facts_read_fails_without_the_configuration_daemon` (the test binary again under
  `sandbox-exec`, configd's Mach service denied), `a_stuck_configuration_daemon_fails_the_read_in_time`,
  `two_networks_behind_the_same_router_address_are_two_uplinks_on_macos`,
  `network_signatures_are_read_strictly`.
- `policy::tests` (macOS, round 2): `a_failing_refresh_refuses_after_its_grace_and_recovers`,
  `stale_facts_are_re_read_once_for_every_caller`.
- `nearhop::tests`: `an_unreachable_at_once_is_no_answer_on_macos` and
  `connection_info_is_read_within_what_the_kernel_wrote` (review round 1),
  `the_check_connection_finds_a_public_host_far` (now passes for real),
  `the_check_connection_finds_a_local_listener_near` (v4 and v6),
  `a_near_listener_that_gave_the_probe_no_answer_is_near_on_macos`, and the existing
  `a_local_listener_is_near`, `outcomes_are_classified`. Round 2:
  `the_check_reads_only_an_acknowledged_fin_as_an_answer`,
  `a_peer_that_closes_first_is_never_far`,
  `a_mapped_address_is_probed_as_its_ipv4_address`.
- `macos_tests` (this host's real facts): `loopback_link_local_the_lan_and_the_router_are_refused`,
  `neighbours_own_addresses_site_resolvers_and_deny_cidrs_are_refused` (with the kernel's own
  on-link and local verdicts), `a_public_address_is_admitted_and_vetted`,
  `a_destination_within_the_hop_limit_is_refused` (a loopback listener stands in, real probe:
  accepted, then refused), `this_macs_uplinks_are_its_unscoped_defaults`,
  `a_utun_or_ppp_uplink_needs_internal_ranges`.
- Round 3 (the table in "Review round 3" says which finding each covers):
  `a_datagram_cut_by_the_receive_buffer_is_no_answer`, `a_kernel_that_refuses_the_silent_query_fails_it`,
  `every_interface_holding_the_source_counts`, `live_forged_answers_are_never_taken` (opt-in:
  `ZKMINER_TEST_LIVE_FORGE=1`, on its own), `abandoned_calls_are_counted_before_they_can_return`,
  `a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends`, `a_new_uplink_is_refused_until_the_facts_hold_it`,
  `ipv6_is_refused_while_a_new_uplinks_nat64_prefix_is_learned`, `a_slow_refresh_holds_only_the_caller_that_runs_it`,
  `nat64::tests::{a_new_uplink_is_asked_for_its_prefix_at_once, a_new_uplink_signature_is_unsettled_at_first,
  the_active_and_routed_servers_are_asked_first, the_configuration_daemons_nat64_prefixes_are_read}`,
  `dns_answers_confirm_nothing_without_the_dns_servers`, `nearhop::tests::{a_hang_up_without_an_error_is_a_failed_probe_on_macos,
  a_silent_destination_is_no_answer_to_the_real_probe_on_macos, a_probe_that_timed_out_is_asked_again_once,
  a_fin_acknowledged_at_no_hop_limit_is_never_far, a_peer_that_never_acknowledges_a_fin_is_not_far}`,
  `strict_ci_fails_skips_it_does_not_allow`. Every test that cannot check what it is for here prints
  `SKIPPED: …` and passes, or fails under `ZKMINER_CI_STRICT=1` (none skipped on this Mac:
  `gate-netguard-strict.log`).
- PR #37's tests that failed on macOS and now pass: `nearhop::tests::the_check_connection_finds_a_public_host_far`,
  `policy::tests::this_hosts_site_resolvers_and_public_addresses_are_refused`,
  `real_host::{ordinary_public_hosts_are_admitted_on_this_host, public_hosts_are_far_and_reachable}`,
  `zkminer-chain` `programs::fetch_tests::{a_public_store_is_served_in_public_mode_and_hash_checked,
  a_redirect_to_a_local_url_is_refused_in_public_mode}`. The platform-independent refusal tests
  (`floor_tests`, `policy::tests`, `client::tests` including the DNS-rebinding cases
  `rebind.example.com` → 127.0.0.1) run unchanged on macOS and pass.
- `real_host::a_near_target_is_near` (ignored; `ZKMINER_TEST_NEAR_TARGET`): the ISP's second-hop
  router refused on port 179, timed out on 443.

## Review round 1

Four reviewers (parse, bypass, probe, cross; material in `/Users/user/zkminer/scratch/w11/NGREV/r1-*`).
Each finding was first reproduced on 25764db, then fixed with a test that covers it. Logs:
`/Users/user/zkminer/scratch/w11/NGREV/fix-r1/`.

| # | finding | reproduced on 25764db | outcome | covered by |
|---|---|---|---|---|
| 1 | cross-1 (medium): no test covers the NECP source-interface check | yes: `if admissible && false` left all 139 tests green (`repro1-mutation-on-HEAD.log`) | the check is the pure `decide(route, socket)`; real-host check added; that mutation and two narrower ones now fail (`mutation-r1.log`) | `the_socket_view_decides_an_admissible_answer`, `this_hosts_sockets_leave_by_the_routes_interface` |
| 2 | parse-1 (low): `mask_len` reads `0.255.255.0` as `/0` | yes: the captured LAN reply with that mask parsed as `0.0.0.0/0` on-link, default-like (`repro-on-HEAD.log`) | a non-contiguous route netmask is malformed: the reply refused, the dump failed | `a_non_contiguous_netmask_is_malformed`, `netmasks_and_scopes_read_as_the_kernel_means_them` |
| 3 | parse-3 (low): `feth` counts as a physical uplink | yes: `link_kind(IFT_ETHER, "feth0")` was `None` (physical) | only `en`, `ap`, `awdl`, `llw`, `nan`, `anpi` are physical; other names are `ether-<name>`, not physical | `interface_types_read_as_link_kinds`, `this_hosts_interfaces_read_as_their_kinds` |
| 4 | parse-2 (low): nameservers macOS accepts are dropped; a non-UTF-8 byte drops a file; `read_dir` errors read as no files | yes: `203.0.113.053`, `3405803829`, `0xcb007135`, `10.1` gave nothing; `read_to_string` failed on the file; the `read_dir` error path by reading (`let Ok(dir) = … else { return Vec::new() }`) | `facts::macos_dns`: every macOS parser's reading counts (`getaddrinfo` and `inet_aton` disagree on `053`: both count); bytes read lossily, 1 MiB cap, non-regular files skipped, other errors fail the facts read | `macos_reads_nameservers_as_its_resolvers_do`, `macos_resolver_files_are_read_strictly` |
| 5 | bypass-1 (low): resolvers only configd knows are not read | by reading only: on this Mac configd's servers are `/etc/resolv.conf`'s, so no test could fail here | configd's `State:/Network/Service/*/DNS` and `State:/Network/Global/DNS` `ServerAddresses` are read (system-configuration 0.7.0 at its locked version); an unreadable store fails the facts read | `macos_dns_servers_are_the_configuration_daemons` (against `scutil --dns`) |
| 6 | parse-4 (info): `sockaddr_ip` ignores `sa_len` | yes: an `AF_INET` sockaddr of `sa_len` 4 read as the address in the bytes after it | macOS reads within `sa_len`; a short IP sockaddr names no address | `ip_sockaddrs_are_read_within_their_length` |
| 7 | bypass-2 (info): `RTM_GET` answers the default route for 0.0.0.0 and `::` | yes, and they were refused only because the UDP source check happened to see `lo0` (`Split`); with finding 1's mutation the route check would have admitted them (the address check still refuses them as not global) | answered as a local route, explicitly | `the_unspecified_addresses_are_this_host` |
| 8 | probe-1 (info): libc's `tcp_connection_info` is 176 bytes, the SDK's 112 | yes: the kernel writes 112 of 176 bytes | only `tcpi_state`, `tcpi_rttcur`, `tcpi_srtt` are read, and only when the returned length covers `tcpi_srtt` (48); SDK offsets asserted | `connection_info_is_read_within_what_the_kernel_wrote` |
| 9 | cross-2 (low): three weak real-host tests | by reading: the uplink test asserted on a table that already drops scoped defaults; the LAN test never reached macOS code; the neighbour test could pass with 0 neighbours | the raw dump is checked; router and LAN neighbour asserted `OnLink` by the kernel and the table; at least one neighbour required where a global prefix exists, else `SKIPPED` | `this_macs_uplinks_are_its_unscoped_defaults`, `loopback_link_local_the_lan_and_the_router_are_refused`, `neighbours_own_addresses_site_resolvers_and_deny_cidrs_are_refused` |
| 10 | cross-3, cross-4, cross-5 (docs) | by reading: the cross-platform nearhop test and the zkminer-cli `Cargo.toml` change (all non-Linux Unixes) were not listed; the table said a non-IP gateway is always refused; the `route -n get` test compared no mask and no LAN, neighbour or fe80 row | this note corrected (the list at the top, the routing table rows); the cross-check compares the mask and asks for a LAN neighbour, a `/64` neighbour and `fe80::1` | `this_hosts_answers_agree_with_route_get` |
| 11 | hardening: random sequence start; check the answer is for the destination asked | adopted (round 2 replaced the counter: each query's number is drawn on its own, see parse-1 there): the counter starts at `arc4random()`; a reply's `RTA_IFP` must name the header's `rtm_index` (all 11 captured replies and every live answer do); the destination itself was already checked (`holds`) | | `the_answers_interface_is_the_headers` |
| 12 | hardening: count any interface holding the UDP source, not the first | adopted: `Split` if any interface but the route's holds it; this Mac's public v4 and v6 sources are each on one interface | | `every_interface_holding_the_source_counts` (round 3: the tests cited before, `the_socket_view_decides_an_admissible_answer` and `this_hosts_sockets_leave_by_the_routes_interface`, never had one address on two interfaces, and mutant X41, `.take(1)`, survived them) |
| 13 | hardening: a fast unreachable as failed, not far | adopted without a timing threshold: an unreachable `connect` returns at once (before `EINPROGRESS`) is refused. A threshold was not needed: every real "time exceeded" (177 of 180 probes to 9 public hosts, v4 and v6) came after `EINPROGRESS`, at 2.18 ms or more, and every Local Network denial (40 of 40) from `connect` itself, in 0.13 to 0.35 ms; no public host is refused (`h13-*.log`). A fixed threshold, by contrast, would rest on a margin a faster network could erode (the first hop answered in 0.98 ms here at hop limit 1) | | `an_unreachable_at_once_is_no_answer_on_macos`, `real_host::public_hosts_are_far_and_reachable` |

## Review round 2

Four reviewers again (parse, bypass, probe, cross; material in
`/Users/user/zkminer/scratch/w11/NGREV/r2-*`). Each finding was reproduced on 334624d first (or
shown not to be reproducible), then fixed with a test that covers it. Logs:
`/Users/user/zkminer/scratch/w11/NGREV/fix-r2/`. Round 1 said no other process can forge a
route reply because the kernel sets `rtm_pid`; that was wrong for writes the kernel refuses
(finding 1).

| # | finding | reproduced on 334624d | outcome | covered by |
|---|---|---|---|---|
| 1 | parse-1 (medium): forged `RTM_GET` answers | yes: `rtforge` shows a 200-byte write with `rtm_msglen` 128 delivered raw, pid and sequence number as written (`repro-rtforge-on-HEAD.log`); the reviewer's forger had 18,663 of 23,550 queries for 192.168.1.50 take its default route, all admitted by the judge (`repro-parse1-parse2-on-HEAD.log`) | (a) a datagram is the answer only if its length is its `rtm_msglen`, version 5, type `RTM_GET`, this pid and this sequence number; (b) each sequence number from `arc4random`; (c) `RTM_GET_SILENT` adopted (works on this macOS: `rtm-get-silent.log`), with `RTM_GET` kept as the fallback (round 3 removed the fallback, and found the 4,096-byte receive buffer cut oversized forgeries to their `rtm_msglen`); (d) the dump cross-check not adopted (the forged answer was the real default route, which the dump holds; real answers are often clones made after the dump). Then 23 kinds of forged write (`exp/rtvariants.c`, `forge-variants.log`): none reaches another socket in the accepted shape. Live: 324,125 queries answered by the kernel while 1,411,650 forged datagrams with this pid and the query's own sequence number arrived, none taken (`live-forge-after.log`); the reviewer's forger, rerun, saw no answer to forge from and took 0 of 2,438,375 (`reviewer-spoof-after.log`) | `forged_and_refused_writes_are_no_answer`, `live_forged_answers_are_never_taken` (named `forged_answers_are_never_taken` and ignored by default until round 3; now opt-in, `ZKMINER_TEST_LIVE_FORGE=1`), `queries_are_answered_to_the_asking_socket_alone`, `the_answers_interface_is_the_headers` |
| 2 | parse-2 (low): an 8-byte message fails queries | yes: 729,503 of 730,007 queries failed during the reviewer's flood | any datagram that is not an exact-length `RTM_GET` with this pid and sequence number is skipped; only a matching answer that does not parse is an error. Rerun: 0 of 7,449 failed. A flood that fills the socket buffer can still lose the answer: the query times out and the destination is refused (fail-closed denial of service, documented) | `forged_and_refused_writes_are_no_answer`, `malformed_and_truncated_input_is_an_error` (a datagram of the wrong length is now no answer instead of an error) |
| 3 | bypass-1 (medium): a failed facts refresh keeps the old snapshot | yes: with the reviewer's flag-file patch the first snapshot stayed in force 5 s and 8.8.4.4 stayed admitted (`repro-bypass1-bypass2-on-HEAD.log`) | macOS: the verdict cache is dropped on a failed re-read; after `FACTS_TTL` + `REFRESH_GRACE` (1 + 2 s) every requester connection is refused with `Denied::FactsUnreadable` naming the failure; re-read retried at most every 100 ms; service resumes when it succeeds | `a_failing_refresh_refuses_after_its_grace_and_recovers` |
| 4 | parse-3 + bypass-1 (low): one bad `/etc/resolver` entry fails every facts read | yes (`r2-bypass/resolver-conditions.log`: unreadable file, file over 1 MiB, symlink loop, unreadable directory all fail the read) | decided per condition. configd reads `/etc/resolver/*` as root (dnsinfo's flat-file resolvers, by configd's source, `dnsinfo_flatfile.c`) and publishes their servers only in dnsinfo, which the guard cannot read, never in a `State:` key: skipping a file this user cannot read, or reading only part of a big one, would leave a site resolver unrefused, so those stay fail-closed, the message naming the file, with a README troubleshooting line. A looping symlink cannot be opened by configd either, so it names no resolver: skipped with a warning. The doc sentence "skipped without being opened" corrected (opened `O_NONBLOCK`, `fstat`ed, never read) | `macos_dns_servers_come_from_every_source`, `macos_resolver_files_are_read_strictly` |
| 5 | manual DNS on a non-primary service | not reproducible here (no `Setup:` DNS key on this Mac, and writing one needs root); by reading configd's IPMonitor, which merges `Setup:/Network/Service/<id>/DNS` into the service's resolver for dnsinfo without a `State:` key | `Setup:/Network/Service/[^/]+/DNS` read too (unprivileged). `dns_configuration_copy` evaluated: exported by `libsystem_configuration.dylib`, but its structs are configd's private `dnsinfo.h` (absent from the SDK), a pointer tree whose layout is no ABI promise; a misread is undefined behaviour, so it is not used (documented) | `this_hosts_dns_keys_are_all_read`, `macos_dns_servers_are_the_configuration_daemons` (against `scutil --dns`), mutation N06 |
| 6 | bypass-2 (low, shared): same gateway IP, same interface, same uplink signature | yes: the reviewer's two tables give the same signature (`repro-bypass1-bypass2-on-HEAD.log`) | the gateway's link-layer address is not available unprivileged (no ARP entry at all, every NDP address `02:00:00:00:00:00`: `llinfo-unprivileged.log`), so macOS hashes configd's `NetworkSignature` of every service (router address and hardware address, IPv6 prefix and router hardware address) into the signature | `two_networks_behind_the_same_router_address_are_two_uplinks_on_macos`, `network_signatures_are_read_strictly` |
| 7 | cross-1 / cross-2 (low): mutation survivors M16, M20, M21, M22, M25, M27, M30, M32 | yes (`r2-cross/mut/summary.txt`) | tests added (below); `server_addresses` already took a `CFPropertyList`, and `servers_of`, `signatures_of` and `read_with` make the callers testable. `fix-r2/mut/run.py` with 52 mutations (the reviewer's 32, some retargeted to moved code, and 20 for this round's decision points): 50 killed (`mut/summary.txt`). Two survive, both equivalent here: N13 (the check connection's state before its FIN unchecked: a peer that closed first then shows `LAST_ACK` or `CLOSED` after it, also a failure, so only the message differs) and N15 (the check connection not unmapping: on this kernel `IPV6_UNICAST_HOPS` does limit an established mapped connection's FIN, `repro-probe1-probe2-on-HEAD.log`; the unmapping is defence in depth) | `configd_values_are_read_strictly`, `macos_dns_servers_come_from_every_source`, `this_hosts_dns_keys_are_all_read`, `netmasks_are_read_within_their_length`, `the_facts_read_fails_without_the_configuration_daemon`, `the_destination_port_reaches_the_socket_check`, `plain_clones_in_the_dump_are_not_read`, real-host subset asserts in `macos_dns_servers_are_the_configuration_daemons` |
| 8 | cross-3 (low, shared): blocking calls on tokio workers, no single-flight | by reading (`resolve.rs:176`, `doh.rs:449` call `policy.admit()` on the runtime) | macOS: one facts re-read at a time (callers wait for it and take its facts); configd asked on a thread of its own within 2 s, at most four abandoned calls. Moving the admit loop into `spawn_blocking` is shared code: recommended for #37 | `stale_facts_are_re_read_once_for_every_caller`, `a_stuck_configuration_daemon_fails_the_read_in_time` |
| 9 | probe-1 (low, shared logic): a peer that closes first counts as answered | yes: NIST's daytime server 129.6.15.28:13, two hops out, read `Answered` 3 of 3 times (`repro-probe1-probe2-on-HEAD.log`) | macOS: only `FIN_WAIT_2` / `TIME_WAIT` is an answer; a peer that closed or reset first is a failed check (refused, not near, never far). (`snd_una` is not in `TCP_CONNECTION_INFO`'s 112 bytes.) Now `Failed("the peer closed the check connection …")` | `the_check_reads_only_an_acknowledged_fin_as_an_answer`, `a_peer_that_closes_first_is_never_far` (loopback listeners that close or reset at once, and the daytime server) |
| 10 | probe-2 (info): the probe ignores the hop limit for v4-mapped addresses | yes: the probe of `[::ffff:1.1.1.1]:443` at hop limit 2 connected (`repro-probe1-probe2-on-HEAD.log`); not reachable through `vet_connection`, which unmaps | macOS: the probe and the check connection unmap | `a_mapped_address_is_probed_as_its_ipv4_address` |
| 11 | documentation | | Network Extension flow-divert / app-proxy VPNs, DNAT/hairpin routers, the time between check and connection, a routing-message flood (residual risks); `ENETUNREACH`/`EHOSTUNREACH` as no route (the query section); this section; the round-1 claim corrected | |

`this_hosts_answers_agree_with_route_get` now gives `route -n get` 5 s and asks again: route(8)
waits for its own answer with no timeout, and a routing socket whose buffer fills drops
messages (once under the live forge test and once during the mutation run it waited for ever).

### Recommended for #37 (shared code)

None of these is applied on Linux; each is for the owner of #37 to decide.

1. **A failed facts re-read keeps the old facts for ever** (bypass-1): Linux's `FactsCell` keeps
   the last good snapshot, cached kernel verdicts included, for as long as the netlink re-read
   fails. Suggest the macOS behaviour: drop the verdicts, refuse after a short grace, retry.
2. **Single-flight re-reads and blocking calls off the runtime** (cross-3): every caller that
   finds the facts stale re-reads them; `resolve.rs:176` and `doh.rs:449` call `policy.admit()`
   (route queries, `getifaddrs`, netlink) on tokio workers. Suggest the macOS single-flight in
   `FactsCell`, and the admit loops in `spawn_blocking`.
3. **The uplink signature** (bypass-2): two networks behind the same router address on the same
   interface share it. Linux can add the gateway's link-layer address from the neighbour table
   (`RTM_GETNEIGH`, unprivileged and not redacted on Linux).
4. **The check connection reads a peer's own close as an answer** (probe-1): Linux's
   `confirm_once` returns `Answered` for any state but `FIN_WAIT1` (`CLOSE_WAIT`, `LAST_ACK`,
   `CLOSING`, `CLOSE`). Suggest: answered only on `FIN_WAIT2` / `TIME_WAIT`, a peer that closed
   or reset first a failure (or use `tcpi_snd_una` past the FIN, which Linux's `TCP_INFO` has).
5. **Unmap inside the probe primitives** (probe-2): defence in depth; `vet_connection` already
   unmaps.
6. **The time between check and connection** (bypass-3): re-check the connected socket
   (`getsockname`, its interface) after `connect`, or connect through a connector that binds the
   checked source.

## Review round 3

Four reviewers again (parse, bypass, probe, cross; material in
`/Users/user/zkminer/scratch/w11/NGREV/r3-*`), the last round. Each finding was reproduced on
30ea435 first (a failing test or a live repro) or shown by reading, then fixed with a test that
covers it. Logs: `/Users/user/zkminer/scratch/w11/NGREV/fix-r3/`. Round 2 said a forged answer
needed "exactly one message (its length its `rtm_msglen`)"; that rule was right, but the receive
buffer could make a longer datagram look like one (finding 1).

| # | finding | reproduced on 30ea435 | outcome | covered by |
|---|---|---|---|---|
| 1 | parse-1 (high): an oversized forged datagram, cut by the 4,096-byte receive buffer to exactly its `rtm_msglen`, passes the exact-length rule | yes: the reviewer's unit test took a 4,096-byte prefix of a longer datagram as a default route; `rttrunc` (5 sizes from 4,097 to 8,000 bytes accepted: `repro-rttrunc-on-30ea435.log`); live with the reviewer's `rtforge3`: 8,277 of 8,283 silent queries with a known sequence number and 7,401 of 7,513 fallback (`RTM_GET`) queries with learned sequence numbers took the forged default route (`repro-live-forge-on-30ea435.log`) | `recvmsg` into 16 KiB; a datagram that fills it or carries `MSG_TRUNC` is never read (`recv_whole`, `whole`). Forgery matrix below: 134 kinds of write, none accepted (24 were by round 2's rule). Live forge, twice: 316,137 and 318,484 queries answered by the kernel while 1.31 M forged datagrams with this pid and the query's sequence number (oversized ones among them) arrived, none taken (`gate-live-forge-run{1,2}.log`); the reviewer's `rtforge3` rerun (its tests adapted: no fallback to force): 0 of 683,472 queries with a known sequence number took its default route while it wrote 10.6 M forgeries, and in learn mode it saw 0 answers and 0 of 658,387 queries were forged (`reviewer-rtforge3-after.log`) | `a_datagram_cut_by_the_receive_buffer_is_no_answer` (live: a 4,100-byte forgery into a 4,096-byte buffer is `MSG_TRUNC`, into the real one 4,100 bytes, no answer), `forged_and_refused_writes_are_no_answer` (oversized kinds added), `live_forged_answers_are_never_taken` |
| 2 | parse-2 (medium): the `RTM_GET` fallback re-opens sequence-number observation, and one `EPERM`/`EOPNOTSUPP` latches it for the process | by reading (`ask_as`: `SILENT_REFUSED.store(true)`), and the fallback's exposure live (7,401 of 7,513 above) | `RTM_GET_SILENT` is the only way a query is asked; a kernel that refuses it fails the query (`this kernel refused a route query sent as RTM_GET_SILENT …`, the destination refused), nothing latched. macOS versions: works on this Mac (27.2, 26B131). `RTM_GET_SILENT` (0x11) is in xnu's open-source `bsd/net/route.h` (its `PRIVATE` section, beside `RTM_GET_EXT`) and handled in `rtsock.c`'s `route_output` (`sendonlytoself`) in every xnu release I know of for over a decade, macOS 26's included (from memory of the public source; not fetched, and not tested on a macOS 26 machine: none here). Were a supported version to lack it, every requester connection would be refused with that message: fail closed, never a forgeable query | `a_kernel_that_refuses_the_silent_query_fails_it` (a type the kernel refuses fails the query; the next one is asked silently), `queries_are_answered_to_the_asking_socket_alone` |
| 3 | bypass-1 (medium, shared): NAT64 network-specific prefixes are learned at startup and every 300 s only | yes: the reviewer's `r3_an_unlearned_nsp_carries_private_ipv4_as_global`, `<NSP>::10.0.0.1`, `::192.168.1.1`, `::169.254.169.254`, `::127.0.0.1` admitted on an IPv6-only host until the NSP was learned (`repro-on-30ea435.log`) | macOS: discovery per uplink signature (a change starts a round at once; 15 s retries while an IPv6-only host has none; configd's per-interface NAT64 state read too); while a new signature's round has not finished, an IPv6-only host refuses every IPv6 destination (`Denied::Nat64Unsettled`, facts-dependent); a dual-stack host is never refused for it. Recommended for #37 (the trigger and the retry) | `a_new_uplink_is_asked_for_its_prefix_at_once`, `a_new_uplink_signature_is_unsettled_at_first`, `a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends`, `ipv6_is_refused_while_a_new_uplinks_nat64_prefix_is_learned` (the reviewer's test, adapted), `the_configuration_daemons_nat64_prefixes_are_read` |
| 4 | bypass-2 (low): NAT64 discovery asks the first 8 of the sorted resolver list, IPv4 first | yes: the reviewer's test, eight silent IPv4 servers ahead of a DNS64 on `[::1]` hid its prefix (`repro-on-30ea435.log`) | macOS: active servers (`State:/Network/Global/DNS`) first, servers of an unrouted family skipped (IPv6 first without IPv4), cut after ordering. Recommended for #37 | `the_active_and_routed_servers_are_asked_first` (the reviewer's test, adapted) |
| 5 | bypass-3 (low, shared rule): any default-like kernel answer is admitted, whatever its interface or gateway | yes: the reviewer's `r3_a_new_uplink_passes_the_kernel_check_of_old_facts`, three answers through uplinks the facts do not hold admitted | macOS: a default-like answer (not through a facts uplink) must be one of the facts' default-like routes (family, hop, interface), else refused as off the default path (facts-dependent: the forced re-read runs). No false refusal here: `admit_to` for every address of the 101-name list (`fix-r3/admit-sweep.log`, `exp/admitsweep.rs`) admitted 291 (136 of them IPv6) and refused 2, 1.1.1.1 and 9.9.9.9, which are this Mac's own DNS servers; the real-host tests and `zkminer-chain`'s real downloads pass. Recommended for #37 | `a_new_uplink_is_refused_until_the_facts_hold_it` (the reviewer's test, adapted), `the_kernels_answer_per_destination_is_judged` (macOS asserts) |
| 6 | bypass-4 + cross-4 (info): `Bounded`'s abandoned count can wrap; the doc said "at most one at a time" | yes: the reviewer's test saw the count above 10^18 in 2 of 4 runs here (`repro-on-30ea435.log`) | counted before the call is marked abandoned, uncounted if it returned meanwhile; the doc describes the concurrency (requests not serialised, live calls not capped, timed-out ones capped at four) | `abandoned_calls_are_counted_before_they_can_return` (16 racing callers, 3 s; round 2's order fails it, not every run: the window is microseconds) |
| 7 | probe-1 (low, shared logic): a peer that never acknowledges a bare FIN reads as far at any distance | yes: every S3 front end tested stays in `FIN_WAIT_1` at the full hop limit (`r3-probe/finack-s3.log`; `fix-r3/exp/finrestore-1.log`) | macOS: positive control (restore the hop limit, wait the RTO, two round trips and 250 ms for the retransmitted FIN's ACK; ACK: far; none, or a close or reset: failed) and a second probe attempt within the probe's 1.5 s. Cost and decision below. Recommended for #37 | `a_fin_acknowledged_at_no_hop_limit_is_never_far`, `a_peer_that_never_acknowledges_a_fin_is_not_far` (live, S3), `a_probe_that_timed_out_is_asked_again_once`, `the_check_connection_finds_a_public_host_far` (1.1.1.1 still far) |
| 8 | cross-1 + cross-3 (low/info, tests): mutants X37, X30, X41 survived; the doc cited the wrong test for round 1 #12 | yes (`r3-cross/mut/summary.txt`) | tests added; `connect_result` and `interfaces_holding` made pure; round 1's table corrected | `a_silent_destination_is_no_answer_to_the_real_probe_on_macos` (the reviewer's X37 test), `a_hang_up_without_an_error_is_a_failed_probe_on_macos`, `every_interface_holding_the_source_counts`; mutation run below |
| 9 | cross-2 (low): no CI runs the netguard suite; several tests SKIP silently | by reading | `ZKMINER_CI_STRICT=1` fails every SKIPPED path (unless `ZKMINER_CI_ALLOW_SKIP` names part of its reason); `ZKMINER_TEST_LIVE_FORGE=1` runs the live forge test (it does nothing otherwise); CI commands below | `strict_ci_fails_skips_it_does_not_allow`; the strict run here (`gate-netguard-strict.log`) |
| 10 | cross-5 (info): `system_resolvers()` is empty when reading fails, so discovery loses its DNS-server exclusion | by reading (`facts.rs`: `read_system_resolvers().unwrap_or_default()`) | public-address discovery reads the servers itself; on an error no DNS reflector answer confirms anything that round (only the HTTPS reflector); NAT64 discovery fails its round | `dns_answers_confirm_nothing_without_the_dns_servers` |
| 11 | cross-6 (info): the operator's warnings never mention `FactsUnreadable` | by reading (`ElfFetcher::guard_warnings`) | `HostFacts::unreadable_reason()` (cfg-free, `None` off macOS), shown first by `guard_warnings` | `a_failing_refresh_refuses_after_its_grace_and_recovers` (asserts it) |
| 12a | suspicion: one non-numeric `ServerAddresses` entry fails every facts read | yes, by the reviewer's shapes (`SA ['']`, `SA [' 10.0.0.1']` fail the read: `r3-parse/r3-tests.log`) | adopted: configd's `_SC_string_to_sockaddr` (`inet_aton`, then `inet_pton`) skips a string it cannot parse (from memory of configd's source: `dns-configuration.c` adds a nameserver only when it parses), so it names no server the system asks; the guard's parsers are a superset (`getaddrinfo`, `inet_aton`, the plain form), so skipping what none of them reads cannot leave a real server unrefused. Skipped with one warning per entry; a non-string value still fails the read | `configd_values_are_read_strictly` (updated) |
| 12b | suspicion: a configd that answers just after 2 s keeps re-reads failing and blocks every caller | yes: 24 calls held for 3 re-reads (`repro-12b-before.log`) | callers wait for a re-read under way until it is 500 ms old; then the facts in force within their grace, or a refusal at once; 3 slow calls for 3 re-reads after (`12b-after.log`), none admitted on facts past their grace | `a_slow_refresh_holds_only_the_caller_that_runs_it` |

**Forgery matrix** (`fix-r3/exp/rtvariants3.c`, `fix-r3/forge-variants-r3.log`): a child writes
each kind with the parent's pid and a fixed sequence number; two routing sockets (the default
8,192-byte receive buffer, and one raised to 1 MiB) receive with `recvmsg` into 16 KiB and apply
the round-3 rule (whole, length = `rtm_msglen`, version 5, `RTM_GET`, pid, sequence number);
round 2's rule (a 4,096-byte `recv`) is applied to the same datagrams for comparison.

| kinds of write | delivered to the guard's sockets with its pid | round 3 accepts | round 2 accepted |
|---|---|---|---|
| round 2's 16 shapes (exact forged answer, +4 and +127 bytes, cut, 8-byte stub, `rtm_msglen` 0, versions 4 and 6, types 0x55 and 0, bad sockaddr, `RTM_ADD`/`DELETE`/`CHANGE`/`LOCK`, `RTM_GET_SILENT`) | refused writes, as written (exact-length `RTM_GET` writes are taken as queries: the kernel sets the writer's pid) | 0 | 0 |
| `rtm_msglen` 2,140, 4,095, 4,096, 4,097, 8,000, 8,191, 8,192, 16,383, 16,384, 16,385, 32,768, 65,535, written exactly, +1, +4, +100, +4,096 bytes, with and without `SO_SNDBUF` 1 MiB (108 kinds) | longer than `rtm_msglen` and up to ~8 KiB: delivered whole (`MSG_TRUNC` unset, the length not `rtm_msglen`); over the writer's 8 KiB default `SO_SNDBUF`: `EMSGSIZE`, never sent; up to 1 MiB with `SO_SNDBUF` raised: only the 1 MiB socket receives them, cut to 16 KiB with `MSG_TRUNC` | 0 | 24 (every `rtm_msglen` 4,096 written 4,097 to 8,191 bytes) |
| `rtm_msglen` 4,096 written 4,093 to 4,100 bytes; the same as `RTM_GET_SILENT`, and with a bad sockaddr | as above | 0 | 4 (4,097 to 4,100) + 1 (bad sockaddr) |
| live, `rtforge3` (the reviewer's: 4,100-byte writes, `rtm_msglen` 4,096, known sequence number; and learned sequence numbers) | yes | 0 of 683,472 (known sequence number), 0 of 658,387 (learned: nothing to learn) | 8,277 of 8,283 (silent), 7,401 of 7,513 (fallback) |

There is no non-silent path any more (finding 2), so every row is the silent path; a forger
reaches the guard's socket only with refused writes, which are delivered to every routing socket
whatever the query's type.

**The positive control's cost (finding 7).** 101 public addresses (`r3-probe/hosts.txt`: GitHub,
Arweave and IPFS gateways, S3, CloudFront, R2, GCS, Fastly, Akamai, crates.io, PyPI, npm, Hugging
Face, …, v4 and v6), on this Mac's home path:

- Peers that never acknowledge a bare FIN, at any hop limit: the 5 S3 endpoints (4 names, v4
  and v6); every other store acknowledges it (`r3-probe/sweep-h2.log`: 96 answered at hop limit
  64). With the control, a check-only decision (the probe silenced, as on a path whose first two
  routers send no ICMP) refuses all 10 S3 decisions, and 192 of the other 199 are far as before
  (6 refusals are NIST's daytime servers, which close first, refused since round 2; 1 is one
  R2 IPv6 check connection that took 9 s to connect) (`sweep-h2-after.log`).
- How often the real decision needs the check connection here: the probe went unanswered in 16 of
  212 decisions in the reviewer's sweep (7.5%, a router rate-limiting its ICMP) and 15 of 209 in
  ours before the second attempt, 1 of them an S3 decision, refused (`sweep-h2-after.log`); with
  the probe's second attempt, 10 of 318 (3.1%), no S3 decision among them (0 of 15 refused;
  `sweep-real-retry.log`).
- So, with the control: on this path an S3 download is refused in roughly 3% of attempts (each
  attempt is decided anew); on a path that filters ICMP within two hops (some corporate and cloud
  networks; an EC2 instance's first hops often send none), every S3 download is refused, saying
  `the peer acknowledged the check connection's FIN neither within the hop limit nor at the
  default one`. Without it, a near device that never acknowledges a bare FIN and drops the
  probe's SYN is admitted as far. That device is the guard's victim, not the attacker (the
  attacker picks the URL, not the device's TCP stack), and no such device is known; S3 is a
  major store. Decision: adopted, because the guard fails closed everywhere else and the cost is
  bounded by the probe's answer rate, which the second attempt halves; the operator sees which
  store and why, and README's troubleshooting names it. If S3-hosted programs matter more than
  that residual on ICMP-filtering hosts, the alternative is to drop the control and accept
  probe-1 (a one-line change in `confirm_once`). Recommended for #37 with that cost stated.

**CI** (finding 9). `scripts/ci/macos-cpu-tests.sh` lives on `item/W11-ON37`, so nothing is
committed there; the ready-to-apply change (that script, and a Linux workflow) is
`fix-r3/ci-recommended.diff`. In short, add to `macos-cpu-tests.sh`, after the zkminer-prover step:

```bash
echo "== the network guard (zkminer-netguard), every skip a failure"
ZKMINER_CI_STRICT=1 ZKMINER_CI_ALLOW_SKIP="${ZKMINER_CI_ALLOW_SKIP:-}" \
  cargo test --locked --release -p zkminer-netguard
echo "== the network guard: forged routing-socket answers (floods every routing socket: on its own)"
ZKMINER_TEST_LIVE_FORGE=1 cargo test --locked --release -p zkminer-netguard --lib live_forge -- --test-threads=1
```

and a Linux job (a new workflow, or a job in `e2e.yml`):

```bash
ZKMINER_CI_STRICT=1 ZKMINER_CI_ALLOW_SKIP="IPv6,[::1]" cargo test --locked -p zkminer-netguard
cargo clippy --locked -p zkminer-netguard --all-targets -- -D warnings
```

A runner without IPv6 (GitHub's hosted runners have none) sets `ZKMINER_CI_ALLOW_SKIP=IPv6`;
every other skip then fails the job. The suite needs outbound DNS, HTTPS and the near-hop probe's
ICMP; a runner whose first hops send no ICMP "time exceeded" fails
`public_hosts_are_far_and_reachable`-style tests by design.

**Mutation run** (`fix-r3/mut/run3.py`, `muts3.py`; `summary-run1.txt`, then `summary.txt` for
the reruns): the reviewer's 39 mutants (X01–X46, the ones whose code moved retargeted: X08, X14,
X21, X24, X28, X30, X33, X38, X41, X44) and 40 for round 3's decisions (N01–N40; N12 dropped with
the redundant branch it targeted). 78 run, 73 killed, X30, X37 and X41 among them. Five survive:
X10 (the socket view asked for a non-unicast route as well: such a route is refused whatever the
socket says, so only the message differs; it survived round 2 too), X32 (the check connection's
state before its FIN unchecked: equivalent, round 2's N13), N04 (`RECV_BUF` back to 4,096: still
safe, since `MSG_TRUNC` rejects a cut datagram, and no routing message is longer than 2,140
bytes), N31 (an error restoring the hop limit ignored: equivalent unless `setsockopt` fails), and
N25 (NAT64's round asking round 2's sorted list: the ordering, `order_servers`, is tested, but
the glue in `round_on` that calls it needs configd's servers and port-53 DNS servers to test).
N06 (`Bounded` counting after marking, round 2's order) is caught by a race test, killed in both
runs here, but not certain on every run (the window is microseconds).

**Gates** (`fix-r3/gates.sh`, `gates-summary.log`): `cargo test -p zkminer-netguard` twice and
once with `ZKMINER_CI_STRICT=1` (193 passed each, nothing skipped), the live forge test twice,
`cargo test -p zkminer-chain` (225 passed) and its real-network downloads (busybox.net's
connect timed out once, a slow server, `curl` took 5 s; passed twice on rerun:
`gate-chain-real-network-rerun{1,2}.log`), clippy on macOS and, with stub C compilers, check and
clippy `--all-targets` for `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` (no warnings),
the expanded-source comparison above, and `git merge-tree` into `item/W11-ON37` (clean).

### Recommended for #37 (shared code), after round 3

None of these is applied on Linux; each is for the owner of #37 to decide. Round 2's six, then
round 3's:

1. **A failed facts re-read keeps the old facts for ever** (round 2, bypass-1): drop the
   verdicts, refuse after a short grace, retry.
2. **Single-flight re-reads and blocking calls off the runtime** (round 2, cross-3): the macOS
   single flight in `FactsCell`, with round 3's bounded wait for callers (12(b)); the admit loops
   (`resolve.rs`, `doh.rs`) in `spawn_blocking`.
3. **The uplink signature** (round 2, bypass-2): add the gateway's link-layer address from the
   neighbour table (`RTM_GETNEIGH`, unprivileged on Linux).
4. **The check connection reads a peer's own close as an answer** (round 2, probe-1): answered
   only on `FIN_WAIT2` / `TIME_WAIT`; a peer that closed or reset first a failure.
5. **Unmap inside the probe primitives** (round 2, probe-2).
6. **The time between check and connection** (round 2, bypass-3): re-check the connected
   socket after `connect`, or connect through a connector that binds the checked source.
7. **NAT64 prefixes per uplink** (round 3, bypass-1): start discovery when the uplink signature
   changes (as `public::learned_on` does), retry failed or empty rounds every 15 s on an
   IPv6-only host, and refuse IPv6 on such a host until the new network's round has finished.
   Linux has no configd; its PREF64 (RFC 8781) is in the kernel's RA handling (`ip -6 route`
   does not show it; `rdisc`/systemd-networkd expose it).
8. **NAT64 server order** (round 3, bypass-2): ask the resolvers in use first, skip servers of
   an unrouted family, cut after ordering.
9. **A default-like kernel answer must be a default route the facts hold** (round 3, bypass-3).
10. **The check connection's positive control** (round 3, probe-1), with its cost (S3 refused
    on ICMP-filtering paths) and a second probe attempt; Linux's `confirm_once` can read the
    FIN's acknowledgement from `tcpi_snd_una` and needs no state polling.
11. **Strict CI** (round 3, cross-2): already applied to the shared tests (it changes nothing
    without the variable); a Linux CI job (above).

## Review round 4

The findings and fixes, on every platform, are in
[netguard-hardening.md](netguard-hardening.md#review-round-4). What changes on macOS:

- **The check connection** (probe-1) is two connections: the check connection keeps its low hop
  limit for good (its FIN first), and a control connection, made after it at the default hop
  limit, replaces round 3's restored hop limit. Any acknowledgement of the check's FIN is near;
  far only once the control's FIN was acknowledged and the check's stayed unacknowledged past
  the window, one retransmission and the control's round trip again. Read from
  `TCP_CONNECTION_INFO` through `ConnReader` as before. Its live tests pass here
  (`the_check_connection_finds_a_public_host_far`: 1.1.1.1 far; `a_peer_that_never_acknowledges_a_fin_is_not_far`: S3 refused;
  `the_check_connection_finds_a_local_listener_near`; `a_peer_that_closes_first_is_never_far`).
- **Each hop's connection is the guard's own** (bypass-2): checked before its TLS handshake,
  bound to the vetted source (the UDP socket's choice on macOS: its route oracle gives no TCP
  source, and macOS has no protocol-selective routing rules).
- **NAT64**: the configuration daemon's prefixes are one source (`Source::System`, at most 8),
  kept per uplink; configured prefixes always in force; DNS64 answers validated (RFC 7050 §3).
- **Probes**: a third attempt after a 1 s pause, at most two in flight, a name's addresses one
  after another; a check that cannot decide is `NearCheckFailed`.


## Review round 5

The findings and fixes, on every platform, are in
[netguard-hardening.md](netguard-hardening.md#review-round-5). What changes on macOS:

- **NAT64**: an uplink whose sources name more prefixes than the guard holds is refused with its
  own reason (`Nat64Unheld`, naming the source: the configuration daemon's NAT64 state, a DNS
  server), and a source's next naming that fits clears it at once; a round's mark is replaced when
  the round ends, never cleared while it runs. A host with an address in 192.0.0.0/29 (macOS's
  CLAT, on an IPv6-only network that offers 464XLAT) is IPv6-only for NAT64: IPv6 is refused until
  its uplink's round ends. The macOS uplink signature (the configuration daemon's network
  signatures) is unchanged; the Linux one now changes at once with the gateway's MAC, as the
  macOS one always did.
- **Near-hop checks run within the caller's deadline**: the probe's turn, its attempts and pause,
  the check connection's connects and its wait (`TCP_CONNECTION_INFO` polling) all stop at the
  deadline the guarded request gives them; probes are also paced (a burst of 6, then 3 a
  second). The live check-connection tests pass here.
- **Each hop** races its two addresses (IPv6 first, IPv4 250 ms later), vets a name's two
  families at once, and bounds its TLS handshake by the connect timeout.
- **The check connection's failures** name the connection (check or control) within the 120
  characters a refusal shows.
