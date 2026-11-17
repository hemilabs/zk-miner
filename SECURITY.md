# Security notes

## The network guarantee

zkminer serves a permissionless market: anyone can register a program in the
ProgramRegistry (with the URLs its ELF is downloaded from) and post a job for it. So a miner
follows URLs that strangers chose. A malicious requester would aim them at the miner's own
network — a service on loopback, the LAN, the cloud metadata endpoint, the miner's own public
address, a neighbour on its link, an internal DNS name — and could have a guest commit what
came back to a public journal.

**A regular miner never connects to anything that is not on the public internet on a
requester's behalf.** Private access exists only behind the default-off developer setting
`[dev] private_network`, described below.

Every connection a requester can cause goes through one guard
(`crates/zkminer-netguard`). In the default (public) mode:

- **Only globally routable unicast addresses** are connected to (`is_global`). Refused:
  `0/8`, RFC 1918, CGNAT `100.64/10` (which holds Alibaba's metadata address), loopback,
  link-local `169.254/16` (cloud metadata), `192.0.0/24`, the TEST-NETs, benchmarking,
  multicast, `240/4`, Azure's `168.63.129.16`, the AMT relay anycast `192.52.193.0/24` and the
  AS112 anycast sinks `192.31.196.0/24` and `192.175.48.0/24`; on IPv6 everything outside
  `2000::/3` (loopback, ULA `fc00::/7` with AWS's `fd00:ec2::254`, link-local, site-local,
  multicast, discard, SRv6), documentation, 6to4, Teredo and **all of the IETF block
  `2001::/23`**, IANA's globally reachable assignments in it included: the PCP, TURN and
  DNS-SD SRP anycast addresses in `2001:1::/32`, AMT's relay anycast `2001:3::/32` and
  AS112-v6 `2001:4:112::/48` (the nearest instance of an anycast service may be a box on your
  own network), the Direct Delegation AS112 block `2620:4f:8000::/48` (the twin of
  `192.175.48.0/24`), and the ORCHIDv2 and DRIP identifier prefixes (`2001:20::/28`,
  `2001:30::/28`), which are not locators. Every entry of IANA's two special-purpose address
  registries is refused (a unit test walks them). An
  IPv6 address that carries an IPv4 one (mapped, SIIT, the well-known NAT64 prefix, and a
  **network-specific NAT64 prefix** — RFC 6052, any /32 to /96 a network picks for its
  translator) is judged by that IPv4 address, which the translator would connect to from its
  own IPv4 side; IPv4-compatible addresses are refused. The network-specific prefix is learned
  at startup and every 5 minutes by asking the host's own DNS servers for `ipv4only.arpa`
  (RFC 7050: a DNS64 resolver answers under its prefix), or named in `[egress]
  nat64_prefixes`. Deny CIDRs and the host's prefixes match every such spelling too
  (`64:ff9b::808:808/128` denies `8.8.8.8`, and a deny of `64:ff9b::/64` holds the addresses it
  holds as written).
- **Not this host, not its neighbours, not its site.** Refused, whatever the spelling:
  - the host's own addresses, **including its public address behind NAT**: at startup and
    every 5 minutes the miner asks fixed reflectors which address its query came from
    (`o-o.myaddr.l.google.com` TXT, asked of Google's authoritative `ns1.google.com`;
    `whoami.cloudflare` CH TXT, asked of `1.1.1.1`; and Cloudflare's `/cdn-cgi/trace` over
    HTTPS at `1.1.1.1`, an IP literal whose certificate is verified for that address), each over
    IPv4 and over IPv6, and refuses every address any reports (a warning says when they
    disagree). The names and servers are compiled in: nothing a requester sends chooses them,
    and an answer can only add an address to refuse. An address is **confirmed** when the HTTPS
    reflector reports it (a box that intercepts DNS cannot forge that answer) or both DNS
    reflectors report it alike — unless the HTTPS reflector's TCP connection was made but TLS or
    its answer failed (something on the path answers for `1.1.1.1`, and could answer the DNS
    queries alike too: then DNS confirms nothing for that family), and a DNS answer that is one
    of the host's own DNS servers (an intercepting resolver reporting itself) confirms nothing
    either. A confirmation lasts 10 minutes (two discovery rounds): a family no round has
    confirmed for that long is unknown again. Discovery also runs again at once when the host's
    uplink changes (its default routes, or the interface its internet traffic leaves by), and
    until it has, nothing confirmed on the old uplink counts. Only a confirmed address gives
    its IPv6 site (below), so one forged answer cannot refuse someone else's whole site. Facts
    read while the first discovery runs wait for it. `[egress] public_addresses` states the
    public addresses instead (or as well); `[egress] discover_public_addresses = false` turns the
    queries off, and then `public_addresses` must name an address of every family the host
    routes or the miner does not start;
  - **fail closed:** for every address family the host routes (has a default route for), a
    public address must be **known** — confirmed by discovery, or stated in `[egress]
    public_addresses` — or **no requester connection goes out over that family**: behind NAT,
    a destination at the unknown address would reach this host or its router by hairpin. The
    miner warns at startup and whenever it changes, `zkminer status` says so, and both name the
    line to add; discovery is retried every 15 seconds meanwhile. On an **IPv6-only host behind
    NAT64**, the IPv4 reflectors are asked at their addresses under the NAT64 prefix in force
    (configured, or learned from the host's DNS64), which reports the translator's own IPv4
    address: refused as the host's own, and until it is known (or an IPv4 address is stated)
    every address under that prefix is refused. A host with IPv4 of its own never connects to an
    IPv6 address that carries an IPv4 one (NAT64, SIIT): there is no translator it needs, and
    one it reached could hairpin;
  - **every address a `local`, `broadcast` or `anycast` route delivers to the host itself**, in
    any routing table: an AnyIP range (`ip route add local 185.199.108.0/24 dev lo`, as
    freebind, anycast and IPv6-proxy hosts install) is this host though no interface carries it.
    A `local` route of length `/0` (a transparent proxy's catch-all, which only a `fwmark` rule
    consults) is left alone; shorter local routes (`/1` to `/4`) refuse what they hold, and if
    they leave no public address at all the miner refuses to start and says why;
  - every network the host is connected to: each interface's network under its netmask, a
    point-to-point peer, and **every on-link route** (no gateway, not on loopback, not a
    default route) from the routing table, so a DHCPv6 host (a /128 address whose /64 is only
    a route), an IPv4 /32 with its subnet as a route, and WireGuard, Docker or VPN networks are
    covered;
  - **any destination whose route is not the default path.** Every routing table and every
    policy-routing rule (`ip rule`) is read (netlink, no privileges needed), each rule for the
    miner's own connections (firewall mark 0, its uid, input interface `lo`, no output
    interface, TCP). The default routes are those of the **ordinary tables**, the ones a rule
    with no destination selector sends every such connection to (`main` on a stock host; a
    wg-quick or Mullvad table reached by `not fwmark` too); a default route of any other table
    — a VPN table only a `from` or `to` rule reaches — is not one, and its gateway does not make
    other routes default-path. For a destination, the routes holding it with the longest
    prefix must all be such a default route (`/0`, or a "split default" no longer than `/4`, as
    full-tunnel VPNs install; with a gateway or without, as on PPPoE) or go through one's own
    gateway (a DHCP option 121 route to a DNS server via your router reaches nothing the
    default route does not). An on-link route, a route on loopback, a route through any other
    gateway (a VPN's pushed company ranges, a static route into a DMZ), in any table, refuses
    it, and so does a destination rule (`ip rule add to 52.95.0.0/16 lookup 100`) into a table
    that is not ordinary, for its whole prefix. On top of that, **the kernel itself is asked**,
    for every address a connection would go to: one unprivileged `RTM_GETROUTE` per
    destination (with the miner's uid, TCP, the connection's destination port, and the "which
    routing entry matched" and "which table matched" flags), which applies every rule exactly,
    port rules included; only a unicast route through a default route's gateway, or a default
    route of an ordinary table, is admitted (a local route, no route, a default route a
    selector picks, an on-link route or another gateway is refused). For IPv4 it is asked twice,
    as a `connect` does (`ip_route_connect`): once without a source address, which tells the
    source the kernel picks, then with that source; a `from` rule that sends the connection to
    another table than the first lookup used is refused. (IPv6 looks the route up once, matching
    source rules inside that lookup, and is asked once.) Answers are reused for the life of one
    facts snapshot (about a second). Linux only;
  - **the site around each of the host's global IPv6 addresses**: its enclosing `/32`
    (`[egress] ipv6_site_prefix_len`, 16 to 64), what an organisation (a campus, a company)
    usually holds, whose other networks hold its other machines. This also refuses the rest of
    the host's own ISP's `/32` over IPv6 (a name there that also has an IPv4 address still
    connects over IPv4); an operator whose site is no wider can set 48 or 56. And **the site around each
    global IPv4 address on its interfaces**: its enclosing `/16` (`[egress]
    ipv4_site_prefix_len`, 8 to 32), since a host numbered from public IPv4 space sits in a
    network (a campus, a data centre) whose other subnets the default gateway reaches;
  - **your own network's ranges, where the host cannot see them** (`[egress]
    internal_ranges`, refused like `deny_cidrs`). A host with a global IPv4 address on an
    interface, or whose uplink is not plainly physical, reaches other hosts of its own
    organisation (or a VPN's far side) by the same route as the internet. The uplink is judged
    **fail closed**, against what is known to be physical: every interface a default route of an
    ordinary table goes out of, and the one the kernel sends internet traffic out of, must have
    no kind (a NIC) or be a `bridge`, `bond`, `team`, `vlan`, `macvlan`, `ipvlan`, `veth` or `vrf`.
    Anything else needs the statement: a tunnel (WireGuard, OpenVPN's `tun` and data-channel
    offload `ovpn`/`ovpn-dco`, `tap`, `ipip`, `gre`, `sit`, `vti`, `xfrm`, `bareudp`, `amt`, …), a
    kind nobody listed, and `ppp` unless `/proc/net/pppoe` lists a PPPoE session for every `ppp`
    link (else it is a VPN: L2TP, PPTP, SSTP, openfortivpn). So does a default route in an
    ordinary routing table other than `main` and `default` (a policy-based IPsec client's, such
    as strongSwan's table 220: the IPsec policies themselves are not readable without
    privileges), and a default route through a nexthop object whose interface cannot be read
    (it is resolved with `RTM_GETNEXTHOP`). In public mode such a host **refuses to start**
    until `internal_ranges` lists those ranges (`internal_ranges = []` is the statement that
    there are none), and the error names what applies. The conditions are **judged again with
    every facts snapshot**: when one appears after startup (a VPN that comes up later, a global
    address acquired later) and the config has no statement, **every** requester-caused
    connection is refused until it does or the condition clears; the miner warns once per change
    and `zkminer status` says so;
  - **the DNS servers the host uses**: the `nameserver`s of `/etc/resolv.conf` and of
    systemd-resolved's `/run/systemd/resolve/resolv.conf` (the upstream servers behind its
    `127.0.0.53` stub), which may answer only their own customers.

  These facts are read again once they are a second old, and again before any refusal that
  rests on them. **Run the miner on the host's network:** a containerized miner sees only the
  container's interfaces and routes, so use host networking (`--network host`), or list the
  host's networks and addresses in `[egress] deny_cidrs`.
- **Nothing within two hops.** Right before every connection (each hop of the ELF fetch, and
  each connection the witness connector makes), a **probe** asks whether the destination is
  near: a fresh TCP socket whose packets may cross at most `[egress] near_hop_limit` hops
  (`IP_TTL` / `IPV6_UNICAST_HOPS`, default 2: the first-hop router and what sits directly
  behind it) connects to the exact address and port, for at most 1.5 s, and is closed without
  sending data. If something answers — the connection is accepted, refused or reset — the
  destination is this host's own network (the home router's own global address on its WAN
  side, which many routers serve their admin page, DNS and UPnP on; a NAT router or NAT64
  translator hairpinning its own public address; a neighbour in the same cloud VPC; the far
  side of a tunnel) and is refused. If the probe runs out of hops (Linux reports the router's
  "time exceeded" as host unreachable), the destination is farther and the real connection is
  made, on a new socket with the usual hop limit. **No answer in time decides nothing** (a path
  that filters ICMP, or a near host dropping SYNs for a while: a full accept queue, a SYN rate
  limit, a device waking up): a **check connection** is made with the usual hop limit, and once
  it is established its hop limit is lowered to the probe's and it is half-closed, without a
  byte written. Its FIN reaches the peer only if the peer is within the limit, and a peer that
  gets it acknowledges it: acknowledged (or reset) within a few round trips, refused; a "time
  exceeded" or no acknowledgement, farther, and the real connection is made. A check connection
  that does not connect refuses. Any other probe error (a local firewall's) refuses.
  Unprivileged; developer mode sends no probe.
- **Host-name hygiene** before any lookup: single-label names, `localhost` and `*.localhost`,
  and names under `local`, `internal` (`metadata.google.internal`), `lan`, `home`, `arpa`
  (`home.arpa`), `corp`, `intranet`, `private`, `localdomain`, `svc`, `consul`, `test`,
  `invalid`, `example`, `onion`, `alt`, `mail`, `workgroup`, `internal.cloudapp.net` and
  `metadata.goog` are refused, as are trailing dots, non-ASCII names (write them in their
  `xn--` form), and IP addresses written other than as four decimal octets (`2130706433`,
  `0x7f.1`, `0177.0.0.1`, `127.1`). The full list is `INTERNAL_SUFFIXES` in
  `crates/zkminer-netguard/src/host.rs`.
- **Requester names never reach this host's resolver.** The system resolver answers from
  `/etc/hosts`, NSS modules and the local stub, which forwards to the LAN's, the company's or
  the ISP's resolver, whose split-horizon zones answer internal names. So every name a requester
  chooses — a storage URI's host, a redirect's, and the fixed IPFS and Arweave gateways' — is
  resolved by netguard's own **DNS-over-HTTPS** client (rustls, compiled-in roots) at public
  resolvers addressed by IP literal: Cloudflare (`1.1.1.1`, `2606:4700:4700::1111`, `1.0.0.1`),
  Google (`8.8.8.8`, `2001:4860:4860::8888`, `8.8.4.4`) and Quad9 (`9.9.9.9`, `2620:fe::fe`),
  tried in turn, or the operator's `[egress] doh_resolvers` (https URLs whose host is a public
  IP literal). Each query asks the resolver not to pass on this host's subnet (EDNS Client
  Subnet, source prefix 0); only the name's own records and its `CNAME` chain are read. On an
  IPv6-only host with a NAT64 prefix, a name with only `A` records gets the addresses a DNS64
  resolver would synthesize. A resolver the floor refuses (the host's own network) is skipped.
  Developer mode uses the system resolver, with names looked up absolute (a trailing dot added,
  so `search` domains and `ndots` never apply).
- **URL hygiene:** `http` and `https` only; no user information; nothing but printable ASCII
  (no whitespace or backslashes, which the URL standard would quietly rewrite); no IPv6 zone
  ids; and the URL must read the same — scheme, host and port — to a strict parser and to the
  standard parser the HTTP client connects with.
- **One lookup, then that address:** each hop resolves its name once, every answer passes
  the checks above, each admitted address is checked again right before the connection (the
  kernel asked with the port, the near-hop probe), and the hop's HTTP client is pinned to
  exactly the addresses that passed (it resolves nothing itself), so a name that answers
  differently a moment later (DNS rebinding) cannot move the connection. An IP-literal URL is
  checked the same way.
- **No proxies, no automatic redirects:** proxy settings are ignored (a proxy would resolve
  the name itself). Redirects are followed by hand, at most 5, each target checked like the
  first URL before anything connects to it, within one time budget.
- **Content-addressed storage** (IPFS CIDs, Arweave ids) is fetched from fixed gateways
  (`ipfs.io`, `arweave.net`). The id and its path are syntax-checked against an alphabet with
  no URL metacharacters, so a requester names only content, never the gateway's scheme, host
  or port.
- On top of that, unchanged: every ELF is checked against its registry and content hashes,
  capped at 248 MiB, and fetched within a time budget, no compression is decoded, and the
  `User-Agent` is a constant `zkminer`.

## Developer mode: `[dev] private_network`

Local test networks serve programs from the same machine, which the guard refuses. For them,
and only for them:

```toml
[dev]
private_network = true
chain_id = 743111   # the test network's chain id: must equal [chain] chain_id
```

It admits every destination for requester-caused connections (scheme and URL syntax checks
still apply), resolves names through the system resolver, and sends no near-hop probe. It is
gated as follows:

- **The config file is the only switch.** There is no environment variable or command-line
  flag; `ZKMINER_ELF_ALLOW_PRIVATE_URLS`, which older builds read, is gone. `[dev]` refuses
  unknown keys, so a typo is an error, not a silent no-op.
- **It names the network it is for.** `[dev] chain_id` must be set and equal `[chain]
  chain_id`, which the RPC must confirm at startup (`eth_chainId`); otherwise `zkminer` stops
  with an error and the mode stays public even on a code path that skipped validation. A
  developer config copied to another network — a production deployment under a chain id
  zkminer does not list as one included — does not open the guard there.
- **Refused on Hemi mainnet (43111)** whatever `[dev] chain_id` says: `zkminer` stops with an
  error on a config that sets it there, before connecting anywhere, and the mode stays public
  on mainnet even on a code path that skipped validation.
- **Announced every time:** every start logs
  `DEV MODE: private network access enabled — never run on a public market`, `zkminer status`
  prints it, and the TUI's status bar shows a red `DEV MODE: PRIVATE NETWORK` badge on every
  frame.

Never set it on a miner that serves a public market, testnet included: anyone who can post a
job there could then reach this host's private network.

## Outbound connections zkminer makes

| Connection | Destination chosen by | Guard |
|---|---|---|
| Program ELF downloads (measure, claim, prove, recovery; `simulate`) and their redirects | **the requester** (ProgramRegistry storage URIs) | the network guard, as above |
| IPFS / Arweave gateways for those downloads | fixed in the build; path from the requester | content ids syntax-checked; then the network guard |
| Chain JSON-RPC (`[chain] rpc_url`) | the operator | none needed: requesters cannot change it. It may be a local node. |
| risc0 Groth16 component download (worker warm-up) | fixed in the build (RISC Zero's artifact store), SHA-256 pinned | none needed |
| SP1 Groth16 circuit artifacts download and size probe (SP1 worker warm-up) | fixed in the build (the SP1 SDK's artifact URL) | none needed |
| `sp1-gpu-server` | local IPC between the SP1 worker and its server | not a network destination; both ends confined (below) |
| `sp1-demo` (optional command) | serves an ELF on 127.0.0.1 for a local miner | the miner needs developer mode to fetch it |
| Witness builder fetches (`evm-rpc/v1`) | the operator's `[[evm_rpc]]` endpoints; the request body from **the builder** | the broker's connections are made by the miner's connector (below); the broker has no network |
| Witness `blob/v1` fetches | the operator's `[[blob_mirror]]` templates; the hash from **the builder** | the connector; the URL is built by the broker |
| `hemi-code` artifact reads | the operator's `[artifacts]` endpoint and mirror; the address from **the job** | the connector |
| The connector's DNS resolver (in the miner) | the operator (`[dns] servers`, else `/etc/resolv.conf`) | dials only those servers, for the operator's endpoint names only; never a fetch destination |
| Public-address discovery (miner and broker, at startup and every 5 minutes; every 15 seconds while a family is unknown) | fixed in the build: `ns1.google.com` and `1.1.1.1` (and their IPv6 addresses), UDP port 53; `https://1.1.1.1/cdn-cgi/trace` and its IPv6 twin (the miner); on an IPv6-only host, the same IPv4 reflectors through the NAT64 prefix | none needed: requesters cannot change them; `[egress] discover_public_addresses = false` turns it off |
| DNS-over-HTTPS resolution of requester names (public mode) | fixed in the build (Cloudflare, Google, Quad9 by IP literal), or the operator's `[egress] doh_resolvers`; the **name** from the requester | the resolver's address must pass the floor (being one of the host's DNS servers is allowed); certificate verified for the IP literal |
| The near-hop probe (public mode, right before each guarded connection) | the destination being vetted, with at most `near_hop_limit` hops | a SYN with no data, closed without data; when it gets no answer, a check connection to the same address and port (a handshake, then a FIN and a reset limited to `near_hop_limit` hops; never data) |
| The builder runner and the execute worker | none | seccomp denies `socket`, `socketpair`, `connect`, and every `setsockopt` but the socket timeouts |
| The broker itself | none | seccomp denies `socket`, `connect`, `bind`, `listen`, `accept*` (and `socketpair` once its runtime is up), and every `setsockopt` but `TCP_NODELAY`; Landlock grants no TCP port |
| The inline measure and prove workers (risc0, SP1, OpenVM) and `sp1-gpu-server` | none | confined before their first guest: no sockets, Unix ones included; Landlock (below) |
| The miner's witness host (pipeline, builder runs, store) | none | talks to the broker over a Unix socket pair only |

Job inputs come from the chain (calldata), not from URLs. A zkVM guest runs in a process that is
confined before the guest runs, and assumed compromised if the guest escapes its executor: see
the next section.

## Inline workers: confined

The inline measure and prove workers run requester guests in their own process, and the GPU
stack they need (device nodes, ioctls, threads, helper processes) rules out the sandbox profiles
of the builder runner and the execute worker. Workers that run requester guests are confined
instead (`zkminer_witness_sandbox::confine`), on the assumption that a guest can escape its
executor:

- **When.** Before the first command that runs a guest or uses the GPU (`Execute`, `Prove`,
  `ProgramId`, a benchmark or calibration, an Intel warm-up's proof), for the rest of the process's
  life, on every thread at once (seccomp `TSYNC`, Landlock `RESTRICT_SELF_TSYNC`), and inherited by
  everything it starts. No requester's bytes are parsed and no guest runs before it is in place.
  The one-time setup that downloads (the Groth16 artifacts, in `Warmup`) runs before; a `Warmup`
  after refuses to download, and the miner runs it on a fresh worker. Any failure fails closed:
  the worker answers the command with an error and runs nothing.
- **Sockets (seccomp).** The risc0 and OpenVM workers have none at all: no `socket` or
  `socketpair` of any domain, Unix included, and no `connect`, `bind`, `listen` or `accept`. (The
  CUDA driver opens a listening Unix socket at `cuInit`, so a CUDA worker initialises the driver
  first; with `accept` gone, nothing comes in through it.) The SP1 worker likewise creates no
  socket and connects nowhere, but it and its server may make Unix stream and seqpacket
  `socketpair`s (the SDK's tokio runtime and Rust's `Command` use them), which connect only their
  two ends: a seqpacket socket ignores any address `sendto` gives it, and datagram pairs, which
  would not, are refused. A proving SP1 worker starts its server and connects to it first, then
  keeps that one connection. A socket left open from before that the policy does not allow fails
  the confinement.
- **Files (Landlock).** Read the system's files (`/usr`, `/etc`, `/opt`, the `lib`/`bin`
  directories, `/sys`), of `/proc` only the process's own entries (`/proc/self`, its threads
  included) and the host-wide files GPU runtimes read (`cpuinfo`, `meminfo`, `stat`, `uptime`,
  `loadavg`, `version`, `devices`, `driver`, two `sys/vm` values) — traced, that is all the CUDA,
  ROCm and Intel workers read once confined — so another process's command line, status or
  anything else under `/proc/<pid>` is out of reach. The SP1 worker and its server keep all of
  `/proc`: the executor's memory monitor reads its runner child's `/proc/<pid>/{stat,statm,io,exe}`
  and the worker its server's `/proc/<pid>/stat`, at pids no rule can name ahead. Read also the
  worker's own directory, `LD_LIBRARY_PATH`, and what the
  backend proves with (`~/.risc0` or `RISC0_HOME`, `~/.sp1`); for witness proofs, the retention
  store (read) and the segment directories (write). Write only a private temporary directory
  (`TMPDIR`, made per worker, mode 0700), the GPU caches the build needs (risc0's CUDA Groth16
  cache; the Intel SYCL and compute-runtime kernel caches) and, for SP1, `/dev/shm`. Execute only
  the dynamic loader and what the worker must start (SP1's executor runner in its temporary
  directory, the server's own Groth16 helper). Open only the GPU device nodes. Nothing else in the
  home directory is readable or writable: not the dotfiles, `~/.config` (autostart, `systemd
  --user` units, `environment.d`), `~/.ssh`, `~/.zkminer` (keys, config, the provers); `~/.risc0`
  and `~/.sp1` (the server binaries included) are read-only. TCP bind and connect are denied by
  Landlock as well.
- **Filesystems within reach.** Landlock decides what may be opened, read, written or executed,
  but not the path walk: `stat`, `access`, `readlink`, `getxattr`, `statfs`, and the lookups of
  an `open` that Landlock then refuses, go through every directory on the way. On a network
  filesystem each lookup is a request to its server carrying a name the process chose; on a FUSE
  filesystem, to a user-space daemon (sshfs, rclone, gvfs) that may go anywhere; on an automount
  map, a mount of whatever the name says (autofs `/net/<host>`). So a worker (and the server's
  supervisor, before it starts the server) refuses to confine itself, and runs no guest, while any
  filesystem it can reach is not local: every mount of its mount table that a path reaches (not
  only below the paths it is granted; a mount hidden under another is left out) must be of a type
  known to be local — disk, memory and kernel filesystems (`ext4`, `xfs`, `btrfs`, `zfs`, `tmpfs`,
  `overlay`, `squashfs`, `proc`, `sysfs`, ...); anything else is refused, unknown types included.
  Every path it is granted must be on a local filesystem by `statfs`, and so must its working
  directory and every file or directory it holds open. The error names each mount, its type and
  its source. The exceptions:
  - another user's FUSE mount without `allow_other`: the kernel refuses this user's lookups before
    the daemon sees them (a `statx` of its root must fail to confirm it);
  - two FUSE filesystems that only root can mount and that serve only what is on this host: lxcfs
    (`fuse.lxcfs`, root's, source `lxcfs`: containers' views of `/proc` and `/sys` computed from
    this kernel's data) and a FUSE driver of a block device (`fuseblk`, root's, whose source must
    be a block device: ntfs-3g, exfat-fuse; the kernel opens the device and `fusermount3` refuses
    `blkdev` to users). Every FUSE mount of an unprivileged user is refused whatever its subtype
    and source, since its program chooses both (`fusermount3 -o subtype=,fsname=`): an rclone
    mount named like an AppImage is still an rclone mount. So the document portal (`fuse.portal`),
    squashfuse and AppImage mounts of the user refuse guests too — gvfs, sshfs, rclone, s3fs,
    davfs, smbnetfs, curlftpfs, gocryptfs and encfs as before;
  - a direct automount point whose target is local (systemd's for `binfmt_misc` or the EFI
    partition; an idle one is triggered once to see what it mounts).

  9p and virtiofs (a VM host's shares, WSL's drives) are refused: they carry lookups to another
  machine. On such a host, unmount the shares (WSL: `[automount] enabled = false` in
  `/etc/wsl.conf`) or run the miner in a mount namespace or container without them. A desktop
  session's FUSE mounts (gvfs, the document portal, AppImages) are refused too: run the miner as a
  dedicated user (another user's FUSE mount without `allow_other` is closed to it). The check runs again
  once the confinement is on and before every command that runs a guest, and a thread of each
  confined worker watches its mount table (`/proc/self/mountinfo`, which signals every change) and
  checks again on each change: the worker exits (status 78) as soon as a filesystem that is not
  local comes within reach, whatever it is doing; `sp1-gpu-server`'s supervisor does the same for
  the server and kills it. A change that leaves everything local (a container started, a disk
  mounted) changes nothing. The builder runner, the execute worker and the broker make the check
  before their sandbox is applied (the broker's paths by `statfs` as well).
- **Other processes.** Landlock's signal and abstract-socket scoping, and its `ptrace` rules: a
  confined process cannot signal, trace or open `/proc/<pid>/mem`, `environ`, `maps` or `fd` of a
  process outside its domain (the miner, other workers, their servers): `kill`, `tgkill`,
  `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and `pidfd_send_signal` alike. The miner can still signal
  its workers. seccomp also denies `ptrace`, `process_vm_*`, `pidfd_getfd`, `io_uring`, `bpf`, the
  kernel keyrings, `mknod`, `TIOCSTI`, and a seccomp listener of the process's own.
- **File metadata.** Landlock has no right for a file's mode, owner, extended attributes or
  times, and a confined process runs as the miner's uid, which owns most of what it can name by
  path (keys, the miner's configuration, the provers, git hooks). So seccomp refuses every such
  write, by path and through an fd: `chmod`, `fchmodat`, `fchmodat2`, `fchmod`, `chown`, `lchown`,
  `fchownat`, `fchown`, `setxattr`, `lsetxattr`, `fsetxattr`, `setxattrat`, `removexattr`,
  `lremovexattr`, `fremovexattr`, `removexattrat`, `utime`, `utimes`, `futimesat`, `utimensat`
  (with a path or without) and `file_setattr`. Traced, the CUDA, ROCm and Intel workers make none
  of these calls, kernel caches cold or warm included. SP1's executor unpacks a runner into the
  private temporary directory and makes it executable with `chmod`: the worker puts its runner
  there itself before it confines itself, without running anything — it finds the runner in its own
  executable (the one ELF image of the machine whose SHA-256, the name the SDK gives the file, the
  executable also holds), writes it (mode `0755`), and the executor then finds exactly its bytes in
  place and changes nothing; nothing executes before the confinement. The server's mode changes
  go to its supervisor, which makes the runner files in that directory executable itself — a
  regular file named as SP1 names it, opened without following a link, owned by the user, with a
  single link, in a directory closed to others — and refuses every other mode change. It decides
  on the call's registers (the syscall and the mode `0755`), never on the server's memory, and the
  kernel never runs the server's own call. Links, renames, removals, new directories and symlinks,
  and truncation outside the writable paths are Landlock's to refuse.
- **Process control.** A confined process cannot leave its session or process group (`setsid`,
  `setpgid`: where a worker has no cgroup of its own, the miner ends it and everything it started
  by killing its process group), nor change another process's limits, priority, I/O priority or scheduling
  (`prlimit64` with a new limit, `setpriority`, `ioprio_set`, `sched_setaffinity`,
  `sched_setscheduler`, `sched_setparam`, `sched_setattr`; `PRIO_PGRP`, `PRIO_USER` and their I/O
  twins too), which Landlock does not scope: a CPU-time limit set on the miner would kill it. Its
  own stay open (pid 0). One exception: the ROCm worker may set the CPU affinity of any thread
  (`sched_setaffinity`), because ROCm starts its threads with a CPU set, which glibc applies by the
  new thread's id (refused, `pthread_create` fails and the runtime aborts), and the filter cannot
  tell its own threads from another process of the user; an escaped guest there could pin another
  process of the user to some CPUs. The ioctl forms of metadata writes (`FS_IOC_SETFLAGS`,
  `FS_IOC_FSSETXATTR`, `FS_IOC_SETVERSION`, their 32-bit twins, `FS_IOC_ENABLE_VERITY`) are
  refused like the rest.
- **Ending.** Nothing a worker started outlives it. Where the miner runs in a cgroup delegated to
  it (as witness jobs need: a systemd service with `Delegate=yes`, or
  `systemd-run --user --scope -p Delegate=yes`), each worker starts in a cgroup of its own below
  it (`zkminer-worker-<miner pid>-<n>`), joined before `exec`, with the worker's memory ceiling as
  its `memory.max`. Elsewhere the user's systemd manager adopts the worker into a transient scope,
  and the miner sends it nothing (so no guest runs in it) until the scope holds it. Every end of a
  worker (a recycle, a timeout, a kill, its death, shutdown) writes that cgroup's `cgroup.kill`,
  which reaches every process in it whatever its process group or session. If the miner dies,
  however abruptly (SIGKILL, the OOM killer), a reaper it started with its first worker
  (`/bin/sh` in a session of its own, reading a pipe only the miner writes) sees the pipe end and
  kills every worker's cgroup and process group; no worker starts without it. A thread of the
  miner, outside every confinement, watches the mount table and kills every worker when a mount
  they could reach is not local, within microseconds of seeing the change; the workers that
  replace them refuse guests until it is gone.
- **Kernel surface.** No namespaces and no mounts: seccomp denies `unshare`, `setns`, `clone` with
  any `CLONE_NEW*` flag, `mount`, `umount2`, `pivot_root`, `chroot` and the new mount API
  (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`, `open_tree_attr`,
  `mount_setattr`), so even where unprivileged user namespaces are allowed a confined process
  cannot make one (and reach the kernel code a namespace's capabilities open up). Also denied:
  `userfaultfd`, `perf_event_open` and file handles (`name_to_handle_at`, `open_by_handle_at`).
  `clone3` fails as unimplemented (`ENOSYS`), since a filter cannot see its flags; libc then falls
  back to `clone`, so threads, `fork` and `posix_spawn` keep working. The worker and the
  supervised server check that `unshare` and `clone3` are refused before they run anything.
- **`sp1-gpu-server`** runs every SP1 proof's guest, so it is confined from its first
  instruction. The SDK starts it as `~/.sp1/bin/zkminer-confined-<name>`, a link to the worker,
  which starts the real server under a supervisor: the server's `socket`, `bind`, `listen` and
  `accept` go to the supervisor (a seccomp user notification), which lets them through until the
  server accepts its first connection (the first moment a requester's bytes can reach it) and
  refuses `socket`, `bind` and `listen` from then on; `connect` and every socket but a Unix stream
  or seqpacket one are refused outright. The decision rests on the syscall and that moment, never
  on an argument in the server's memory. Landlock as for the worker, plus creating its socket under
  `/tmp` and executing itself (its Groth16 CPU helper); stdin is `/dev/null`. The servers'
  host-wide Groth16 queue moves from `/run/lock` to `/dev/shm` (`SP1_GROTH16_QUEUE_DIR`). The
  supervisor kills the server when the worker exits, and the server dies with the supervisor. Its
  socket is `/tmp/zkminer-confined-<name>-<device>.sock`.
- **Docker.** The CPU risc0 worker (and an Intel worker with `RISC0_GROTH16_INTEL_PROVER=docker`)
  wraps Groth16 in RISC Zero's prover image. A confined worker cannot reach the Docker daemon (its
  socket is root-equivalent, with the host's network), so a helper process started before the
  confinement does the wrap. It never runs a guest, and since it is not confined it trusts nothing
  the worker sends (a guest that escaped into the worker may send it anything): the worker turns
  its `identity_p254` seal into the prover's input itself, and the helper accepts only that
  input's exact shape — the fixed JSON form RISC Zero's converter writes, one canonical decimal per
  element of an `identity_p254` seal, each below its field's modulus (BabyBear for a field element,
  BN254's scalar field for a digest) — and writes the prover's input from the numbers it checked.
  Anything else, or anything larger than such an input, is refused before Docker runs; a request
  that makes the helper fail is answered as an error and the helper serves the next one. The
  helper works below the temporary directory the worker was started with (its own private
  directory there, mode 0700), never below the worker's own `TMPDIR`, which the confined worker may
  write, so nothing the worker runs can change an input after the helper checked it. The container
  sees its input read-only (`/mnt`), may write only the proof file bound over `/mnt/proof.json`,
  and the helper reads that back as a regular file without following a link. The
  prover image is pinned by digest
  (`risczero/risc0-groth16-prover@sha256:e8c2068fb34bbc41447255aa980a89cbb7d6e5a80c0d66041264431f2a955e47`,
  the tag the pinned `risc0-groth16` runs) and runs with `--network none`. The supported GPU paths
  (CUDA, ROCm, Intel with the `risc0-groth16` component) wrap in-process and use no Docker.
- **The miner** holds the signing key and is not dumpable (`PR_SET_DUMPABLE 0`): its `/proc`
  entries belong to root, so no process of the same uid can read its memory or environment,
  whatever the host's `ptrace_scope`, and it leaves no core dump.

Linux with Landlock ABI 6 or later is required; a worker with more than one thread at the moment
it confines itself (the SP1 worker, a GPU runtime's threads) needs ABI 8
(`LANDLOCK_RESTRICT_SELF_TSYNC`), or it refuses to run guests.

## Witness jobs: the broker

A witness job's builder asks the miner's broker (`zkminer-witness-broker`, sandboxed) for data.
The broker parses untrusted bytes (builder requests, endpoint answers), so it is treated as the
process an attacker may get code execution in, and **it has no network of its own**: its seccomp
filter denies `socket`, `connect`, `bind`, `listen` and `accept*`, Landlock grants it no TCP port,
and once its runtime is up even `socketpair` is denied. Without `connect` it cannot disconnect a
socket it holds (`connect(AF_UNSPEC)`) and aim it elsewhere, and TCP Fast Open to another address
fails on a connected socket. Nor can it re-route one at the IP layer: its only socket option is
`setsockopt(IPPROTO_TCP, TCP_NODELAY)`, and any other level or option fails with `EPERM` (an IPv6
routing header, which unprivileged would send later segments to the address it names; IPv4 source
routing; `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX`, `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, `IPV6_NEXTHOP`,
`IP_TRANSPARENT`, `SO_MARK`, the TTLs, `TCP_ULP`, …). Ancillary data on `sendmsg` is no way
around it: TCP ignores `IPPROTO_IP` and `IPPROTO_IPV6` control messages (routing headers,
`PKTINFO` interfaces, next hops, IP options), and the one `SOL_SOCKET` message that selects a
route, a per-packet `SO_MARK`, needs `CAP_NET_ADMIN`; every sandbox drops all capabilities when it
starts, whoever runs the miner. The builder runner and the execute worker may set only the socket
timeouts (`SO_RCVTIMEO`/`SO_SNDTIMEO`, which the runner uses on its job socket), so a socket that
reached one of them (passed over the runner's job socket) cannot be re-routed there either.

Every connection the broker uses is made by the **connector**, in the miner
(`crates/zkminer-witness-broker/src/connector`, run by `zkminer-witness-host`): the broker sends a
fixed 32-byte request naming an operator endpoint **by index** (with the role and port it expects,
which must match) over a Unix socket pair the miner created before starting it, and gets back the
connected TCP socket (`SCM_RIGHTS`) or a refusal. The connector:

- uses the broker's config file **as the miner loaded it** (in the miner's network mode, without
  reading the provider keys), never anything the broker says; the broker can name an endpoint,
  never a host, an address or a port of its own;
- resolves the endpoint's host name itself (the broker resolves nothing), with the operator's DNS
  servers (operator endpoint names only; requester names never go there), and keeps only the
  answers its role entry admits;
- admits each address with netguard's floor over **the miner's** host facts (gathered with the
  stricter of the miner's and the broker file's `[egress]` options), the miner's `[egress]
  deny_cidrs` and `internal_ranges`, the broker file's deny CIDRs and the DNS servers; developer
  mode only from the miner's own `[dev] private_network`;
- right before each connection the floor applies to (public mode, or a DNS-named endpoint),
  checks the exact address and port again: the kernel's route with the port, and the near-hop
  probe; an address that answers within `near_hop_limit` hops (an operator node in the same VPC
  by its public address) is refused and never connected to;
- connects with the configured connect timeout, and paces attempts (64 at once, 16 a second: a
  hard budget of `64 + 16·t` connections in any `t` seconds; at most each endpoint's
  `max_concurrency` in flight);
- treats the broker as hostile: strict fixed-size decoding, and a malformed frame, a file
  descriptor sent to it, more than 64 requests in flight, a request id reused while in flight,
  more than 8 requests in a minute for an endpoint that does not exist (counted before the refusal
  is answered), an answer left unread for longer than a request's budget (the connect timeout plus
  12 seconds), or an answer that cannot be written while the broker keeps sending (it shut the
  reading side of its socket) **cut the broker off** — the socket is closed, the requests still
  being served are aborted (nothing more is connected for it), the miner pages
  `WITNESS-BROKER-CUT-OFF`, kills the broker's cgroup and stops witness serving. So does a broker
  that closes its connector socket and is still running 5 seconds later (an honest broker closes
  it only by exiting). However the session ends, every builder runner registered with the broker
  is killed with it, and one registered afterwards at once: the broker can pass a runner any
  descriptor it holds over the runner's job socket, a TCP socket from the connector included, and
  such a socket must not outlive the broker in the runner;
- holds at most 64 sockets for a broker that stops reading: a request counts as in flight until
  its answer is handed to the socket, and the socket's send buffer is the kernel's minimum (about
  six written answers the broker has not read).

So a broker an attacker controls can reach only the operator's configured endpoints, at addresses
the miner's floor admits — the same set an honest broker reaches. The broker still checks every
socket it is handed against its own floor (the endpoint's port and role entry; the public floor
for a DNS-named endpoint) as a second layer.

The configured endpoints themselves are held to the same rule, with netguard's predicate (there is
no second one):

- **Public mode** (the default, and the only mode on mainnet): the broker's config is refused when
  it loads if any endpoint's explicit `cidrs` or IP-literal host is not **entirely** global
  (`0.0.0.0/0`, `::/0`, a `/8` holding private space and `::ffff:0:0/96` are refused), overlaps
  the deny CIDRs or a DNS server, or — once the host's facts are read (the same facts as above:
  own and public addresses, connected prefixes and on-link routes, the IPv6 site, routes off the
  default path, local routes, destination policy rules, NAT64 prefixes, the host's DNS servers;
  `[egress] ipv6_site_prefix_len` and `discover_public_addresses` in the broker's own config) —
  holds one of the host's addresses or overlaps one of its prefixes; or if a URL host name fails the host-name hygiene above. An
  IP-literal host must lie inside the endpoint's own `cidrs` when it has them, and is judged
  too. The miner applies these checks to its own copy of the file before it starts the broker,
  and the broker again to its copy. Every connection is admitted by the connector, and the
  self-test fails (`RoleEntriesPublic`, `ConnectorRefusesPrivate`) if any role entry in force is
  not public or the connector admits a private probe. The sandboxed broker cannot read the host
  itself, so the miner re-reads the host's facts every 5 seconds and sends them, with its
  `[egress] deny_cidrs`, whenever they change; the broker keeps the union of these and of what it
  read at startup (a refresh never removes an address or prefix its own options found). The
  connector, in the miner, also asks the kernel per destination (netguard's `admit`); the broker
  cannot (its sandbox denies netlink), so its second-layer check judges by those prefixes alone,
  which refuse every route off the default path, every destination rule's prefix and every local
  route whole — at least what the miner's prefix model refuses.
- **The self-test** (at startup and hourly) also checks, from inside the sandboxed broker, that
  `socket(AF_INET/AF_INET6)` fails and `connect`, `bind`, `listen` and `accept4` fail with the
  filter's `EPERM`, that every re-routing socket option fails with `EPERM` on fd -1 and on a
  socket the connector hands it for its first endpoint while `TCP_NODELAY` works, and that the
  connector refuses an index past the configuration; and, in the
  miner, that the connector refuses an address outside every role entry, a private address (public
  mode) and a malformed request.
- **Keys** (`key_file`) travel only over `https` in public mode. In developer mode they may also
  go over `http` to an IP literal that is **not global** and is loopback or inside the endpoint's
  own `cidrs` (a global literal is never "the operator's own wire", whatever its `cidrs`).
- **TLS** is rustls with the compiled-in webpki roots, in the broker (over the sockets the
  connector hands it) and in every other HTTP client of the workspace; nothing links OpenSSL
  (inside the sandbox OpenSSL could not read a CA store). The chain RPC client therefore trusts
  the webpki roots, not the system's CA store.
- **Cached RPC answers are per requester.** Answers to pinned queries are cached by the job's
  requester (its trust domain), so one requester's builder cannot tell, from how fast an answer
  comes back, whether another requester asked the same query.
- **Host names** resolve through the connector's resolver, and only global answers outside the
  deny CIDRs, connected prefixes and own addresses become an endpoint's addresses, in both modes.
- **DNS servers** are operator infrastructure the connector's resolver dials, so a stub such as
  `127.0.0.53` is fine; every DNS server's address is added to the deny CIDRs, so no fetch
  connects to one.
- **Developer mode** comes only from the miner: with `[dev] private_network = true` the miner
  starts the broker with `--dev-private-network`, and only then may explicitly configured
  endpoints be private (DNS answers still may not). The broker's config file has no key for it;
  the broker refuses it when an endpoint serves Hemi mainnet (43111) and logs the DEV MODE banner.

## Known limits

- **DNS lookups leak, to public resolvers.** Resolving a requester's name tells the
  DNS-over-HTTPS resolver the name, and the name's own DNS servers that the resolver asked, and
  when (not this host's subnet: Client Subnet is asked off). Where the compiled-in resolvers are
  blocked (a network that filters DNS-over-HTTPS), requester names do not resolve until
  `[egress] doh_resolvers` names one that is reachable.
- **The miner is a timing oracle for public hosts.** Whether and how fast a public address
  answers is observable to the requester; the guard bounds where connections go, not what can
  be inferred from public ones.
- **Global addresses inside your own network, farther than two hops.** The guard sees the
  host's interfaces, routes, sites and public addresses, refuses the IPv6 /32 and the IPv4 /16
  around them, makes a host with a public IPv4 interface address or an uplink that is not
  plainly physical list its `internal_ranges` (at startup and whenever that appears later), and
  refuses whatever answers within `near_hop_limit` hops. What remains is your organisation's own
  space beyond all of that: a VPC neighbour or campus subnet more than two hops away and outside
  the sites and the ranges you listed, an IPv6 organisation wider than `ipv6_site_prefix_len`
  on a host without a public IPv4 address, a policy-based IPsec tunnel that installs no routing
  table of its own (its policies are not readable without privileges), or a service that
  trusts this host's public address by allowlist. List such ranges in `[egress]
  internal_ranges` or `deny_cidrs` (and raise `near_hop_limit` where your network is deeper).
  On a cloud host, also block the metadata service inside the instance (IMDSv2 required, hop
  limit 1, or the endpoint off) as defense in depth.
- **The near-hop probe's own limits.** The probe is a SYN with no data, and the check
  connection a handshake, a FIN and a reset with no data, but a near host does receive them
  before the connection is refused. A near host that drops the probe's SYNs **and** the check
  connection's FIN (but answers the real connection) reads as far: a firewall that filters by
  hop count could do that. A transparent proxy within the limit answers for every destination,
  so every connection through it is refused. A router that does not decrement the hop count is
  invisible to the probe. A far destination whose path drops ICMP costs the probe's 1.5 seconds
  plus a check connection (a round trip and a few hundred milliseconds) per address, and leaves
  that destination a half-open connection. The probe and the connection are connects a moment
  apart; a route that changes in between is not followed.
- **What the routing checks cannot see.** The kernel is asked as a connection's route
  lookups are made: with the destination port and (IPv4) the source address the kernel picks,
  firewall mark 0, and no source port (one is chosen after these lookups; a rule that selects by
  source port is followed by the kernel's third lookup only). So a source-port rule (`sport`), a
  mark that a firewall (nftables/iptables `OUTPUT` mangle) sets on the miner's packets, a VRF
  the miner is run inside (`ip vrf exec`), and eBPF or netfilter rerouting are not followed for
  that connection; the prefix model still refuses every specific route of every table that is
  not the default path, and every destination rule's prefix. If you route the miner's own
  traffic by source port, mark or cgroup, list what those paths reach in `[egress] deny_cidrs`.
  A destination rule into a table that routes it out the same uplink is refused all the same
  (refusing too much). Routes and rules are read on Linux only.
- **Public-address discovery depends on outside services.** If the reflectors cannot confirm
  a family's address (a firewall blocking outbound DNS and HTTPS to them, an outage), no
  requester connection goes out over that family until they can or `[egress]
  public_addresses` names it: the miner stays safe and stops fetching. Where TCP to the HTTPS
  reflector is **blocked outright** (refused or filtered, never answered by an impostor), the two
  DNS reflectors agreeing still confirm, so a box that blocks it and answers both DNS queries
  alike with a forged address (or a transparent DNS proxy that forwards both from its own
  address) has that address confirmed; the near-hop probe still catches a home router behind
  it, not a carrier-grade NAT pool farther away. A box that answers the HTTPS connection itself
  (any certificate this host does not trust) makes the DNS agreement count for nothing. A host
  whose public address changes without any change on the host (a new address from the ISP) is
  caught at the next discovery, at most 5 minutes later; while the reflectors are unreachable,
  the last confirmed address counts for at most 10 minutes after it was confirmed.
- **The facts can be a second stale.** A host that just joined a network is judged on facts at
  most a second old (a refusal re-reads them at once).
- **NAT64 prefixes the host cannot learn.** A network-specific NAT64 prefix is learned from
  the host's DNS servers (RFC 7050); a translator reached without DNS64 (a static route to a
  NAT64 box, a DNS64 the host does not use) must be named in `[egress] nat64_prefixes`. On an
  IPv6-only host, addresses under a prefix are refused until the translator's IPv4 address is
  learned through it (or stated in `public_addresses`). The
  witness broker learns the prefix itself at startup and also gets, from the miner, the
  refusals it implies as prefixes; under a prefix shorter than `/64` that is the whole prefix
  (its "u" octet sits inside the embedded address), so the broker reaches no IPv4-only
  endpoint through such a translator.
- **Plain `http` and any port** are still accepted for program URLs on public addresses, as
  before; content hashes, not the transport, protect the bytes.
- **The broker's requester path is not in use yet.** Requester-chosen URLs (builder URIs, later
  phases) will go through the broker's requester floor (global, not an operator endpoint, port
  443), which stays public in developer mode; nothing calls it today.
- **Your own endpoints are trusted.** The chain RPC and the fixed download URLs are not
  checked by the guard: requesters cannot change them, and a local chain node is a normal
  setup.
- **What an escaped guest in an inline worker can still do.** It cannot open a socket or connect
  anywhere, make a namespace, mount anything or change a file's metadata, but it keeps what the GPU
  stack needs: the GPU device nodes and their ioctls (a kernel driver bug is outside this model),
  reading the system's files and its own `/proc` entries (an SP1 worker or server all of `/proc`:
  other processes' command lines and status, not their memory or environment), and writing the
  caches listed above, which other GPU programs of the same user also load (a confined worker could
  poison an Intel kernel cache or risc0's CUDA Groth16 cache for them). An SP1 worker, its
  executor's runner and its server can read, write, create and remove anything of the uid in
  `/dev/shm`, pending a change to SP1's executor (the grant goes when that lands). SP1 needs it for
  the named shared memory between its executor and the runner child (`/<id>_m` for the guest's
  memory, `/<id>_t` for the trace, the `_filled` and `_empty` semaphores), and the server for its
  Groth16 files (the GPU proving key cache, about 9 GB, each proof's witness directory, the
  host-wide Groth16 queue). So a guest that escaped in one SP1 process can read or change the guest
  memory and traces of another SP1 proof running at the same time (its result or its failure, not
  the network), the server's Groth16 files, and whatever other programs of the same user keep there:
  ROCm SMI's process-shared mutexes (`rocm_smi_renderD*`, mode 0777, which `rocm-smi`, `amd-smi` and
  other ROCm SMI users lock, so they can be made to hang; the miner's own `rocm-smi` query at
  discovery is bounded by a timeout), other programs' shared memory and semaphores (browsers,
  PulseAudio and PipeWire, Python `multiprocessing`). Run SP1 under a user that runs nothing else. A
  witness proof's worker can read every bundle in the retention store, other requesters' included.
  Its results go back to the miner over its pipe, and a guest controls its journal, so anything it
  can read it can publish: keep secrets out of the readable paths.
- **Workers without a cgroup of their own.** With neither a delegated cgroup nor a systemd user
  manager (a container without systemd, another init), the miner logs that a worker is in no cgroup
  of its own, and the worker and what it starts end by process group, which a confined process
  cannot leave (the reaper kills that group too). A scope adopts its worker after `exec`: what the
  worker itself starts before the scope holds it (before its first command, so nothing a guest
  started) stays outside the scope and ends by process group.
- **Filesystems mounted later, or remote underneath.** A network or FUSE filesystem mounted while
  workers run ends every worker and everything they started (the miner's mount watch; each
  confined process also watches its own table) and refuses every later guest, but a guest that
  already escaped its executor has the moment between the mount and the kill (the kernel's
  notification, then microseconds) to look a name up on it: mount nothing of the kind while the
  miner runs. A builder runner, an execute worker or the broker
  checks only when it starts (each runs briefly per job, the broker for as long as the miner).
  Filesystems are judged by their own
  type, so storage that is remote underneath a local type is not seen: a block device on iSCSI,
  NBD, Ceph RBD or a file on NFS holding an `ext4` (a cloud VM's network disk included: such I/O
  carries no name the process chose), or an `overlay`/`ecryptfs` with a layer on a network
  filesystem that is not in the mount table.
- **Descriptors passed between confined processes.** `SCM_RIGHTS` over a Unix connection hands
  over an open socket, network ones included. The only connection a confined process keeps is an
  SP1 worker's to its own server, and both ends are confined from before either runs a guest, so
  neither has a network socket to pass. A confined process has no way to obtain one from an
  unconfined process: it cannot connect to one, and only its own worker connects to a server
  (another local program of the user could, but would have to choose to hand it a socket).
- **The server's socket.** Before its first connection the server may create Unix sockets and
  bind them anywhere below `/tmp`; it runs only its own code then. Other local processes of the
  user can connect to its socket, as before.
- **What an escaped builder can still learn about the host.** The builder runner and the
  execute worker open no files (Landlock), start in `/`, and may not call `uname`, `sysinfo`,
  `readlink*`, `access`/`faccessat*`, `statfs`/`fstatfs`, the `*getxattr`/`*listxattr` family or
  `chdir`/`fchdir`; `statx` fails as unimplemented. `stat` by path (`newfstatat`) stays open:
  Rust and glibc need it, and only a mount namespace (the system mode, not implemented) hides
  the filesystem from it, so a compromised builder can still tell whether a path exists and read
  its size, owner, mode and times, though never its contents. No such lookup leaves the host: the
  runner and the worker refuse to start while a network or FUSE filesystem, or an automount map,
  is within reach (see "Filesystems within reach" above). They also may not read the mount
  table (`listmount`/`statmount`, which would show the internal host names of NFS or CIFS
  servers), the LSMs (`lsm_list_modules`, `lsm_get_self_attr`), `ustat` or `sysfs`, nor the
  session or process group of another process (`getsid`/`getpgid` of any pid but their own);
  their `argv[0]` is the binary's file name. What remains, irreducibly without a mount and pid
  namespace: whether `/proc/<pid>` exists for any pid (so the host's process ids, and with `stat`
  their owners, can be enumerated), the boot time (`CLOCK_BOOTTIME`), the kernel version (the
  vDSO's ELF note, readable without a syscall), the CPU count (`sched_getaffinity`), and the
  absolute path of the binary the miner started (`AT_EXECFN` in the auxiliary vector: the kernel
  records the path `execve` was given).
- **What a compromised broker can still do.** Within its sandbox, with the connector: open
  connections to the operator's configured endpoints only (at the paced rate), and send them
  anything — including requests its method sets would refuse, with the provider keys it holds.
  So an endpoint's own exposure (an operator node with admin APIs, a provider account's quota)
  is reachable by a broker compromise; keep endpoint nodes minimal (§11.1 of the design: `eth`,
  `net`, `web3` only) and keys scoped. It can lie to the miner about fetch results (the guest
  re-checks everything it uses) and read its spool directory. It cannot reach any other host,
  port, or address, private or public, nor resolve a name: every socket it holds was connected
  by the miner to an admitted address, and it can neither reconnect one (no `connect`) nor
  re-route one (no socket option but `TCP_NODELAY`, IP-level control messages ignored by TCP, no
  capability). Bytes it writes go to the peer the connector chose and nowhere else.
