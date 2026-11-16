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
  multicast, `240/4`, Azure's `168.63.129.16`; on IPv6 everything outside `2000::/3` (loopback,
  ULA `fc00::/7` with AWS's `fd00:ec2::254`, link-local, site-local, multicast, discard,
  SRv6), documentation, 6to4, Teredo and the IETF block `2001::/23` except IANA's globally
  reachable AMT (`2001:3::/32`), AS112-v6 (`2001:4:112::/48`) and DRIP (`2001:30::/28`)
  ranges. All of `2001:1::/32` is refused, IANA's PCP, TURN and DNS-SD SRP anycast addresses
  included: the nearest instance of an anycast service may be a box on your own network. An
  IPv6 address that carries an IPv4 one (mapped, SIIT, the well-known NAT64 prefix) is judged
  by that IPv4 address; IPv4-compatible addresses are refused. Deny CIDRs and the host's
  prefixes match every such spelling too (`64:ff9b::808:808/128` denies `8.8.8.8`).
- **Not this host, not its neighbours, not its site.** Refused, whatever the spelling:
  - the host's own addresses, **including its public address behind NAT**: at startup and
    every 5 minutes the miner asks two fixed DNS reflectors which address its query came from
    (`o-o.myaddr.l.google.com` TXT, asked of Google's authoritative `ns1.google.com`; else
    `whoami.cloudflare` CH TXT, asked of `1.1.1.1`), once over IPv4 and once over IPv6. The
    names and servers are compiled in: nothing a requester sends chooses them, and an answer
    can only add an address to refuse. If no reflector answers, a loud warning says so and the
    miner carries on: list the public address in `[egress] deny_cidrs` then (or always).
    `[egress] discover_public_addresses = false` turns the queries off;
  - every network the host is connected to: each interface's network under its netmask, a
    point-to-point peer, and **every on-link route** (no gateway, not on loopback, not a
    default route) from the routing table, so a DHCPv6 host (a /128 address whose /64 is only
    a route), an IPv4 /32 with its subnet as a route, and WireGuard, Docker or VPN networks are
    covered;
  - **any destination whose best route is not the default path.** For a destination, the
    routes holding it with the longest prefix (the kernel's choice) must all be a default
    route (`/0`, or a "split default" no longer than `/4`, as full-tunnel VPNs install; with a
    gateway or without, as on PPPoE) or go through a default route's own gateway (a DHCP
    option 121 route to a DNS server via your router reaches nothing the default route does
    not). An on-link route, a route on loopback, or a route through any other gateway (a VPN's
    pushed company ranges, a static route into a DMZ) refuses it. Every routing table is read
    (netlink, no privileges needed) and they are merged: policy routing (`ip rule`) is not
    modelled, which errs towards refusing. Linux only;
  - **the site around each of the host's global IPv6 addresses**: its enclosing `/56`
    (`[egress] ipv6_site_prefix_len`, 48 to 64), the usual delegation to a home or office,
    whose other /64s hold your other machines;
  - **the DNS servers the host uses**: the `nameserver`s of `/etc/resolv.conf` and of
    systemd-resolved's `/run/systemd/resolve/resolv.conf` (the upstream servers behind its
    `127.0.0.53` stub), which may answer only their own customers.

  These facts are read again once they are a second old, and again before any refusal that
  rests on them. **Run the miner on the host's network:** a containerized miner sees only the
  container's interfaces and routes, so use host networking (`--network host`), or list the
  host's networks and addresses in `[egress] deny_cidrs`.
- **Host-name hygiene** before any lookup: single-label names, `localhost` and `*.localhost`,
  and names under `local`, `internal` (`metadata.google.internal`), `lan`, `home`, `arpa`
  (`home.arpa`), `corp`, `intranet`, `private`, `localdomain`, `svc`, `consul`, `test`,
  `invalid`, `example`, `onion`, `alt`, `mail`, `workgroup`, `internal.cloudapp.net` and
  `metadata.goog` are refused, as are trailing dots, non-ASCII names (write them in their
  `xn--` form), and IP addresses written other than as four decimal octets (`2130706433`,
  `0x7f.1`, `0177.0.0.1`, `127.1`). The full list is `INTERNAL_SUFFIXES` in
  `crates/zkminer-netguard/src/host.rs`. Names are then looked up **absolute** (with a
  trailing dot added), so the resolver's `search` domains and `ndots` never turn a requester's
  `secrets.corp` into `secrets.corp.<your search domain>`.
- **URL hygiene:** `http` and `https` only; no user information; nothing but printable ASCII
  (no whitespace or backslashes, which the URL standard would quietly rewrite); no IPv6 zone
  ids; and the URL must read the same — scheme, host and port — to a strict parser and to the
  standard parser the HTTP client connects with.
- **One lookup, then that address:** each connection resolves its name once, every answer
  passes the checks above, and the HTTP client is handed only the admitted addresses, so a
  name that answers differently a moment later (DNS rebinding) cannot move the connection.
  An IP-literal URL is checked directly.
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
```

It admits every destination for requester-caused connections (scheme and URL syntax checks
still apply). It is gated as follows:

- **The config file is the only switch.** There is no environment variable or command-line
  flag; `ZKMINER_ELF_ALLOW_PRIVATE_URLS`, which older builds read, is gone. `[dev]` refuses
  unknown keys, so a typo is an error, not a silent no-op.
- **Refused on Hemi mainnet (43111).** `zkminer` stops with an error on a config that sets it
  there, before connecting anywhere, and the mode stays public on mainnet even on a code path
  that skipped validation. The chain id is the one the RPC confirms at startup.
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
| Witness builder fetches (`evm-rpc/v1`) | the operator's `[[evm_rpc]]` endpoints; the request body from **the builder** | the witness broker's floor (below) |
| Witness `blob/v1` fetches | the operator's `[[blob_mirror]]` templates; the hash from **the builder** | the broker's floor; the URL is built by the broker |
| `hemi-code` artifact reads | the operator's `[artifacts]` endpoint and mirror; the address from **the job** | the broker's floor |
| The broker's DNS resolver | the operator (`[dns] servers`, else `/etc/resolv.conf`) | dials only those servers; never a fetch destination |
| Public-address discovery (miner and broker, at startup and every 5 minutes) | fixed in the build: `ns1.google.com` and `1.1.1.1` (and their IPv6 addresses), UDP port 53 | none needed: requesters cannot change them; `[egress] discover_public_addresses = false` turns it off |
| The builder runner and the execute worker | none | seccomp denies `socket`, `socketpair` and `connect` |
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
  directories, `/sys`, `/proc`), the worker's own directory, `LD_LIBRARY_PATH`, and what the
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
- **Other processes.** Landlock's signal and abstract-socket scoping, and its `ptrace` rules: a
  confined process cannot signal, trace or open `/proc/<pid>/mem`, `environ`, `maps` or `fd` of a
  process outside its domain (the miner, other workers, their servers). The miner can still signal
  its workers. seccomp also denies `ptrace`, `process_vm_*`, `pidfd_getfd`, `io_uring`, `bpf`, the
  kernel keyrings, `mknod`, `TIOCSTI`, and a seccomp listener of the process's own.
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
  confinement does the wrap: it never runs a guest, receives only an `identity_p254` seal, and
  runs the prover image with `--network none`. The supported GPU paths (CUDA, ROCm, Intel with the
  `risc0-groth16` component) wrap in-process and use no Docker.
- **The miner** holds the signing key and is not dumpable (`PR_SET_DUMPABLE 0`): its `/proc`
  entries belong to root, so no process of the same uid can read its memory or environment,
  whatever the host's `ptrace_scope`, and it leaves no core dump.

Linux with Landlock ABI 6 or later is required; a worker with more than one thread at the moment
it confines itself (the SP1 worker, a GPU runtime's threads) needs ABI 8
(`LANDLOCK_RESTRICT_SELF_TSYNC`), or it refuses to run guests.

## Witness jobs: the broker

A witness job's builder asks the miner's broker (`zkminer-witness-broker`, sandboxed) for data,
and only the broker connects anywhere. Its endpoints are configured by the operator, but a builder
can ask one anything its method set allows, so a node on loopback or the LAN would expose whatever
that node can reach. The broker therefore holds them to the same rule, with netguard's predicate
(there is no second one):

- **Public mode** (the default, and the only mode on mainnet): the broker's config is refused when
  it loads if any endpoint's explicit `cidrs` or IP-literal host is not **entirely** global
  (`0.0.0.0/0`, `::/0`, a `/8` holding private space and `::ffff:0:0/96` are refused), overlaps
  the deny CIDRs or a DNS server, or — once the host's facts are read (the same facts as above:
  own and public addresses, connected prefixes and on-link routes, the IPv6 site, routes off the
  default path, the host's DNS servers; `[egress] ipv6_site_prefix_len` and
  `discover_public_addresses` in the broker's own config) — holds one of the host's addresses
  or overlaps one of its prefixes; or if a URL host name fails the host-name hygiene above. An
  IP-literal host must lie inside the endpoint's own `cidrs` when it has them, and is judged
  too. Every connection is checked against the same floor again, and the broker's self-test
  fails (`RoleEntriesPublic`) if any role entry in force is not public. The sandboxed broker
  cannot read the host itself, so the miner re-reads the host's facts every 5 seconds and
  sends them whenever they change.
- **Keys** (`key_file`) travel only over `https` in public mode. In developer mode they may also
  go over `http` to a loopback IP literal or one inside the endpoint's own `cidrs`.
- **Cached RPC answers are per requester.** Answers to pinned queries are cached by the job's
  requester (its trust domain), so one requester's builder cannot tell, from how fast an answer
  comes back, whether another requester asked the same query.
- **Host names** resolve through the broker's own resolver, and only global answers outside the
  deny CIDRs, connected prefixes and own addresses become an endpoint's addresses, in both modes.
- **DNS servers** are operator infrastructure the resolver dials, so a stub such as `127.0.0.53`
  is fine; every DNS server's address is added to the deny CIDRs, so no fetch connects to one.
- **Developer mode** comes only from the miner: with `[dev] private_network = true` the miner
  starts the broker with `--dev-private-network`, and only then may explicitly configured
  endpoints be private (DNS answers still may not). The broker's config file has no key for it;
  the broker refuses it when an endpoint serves Hemi mainnet (43111) and logs the DEV MODE banner.

## Known limits

- **DNS lookups leak.** Resolving a requester's name tells that name's DNS server that this
  host (or its resolver) asked, and when. Hygiene keeps local names away from the resolver,
  but a public name always reaches the system resolver.
- **The miner is a timing oracle for public hosts.** Whether and how fast a public address
  answers is observable to the requester; the guard bounds where connections go, not what can
  be inferred from public ones.
- **Global addresses inside your own network, reached through the default route.** The guard
  sees the host's interfaces, routes, IPv6 site and public address. Other subnets of the same
  cloud VPC, a data centre's other public ranges, or a site delegated more than the configured
  `ipv6_site_prefix_len` are reached through the default gateway like the internet, so the
  guard cannot tell them from it. Put your VPC's IPv6 range (and any public IPv4 range your
  network uses internally) in `[egress] deny_cidrs`. On a cloud host, also block the metadata
  service inside the instance (IMDSv2 required, hop limit 1, or the endpoint off) as defense in
  depth.
- **Policy routing is not modelled.** Routes of every table are merged and a specific route in
  any of them refuses its destinations; an `ip rule` that sends some traffic elsewhere is not
  followed. Routes are read on Linux only.
- **Public-address discovery depends on two outside services.** If neither answers (a firewall
  blocking outbound DNS to them, an outage), the NAT public address is unknown until one does:
  list it in `[egress] deny_cidrs`. A host whose public address changes is caught at the next
  discovery, at most 5 minutes later.
- **The facts can be a second stale.** A host that just joined a network is judged on facts at
  most a second old (a refusal re-reads them at once).
- **NAT64 with a network-specific prefix.** Addresses under the well-known NAT64 prefix
  `64:ff9b::/96` are judged by the IPv4 address they carry; a DNS64 resolver that synthesizes
  under a prefix of your own network would hand out global-looking addresses for private IPv4
  targets. On such a network, keep the miner off DNS64 or ask for support.
- **Plain `http` and any port** are still accepted for program URLs on public addresses, as
  before; content hashes, not the transport, protect the bytes.
- **The broker's requester path is not in use yet.** Requester-chosen URLs (builder URIs, later
  phases) will go through the broker's requester floor (global, not an operator endpoint, port
  443), which stays public in developer mode; nothing calls it today.
- **Your own endpoints are trusted.** The chain RPC and the fixed download URLs are not
  checked by the guard: requesters cannot change them, and a local chain node is a normal
  setup.
- **What an escaped guest in an inline worker can still do.** It cannot open a socket or
  connect anywhere, but it keeps what the GPU stack needs: the GPU device nodes and their ioctls
  (a kernel driver bug is outside this model), reading the system's files and `/proc` (other
  processes' command lines and status, not their memory or environment), and writing the caches
  listed above, which other GPU programs of the same user also load (a confined worker could
  poison an Intel kernel cache or risc0's CUDA Groth16 cache for them). An SP1 worker and its
  server can read and write any POSIX shared memory object and semaphore of the uid in `/dev/shm`
  (SP1's executor needs it), the shared memory of unconfined programs of the same user included.
  A witness proof's worker can read every bundle in the retention store, other requesters'
  included. Its results go back to the miner over its pipe, and a guest controls its journal, so
  anything it can read it can publish: keep secrets out of the readable paths.
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
  its size, owner, mode and times, though never its contents.
