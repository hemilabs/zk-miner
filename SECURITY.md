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
  reachable entries. An IPv6 address that carries an IPv4 one (mapped, SIIT, the well-known
  NAT64 prefix) is judged by that IPv4 address; IPv4-compatible addresses are refused.
- **Not this host, not its neighbours:** the host's own addresses and every network its
  interfaces are connected to (read from the interfaces, and read again once older than
  30 s) are refused, so a hairpin to the host's public address or a NAS with a global IPv6
  address on the same /64 is out of reach. A public address the host only has behind NAT is invisible to it: name it
  in `[egress] deny_cidrs`, with the rest of your fleet.
- **Host-name hygiene** before any lookup: single-label names, `localhost` and `*.localhost`,
  and names under `local`, `internal` (`metadata.google.internal`), `lan`, `home`, `arpa`
  (`home.arpa`), `corp`, `intranet`, `private`, `localdomain`, `svc`, `consul`, `test`,
  `invalid`, `example`, `onion`, `alt`, `mail`, `workgroup`, `internal.cloudapp.net` and
  `metadata.goog` are refused, as are trailing dots, non-ASCII names (write them in their
  `xn--` form), and IP addresses written other than as four decimal octets (`2130706433`,
  `0x7f.1`, `0177.0.0.1`, `127.1`). The full list is `INTERNAL_SUFFIXES` in
  `crates/zkminer-netguard/src/host.rs`.
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
| `sp1-gpu-server` | local IPC between the SP1 worker and its server | not a network destination |
| `sp1-demo` (optional command) | serves an ELF on 127.0.0.1 for a local miner | the miner needs developer mode to fetch it |
| Witness builder fetches (`evm-rpc/v1`) | the operator's `[[evm_rpc]]` endpoints; the request body from **the builder** | the witness broker's floor (below) |
| Witness `blob/v1` fetches | the operator's `[[blob_mirror]]` templates; the hash from **the builder** | the broker's floor; the URL is built by the broker |
| `hemi-code` artifact reads | the operator's `[artifacts]` endpoint and mirror; the address from **the job** | the broker's floor |
| The broker's DNS resolver | the operator (`[dns] servers`, else `/etc/resolv.conf`) | dials only those servers; never a fetch destination |
| The builder runner and the execute worker | none | seccomp denies `socket`, `socketpair` and `connect` |
| The miner's witness host (pipeline, builder runs, store) | none | talks to the broker over a Unix socket pair only |

Job inputs come from the chain (calldata), not from URLs, and zkVM guests have no network
access.

## Witness jobs: the broker

A witness job's builder asks the miner's broker (`zkminer-witness-broker`, sandboxed) for data,
and only the broker connects anywhere. Its endpoints are configured by the operator, but a builder
can ask one anything its method set allows, so a node on loopback or the LAN would expose whatever
that node can reach. The broker therefore holds them to the same rule, with netguard's predicate
(there is no second one):

- **Public mode** (the default, and the only mode on mainnet): the broker's config is refused when
  it loads if any endpoint's explicit `cidrs` or IP-literal host is not **entirely** global
  (`0.0.0.0/0`, `::/0`, a `/8` holding private space and `::ffff:0:0/96` are refused), overlaps
  the deny CIDRs or a DNS server, or — once the host's interfaces are read — holds one of the
  host's addresses or overlaps a connected prefix; or if a URL host name fails the host-name
  hygiene above. Every connection is checked against the same floor again, and the broker's
  self-test fails (`RoleEntriesPublic`) if any role entry in force is not public.
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
- **Global addresses inside your own network.** Connected prefixes come from the interfaces'
  netmasks. A cloud instance whose IPv6 address shows as a /128 (AWS does this) does not reveal
  its subnet, and other subnets of the same VPC hold global addresses too, so the guard cannot
  tell them from the internet. Put your VPC's IPv6 range (and any public IPv4 range your
  network uses internally) in `[egress] deny_cidrs`. On a cloud host, also block the metadata
  service inside the instance (IMDSv2 required, hop limit 1, or the endpoint off) as defense in
  depth.
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
