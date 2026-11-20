# The network guard's review, rounds 1-6: a summary

`zkminer-netguard` keeps every connection a requester can influence (program and ELF downloads,
redirects, witness data sources, the witness broker's connector) on the public internet in
public mode. Six rounds of four independent adversarial reviewers (bypass, parse, probe, cross)
attacked it on macOS, Linux (a VM, live), Windows and Android (type-checked); after each round
every finding was reproduced, fixed on every platform and covered by a test. Details per round:
[netguard-macos.md](netguard-macos.md) (rounds 1-3, and what each later round changed on macOS)
and [netguard-hardening.md](netguard-hardening.md) (rounds 4-6, the Linux application, gates).

## Findings per round (after merging duplicates)

| round | high | medium | low | info | what dominated |
|---|---|---|---|---|---|
| 1 | 0 | 1 | 5 | 3 | macOS parsing (netmasks, sockaddrs, resolver files), an untested source check |
| 2 | 0 | 2 | 6 | 1 | the macOS routing socket and facts staleness, the uplink signature |
| 3 | 1 | 2 | 5 | 3 | a forged routing-socket answer cut to its stated length (high), NAT64 prefixes learned only every 300 s |
| 4 | 1 | 3 | 9 | 1 | NAT64 list crowding (high), a late ACK read as far, neighbour flushes, the ClientHello before the re-check |
| 5 | 0 | 4 | 6 | 2 | PREF64 accumulation, the MAC debounce, signature churn, the broker's per-address share |
| 6 | 0 | 4 | 10 | 1 | NAT64 state robustness, the probe gate's lost wakeup, macOS's zero RTO, availability under spoofing |

No round found a reachable private or near connection that survived its fix; no memory
unsafety was found in any round. Round 3's high was an oversized forged macOS routing-socket
datagram, cut by the receive buffer to exactly its stated length, passing the exact-length rule
(a forged route answer could be believed); round 4's was 16 learned NAT64 prefixes crowding the
configured one out of the address predicate (`<NSP>::10.0.0.1` admitted). Both were fixed in
their round and are covered (the live forge test; the NAT64 caps).

## The classes of bugs found

- **Parsing the host** (rounds 1-3): sockaddr lengths, non-contiguous netmasks, resolver syntax
  macOS accepts, the kernel's struct sizes. Fixed by reading strictly within what the kernel
  wrote; fuzzed.
- **Stale or wrong facts** (rounds 2-5): an uplink change not seen (a VPN, a second network
  behind the same router address), facts trusted past a failed re-read, a default route the facts
  did not hold. Fixed by the uplink signature, the post-connect re-check and the default-path
  check.
- **NAT64** (rounds 3-6): network-specific prefixes not learned, crowded out, accumulated, or,
  once bounded, kept long enough to refuse for hours. Now: learned per uplink and source, capped,
  and bounded in time (round 6).
- **The near-hop probe** (rounds 1-6): a late ACK read as far, a reset read as a close, ICMP rate
  limits, a lost wakeup in the gate, macOS's zero RTO. Now: two-connection check, paced and fair
  gate, deadlines everywhere.
- **Fixes that opened holes** (rounds 3, 5, 6's reviews of 2, 4, 5): a debounce that kept the old
  network, a cap that accumulated withdrawn entries, a pacer that lost wakeups. Round 6 states an
  invariant for each fix and tests it on random sequences.
- **Availability** (rounds 4-6): refusals of legitimate hosts (flushes, S3, many AAAA records,
  blackholed IPv6, spoofed MACs). Fail-closed throughout; round 6 bounded what an attacker can
  cause and restored IPv4 fallback.

## What is now guaranteed, and what backs it

| guarantee | backed by |
|---|---|
| Only global unicast destinations, never the host's own addresses, connected prefixes, site prefixes, DNS resolvers, deny CIDRs or anything under a NAT64 prefix in force carrying a non-global IPv4 address | `ip.rs`/`policy.rs` table tests, `prefix_is_global` exactness, the floor tests, fuzzing |
| Nothing within `near_hop_limit` hops: a hop-limited probe, and when it has no answer a two-connection check that reads only an acknowledged FIN | every interleaving of the check (`r4_the_two_connection_check_never_reads_a_late_ack_as_far`), live near/far tests on macOS and Linux, the RTO never zero (round 6) |
| The kernel's route for the destination (with the port, rules, nexthop objects) is a default path the facts hold; the connection is checked again once made, before any byte | `default_path_known` tests, `r4_nothing_is_written_on_a_connection_the_check_refuses`, the live forge test (1.29 M forged routing answers, none taken) |
| NAT64: an attacker who stops leaves IPv6 refused at most 95 min; the real gateway's prefix is in force after each of its advertisements; a prefix learned on the network is refused (or all IPv6 is) until an hour after its source last named it | `r6_an_attacker_who_stops_causes_a_bounded_refusal` (random sequences), live `fix-r6/vm-r6-ra*.log` |
| The probe gate: per family at most 2 in flight, paced, first come first served, never a turn after the deadline, no lost wakeup | `r6_the_gate_never_loses_a_turn_on_random_callers` |
| A remembered far verdict admits only its exact address and port on unchanged facts, for 10 s | `r6_far_verdicts_are_remembered_only_for_the_same_destination_and_facts`, the reasoning in hardening.md round 6 |
| Linux: a new network behind the same gateway address is never judged as the old one (carrier changes, addressing, IPv6 /64s, the gateway's MAC per family; a known gateway missing from the table refuses its family until it resolves) | `facts::r6_tests` (random spoofers), live flush, flap and MAC-change repros |
| Bounded resources: every table capped, every wait deadline-bound, no lock held across a spawn | the bounds asserted in the randomised tests, `r6_a_round_that_cannot_start_does_not_deadlock`, `r6_a_flood_of_non_answers_ends_at_the_timeout` |

## Residual risks per platform

- **macOS**: the configuration daemon's NAT64 state is read without lifetimes; macOS's own CLAT
  is recognised by its 192.0.0.0/29 address only; an unprivileged process cannot read ARP, so two
  networks behind one router address are told apart by the daemon's network signatures alone.
- **Linux**: PREF64 only where the kernel processes router advertisements (not under
  systemd-networkd's or NetworkManager's own RA handling); a CLAT is recognised by address, name
  or a tun device; an ARP spoofer on the LAN still costs IPv4 one relearning (fail-closed); a
  real IPv6-only host, a real CLAT and Android never ran.
- **Windows**: no check connection; whether an ICMP time exceeded for a SYN in `SYN-SENT` fails
  the connect at all is unverified, so every public host may be refused there.
- **All**: an attacker on the link who keeps forging RAs or DNS64 answers keeps IPv6 refused while
  it does (by design: refusing less could admit what is under a prefix the network may still use);
  S3 is refused behind first hops that never answer ICMP.

## Open items for the owner

1. **Windows ICMP behaviour**: run the probe against a far public host with hop limit 2 on a
   Windows runner; if the connect does not fail fast, Windows needs another near-hop method or
   must refuse public mode.
2. **S3 positive control**: keep refusing peers that never acknowledge a bare FIN (S3) when the
   probe goes unanswered, or accept that one class of far host as far.
3. **CLAT heuristics**: whether to treat any tun-routed IPv4 default as a CLAT (refusing IPv6 until
   NAT64 settles), or keep warning only.
4. **MAC-change fail-closed cost**: whether an ARP spoofer's relearning cost (IPv4 only, once per
   unsettled state) is acceptable, or MAC changes should be debounced longer.
5. **The far-verdict memory (10 s)** and **the NAT64 grace (1 h) and lifetime cap (30 min)**:
   constants with stated reasoning; change them if the trade-offs differ for your deployments.
6. **The macOS CI change** (hardening.md) is ready to apply on `item/W11-ON37`.
