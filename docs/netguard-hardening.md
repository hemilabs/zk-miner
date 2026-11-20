# The network guard's hardening, on every platform

Review rounds 1 to 3 of the macOS port ([netguard-macos.md](netguard-macos.md)) found weaknesses
in decisions the platforms share, and fixed them on macOS only, listing the rest as "recommended
for #37". All of them are now applied on Linux and Android too, and on Windows where Windows has
the code path, on purpose: this changes what PR #37 decides on Linux and Windows. One new check
(each connection checked again once made) applies on every platform, macOS included.

The logic is the macOS one, lifted out of `cfg(target_os = "macos")` into shared code; what
differs per platform is only the primitive behind it (netlink or the routing socket, `TCP_INFO`
or `TCP_CONNECTION_INFO`, the neighbour table or configd). Decisions are pure functions where
they can be, so their tests run on every platform.

## What every platform does now

1. **Facts that cannot be read again refuse.** A failed re-read drops the cached kernel
   verdicts; the last good facts stay in force for `REFRESH_GRACE` (2 s) past `FACTS_TTL` (1 s);
   after that every requester connection is refused with `Denied::FactsUnreadable` (now on every
   platform), naming what failed, until a re-read (tried again at most every 100 ms) succeeds.
   `HostFacts::unreadable_reason()` says why everywhere, so `zkminer-chain`'s operator warning
   shows it. Before, Linux kept the last good snapshot, cached verdicts included, for as long as
   the netlink re-read failed.
2. **One re-read at a time, and nothing blocking on the runtime.** A caller that finds a re-read
   under way waits for it at most `REFRESH_WAIT` (500 ms), then gets the facts in force within
   their grace, or a refusal. The resolver's admit loop (`resolve.rs`), the DoH server check
   (`doh.rs`) and the client's URL checks (an IP literal is judged by `admit`) run in
   `spawn_blocking`. Before, every stale caller re-read the facts itself, on a tokio worker.
3. **The uplink signature tells two networks behind the same router address apart.** Linux adds
   each default gateway's link-layer address from the neighbour table (`RTM_GETNEIGH`,
   unprivileged; macOS keeps configd's network signatures, since macOS redacts the table). A
   missing entry is hashed as missing; when no gateway is known at all, every facts read is an
   uplink of its own (discovery runs again until an entry appears, which its own traffic
   brings), so missing never merges two networks; when some gateway is known the signature stays
   put (a dual-stack host with an unreachable IPv6 router keeps its IPv4 address confirmed).
   Since review round 4 (cross-2, bypass-3): an entry that goes missing, or first appears, changes
   nothing, and another known address counts only once it holds for 3 reads and 2 s; a neighbour
   dump that fails no longer fails the facts read (the addresses are taken as unknown).
4. **Only an acknowledged FIN answers the check connection.** One `confirm_once` for Linux,
   Android and macOS, deciding from a platform-neutral `TcpState`: `FIN_WAIT_2` / `TIME_WAIT`
   (this side's FIN acknowledged) is near; a peer that closed or reset first is a failed check,
   never near and never far. Linux never shows `TIME_WAIT` on the socket (it hands the
   connection to a timewait mini-socket and the socket reads `TCP_CLOSE`), so `TCP_CLOSE` with
   no pending error (`SO_ERROR` 0) reads as acknowledged-and-closed, with one (`ECONNRESET`,
   `EPIPE`, …) as reset; since review round 4 (parse-2) a reset read once stays a reset for that
   socket, and an unreadable `SO_ERROR` is a reset. Before, Linux read every state but
   `FIN_WAIT1` as near.
5. **IPv4-mapped addresses are unmapped inside the probe and the check connection**, on every
   platform (Windows' probe too).
6. **Each connection is checked again once made**, before any request byte is written (new on
   every platform). `NetPolicy::vet_path` vets as before and then records the source address the
   kernel chooses for the connection (a UDP socket connected to it: nothing sent);
   `NetPolicy::recheck_connected` requires the connection's own peer and source (`getpeername`,
   `getsockname`) to be the vetted ones (`connected_as_vetted`, pure) and admits the destination
   again on the facts in force with no cached kernel verdict, so the kernel is asked how it
   routes now. A mismatch is `Denied::PathChanged` (new variant); a refused route is the usual
   refusal; either way the connection is dropped. Since review round 4 (bypass-2, cross-3) each
   hop's TCP connection is the guard's own (`hop.rs`), bound to the vetted source (the kernel's
   TCP route answer on Linux), checked, and only then given its TLS handshake and request: no
   ClientHello reaches an unchecked path. The witness broker's connector checks its sockets the
   same way before handing them over.
7. **NAT64 prefixes are learned per network.** The facts compute the uplink signature once per
   read and hand it to public-address discovery and to `nat64::ensure_discovered_on`: a changed
   signature starts a round at once, an IPv6-only host that found nothing asks again every 15 s,
   one round runs at a time. Until the round for a new signature has finished, a host with IPv6
   and no IPv4 route refuses every IPv6 destination (`Denied::Nat64Unsettled`, now on every
   platform). The servers in use are asked first (macOS: configd's global resolvers; elsewhere
   the `resolv.conf` files' `nameserver` lines in file order, `/etc/resolv.conf` first), servers
   of an unrouted family are skipped, and the list is cut to 8 only after ordering. Linux also
   reads PREF64 (RFC 8781), below. Before, Linux learned at startup and every 300 s from the
   first 8 of the sorted list, IPv4 first. Since review round 4 the registry is per uplink and
   per source, configured prefixes always in force (below).
8. **A default-like kernel answer must be a default route the facts hold** (family, hop,
   interface, and since review round 4 the same nexthop object, resolvable), or it is refused as off the default path, a refusal that rests on the facts (the
   policy reads them again at once and judges once more). Before, Linux admitted any default-like
   route of an ordinary table until the next facts read.
9. **The positive control, and a second probe attempt.** A FIN unacknowledged within the hop
   limit is far only if the peer acknowledges a FIN at the default hop limit; otherwise a failed
   check, refused. (Since review round 4, probe-1, the control is a second connection and the
   check connection keeps its low hop limit; the probe has a third attempt: below.) The probe is asked twice within its 1.5 s (1 s,
   then 0.5 s after a timeout), on every platform, Windows included (where a probe without an
   answer is refused outright, so the second attempt saves refusals). Linux's early "far" from
   an ICMP error for the FIN (`SO_ERROR`) is gone: Linux keeps such an error as a soft error that
   `SO_ERROR` does not report without `IP_RECVERR`, and a far verdict from it would skip the
   control. **The S3 trade-off:** AWS S3's front ends never acknowledge a bare FIN, at any hop
   limit, so on a path whose first two routers send no ICMP "time exceeded" (some corporate and
   cloud networks; an EC2 instance's first hops often send none) every S3 download is refused;
   on a home path about 3% of attempts (each decided anew) are. The refusal now names the cause
   within the 120 characters a refusal shows of it: `the peer acknowledged the check's FIN
   neither within the hop limit nor at the default one (AWS S3 never does)` (the old text was
   cut before it named anything). Dropping the control is a one-line change in `Check::step`
   (the `None` arm) if S3-hosted programs matter more than a near device that never acknowledges
   a bare FIN and drops the probe's SYN.
10. **CI.** `.github/workflows/netguard-linux.yml` runs the suite with `ZKMINER_CI_STRICT=1`
    (`ZKMINER_CI_ALLOW_SKIP=ipv6`, a token a skip reason starts with: GitHub's runners have no
    IPv6) and clippy `--all-targets -D warnings`, and since review round 4 a `callers` job
    (`zkminer-chain`, the broker's library tests); the macOS half is the diff below.

### PREF64 on Linux

The kernel hands a router advertisement's "user options" (RDNSS, DNSSL, captive portal, and
PREF64 since Linux 5.8: `ndisc_is_useropt`) to the `RTNLGRP_ND_USEROPT` netlink group as
`RTM_NEWNDUSEROPT` messages, and any process may join it (rtnetlink is `NL_CFG_F_NONROOT_RECV`).
`nat64::pref64` starts a listener thread on the first NAT64 round and keeps what each router
says (since review round 4: per router and interface, at most 5 prefixes each and 16 routers,
learned only from an IPv6 default gateway on its route's interface, with its lifetime). There is no table to read: only
advertisements that arrive while it listens are seen (routers repeat them every few minutes), so
RFC 7050 discovery still runs. And only advertisements the kernel processes arrive: where
systemd-networkd (its own `IPv6AcceptRA`) or NetworkManager handle router advertisements in
userspace, the kernel's `accept_ra` is 0 and nothing arrives (the test VM's uplink is such a
host: `accept_ra` 0 under systemd-networkd). systemd-networkd and NetworkManager keep the PREF64
they saw behind their own interfaces (`networkctl`, varlink, D-Bus) and write it nowhere an
unprivileged process can read without those APIs; neither is read. A network whose only NAT64
signal is a PREF64 on such a host needs `[egress] nat64_prefixes` (or a DNS64, which RFC 7050
finds).

### The macOS CI change (ready to apply on `item/W11-ON37`)

`scripts/ci/macos-cpu-tests.sh` lives on `item/W11-ON37`, so nothing is committed there. Against
that branch's file (`shellcheck` clean):

```diff
--- a/scripts/ci/macos-cpu-tests.sh
+++ b/scripts/ci/macos-cpu-tests.sh
@@ -16,6 +16,12 @@
 #    assert this Mac's GPU, input devices and power source (MACOS_HOST_TESTS below).
 # 3. scripts/ci/test-metal-tc.sh with risc0-build-kernel from the pinned risc0 checkout: the Metal
 #    compiler wrapper the kit uses, through risc0-build-kernel and cargo (compiles kernels, runs none).
+# 4. The network guard (zkminer-netguard), with ZKMINER_CI_STRICT=1: a test that cannot check what it
+#    is for on this runner (no IPv6, no network) fails instead of printing SKIPPED and passing, unless
+#    ZKMINER_CI_ALLOW_SKIP (comma-separated, from the job's env) names part of its reason, such as
+#    "IPv6" on a runner without it. Then its live forge test, on its own (it floods every routing
+#    socket on the host). It needs outbound DNS and HTTPS and the near-hop probe's ICMP.
+#    docs/netguard-hardening.md, "CI".
 set -euo pipefail
 ci=$(cd "$(dirname "$0")" && pwd)
 repo=$(cd "$ci/../.." && pwd)
@@ -55,6 +61,12 @@
 echo "== zkminer-prover discovery and dispatcher (without ${MACOS_HOST_TESTS[*]})"
 cargo test --locked --release -p zkminer-prover --lib -- discovery:: dispatcher:: "${host_skips[@]}"
 
+echo "== the network guard (zkminer-netguard), every skip a failure"
+ZKMINER_CI_STRICT=1 ZKMINER_CI_ALLOW_SKIP="${ZKMINER_CI_ALLOW_SKIP:-}" \
+  cargo test --locked --release -p zkminer-netguard
+echo "== the network guard: forged routing-socket answers (floods every routing socket: on its own)"
+ZKMINER_TEST_LIVE_FORGE=1 cargo test --locked --release -p zkminer-netguard --lib live_forge -- --test-threads=1
+
 echo "== test-metal-tc.sh (the Metal compiler wrapper through risc0-build-kernel)"
 bk=$(cargo metadata --locked --format-version 1 | python3 -I -c 'import json, os, sys
 m = json.load(sys.stdin)
```

(Also at `/Users/user/zkminer/scratch/w11/NGREV/fix-linux/macos-ci.diff`.)

## Linux application

Logs: `/Users/user/zkminer/scratch/w11/NGREV/fix-linux/`.

**Where Linux ran.** A Linux VM on this Mac, unprivileged for every test: `tart` (Apple's
Virtualization.framework) running `ghcr.io/cirruslabs/ubuntu:latest` (Ubuntu 24.04, kernel
7.0.0-43-generic, aarch64, 6 CPUs, 10 GiB), started from this SSH session without a GUI login,
reached with `tart exec`, the worktree shared read-only over virtiofs and copied in. Tests ran as
the VM's ordinary user; `sudo` was used inside the VM only to set it up (packages, mounts, the
Rosetta binfmt entry) and to stage conditions (`ip neigh flush`, a veth pair and a network
namespace sending a router advertisement). The same suite also ran as **x86_64** Linux binaries
(`--target x86_64-unknown-linux-gnu`, cross-linked in the VM, executed by Rosetta for Linux; the
syscalls are the real arm64 kernel's). The VM's network: NAT through this Mac (192.168.64.0/24,
gateway 192.168.64.1, then the home router); IPv6 a ULA prefix with a default route through the
Mac, translated (NAT66) to the Mac's own IPv6, so IPv6 reaches the internet from the VM
(`ping -6 2606:4700:4700::1111` answers) though no global address is on the VM (corrected in
review round 4, cross-7: this said "no global IPv6, so the IPv6 paths that need the internet
skip"). Windows ran nothing: it is
type-checked (`cargo check` and `clippy --all-targets`) with stub C compilers.

| item | Linux / Android | Windows | macOS | verified |
|---|---|---|---|---|
| 1 facts unreadable refuse | new: `FactsCell` single flight and grace, `FactsUnreadable`, `unreadable_reason` | same (shared code) | unchanged (the code it came from) | run on Linux (aarch64, x86_64) and macOS: `a_failing_refresh_refuses_after_its_grace_and_recovers` (staged failure through the test seam); Windows type-checked |
| 2 single flight, bounded wait, off the runtime | new: as macOS; admit loops in `spawn_blocking` | same | `spawn_blocking` is new | run: `stale_facts_are_re_read_once_for_every_caller`, `a_slow_refresh_holds_only_the_caller_that_runs_it`, `the_admit_loop_runs_off_the_runtime`, `the_server_check_runs_off_the_runtime` |
| 3 gateway link-layer address in the signature | new (`RTM_GETNEIGH`) | n/a (routes alone, as before) | unchanged (configd) | pure: `two_networks_behind_the_same_router_address_are_two_uplinks_on_linux` (every platform); Linux live: `neighbour_messages_parse`, `this_hosts_neighbour_table_is_read` (unprivileged dump, the gateway's address read); after `ip neigh flush` one DNS query brought the IPv4 gateway's entry back, the IPv6 one stayed missing (`vm-neigh-flush.log`) |
| 4 only an acknowledged FIN | new: shared `confirm_once`, `TcpState`, `TCP_INFO` parsed from bytes, `TCP_CLOSE` read with `SO_ERROR` | n/a (no check connection) | same decisions, now shared | pure on every platform: `the_check_reads_only_an_acknowledged_fin_as_an_answer`, `linux_tcp_info_is_read_within_what_the_kernel_wrote`; Linux live: `linux_tcp_info_is_the_kernels` (glibc's offsets on x86_64), `linux_a_reset_and_a_completed_close_read_apart`, `a_peer_that_closes_first_is_never_far` (loopback, and NIST's daytime server: "closed"), `the_check_connection_finds_a_local_listener_near`, `a_near_listener_that_drops_syns_for_a_while_is_near` |
| 5 unmap in the primitives | new | new (probe) | unchanged | run: `a_mapped_address_is_probed_as_its_ipv4_address` (Linux and macOS: `[::ffff:1.1.1.1]:443` at hop limit 2 is unreachable, never connected) |
| 6 checked again once made | new | new | **new** | run on Linux and macOS: `a_route_that_changes_between_the_check_and_the_connection_drops_it` (fetch refused, server got no request), `a_connection_that_left_by_another_path_is_refused` (real socket addresses), `the_vetted_source_is_the_kernels`; every guarded fetch in the suite and `zkminer-chain`'s real downloads go through the layer. The broker connector's re-check is type-checked only: no broker test reaches a connection that the public floor admits (loopback stands in, and the floor refuses it); its suite, run as x86_64 Linux under Rosetta, passes as at af17e48 (below) |
| 7 NAT64 per uplink, server order, PREF64 | new; PREF64 listener | per uplink and order (no PREF64) | unchanged but the signature computed once per read | pure: `a_new_uplink_is_asked_for_its_prefix_at_once`, `a_new_uplink_signature_is_unsettled_at_first`, `a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends`, `ipv6_is_refused_while_a_new_uplinks_nat64_prefix_is_learned`, `the_active_and_routed_servers_are_asked_first`, `resolv_conf_servers_keep_their_order`, `pref64_options_of_router_advertisements_are_read`; Linux live: `the_pref64_listener_joins_unprivileged`, and with a staged RA carrying PREF64 `2001:db8:6464::/96` on a veth whose other end sat in a network namespace, the unprivileged test received and learned it (`vm-pref64-ra.log`) |
| 8 default-like answer held by the facts | new | same (no oracle there) | unchanged | run: `a_new_uplink_is_refused_until_the_facts_hold_it`, `the_kernels_answer_per_destination_is_judged` (changed, below); the real-host tests on the VM's kernel |
| 9 positive control, second attempt | new (control); new (attempt) | new (attempt) | unchanged; message shortened | pure: `a_fin_acknowledged_at_no_hop_limit_is_never_far`, `a_probe_that_timed_out_is_asked_again_once`; Linux live: `the_check_connection_finds_a_public_host_far` (1.1.1.1 acknowledged the restored FIN: far), `a_peer_that_never_acknowledges_a_fin_is_not_far` (an S3 front end: refused, the message naming S3) |
| 10 CI | workflow added | n/a | diff above | `actionlint` clean; the strict suite run in the VM (no global IPv6) |

**Shared test assertions changed on purpose.** `policy::tests::the_kernels_answer_per_destination_is_judged`:
PR #37 asserted that Linux admits 93.184.216.34 (a split default via a VPN gateway the facts do not
hold) and 1.0.0.1 (wg-quick's table on interface 9); both are now refused on every platform
(item 8), as on macOS. No other shared assertion changed; tests that were macOS-only and now run
everywhere are listed per item, and six nearhop tests lost their `_on_macos` suffix.

**Linux code paths never executed** (type-checked, and their pure parts unit-tested):

- a real IPv6-only Linux host: `Nat64Unsettled` from a real facts read, and RFC 7050 against a
  real DNS64 (the decisions run as pure tests and with staged facts; the VM has IPv4);
- a real move between two networks whose routers share an address (the signature is a pure
  function, tested; the neighbour dump runs live);
- a PREF64 from a real router (only the staged advertisement), and on a host whose kernel
  processes advertisements on its real uplink;
- the post-connect check refusing a real route change (staged by a route oracle; the live
  success path runs on every guarded fetch);
- `default_path_known` for default routes through nexthop objects (no nexthop objects in the
  VM);
- Android at all: `cargo check --target aarch64-linux-android` (stub C compilers) passes with
  no warnings at HEAD; at af17e48 it did not compile (`libc::tcp_info` does not exist for
  Android, which the old Linux `confirm_once` used; the check connection now parses `TCP_INFO`
  from bytes);
- the witness broker connector's re-check once connected (no test reaches it: above); the crate
  does not build on aarch64 Linux (`libc::SYS_fchmodat2` is not defined for aarch64, before and
  after this change), and its suite ran as x86_64 under Rosetta: 135 unit tests, of which
  `a_broker_that_shuts_its_reading_side_is_cut_off` fails now and then under emulation at
  af17e48 as at HEAD (3 of 6 and 2 of 6 alternating runs: `x86-broker-alternating.log`), and the
  integration test `held_lock_fetches_pass_a_flood_of_simulations` fails at both.

**Windows** changes (type-checked only): `FactsCell`'s grace and single flight, `FactsUnreadable`
and `Nat64Unsettled`, NAT64 per uplink with the ordered servers, the probe asked twice and
unmapped, the post-connect check in the guarded client, the admit loops off the runtime, and the
check-connection stub's message ("Linux and macOS only"). Windows still refuses every requester
connection in public mode (it has no route oracle), so none of these changes what it admits.

**Mutation run.** `fix-linux/mut/run.py` and `muts.py`, on macOS over a copy of the branch:
38 mutants of the decisions this application shares or adds (L01 to L38: the grace, the verdict
drop, the refusal, the bounded wait, the single flight, the admit loops on the runtime, the FIN
states, the control, `TCP_CLOSE` with and without an error, `TCP_INFO`'s offsets and length, the
second attempt, the unmapping, the default-route membership, the signature's link-layer
addresses and its missing-gateway rule, NAT64's trigger, retry, refusal and server order,
PREF64's PLC and ICMP type, the post-connect peer, source and route checks, the connector layer).
37 killed (`mut/summary.txt`). One survives: L32, the facts read never setting
`nat64_unsettled` (its decision, `nat64_unsettled_on`, is tested; the glue in `gather_with`
needs an IPv6-only host to test, like round 3's N25). Then, in the Linux VM (`mut/vm_muts.py`),
6 mutants of Linux-only code that does not compile on macOS (the neighbour parser's state and
proxy filters, `SO_ERROR` for `TCP_CLOSE`, the IPv6 neighbour dump, the PREF64 listener's start,
the active servers' file order): 3 survived the first run (`mut/vm-summary.txt`), the tests were
strengthened, and all 6 are killed (`mut/vm-summary-2.txt`).

**Expanded source.** `RUSTC_BOOTSTRAP=1 cargo rustc -Zunpretty=expanded` of the library, its
tests, the integration tests and `zkminer-chain` for `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc`, at af17e48 and at HEAD, normalised as round 3 did (doc comments and
line metadata dropped): every Linux and Windows difference is one of the items above, the new
tests, or `zkminer-chain`'s unchanged code (`linux-windows-expanded-diff.log`, reviewed hunk by
hunk: `expanded-review.txt`).

## Gates

`fix-linux/gates.sh` (`gates-summary.log`), `vm-gates.sh`, `vm-gates-aarch64-rerun.sh`
(`vm-gates-summary.log`, `vm-gates-rerun-summary.log`):

- **macOS:** `cargo test -p zkminer-netguard` twice and once with `ZKMINER_CI_STRICT=1` (197
  library tests passed each, nothing skipped), the live forge test twice (308,785 queries answered
  while 1.3 M forged datagrams arrived, none taken), `zkminer-chain` (225 passed) and its two
  real-network downloads in public mode, clippy `--all-targets` (no warnings).
- **Linux, run** (the VM): the netguard suite twice on aarch64 (168 library tests), once with
  `ZKMINER_CI_STRICT=1 ZKMINER_CI_ALLOW_SKIP="IPv6,[::1]"` as the workflow sets them (nothing
  skipped), clippy `--all-targets -D warnings`; on x86_64 under Rosetta, the netguard suite (168)
  and `zkminer-chain` (225, and the two real downloads, through the new connector layer and the
  Linux kernel's route answers). The first aarch64 runs after the VM mutation run used a stale
  binary of the last mutant (rsync keeps the restored sources' older mtime, so cargo did not
  rebuild); after `cargo clean -p zkminer-netguard` they pass (`vm-gates-rerun-summary.log`). The
  first strict run skipped one test whose S3 precheck polled past a reset (fixed: a971c7e).
- **Linux and Windows, type-checked:** `cargo check` and `clippy --all-targets -D warnings` of
  zkminer-netguard for `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` with stub C
  compilers: no warnings; `zkminer-chain` checks for both; `zkminer-witness-broker` clippy for
  linux-gnu (its only warning, in `net.rs`, predates this change); Android
  (`aarch64-linux-android`) `cargo check --all-targets`: no warnings (it did not compile at
  af17e48).
- **Merge:** `git merge-tree --write-tree item/W11-ON37 HEAD`: clean.


## Review round 4

Four reviewers (bypass, parse, probe, cross; material in
`/Users/user/zkminer/scratch/w11/NGREV/r4-*`) on 46ba1a0. Each finding was reproduced first
(the reviewers' failing tests rerun on 46ba1a0: `fix-r4/prefix-reviewer-tests.log`; a failing
test of mine where the reviewers had only a live repro; their live repros rerun in the Linux VM
after the fix), then fixed on every platform with a test. Logs: `fix-r4/`
(`/Users/user/zkminer/scratch/w11/NGREV/fix-r4/`).

| # | finding | reproduced | fix | test |
|---|---|---|---|---|
| 1 | bypass-1 = parse-1 = cross-1 (high): `publish` sorted configured and learned NSPs together and kept 16, so 16 learned ones (one DNS64 answer, one rogue RA's PREF64 options) pushed the configured NSP out of what `is_global` reads while DoH synthesized with it; a full list never learned the real NSP of a later network. With parse-4 (low): learned NSPs never expired and were synthesized with on every uplink | the reviewers' four tests fail on 46ba1a0 (`prefix-reviewer-tests.log`); live: their hostile DNS64 left the configured NSP out and admitted `<NSP>::10.0.0.1` (`r4-cross/vm-r4-dns64.log`), their rogue RA evicted it (`vm-r4-rogue-ra.log`) | configured NSPs always in force, never truncated; learned ones kept per uplink and per source (a DNS server, a router and interface, the system), capped per source (2 per RFC 7050 answer, 4 per router, 8 system), 32 per uplink, 64 in all, room made from another uplink's least recently seen; a source naming more than its cap, or a prefix that cannot be held, marks the uplink unsettled (`nat64::unheld`), which refuses IPv6 there on any host (`Nat64Unsettled`, logged with the source); RFC 7050 §3: a prefix only where both 192.0.0.170 and .171 sit under it, at most 2 per answer; PREF64 kept per sender (`NDUSEROPT_SRCADDR`, ifindex) and learned only from an IPv6 default gateway on its route's interface, with its lifetime (0 withdraws: not synthesized with, still refused); synthesis (DoH, public-address discovery) only with configured prefixes and those of the uplink in use, still named and within their lifetime | `nat64::r4_tests::*` (configured never crowded out, caps, eviction, synthesis per uplink and lifetime, RFC 7050 validation, the hostile DNS64 over UDP, PREF64 from the gateway alone, the listener's ENOBUFS), `facts::tests::a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends` (unheld refuses on a dual-stack host); live in the VM: `r4_rogue_router_advertisements_never_evict_the_configured_nsp` with `repro/rogue-ra.sh` (`vm-rogue-ra.log`: 5 heard, none learned from a non-gateway; as the gateway 4 learned and the uplink unsettled; the configured NSP in force throughout), the reviewers' hostile DNS64 (`vm-dns64.log`: nothing learned, the configured NSP in force, `<NSP>::10.0.0.1` refused) and a variant answering 16 validated prefixes (`vm-dns64-validated.log`: nothing learned, IPv6 refused as unsettled) |
| 2 | probe-1 (medium): a late ACK of the hop-limited FIN (after the deadline capped at 1.5 s) landed inside the positive control and read as far | `probe1-before.log` (`fin_after_control(FIN_WAIT_2)` is far) | two connections: the check connection keeps the low hop limit for its whole life; its FIN goes first; a control connection is then made at the default limit and half-closed. Any ACK of the check's FIN is near; far only once the control's FIN was acknowledged and the check's stayed unacknowledged for max(4 RTT + 250 ms, RTO + 2 RTT + 250 ms, control ACK + max(control round trip, 250 ms)); no cap below the round trip: waits past 10 s are refused (`MAX_CHECK_WAIT`). Linux and macOS | `nearhop::tests::r4_the_two_connection_check_never_reads_a_late_ack_as_far` (every interleaving: ACK before, with, after the control's, after the old window, bufferbloat at 1.6 s, a lost ACK answered after the RTO, S3, resets and closes on either connection, unreadable states, too slow), the live check-connection tests on macOS and in the VM |
| 3 | parse-2 (medium): on Linux the control's RTO read consumed a reset's `SO_ERROR`, after which `TCP_CLOSE` read as an acknowledged close | the reviewers' `r4_a_reset_read_for_its_rto_then_reads_as_far` fails on 46ba1a0 | every state read of both connections goes through `ConnReader`, which keeps a `Closed` (a reset) for good; an unreadable `SO_ERROR` is a reset (`so_error_read`) | `r4_a_reset_read_once_stays_a_reset` |
| 4 | cross-2 (medium, a regression against pr/37) + bypass-3 (low): a flushed, `FAILED` or flapping neighbour entry changed the Linux uplink signature: ~1.5 s refusals of all public IPv4 with the `public_addresses` advice | the reviewers' live `ip neigh flush` (`r4-cross/vm-r4-batch2.log` NF: two refusals in 20 s) | `MacHistory`: per routing signature the known link-layer address of each default gateway; missing keeps it; first seen changes nothing; another address counts only after 3 reads in a row and 2 s (an epoch in the signature); with none ever known every read is its own uplink (never merging); a neighbour dump that fails (denied, unsupported, interrupted) is taken as no entry, warned once, and does not fail the facts read; a refusal while the address is learned again is `Denied::PublicAddressRelearning`, saying so (also in the re-read warning and `guard_warnings`) | `facts::tests::two_networks_behind_the_same_router_address_are_two_uplinks_on_linux` (rewritten: flush, FAILED, first seen, flapping, debounce, an unreadable table, `next_read`), `policy::tests::r4_a_public_address_being_learned_again_says_so`, `public::tests::confirmations_expire_and_belong_to_their_uplink`; live: the reviewers' NF rerun (`vm-batch2.log`: no refusal in 20 s with both flushes) |
| 5 | bypass-2 (low): for `https` the ClientHello (SNI) went out before the post-connect re-check; a refusal surfaced as an HTTP error | the reviewers' `r4_bypass_clienthello_precedes_the_recheck` passes on 46ba1a0 (the ClientHello arrives) | each hop's own connector (`hop.rs`): a tokio TCP connection to a pinned address, checked (`recheck_connected`), then tokio-rustls (ring, web roots, ALPN http/1.1), then one hyper HTTP/1.1 exchange; the response is a `reqwest::Response` (its URL set; the body bounded by the read timeout per read and the request's deadline); a refusal is `FetchError::Denied`, a transport failure the new `FetchError::Connection`. The lock gains no package | `client::tests::r4_nothing_is_written_on_a_connection_the_check_refuses` (no byte reaches the listener), every guarded fetch in the suites, `zkminer-chain`'s real downloads (macOS, and x86_64 Linux under Rosetta) |
| 6 | cross-3 (low): the expected source came from a UDP socket, so `ip rule ipproto udp lookup 100` made every fetch `PathChanged`; parse suspicion: the re-check's route query lacked `RTA_SRC` | the reviewers' live repro (`r4-cross/vm-r4-udp-rule.log`) | the vetted source is the kernel's TCP route answer (`RouteOracle::source_for`: Linux `RTA_PREFSRC`; the UDP socket elsewhere), the hop's socket (and the broker connector's) is bound to it, and the re-check asks the kernel how it routes a connection from the socket's own source (`RouteOracle::route_from`: Linux `RTA_SRC`; only for the address judged, not a test's loopback stand-in) | `client::tests::r4_the_vetted_source_is_the_tcp_routes_and_the_recheck_asks_from_it`; live: the reviewers' repro rerun (`vm-udp-rule.log`: source 192.168.64.3, re-check passes, the fetch answered) |
| 7 | cross-4 (low): `default_path_known` with nexthop objects (`nexthop_compat_mode` 0: no gateway, no interface) held any default-like route through any object | the reviewers' live N0 (`r4-cross/vm-r4-batch2.log`: the `0/1 nhid 30` via the LAN box passed the route checks) | the answer's route must name the same nexthop object as a default route of the facts, and that object must resolve in the facts' nexthop dump (now kept in `HostFacts`) | `facts::tests::r4_a_nexthop_object_default_is_held_only_through_the_same_object`; live: the reviewers' N0 and N1 rerun (`vm-batch2.log`: both refused as off the default path), H0-H3 (`vm-rules.log`: the defaults through objects admitted, a host route through one refused) |
| 8 | cross-5 (low): `Verdict::Failed`/`Undecided` refused as `NearHop`, "on its own network" | by reading | `Denied::NearCheckFailed { addr, hops, why }`: "could not tell how near X is (whether it is within N hops of this host): why"; `NearHop` only for near answers | `floor_tests::r4_a_failed_near_check_is_not_called_near` |
| 9 | parse-3 (low): DoH synthesis called `policy.facts()` on a runtime worker | `parse3-before.log` (3 s with a staged slow re-read) | `NetPolicy::facts_in_force` (no re-read) | `doh::tests::r4_synthesis_never_rereads_the_facts_on_a_worker` (`parse3-after.log`) |
| 10 | probe-2 (low): up to 8 probes at once through the same first hops, whose ICMP rate limit then dropped answers; S3 refused intermittently | `probe2-before.log` (every address of a name probed) | a third probe attempt after a 1 s pause (1 s, 0.5 s, pause, 1 s); at most 2 probes in flight in the process (`ProbeGate`); a name's addresses vetted one after another, in answer order, until one of each family is admitted. The control stays (the owner has not decided on S3) | `client::tests::r4_only_the_addresses_needed_are_probed`, `nearhop::tests::a_probe_that_timed_out_is_asked_again`, `probes_take_turns` |
| 11 | cross-6 (low): 7 mutants survived; no test reached the broker connector's re-check | the reviewers' VM mutation logs | tests for each: `nl_pid` (`pref64_from`, in `pref64_options_of_router_advertisements_are_read`), ENOBUFS (`r4_the_pref64_listener_survives_enobufs`, a seam), `SO_ERROR` rc != 0 (`r4_a_reset_read_once_stays_a_reset`), `next_read` (in the signature test), the peer match with two vetted addresses (`r4_a_connection_is_checked_against_its_own_vetted_address`), the missing `HttpInfo` (the layer is gone: the hop reads `getsockname`/`getpeername` itself), the PREF64 cap (`r4_pref64_is_learned_from_the_default_gateway_alone`); the broker: `connector::server::tests::a_connection_is_checked_again_once_made` (a real peer, 1.1.1.1:443, a staged route gone once connected: closed, not handed over) | as named |
| 12 | cross-7 (info): the workflow had no timeout, ran only the netguard crate, and `ZKMINER_CI_ALLOW_SKIP` matched substrings; the docs said the VM had no global IPv6; probe suspicion: the broker's abandoned `vet_path` threads ran on | by reading; the VM reaches IPv6 (`ping -6`) | `timeout-minutes`; a `callers` job (x86_64: `zkminer-chain`, the broker's library tests); skips allowed by an explicit token (`[ipv6] …`, `ZKMINER_CI_ALLOW_SKIP=ipv6`); the VM's IPv6 described (NAT66 through the Mac); the broker's floor checks take one of 4 turns (`MAX_CHECKS_AT_ONCE`), held by the blocking work until it ends | `tests::strict_ci_fails_skips_it_does_not_allow`; `actionlint` (with shellcheck) clean (`actionlint.log`) |

**Found while fixing.** Two of my own: the control connection made before the check's FIN let a
near peer whose accept queue was full hold the control's SYN and fail the check (`681ecae`: the
check's FIN now goes first and an acknowledgement of it is near at once); and the re-check's
`RTA_SRC` query failed (EINVAL) for `zkminer-chain`'s loopback stand-ins (`3300ed3`). The
reviewers' D case (`ip rule ipproto udp`) in `vm-rules.log` refused 1.1.1.1 once as "public IPv4
address is not known" (the DNS reflectors' UDP went to the LAN box); `vm-udp-rule.log`, the
same setup alone, admitted it: public-address discovery's timing under that rule, unchanged
code, fails closed.

**Linux code paths never executed** (type-checked and unit-tested): a real IPv6-only host
(`Nat64Unsettled` from a real facts read, a real DNS64); a PREF64 from a router that is the real
uplink's default gateway (the gateway case ran with the gateway list staged); a real move between
two networks behind the same router address (`MacHistory` is pure); a neighbour dump that the
kernel denies (the fallback's glue is tested with a staged error); Android at all (checked with
stub compilers).

**Open for the owner.** S3: the control connection still refuses a peer that never acknowledges
a bare FIN, on a path whose first hops send no ICMP (unchanged decision). The third probe attempt
and the gate add latency to a probe without an answer (worst case 3.5 s before the check
connection, from 1.5 s), and a name's addresses are probed one after another (one per family
pinned, so a connection that fails on the first IPv4 address no longer falls back to the next
one). A network that names more NAT64 prefixes than the caps refuses IPv6 on any host, a dual-
stack one included (fail closed: a hostile DHCP server or router can make a dual-stack host
IPv4-only). The `callers` CI job does not run the broker's integration tests (they need anvil
and the sandboxed binary; `held_lock_fetches_pass_a_flood_of_simulations` fails under Rosetta at
af17e48 as at HEAD).
