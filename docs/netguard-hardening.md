# The network guard's hardening, on every platform

Review rounds 1 to 3 of the macOS port ([netguard-macos.md](netguard-macos.md)) found weaknesses
in decisions the platforms share, and fixed them on macOS only, listing the rest as "recommended
for #37". All of them are now applied on Linux and Android too, and on Windows where Windows has
the code path, on purpose: this changes what PR #37 decides on Linux and Windows. One new check
(each connection checked again once made) applies on every platform, macOS included.

The logic is the macOS one, lifted out of `cfg(target_os = "macos")` into shared code; what
differs per platform is only the primitive behind it (netlink or the routing socket, the ICMP
error queue or an ICMP socket with the private `TCP_INFO`, the neighbour table or configd). Decisions are pure functions where
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
4. **Only an acknowledged FIN answered the check connection** (`confirm_once`, `TcpState`, one
   decision for Linux, Android and macOS). *Removed by the S3 review (2026-11):* there is no
   check connection any more; the near-hop decision is the positive-evidence rule ("Near-hop
   rule: positive evidence", below).
5. **IPv4-mapped addresses are unmapped inside the probes**, on every platform (Windows' probe
   too).
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
   limit was far only if the peer acknowledged a FIN at the default hop limit, which AWS S3's
   front ends never do; the probe was asked more than once. *Removed by the S3 review
   (2026-11):* the control and check connections are gone, and with them the S3 trade-off; a
   decision is now up to two rounds of probes at hop limits `N`, `N+1`, `N+2`, far only on a
   router's ICMP "time exceeded" past the limit, so S3 is judged by distance like any other
   server ("Near-hop rule: positive evidence", below).
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

The witness broker starts no listener (`nat64::without_listener`): it reads the facts once, before
its sandbox, which refuses a process that already has a second thread (and denies the netlink
socket a listener reads). A listener started there would have heard nothing yet; the broker gets
the miner's refusals, PREF64-learned prefixes included, as `RefreshPrefixes`.

### The macOS CI change (ready to apply on `item/W11-ON37`)

`scripts/ci/macos-cpu-tests.sh` lives on `item/W11-ON37`, so nothing is committed there. Against
that branch's file (`shellcheck` clean):

```diff
--- a/scripts/ci/macos-cpu-tests.sh
+++ b/scripts/ci/macos-cpu-tests.sh
@@ -16,6 +16,13 @@
 #    assert this Mac's GPU, input devices and power source (MACOS_HOST_TESTS below).
 # 3. scripts/ci/test-metal-tc.sh with risc0-build-kernel from the pinned risc0 checkout: the Metal
 #    compiler wrapper the kit uses, through risc0-build-kernel and cargo (compiles kernels, runs none).
+# 4. The network guard (zkminer-netguard), with ZKMINER_CI_STRICT=1: a test that cannot check what it
+#    is for on this runner (no IPv6, no network) fails instead of printing SKIPPED and passing, unless
+#    ZKMINER_CI_ALLOW_SKIP (comma-separated tokens, from the job's env) names its reason's token
+#    exactly: "ipv6" allows a skip whose reason starts "[ipv6] " on a runner without IPv6, and no
+#    other. Then its live forge test, on its own (it floods every routing socket on the host). It
+#    needs outbound DNS and HTTPS and the near-hop probe's ICMP.
+#    docs/netguard-hardening.md, "CI".
 set -euo pipefail
 ci=$(cd "$(dirname "$0")" && pwd)
 repo=$(cd "$ci/../.." && pwd)
@@ -55,6 +62,12 @@
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

(Also at `/Users/user/zkminer/scratch/w11/NGREV/fix-r6/macos-ci.diff`; review round 6, cross-8:
the comment now describes the exact-token match round 4 introduced.)

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
| 4 only an acknowledged FIN (removed by the S3 review) | new: shared `confirm_once`, `TcpState`, `TCP_INFO` parsed from bytes, `TCP_CLOSE` read with `SO_ERROR` | n/a (no check connection) | same decisions, now shared | pure on every platform: `the_check_reads_only_an_acknowledged_fin_as_an_answer`, `linux_tcp_info_is_read_within_what_the_kernel_wrote`; Linux live: `linux_tcp_info_is_the_kernels` (glibc's offsets on x86_64), `linux_a_reset_and_a_completed_close_read_apart`, `a_peer_that_closes_first_is_never_far` (loopback, and NIST's daytime server: "closed"), `the_check_connection_finds_a_local_listener_near`, `a_near_listener_that_drops_syns_for_a_while_is_near` |
| 5 unmap in the primitives | new | new (probe) | unchanged | run: `a_mapped_address_is_probed_as_its_ipv4_address` (Linux and macOS: `[::ffff:1.1.1.1]:443` at hop limit 2 is unreachable, never connected) |
| 6 checked again once made | new | new | **new** | run on Linux and macOS: `a_route_that_changes_between_the_check_and_the_connection_drops_it` (fetch refused, server got no request), `a_connection_that_left_by_another_path_is_refused` (real socket addresses), `the_vetted_source_is_the_kernels`; every guarded fetch in the suite and `zkminer-chain`'s real downloads go through the layer. The broker connector's re-check is type-checked only: no broker test reaches a connection that the public floor admits (loopback stands in, and the floor refuses it); its suite, run as x86_64 Linux under Rosetta, passes as at af17e48 (below) |
| 7 NAT64 per uplink, server order, PREF64 | new; PREF64 listener | per uplink and order (no PREF64) | unchanged but the signature computed once per read | pure: `a_new_uplink_is_asked_for_its_prefix_at_once`, `a_new_uplink_signature_is_unsettled_at_first`, `a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends`, `ipv6_is_refused_while_a_new_uplinks_nat64_prefix_is_learned`, `the_active_and_routed_servers_are_asked_first`, `resolv_conf_servers_keep_their_order`, `pref64_options_of_router_advertisements_are_read`; Linux live: `the_pref64_listener_joins_unprivileged`, and with a staged RA carrying PREF64 `2001:db8:6464::/96` on a veth whose other end sat in a network namespace, the unprivileged test received and learned it (`vm-pref64-ra.log`) |
| 8 default-like answer held by the facts | new | same (no oracle there) | unchanged | run: `a_new_uplink_is_refused_until_the_facts_hold_it`, `the_kernels_answer_per_destination_is_judged` (changed, below); the real-host tests on the VM's kernel |
| 9 positive control, second attempt (removed by the S3 review) | new (control); new (attempt) | new (attempt) | unchanged; message shortened | pure: `a_fin_acknowledged_at_no_hop_limit_is_never_far`, `a_probe_that_timed_out_is_asked_again_once`; Linux live: `the_check_connection_finds_a_public_host_far` (1.1.1.1 acknowledged the restored FIN: far), `a_peer_that_never_acknowledges_a_fin_is_not_far` (an S3 front end: refused, the message naming S3) |
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
  Android, which the old Linux `confirm_once` used; the check connection then parsed `TCP_INFO`
  from bytes; since the S3 review there is no check connection);
- the witness broker connector's re-check once connected (no test reaches it: above); the crate
  does not build on aarch64 Linux (`libc::SYS_fchmodat2` is not defined for aarch64, before and
  after this change), and its suite ran as x86_64 under Rosetta: 135 unit tests, of which
  `a_broker_that_shuts_its_reading_side_is_cut_off` fails now and then under emulation at
  af17e48 as at HEAD (3 of 6 and 2 of 6 alternating runs: `x86-broker-alternating.log`), and the
  integration test `held_lock_fetches_pass_a_flood_of_simulations` fails at both.

**Windows** changes (type-checked only): `FactsCell`'s grace and single flight, `FactsUnreadable`
and `Nat64Unsettled`, NAT64 per uplink with the ordered servers, the probe asked twice and
unmapped, the post-connect check in the guarded client, the admit loops off the runtime, and the
check-connection stub's message ("Linux and macOS only"; since the S3 review every near-hop
decision on Windows refuses, for want of a way to read the routers' ICMP errors). Windows still refuses every requester
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

**Mutation run** (`fix-r4/mut/`): 59 mutants of the round 4 code on macOS (`muts.py`,
`run.py`): 55 killed on the first run (`summary-run1.txt`); the 4 survivors (the non-kernel
port, the control's round trip from its own FIN, the hop's bind to the vetted source, the body's
read timeout reset by a read) got tests (`23ad4e2`) and are killed (`summary.txt`). In the VM, 6
mutants of Linux-only lines (`vm_muts.py`): 2 killed at once; `sys::source` and `query_from`
survived, got the live test `the_tcp_source_is_the_kernels_and_routes_are_asked_from_it`
(`dac69a2`) and are killed (`vm-summary-2.txt`); 2 survive: the broker connector's
bind to the vetted source (the source is the same either way on a host with no rule that tells
TCP from UDP) and its turns for blocking checks (no test makes checks outlive their share).

**Gates** (`fix-r4/gates-summary.log`, `vm-gates-summary.log`, at 23ad4e2):

- **macOS:** the netguard suite twice and with `ZKMINER_CI_STRICT=1` (215 library tests,
  nothing skipped); the live forge test twice (about 310,000 queries answered while 1.31 M
  forged datagrams arrived, none taken); `zkminer-chain` (185) and its two real downloads in
  public mode; clippy `--all-targets -D warnings`.
- **Linux (the VM):** the suite twice on aarch64 and once strict with `ZKMINER_CI_ALLOW_SKIP=ipv6`
  (189, nothing skipped), clippy; under Rosetta (x86_64) the suite, `zkminer-chain` and its real
  downloads, and the broker's library tests (136, the connector's re-check test among them). The
  broker's integration tests need anvil (not installed in the VM) and a sandboxed binary that
  finds no x86_64 `libgcc_s` under Rosetta; `held_lock_fetches_pass_a_flood_of_simulations`
  fails there at af17e48 as at HEAD.
- **Type-checked:** `cargo check` and clippy `--all-targets -D warnings` for
  `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` and `aarch64-linux-android` (stub C
  compilers): no warnings; the broker's clippy for linux-gnu (its warnings are in files this
  round did not touch).
- **Merge:** `git merge-tree --write-tree item/W11-ON37 HEAD`: clean. `actionlint` 1.7.7 with
  shellcheck 0.9.0 on the workflow: clean.

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
a bare FIN, on a path whose first hops send no ICMP (unchanged decision; resolved by the S3
review, below: no control connection, S3 judged by distance). The third probe attempt
and the gate add latency to a probe without an answer (worst case 3.5 s before the check
connection, from 1.5 s; since the S3 review a decision is at most two rounds), and a name's addresses are probed one after another (one per family
pinned, so a connection that fails on the first IPv4 address no longer falls back to the next
one). A network that names more NAT64 prefixes than the caps refuses IPv6 on any host, a dual-
stack one included (fail closed: a hostile DHCP server or router can make a dual-stack host
IPv4-only). The `callers` CI job does not run the broker's integration tests (they need anvil
and the sandboxed binary; `held_lock_fetches_pass_a_flood_of_simulations` fails under Rosetta at
af17e48 as at HEAD).


## Review round 5

Four reviewers (bypass, parse, probe, cross; material in
`/Users/user/zkminer/scratch/w11/NGREV/r5-*`) on 0a2d1fd. During round 5 the reviewers shared
one `CARGO_TARGET_DIR`, so a test binary could come from another tree; every reviewer test was
therefore rerun in this tree (the files touched first, the test names checked in the output)
before the fixes (`fix-r5/reviewer-*-before.log`) and after (`reviewer-*-after.log`), and each
finding was then reproduced with a failing test of mine or a live repro before it was fixed.
Logs: `fix-r5/` (`/Users/user/zkminer/scratch/w11/NGREV/fix-r5/`).

| # | finding | reproduced | fix | test |
|---|---|---|---|---|
| 1 | cross-1 (medium) = bypass-2 = parse-2: `Heard` kept every PREF64 prefix a gateway ever named, expired and withdrawn ones included, and counted them against the per-router cap; five renumberings, or one forged RA from the gateway's link-local address with five options, left the uplink unsettled for the process's life (all IPv6 refused, on any host); the refusal said "still being learned (at most 2s)" | the reviewers' tests fail (cross, parse) or show the bug (bypass) at 0a2d1fd (`reviewer-*-before.log`); live: `r5-cross/vm-r5-spoof.log` (refused for 340 s) | `Heard` drops a prefix withdrawn with lifetime 0 or whose lifetime ran out (prune on every hear and facts read), names and counts only live ones, and a newer prefix takes an expired one's room; the registry keeps every withdrawn prefix refused (`learn` withdraws what a source stops naming); unheld marks are kept per uplink and source, and a source's next naming clears its own mark under the same lock before judging what it names now (no window: item 5); on Linux each facts read drops what ran out and learns the gateways again; an uplink unheld is refused with `Denied::Nat64Unheld { ip, why }`, naming the source and what it named | `nat64::r5_tests::r5_a_gateway_that_renumbers_its_pref64_never_unsettles_its_uplink`, `r5_one_forged_advertisement_unsettles_its_uplink_only_while_it_lives`, `r5_a_source_that_names_what_fits_clears_its_own_mark`, `r5_pref64_that_runs_out_is_withdrawn_at_the_next_facts_read` (Linux), `policy::tests::r5_an_unheld_nat64_prefix_has_its_own_refusal_naming_the_source`; live: `vm-r5-spoof.log` (IPv6 refused, naming `the router advertisements of fe80::1`, from the forged RA until its withdrawal 3 s later, or until its 8 s ran out; admitted from then on) |
| 2 | bypass-1 (medium): the Linux MAC debounce kept the old network's signature while a new gateway MAC held for 3 reads and 2 s, and an on-link host flipping the entry between two MACs reset it on every read: on a new network behind the same gateway address the old network's NAT64 state and public addresses stood (macOS changes at once) | the reviewer's `r5_a_move_keeps_the_old_networks_signature_for_the_debounce` shows it (`reviewer-bypass-before.log`) | the Linux signature also hashes the uplink's addressing (`uplink_addressing`: the global IPv6 on-link prefixes and IPv4 connected subnets of the uplink's interfaces, and the host's IPv4 addresses in them); another MAC than the known one is another uplink at once (public addresses relearning, IPv6 refused on an IPv6-only host until its NAT64 round ends); the debounce (3 reads, 2 s, timer reset only by the known MAC) only decides when the new MAC becomes the known one, and the signature does not change again when it does (`changed` MACs hashed, not an epoch). Round 4's rules stay: a flushed or `FAILED` entry, and a MAC first seen, change nothing | `facts::tests::two_networks_behind_the_same_router_address_are_two_uplinks_on_linux` (rewritten: the reviewer's flipping sequence never yields the old signature; a real move relearns once; flush, FAILED, first seen unchanged), `r5_the_uplinks_addressing_tells_networks_apart_on_linux`; live: `vm-r5-mac.log` (the gateway's entry replaced by another MAC: public IPv4 and IPv6 refused as relearning at once; the real MAC back: admitted again), `vm-repros.log` NF (two flushes in 20 s: no refusal) |
| 3 | parse-4 (medium): with no gateway MAC known (the neighbour table unreadable, no usable entry) every facts read hashed its own number: a new signature per read, public addresses relearning for good, a NAT64 round per read | by reading (the reviewer's code path) | with no MAC known the routes and the addressing decide, stably, warned about once; networks the addressing tells apart are never merged | in the signature test above (`fresh`, `denied`) |
| 4 | probe-1 (medium): the broker connector bounded each address's floor check by its share of the connect time (5 s / n), but the near-hop decision takes 3.5 s when the probe goes unanswered: with n = 2 every far address was abandoned on a path whose hop at the limit is silent, and abandoned checks kept their turn and probe slot; the probe gate's wait had no bound (parse and probe suspicions) | the new broker test fails at 0a2d1fd (`vm-broker-r5-before.log`: Unreachable after 5 s) | `nearhop::decide_until` / `NetPolicy::vet_path_until` take a deadline: the probe's turn is waited for until it, every attempt, the pause and the check connection's connects and wait are bounded by it, out of time is a failure (never far); `NearProbe::probe_until`/`confirm_until` (defaults call `probe`/`confirm`); the broker checks each address within the request's deadline and bounds only the TCP connect by the share; the guarded client's pin passes the request's deadline | broker `connector::server::tests::r5_a_slow_near_hop_check_does_not_lose_its_address` (a 3.6 s probe fake, two addresses: connected; `vm-broker-r5-after.log`), `nearhop::tests::r5_a_probe_waits_for_a_turn_only_until_its_deadline`, `client::tests::r5_the_checks_run_within_the_requests_time_one_per_family` |
| 5 | bypass-3 (low): `begin_round` cleared the uplink's unheld mark before the round asked again: for up to 2 s every 15 s an over-naming DNS64's uplink was not unsettled | the reviewer's `r5_unheld_is_cleared_for_the_length_of_a_round` shows it | the mark stays while the round runs and is replaced when it ends (cleared only if nothing was marked there since it began); rounds tracked per uplink | `nat64::r5_round_tests::r5_unheld_is_kept_while_a_round_runs_and_replaced_when_it_ends` (the reviewer's test turned around), `r5_a_rounds_marks_replace_the_old_ones_when_it_ends` |
| 6 | parse-3 (low): `Heard` was keyed by (router, interface) only: another network's PREF64 from a router of the same address was learned and synthesized with | the reviewer's test fails | each entry is tied to the uplink it was heard on (`Heard::on`) | `nat64::r5_tests::r5_another_networks_pref64_is_not_named_on_this_one` |
| 7 | bypass-4 (low): a host whose IPv4 default goes through a CLAT (464XLAT) is IPv6-only behind NAT64 but looked dual-stack, so `<NSP>::10.0.0.1` was admitted while the network's prefix was not learned | by reading | `nat64::clat_in_use`: an IPv4 address in 192.0.0.0/29 (RFC 7335: Android's, macOS's, clatd's CLAT) or an IPv4 default out of a `clat*`/`v4-*` interface makes the host IPv6-only for NAT64 (refused until its round ends, asked again every 15 s). Not chosen: refusing IPv6 on every host until a new uplink's round ends (tried: it refused IPv6 on dual-stack hosts at every signature change, and a NAT64 on a dual-stack network is rare). The reviewer's suspicion (an IPv6-only host whose servers answered with no prefix counts as settled): kept (refusing all IPv6 there would leave the host nothing) and now logged once per uplink, naming `[egress] nat64_prefixes` | `nat64::r5_tests::r5_a_clat_host_is_ipv6_only`, `nat64::tests::a_new_uplink_is_asked_for_its_prefix_at_once`, `facts::tests::a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends` |
| 8 | bypass-5 (low): the broker connector made an IPv6 socket for an IPv4-mapped address and bound it to the IPv4 source: `EINVAL` | the new test fails at 0a2d1fd (`vm-broker-r5-before.log`) | connected to the unmapped address on a socket of its family | `connector::server::tests::r5_an_ipv4_mapped_address_is_connected_as_ipv4` |
| 9 | parse-1 (low): the TLS handshake was bounded only by the request's whole time (pr/37: by the connect timeout) | the reviewer's test and mine fail at 0a2d1fd (`hop-r5-before.log`: 8 s) | bounded by `(now + connect_timeout).min(deadline)` | `client::tests::r5_a_stalled_tls_handshake_is_bounded_by_the_connect_timeout` |
| 10 | cross-2 (low): no happy eyeballs: sequential connects with the full timeout each, and only the last failure named; a blackholed IPv6 path added 15 s per hop | live: `r5-cross/vm-r5-happy-eyeballs.log` (27 s a fetch), rerun after the racing connect: still 27 s (`vm-r5-he.log` history in the commit): the time was in the pin, which vetted every IPv6 address (13.5 s each on a blackholed path) before IPv4 | the hop's connect races (RFC 8305: IPv6 first, the next 250 ms later or at once when the one before failed, the first that connects and passes the re-check wins, the others dropped before a byte, every failure named); the pin walks each family on its own, the two at once, and once one has an address the other gets 250 ms more | `client::hop::tests::r5_the_addresses_race_ipv6_first`, `client::tests::r5_a_blackholed_ipv6_family_does_not_hold_the_hop`; live: `vm-r5-he.log` (IPv6 SYNs dropped: 0.6-1.4 s a fetch) |
| 11 | probe-2 (info): a control-connection reset was reported as the check connection's, and "(control connection)" fell past the 120-character cut | by reading | each failure names its connection in its own text, within the cut | `nearhop::tests::the_check_reads_only_an_acknowledged_fin_as_an_answer` |
| 12 | cross-3: seven mutants survived | the reviewer's mutation logs | tests: the exact request line and `Host` with a port and a query, the response head within the read timeout, an https URL's first bytes a ClientHello (R12), an attempt within the deadline, the dual-family pin, the eviction order when a prefix is named again, PREF64 sources from default-like routes only | `client::tests::r5_the_request_line_and_host_are_exact`, `r5_the_response_head_is_bounded_by_the_read_timeout`, `r5_a_stalled_tls_handshake_is_bounded_by_the_connect_timeout`, `client::hop::tests::r5_an_attempt_is_bounded_by_the_deadline_too`, `client::tests::r5_the_checks_run_within_the_requests_time_one_per_family`, `nat64::r5_tests::r5_a_prefix_named_again_is_not_the_first_to_make_room`, `facts::tests::r5_a_nexthop_objects_gateways_are_the_uplinks` |
| 13 | cross-4 (info): the workflow's callers job was not strict and had no cargo cache; with `nexthop_compat_mode` 0 the IPv4 gateway was missing from the uplinks | by reading | the callers job strict (the broker tests' skips fail under it), both jobs cache `~/.cargo` and `target`; nexthop objects' gateways (`NHA_GATEWAY`) resolved for the default routes (`default_gateways`, `routes::nexthop_gateways`) | `facts::tests::r5_a_nexthop_objects_gateways_are_the_uplinks`, `routes` `nexthop_messages_parse` (Linux); `actionlint` (with shellcheck) clean |
| 14 | the probe lens's suspicions | | rate: the probe gate also paces SYNs, a burst of 6 then 3 a second (`PROBE_BURST`, `PROBES_PER_SECOND`); Windows ICMP: open (below) | `nearhop::tests::r5_probes_are_paced` |

**Mutation run** (`fix-r5/mut/`): 55 mutants of this round's code on macOS (`muts.py`, `run.py`):
44 killed on the first run (`summary-run1.txt`); of the 11 survivors six got tests (`7b77c6e`) and
are killed (`summary.txt`). Five survive: `round_on` never ending its round and the gathered
facts never passing CLAT (both glue in code that reads the real host: no unit test drives a
round or `gather_with` with staged inputs), the check connection's connect and wait not bounded
by the deadline (`N02`, `N08`: they run only in the real check connection, against a peer that
answers slowly), and a failed attempt not starting the next address at once (`E07`: equivalent
while a hop has at most two addresses, one per family, since an empty race starts the next one
anyway). In the VM, 4 mutants of Linux-only lines (`vm_run.py`: the PREF64 expiry at a facts
read, `NHA_GATEWAY`, the broker's mapped-address socket and its check bounded by a share
again): all killed (`vm-summary.txt`).

**Gates** (`fix-r5/gates-summary.log`, `vm-gates-summary.log`, macOS at 7b77c6e, the VM at 10a6870, which changes
only a Linux test):

- **macOS:** the netguard suite twice and with `ZKMINER_CI_STRICT=1` (236 library tests, nothing
  skipped); the live forge test twice (308,852 queries answered while 1.29 M forged datagrams
  arrived, none taken); `zkminer-chain` (185) and its two real downloads in public mode; clippy
  `--all-targets -D warnings`.
- **Linux (the VM):** the suite twice on aarch64 and once strict with `ZKMINER_CI_ALLOW_SKIP=ipv6`
  (211, nothing skipped), clippy; under Rosetta (x86_64) the suite, `zkminer-chain` and its real
  downloads, and the broker's library tests (138, strict). The first VM run failed
  `a_near_listener_that_drops_syns_for_a_while_is_near` (`vm-gates-summary-run1.log`): with
  probes paced, the probe's third attempt came after the listener drained and the probe itself
  found it near; the test now accepts either near answer (`10a6870`), and the rerun passes.
- **Type-checked:** `cargo check` and clippy `--all-targets -D warnings` for
  `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` and `aarch64-linux-android` (stub C
  compilers): no warnings; the broker's clippy for linux-gnu (13 warnings, all in files this round
  did not touch, as in round 4).
- **Merge:** `git merge-tree --write-tree item/W11-ON37 HEAD`: clean. `actionlint` (with
  shellcheck) on the workflow: clean.
- **The reviewers' tests after the fixes** (`reviewer-*-after.log`; their patches appended to
  the files' new tails by `append_patch.py`, the bypass lens's facts test ported to the new
  `MacHistory::signature` arguments): the three tests that asserted a bug now fail (the bugs are
  gone), the cross and parse tests that asserted the fix pass, except parse-3's, which builds a
  `Heard` without naming the uplink (`Heard::on`); its ported twin passes.

**Live repros rerun in the VM** (`fix-r5/vm-repros.log`, `vm-r5-spoof.log`, `vm-r5-he.log`,
`vm-r5-mac.log`): round 4's (policy rules, the `ipproto udp` rule, the hostile DNS64 with and
without validated answers, the rogue RA of 16 PREF64 options, nexthop objects with compat 0 and
1, neighbour flushes, the route flipping to the LAN box 150 times) behave as at 0a2d1fd
(`vm-batch2.log` of round 4 and this round's differ in timings only; the LAN box got 0
requests); round 5's spoofed-gateway RA and blackholed IPv6 as in items 1 and 10; the uid,
fwmark and source rules and the nexthop member replaced (`r5-rules.sh`) as in the reviewer's
`vm-r5-rules.log` (refused, the LAN box never reached).

**Linux code paths never executed** (type-checked and unit-tested): a real IPv6-only host or a
real CLAT (`clat_in_use` from a real facts read); a real move between two networks behind the
same router address with different addressing (the MAC change ran live, the addressing is pure);
a neighbour dump the kernel denies; a nexthop object's `NHA_GATEWAY` from a real dump in the
signature (parsed from built messages; the compat-0 repro ran the route side); Android at all.

**Open for the owner.**
- **Windows and ICMP time exceeded** (the probe lens's suspicion): measured since on Windows 11
  (26300): it does not. SYNs with hop limits 1 to 5 to public IPv4 and IPv6 hosts all time out
  after 4 s with `TCP_FAIL_CONNECT_ON_ICMP_ERROR` set, and `TCP_ICMP_ERROR_INFO` holds nothing,
  while an unprivileged `tracert` from the same host gets each router's Time Exceeded (so the
  firewall is not withholding it). Every public host is refused there; `nearhop::supported()`
  now says so, at start and in `zkminer status`, and public mode is documented as unsupported
  on Windows (`[dev] private_network` for a testnet). A different evidence source, such as an
  unprivileged `IcmpSendEcho2Ex` with a TTL, would need its own review.
- **CLAT detection** is by address and interface name; a CLAT numbered otherwise is not seen
  (its host then admits `<NSP>::10.x` until the prefix is learned, as before).
- **A flapping or spoofed gateway MAC** now makes the Linux guard learn its public addresses
  again on each change (it fails closed; round 4 had debounced it).
- **Probe pacing** (6, then 3 a second) adds latency only past a burst: a redirect chain of many
  dual-stack hosts may wait for tokens.
- Unchanged from round 4: S3 behind first hops without ICMP (since the S3 review, every
  destination behind such hops is refused alike); caps that refuse IPv6 on a network
  naming more NAT64 prefixes than the guard holds (now cleared as soon as the source names what
  fits).

## Review round 6

Four reviewers (bypass, parse, probe, cross; material in
`/Users/user/zkminer/scratch/w11/NGREV/r6-*`) on bc48610: four mediums and ten lows after
merging duplicates, one info, and suspicions; no reachable private or near connection and no
memory unsafety on any platform. Every reviewer test was rerun in this tree before the fixes
(`fix-r6/reviewer-*-before.log`: each fails or shows its bug) and after
(`reviewer-*-after.log`, appended to the files' new tails by `reviewer-tests-after.sh`); each
fix has a test that fails without it and, as this is the last round and earlier fixes opened
new holes, the invariant it relies on is written below and tested on random sequences, not
only on the example. Logs: `fix-r6/` (`/Users/user/zkminer/scratch/w11/NGREV/fix-r6/`).

| # | finding | reproduced | fix | test |
|---|---|---|---|---|
| 1 | NAT64 state: cross-1 (medium: one forged RA at the largest lifetime, 65528 s, unsettled the uplink for 18 h and kept the real gateway's prefix out of what is heard), cross-2 = parse-2 (medium: withdrawn entries counted against `MAX_PER_UPLINK` and were never evicted from the uplink in use: after 32 renumberings or eight forged RAs every new prefix unsettled it for good), bypass-1 (low: a hostile network's DNS64 naming a provider's /32 was read as an NSP everywhere for the process's life, and handed to the broker whole), the sixth-prefix suspicion, cross-7 T24/V04/V06 | the reviewers' tests fail or show the bug (`reviewer-*-before.log`); live `r6-cross/vm-r6-ra.log`, `vm-r6-ra-fill9.log` | a PREF64 lifetime is believed up to `MAX_PREF64_LIFETIME` (1800 s, RFC 4861's largest `MaxRtrAdvInterval`); a router's newest advertisement (its options more than `RA_BURST`, 1 s, after the last began: the kernel hands each option over as a message of its own) replaces what it named before; a router naming more than 5 in one advertisement is seen to (its first five kept: keeping the newest instead churned one advertisement's 16 options through the registry, the live rogue-RA rerun), and its next advertisement is heard whole; only active entries count against `MAX_PER_UPLINK`; when 64 entries are held, room comes from other uplinks' inactive, then other uplinks' least recently seen, then the uplink in use's longest-withdrawn entry, which then refuses that uplink's IPv6 until `STALE_GRACE` after its withdrawal (`Registry::forgotten`: never admitted early); a learned prefix that stopped being named, or whose uplink the host left, is refused for `STALE_GRACE` (1 h, two of the largest RA intervals: a router still announcing it, one advertisement lost, names it again first) and then forgotten (neither the predicate nor the broker's refusals read it); the broker gets another uplink's <64 NSP as the IPv4 ranges it would carry, not whole; a DNS server no longer asked names nothing; unheld marks of the uplink in use are never pushed out by other uplinks' (32 kept) | `nat64::r6_tests::r6_an_attacker_who_stops_causes_a_bounded_refusal` (the invariant, 80 random sequences), `r6_one_forged_advertisement_is_ended_by_the_gateways_next`, `r6_eight_forged_advertisements_leave_room_for_the_uplinks_next_prefix`, `r6_another_networks_prefix_is_forgotten_after_its_grace`, `r6_a_young_withdrawn_prefix_makes_room_only_by_refusing_its_uplink`, `r6_a_dns_server_no_longer_asked_names_nothing`, `r6_unheld_marks_are_bounded`, `r6_other_routers_never_push_out_the_gateway`, `r6_a_router_naming_too_many_keeps_its_newest`, `r6_a_router_naming_too_many_keeps_its_newest_in_order`, `r6_a_round_on_an_old_uplink_learns_no_gateways_pref64`; live: `vm-r6-ra.log` (the 65528 s forgery refused IPv6 for 14 s, until the gateway's next RA; before: for good), `vm-r6-ra-fill9.log` (eight forged RAs left to run out, then a renumbering: never refused; before: refused from the renumbering on) |
| 2 | parse-1 (medium): the probe gate's `notify_one` went to a waiter that then left without a turn, and another slept to its own deadline: a legitimate host refused after the whole budget; parse-4 = probe-2 (low): an expired caller still got a turn and took a token, a cut probe burned up to 3 tokens; cross-7 N11/N14 | `r6_parse_a_freed_turn_is_not_lost` (4/4 failed), `r6_parse_an_expired_caller_takes_no_token`, `r6_turn_after_deadline_takes_a_token` | a first-come-first-served ticket queue; every change wakes every waiter and no wait exceeds the token interval (333 ms); out of time no turn, no token, no further attempt, and an attempt never runs past the deadline; the check connection's connect within it too | `nearhop::r6_tests::r6_the_gate_never_loses_a_turn_on_random_callers` (the invariant: random callers, deadlines and holds), `r6_a_freed_turn_is_not_lost`, `r6_an_expired_caller_takes_no_token`, `r6_turns_are_first_come_first_served_and_hopeless_waits_are_shed`, `r6_a_probe_attempt_ends_at_the_deadline`, `r6_the_check_connection_is_bounded_by_the_deadline`; the reviewers' gate tests pass after (`reviewer-parse-after.log`, `reviewer-probe-after.log`) |
| 3 | probe-1 (medium, macOS): `TCP_CONNECTION_INFO` reports `tcpi_rto` 0 until the retransmission timer is armed, so the far margin for a retransmitted FIN's ACK collapsed to ~50 ms (Linux reads the real RTO) | the reviewer's `rto-macos.log` (0 before the FIN, 242 ms after) and pure test | the RTO is read again after the FIN is sent, the larger taken; still zero is `UNKNOWN_RTO` (1 s, RFC 6298's initial); `control_wait` follows; both platforms then use the same margins | `nearhop::r6_tests::r6_the_check_never_uses_a_zero_rto`, `r6_the_live_check_uses_a_nonzero_rto` |
| 4 | parse-3 (low): `ensure_discovered_on` held `ON_UPLINK` across `spawn_round`, whose spawn-failure branch locked it again: a self-deadlock in the facts read | by reading; the new test deadlocks with the old code | the guard is dropped first; a seam (`FAIL_SPAWN`) fails the spawn in tests | `nat64::r6_tests::r6_a_round_that_cannot_start_does_not_deadlock` |
| 5 | bypass-2 = cross-5 (low, Linux) and the L=0 suspicion: after a move over a link that went down to a network numbered like the old one, the first reads (neighbour table emptied) were the old network's | the reviewers' tests show it (`reviewer-bypass-before.log`, `reviewer-cross-before.log`) | the base hashes the uplink interfaces' `IFLA_CARRIER_CHANGES` and the /64s of the host's global IPv6 addresses; a gateway whose MAC was known and that has no entry in a table that was read is unresolved: the read sends it one empty UDP datagram (port 9) and reads the table again for up to `RESOLVE_WAIT` (300 ms); a family still unresolved is refused as relearning. Round 4's rule kept: an ordinary flush resolves within the wait (no refusal) and an unreadable table changes nothing | `facts::r6_tests::r6_a_move_with_a_flushed_neighbour_table_is_never_the_old_network`, `r6_the_hosts_ipv6_64s_are_part_of_the_base`, `routes` `r6_carrier_changes_are_read`; `r6_asking_for_a_neighbour_makes_the_kernel_resolve_it`, `r6_the_links_read_keep_their_carrier_changes` (Linux, live); live: `vm-r6-flush.log` |
| 6 | cross-4 (low, Linux): a spoofed IPv4 gateway MAC refused both families (one signature), a new MAC a second refused 100% and multiplied discovery traffic | live `r6-cross/vm-r6-flap.log` | the uplink is per family (`UplinkId`: IPv4's gateways for its public address, IPv6's for IPv6's and NAT64); any number of differing MACs is one unsettled state (a candidate holds only when the same MAC shows on 3 reads in a row over 2 s); public discovery keeps the last 4 uplinks' confirmed answers per family; back on an uplink a NAT64 round settled within `DISCOVERY_TTL`, no new round | `facts::r6_tests::r6_a_spoofer_of_the_ipv4_gateway_makes_one_unsettled_state` (random spoofers), `public` `r6_a_recent_uplinks_answer_stands_again`, `nat64::tests::a_new_uplink_is_asked_for_its_prefix_at_once`; live: `vm-r6-flap.log` (below) |
| 7 | cross-3 (low): answers AAAA first cut to 8, so www.google.com kept no IPv4 and failed after ~110 s with IPv6 TCP broken (pr/37: ~19 s) | the reviewer's test fails; live `r6-cross/vm-r6-google-pristine.log` | the admitted addresses are interleaved (RFC 8305 §4) before the cut; a family is given up after two near-hop checks that could not tell | `resolve` `r6_a_name_with_eight_aaaa_keeps_its_ipv4_addresses`, `r6_interleaving_keeps_both_families` (random lists), `client` `r6_a_family_is_given_up_after_two_checks_that_could_not_tell`; live: `vm-r6-google.log` |
| 8 | cross-6 (low, a regression against pr/37): the broker connector vetted addresses one after another, each with the whole 17 s, so a blackholed family whose addresses came first starved the other. The reviewer's case (two AAAA first) does not arise as stated: the broker's resolver answers A first; the same holds with the families swapped (IPv4 blackholed) | the new broker test with the old loop: Unreachable after 17.5 s (`vm-broker-r6-before.log`) | per-family chains (the other family 250 ms later; the first on the request's own task, nothing spawned in developer mode), each handing over each address it vetted and going on only when that address's connection failed; a chain stops after two checks that could not tell. The existing `a_broker_that_shuts_its_reading_side_is_cut_off` waited 300 ms for the first answer's write to fail, which took 290 ms under Rosetta with the whole suite: it waits 1 s | broker `connector::server::tests::r6_a_blackholed_family_does_not_starve_the_other` (Rosetta: connected over IPv6 in under 5 s, `vm-broker-r6-after.log`) |
| 9 | probe-3 (low): the global pacer (2 in flight, 6 + 3/s) capped every connection process-wide: 64 vets at once over four hosts, 17 s, left 25-28 refused; probe-4 (low): S3 refused ~15% unloaded | measured before (`exp/burst2-*-before.log`, `exp/s3-before.log`) | per-family gates; a caller whose turns ahead need more tokens than can come before its deadline sheds at once; one decision per destination at a time, its far verdict remembered for `FAR_TTL` (10 s) for that exact address, port, hop limit, facts (routes, rules, addresses, prefixes, uplink) and probe; never a prefix (a /24 or /48 can hold both a far host and a near one: an ISP's access router and its data centre), never a near or failed verdict, never on facts given by the caller; a destination whose check connection failed is probed once more after 2 s when the deadline allows | `nearhop::r6_tests::r6_one_decision_runs_per_destination_at_a_time`, `r6_far_verdicts_are_remembered_only_for_the_same_destination_and_facts`, `r6_a_failed_check_is_followed_by_one_more_probe`, `r6_each_family_has_its_own_gate`, `policy` `r6_a_far_verdict_is_remembered_on_the_same_facts_only`; measured after (macOS): 64 at 17 s: 39 → 64 admitted (p50 14.9 s → 22 ms); 20 at 2 s: 11 → 20 (twice; one run 0 during an ICMP loss episode at hop 2, `burst2-n20-2s-after.log`); S3: 17 → 20 of 20 far |
| 10 | cross-7 (low): mutation survivors V02, V04, V05, V06, F21, F24, T24, N11, N14 | the reviewer's mutation logs | tests | `facts::r6_tests::r6_the_facts_read_the_neighbour_table` (Linux, V02), `nat64` `r6_a_round_on_an_old_uplink_learns_no_gateways_pref64` (V04, the gateway choice now `round_gateways`), `facts` `r6_the_ipv4_defaults_interfaces_include_a_nexthop_objects` (V05, `v4_default_links`), `r6_other_routers_never_push_out_the_gateway` (V06), `r6_the_mac_history_keeps_several_bases` (F21), `r6_only_unicast_on_link_routes_are_addressing` (F24), `r6_the_path_key_changes_with_what_a_path_depends_on`, `r6_unheld_marks_are_bounded` (T24), N11 and N14 above |
| 11 | the CLAT suspicion: no runtime warning when the IPv4 default goes through a CLAT-like interface and no NAT64 prefix is known; a nexthop object's default (ifindex 0) never matched the CLAT name test | by reading | the IPv4 default's interfaces include a nexthop object's devices; a host whose IPv4 default leaves from a `tun` device or a `clat*`/`v4-*`/`tun*` interface (or a CLAT the guard recognises) with no NAT64 prefix known is warned once to set `[egress] nat64_prefixes` | `facts::r6_tests::r6_the_ipv4_defaults_interfaces_include_a_nexthop_objects`; live `vm-r6-clat.log` (behaviour as the reviewer found; the harness shows no log) |
| 12 | the parse lens's suspicion: `hop.rs` added huge connect and read timeouts to `Instant::now()` and panicked | by reading | `later`: saturates far in the future | `client::hop::tests::r6_a_huge_timeout_does_not_overflow` |
| 13 | the parse lens's suspicion: `nat64::ask_servers` and public discovery read datagrams until `WouldBlock`, so a flood kept the thread past its timeout | the new test hangs with the old loop | the deadline is checked on every datagram | `nat64::r6_tests::r6_a_flood_of_non_answers_ends_at_the_timeout` |
| 14 | the parse lens's suspicion: an unheld mark from the PREF64 listener counted only from the next facts read | by reading | facts read from the host carry their NAT64 uplink; the policy reads its marks live | `policy` `r6_an_unheld_mark_counts_before_the_next_facts_read` |
| 15 | cross-8 (info): the macOS CI diff's text described the old substring `ZKMINER_CI_ALLOW_SKIP`; README claims on withdrawn prefixes; the callers job never ran the ignored real downloads; no paths filter; the "never executed" list | by reading | the diff below names the exact token; README corrected (round 6's bounds); the callers job runs `a_real_elf_downloads_in_public_mode` and `real_stores_that_redirect_across_hosts_are_followed`; both jobs only when the guard, its callers or what builds them changed; the list below | `actionlint` (with shellcheck) clean |

**The invariants, and what backs them.**

- *NAT64 (item 1).* An attacker on the link who stops sending at T leaves the uplink in use
  unsettled (all IPv6 refused) for at most `MAX_PREF64_LIFETIME + STALE_GRACE +
  DISCOVERY_TTL` (95 min) after T: its PREF64 entries live at most 1800 s (or until the real
  gateway's next advertisement replaces them), its DNS answers until the next round asks the
  real server (or a server no longer asked is withdrawn), a mark is re-judged on each naming of
  its source and cleared at a round's end with nothing marked, and a forgotten-entry refusal
  ends `STALE_GRACE` after the entry's withdrawal. One forged advertisement from the gateway's
  address ends at the gateway's next one. The real gateway's prefix is in force after each of
  its advertisements once the attacker stopped (its router key is never pushed out by other
  routers, its own next prefix always enters, and the uplink in use's active entries never
  exceed 32 < 64). Security: on the real network, a prefix learned there is refused, or every
  IPv6 destination is, until `STALE_GRACE` after its source last named it. Every bound holds
  throughout (64 entries, 32 active per uplink, 32 marks, 8 forgotten, 16 routers × 5). A facts
  read on Linux always learns its gateways' PREF64 again (`pref64::expire`; the VM mutation run
  showed that learning only when that read's own prune dropped something left a mark standing
  when the listener had pruned first: fixed in `ce829d1`).
  Tested together on 80 random sequences (forged RAs from the gateway's address and from
  routers that make themselves gateways, every lifetime, up to 8 options; spoofed and foreign
  DNS answers; uplink changes; the real gateway every 600 s and its DNS64 every round): worst
  refusal after the attacker stopped 3441 s, every path reached (the registry full on 186,367
  steps, a forgotten mark on 138,639).
- *Probe gate (item 2).* At most `PROBES_AT_ONCE` turns per family; a turn is never given after
  its deadline nor a token taken; a caller without one returns by its deadline; a free turn
  with a token there is never left unclaimed by a waiter whose deadline allows it (no lost
  wakeup). Tested on random callers.
- *Far verdicts (item 9).* A far verdict admits only the exact (address, port, hop limit) it
  was found for, on facts whose routes, rules, addresses, prefixes and uplink are unchanged,
  for 10 s, from the same probe. Why it is safe: a destination's hop count changes only with
  the path, and the path from this host changes only with the facts the key holds (or beyond
  the first hops, which never make a far destination near within seconds without a routing
  change here); a port is in the key because a router can send one port elsewhere (a
  transparent proxy at hop 1); a prefix is not, because a prefix can hold both a far and a near
  host. Near and failed verdicts are never remembered, so remembering can only skip a probe that
  would have said far. *Removed by the S3 review (2026-11):* a far verdict is now evidence about
  one probe's 4-tuple, so it is not remembered at all
  ("Near-hop rule: positive evidence", below).
- *Linux uplink identity (items 5, 6).* Per family: whenever the known MAC of the family's
  gateway shows, the signature is the known network's; differing MACs that never hold are one
  other signature; IPv4's gateway never moves IPv6's signature; a move over a carrier change is
  another base at once; a known gateway missing from a readable table refuses its family until
  it resolves (asked at once; an ordinary flush resolves within 300 ms). Tested on random
  spoofer sequences and pure examples.
- *Addresses (item 7).* Every address kept is one given, each family in its own order, at most
  8, and neither family left out while it has addresses (at least min(its count, 4)). Tested on
  random lists.

**The VM live repros** (`fix-r6/vm-*.log`):

- `vm-r6-ra.log`: one forged RA from the gateway's address naming five PREF64 at 65528 s: IPv6
  refused 14 s, until the gateway's next advertisement (round 6 reviewers: 18 h); eight forged
  RAs of four each, 1 s or 9 s apart, then the gateway renumbering: never refused
  (`vm-r6-ra-fill9.log`; reviewers: refused from the renumbering on).
- `vm-r6-flap.log` (the gateway's IPv4 neighbour entry set to a forged MAC, as an ARP spoofer
  would): IPv6 never refused (before: refused with IPv4, 27-67% of samples); IPv4: a flap every
  1 s 1.6% refused (27%), the guard's discovery traffic 92 packets (284); every 3 s 31% (31%);
  a new MAC every second 65% (67%), 85 packets (211). The forged MAC goes nowhere here (the VM's
  bridge drops frames to it), so IPv4 is cut off for as long as it holds: what is left of the
  refusal is the spoof's own outage, not the guard's (a spoofer that forwards would see IPv4
  learned once on the unsettled state).
- `vm-r6-google.log` (www.google.com, eight AAAA records): with IPv6 SYNs dropped, fetched in
  0.43 s over IPv4 (before: refused after ~110 s); normal and with a broken IPv6 upstream as
  before. `vm-r6-he-redir.log`: the redirect chains of round 5's repro, HEAD and pr/37: HEAD
  fetched every one in every condition (each fetch at most 1.9 s; the runs' totals 3.9, 26 and
  7.0 s include abandoned checks running out at the process's end), pr/37 refused google.com
  with IPv6 SYNs dropped (totals 11.8, 85 and 14.6 s).
- `vm-r6-flush.log`: three `ip neigh flush` of the uplink in 35 s: nothing refused (the facts
  read asks the gateway and its entry is back within the wait).
- `vm-r6-nh.log` (default routes through nexthop objects, compat mode 0): the IPv4 gateway's
  neighbour entry replaced by a spoofed MAC for 5 s refuses IPv4 only (relearning), IPv6 stays
  admitted; a forged RA from a nexthop group member's gateway naming five PREF64 refuses IPv6
  for its 8 s.
- `vm-r6-clat.log` (an IPv4 default out of a staged tun numbered and named as clatd, Android
  and tayga do, and unusually): as the reviewer found; a host the guard takes as behind a CLAT
  whose round names no prefix is settled and admits IPv6, as decided in round 5, and now warns
  (`warn_tunnelled_ipv4_without_nat64`; that harness installs no log subscriber, so the warning
  is checked by the unit test only). The tun has no translator behind it, so this is not a
  real CLAT.
- Round 4's and 5's repros (`vm-r4r5-repros.log`: policy rules, the `ipproto udp` rule, the
  hostile DNS64 with and without validated answers, the rogue RA of 16 PREF64 options, nexthop
  objects, neighbour flushes, the route flipping to the LAN box; round 5's rules, spoofed
  gateway RA, MAC change and blackholed IPv6) behave as at bc48610 (`r6-cross/vm-r4r5-repros.log`)
  but for two differences, both intended: the MAC change (`vm-r5-mac`) refuses IPv4 only (it
  refused both families), and the rogue RA's live test first failed on this round's
  "newest pushes out the oldest" (16 prefixes churned through the registry) and passes since
  `7a9ee3c` (`vm-rogue-ra-rerun.log`). The LAN box got no request.

**Gates** (`fix-r6/gates-summary.log`, `vm-gates-summary.log`; code at 06359ef on both, the
docs commit after it changes no code):

- **macOS:** the netguard suite twice and with `ZKMINER_CI_STRICT=1` (275 library tests,
  nothing skipped); the live forge test twice (312,021 queries answered while 1.32 M forged
  datagrams arrived, none taken); `zkminer-chain` (185) and its two real downloads in public
  mode; clippy `--all-targets -D warnings`.
- **Linux (the VM):** the suite twice on aarch64 and once strict with `ZKMINER_CI_ALLOW_SKIP=ipv6`
  (254, nothing skipped), clippy `-D warnings`; under Rosetta (x86_64) the suite, `zkminer-chain`
  and its real downloads, and the broker's library tests (139, strict). The first Rosetta run
  failed only for want of Rosetta (the VM had been started without it); the broker's
  `a_broker_that_shuts_its_reading_side_is_cut_off` then failed under the whole suite until
  its wait was lengthened (item 8).
- **Type-checked:** `cargo check` and clippy `--all-targets -D warnings` for
  `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` and `aarch64-linux-android` (stub C
  compilers): no warnings; the broker's clippy for linux-gnu: 13 warnings, all in files this
  round did not touch (as in rounds 4 and 5).
- **Merge:** `git merge-tree --write-tree item/W11-ON37 HEAD`: clean. `actionlint` (with
  shellcheck) on the workflow: clean; the macOS CI diff applies to `item/W11-ON37`'s script and
  shellcheck passes on the result (`macos-ci-shellcheck.log`).
- **The reviewers' tests** (`reviewer-*-before.log`, `reviewer-*-after.log`): before, every
  finding's test fails or shows the bug; after, parse's five, cross's three NAT64/resolve tests
  and probe's two pass; bypass's NAT64 test, which asserted the bug, fails at its last
  assertion (the broker is no longer handed the /32 whole); the facts tests of bypass and
  cross call `linux_signature` with round 5's arguments and are ported
  (`facts::r6_tests::r6_a_move_with_a_flushed_neighbour_table_is_never_the_old_network`).

**Mutation run** (`fix-r6/mut/`): 53 mutants of this round's code on macOS (`muts.py`,
`run.py`, each built into the shared target and its binary copied and run): 41 killed on the
first run (`summary-run1.txt`); of the 11 survivors, five got tests or a stronger fixture
(`993be25`: T03, F11, F13, N07, N16, all killed in `run2.out`; F04's stronger variant F04b
killed). Six survive: T16 (the per-datagram deadline check in `ask_servers`: the reader here
always drains the socket before the flood refills it, and the outer loop then checks the
deadline; the check matters only for a flood faster than parsing), F04 (a weak mutant that
stops counting instead of counting on: F04b is the real variant), N01 and N02 (the two
independent defences against a lost wakeup, `notify_all` and the capped wait: each mutant is
masked by the other), N03 (the loop's own check refuses an expired caller before a token, so
the early return is equivalent), U02 (public discovery's per-family judging in its global
state: no seam drives `learned_inner`). In the VM, 7 mutants of Linux-only lines
(`.r6repro/vm_mut.py`, `vm-mut.log`, `vm-mut2.log`): the neighbour table never read, carrier
changes never kept or the wrong attribute, a round on an old uplink learning the current
gateways: killed; three survive: the facts read not waiting for, or not asking for, a missing
gateway (L01, L02: only a root-staged flush reaches them; the live `vm-r6-flush.log` and
`r6_asking_for_a_neighbour_makes_the_kernel_resolve_it` cover their effect), and the PREF64
listener's call passing no gateways (L06: `Heard`'s protection is tested; the listener's state
is process-wide, shared with other tests). The VM run also exposed a race in
`pref64::expire` (fixed in `ce829d1`).

**Linux code paths never executed** (type-checked and unit-tested): a real IPv6-only host or a
real CLAT (`clat_in_use` from a real facts read; the staged tun of `vm-r6-clat.log` is not a
translator); a real move between two networks behind the same router address (the carrier
change, the flush and the MAC change ran live, each alone); a neighbour dump the kernel
denies; Android at all. `NHA_GATEWAY` from a real dump ran live (`r6-cross/vm-r6-nh.log`,
`fix-r6/vm-r6-nh.log`), so it leaves the list.

**Open for the owner.**
- **Windows and ICMP time exceeded** in `SYN-SENT`: measured on Windows 11, not surfaced (see
  above); every public host is refused there and public mode is unsupported on Windows.
- **S3's positive control**: the control connection refuses a peer that never acknowledges a
  bare FIN (every AWS S3 front end); the last probe attempt makes S3 pass when its first hops
  answer ICMP (20/20 here), but behind first hops that never send ICMP S3 is refused every time.
  (Resolved by the S3 review: no control connection; S3 passes by distance where the first hops
  send ICMP, and is refused like every other destination where they do not.)
- **CLAT heuristics**: by address (192.0.0.0/29) and interface name or kind; a CLAT numbered
  and named otherwise is not recognised; such a host is now warned, once, to set
  `[egress] nat64_prefixes`, and admits `<NSP>::10.x` until it does (or the prefix is learned).
- **The MAC-change fail-closed cost**: an ARP spoofer on the LAN still makes IPv4 learn its public
  address again on its first change (one unsettled state, not one per change), and a held change
  once more; IPv6 is no longer affected by an IPv4 spoof. A real move behind the same gateway
  address without a carrier change relearns twice.
- **Bounded NAT64 refusals**: an attacker who keeps sending forged RAs or DNS answers keeps
  IPv6 refused while it sends, and up to 95 minutes after (typically until the gateway's next
  advertisement); refusing less would admit what is under a prefix the network may still use.
- **The far-verdict memory** trades a probe for 10 s of trust in an unchanged path; set
  `FAR_TTL` to zero (a constant) if that is not wanted. (Dropped by the S3 review: no far
  verdict is remembered.)
- **The 4th probe attempt** adds up to 3 s to a refusal that would have come anyway (a check
  connection that failed), only when the deadline allows. (Dropped by the S3 review: at most
  two rounds.)

## Near-hop rule: positive evidence

The S3 review (three rounds, 2026-11-21: measurement, threat, design, evidence, identity and
integration lenses, then a skeptic) asked whether the near-hop check could admit AWS S3 behind
first hops that send no ICMP without admitting anything near. It found the strict check itself
unsound: it read silence, and an unreachable, as far. In the lab an unprivileged near Linux
listener using `IP_MINTTL` (it ignores SYNs that arrive with a low hop count), a TTL filter
(cBPF or `iptables` dropping low-TTL packets), a near host answering low-TTL SYNs with a
host-unreachable, and, now and then, induced loss each made a near destination read as far.
The check is therefore replaced by a rule that admits far only on positive evidence. No method
found, this one included, is safe without assumptions; the wording to use is the one below.

**The rule.** "The network guard admits a destination as far only on positive evidence (a router
past the limit said the probe ran out of hops), never on silence."

- Fresh TCP sockets connect to the exact destination address and port with hop limits `N`,
  `N+1` and `N+2` at once (`N` is `[egress] near_hop_limit`, default 2; `EXTRA_HOPS`), from the
  source address and interface the real connection will use. A round waits at most
  `PROBE_TIMEOUT` (1.5 s) and ends as soon as it is decided; a second round follows after
  `ROUND_PAUSE` (1 s) only when the first decided nothing (`ROUNDS` 2, `DECIDE_BUDGET` 8 s). No
  data is written; a probe that connected is reset. A round takes one turn and one token of the
  probe gate (`PROBES_AT_ONCE` 2 rounds in flight per family, `PROBE_BURST` 6,
  `PROBES_PER_SECOND` 3): each router expires at most one of a round's three SYNs, so its ICMP
  load is that of one probe before the review.
- **Near** (`Denied::NearHop`): the destination answered (SYN-ACK, reset, `ECONNREFUSED`) a probe
  of at most `N` hops.
- **Far**: some probe of `t >= N` hops got an ICMP Time Exceeded code 0 (IPv4 11/0, ICMPv6 3/0)
  the kernel matched to it (4-tuple and initial sequence number), from a unicast, specified
  sender that is not the destination, and the destination answered no probe of at most `t`
  hops.
- **Everything else refuses** (`Denied::NearCheckFailed`, "could not tell how near"): silence,
  any Destination Unreachable, Time Exceeded code 1, a Time Exceeded from the destination, an
  answer only beyond `N`, an unreachable without its ICMP message, inconsistent results, local
  errors, missing ICMP plumbing. An answer always dominates an ICMP error queued for the same
  probe (Linux can queue an error and still complete the connection: `sk_err_soft` while the
  socket is owned by the user).
- **Linux and Android:** `IP_RECVERR` / `IPV6_RECVERR` and `MSG_ERRQUEUE` (`sock_extended_err`,
  `SO_EE_ORIGIN_ICMP(6)`, `ee_type` / `ee_code`, `SO_EE_OFFENDER`), verified live in `SYN_SENT`.
  **macOS:** an unprivileged `SOCK_DGRAM` `IPPROTO_ICMP(V6)` socket opened before the probes;
  a copy counts only if it quotes the probe's destination address and port, source address and
  port and ISN (from the private `getsockopt(IPPROTO_TCP, TCP_INFO 0x200)`, `tcpi_snd_nxt - 1`,
  only in `SYN_SENT`, its length checked; a zero or repeated ISN refuses) and the probe's own
  socket failed with `EHOSTUNREACH` / `ENETUNREACH`; late copies are drained for 30 ms. A Mac
  where the ICMP socket or `TCP_INFO` cannot be read refuses everything (warned once at
  startup). An error `connect` reports at once (Local Network privacy, a Network Extension
  policy) is a local failure, never evidence. **Windows:** no implementation; every decision
  refuses (it already refused every requester connection in public mode).
  `TCP_FAIL_CONNECT_ON_ICMP_ERROR` / `TCP_ICMP_ERROR_INFO` were measured since on Windows 11
  and give nothing for a Time Exceeded; it fails closed, and says so.

**Removed.** The check and control connections (the hop-limited FIN, the `TCP_INFO` /
`TCP_CONNECTION_INFO` state readers, the RTO margins, the "AWS S3 never acknowledges a bare FIN"
refusal, the last probe attempt and the 3+1 attempts), and "unreachable is far". A near host
that drops SYNs (and FINs) is now refused for want of evidence, never far.

**Pinning.** The connection that follows leaves as the probes did: `Vetted` carries the source
address the probes were bound to and the interface that holds it, and the guarded client's hops
and the witness broker's connector make the connection with `Vetted::socket`, bound to that source
(a far probe that left from another source is refused), on that interface (macOS `IP_BOUND_IF` /
`IPV6_BOUND_IF`; Linux sets `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, but measured on kernel 7.0 a TCP
connect ignores them, and `SO_BINDTODEVICE` needs `CAP_NET_RAW`, so on Linux the source address
and the recheck pin the path; the IPv6 option in host byte order failed with `EADDRNOTAVAIL`, found
on the VM and fixed), and on Linux with `IPV6_AUTOFLOWLABEL` off on the probes and the connection,
from a new local port. The far probe's port was reused at first (the review's R4 mitigation) and
then dropped by the owner's decision: stateful home or carrier-grade NATs keep the probe's session and drop a second SYN on the
probe's 4-tuple (measured on this project's own IPv4 home path: every connection that reused the
probe's port timed out, a new port connected at once). The connection is made right after the verdict.

**The far cache is dropped** (`FAR_TTL` 10 s, the single-flight `decide_remembered` and the facts'
path key). A far verdict is evidence about one probe's 4-tuple; another connection may take
another path (per-connection balancers, measured in round 3), so nothing is remembered: the
safer of the review's two options (the other, a cache keyed to the probe's port and very short,
could never be hit while the first connection held the port or its `TIME_WAIT`). Cost: every connection is decided afresh, at most 3
decisions a second per family after a burst of 6. `MAX_UNANSWERED_PER_FAMILY` (the client) and
the broker's `MAX_UNANSWERED` still count `NearCheckFailed`, which now includes every decision
without evidence: a family whose path gives no evidence twice is given up.

**Assumptions and definition.** The far verdict holds under four assumptions: (1) no party that
sees the probe's SYN forges ICMP (root on a near host, an on-path or on-link attacker: a hostile
LAN gets no protection from this check, as from any distance test); (2) routers send Time
Exceeded only for packets they forward (RFC 1812 5.3.1), not for their own addresses reached
through policy routing or a VRF leak; (3) the real connection follows the probe's path (the pin;
a stateless per-packet balancer, a transient loop or a route change can still break it); (4) the
kernel's matching of the ICMP error to the probe (on macOS through a private `TCP_INFO` layout).
"Within `N` hops" means `N - 1` TTL-decrementing routers before the destination. Boxes that hide
hops (a double NAT behind the ISP's router, a VM's NAT, a VPN, a userspace NAT64) move the limit:
`near_hop_limit` 2 then does not reach the ISP's first box. The default stays 2 (raising it
refuses more far destinations on paths with silent hops). Paths whose first hops send no Time
Exceeded refuse every destination.

**What holds** (the review's lab, Linux and macOS, a C prototype and the Rust one; no far for a
near destination in any case without forgery): an `IP_MINTTL` listener, cBPF and `iptables` TTL
filters, Destination Unreachable rejects, a silent on-path drop, FIN/ACK drops, delay, a reply
with TTL 1, a normaliser (near); loss of 50-90 % (0 far in 120); forged Time Exceeded from the
destination, with code 1, a Destination Unreachable, a wrong ISN or a wrong port: refused; a Time
Exceeded racing the SYN-ACK: near; a container DNAT whose Time Exceeded has the destination as
its source: refused. Unprivileged Linux and macOS processes cannot send or spoof a Time Exceeded
(ping sockets `EINVAL`, raw sockets `EPERM`, a user namespace's network namespace isolated); 40
concurrent decisions (12 processes on macOS) were never misattributed; draining a router's ICMP
rate limit causes refusals only. Round 3 reran every round 2 lab decision (74) with identical
results. The far set is a strict subset of the old check's.

**What does not hold.** A root process on a near host, or an on-path or on-link attacker, that
forges a Time Exceeded from another source (IPv4 spoofing past a loose `rp_filter`, IPv6) makes a
near destination far; Linux and xnu abort a connecting socket on the first ICMP error they accept,
so injection alone suffices. This is the documented exception, as for every distance test.
Definitional cases that read far (they did at the old HEAD too): VRF and policy-routing hairpins
to a router's own addresses (measured, the miner's gateway included), a userspace NAT64 (tayga:
three hop-limit units in one box, measured), a VM's NAT hiding a hop (measured: the ISP's CGNAT
box far at `N` 2), a CGNAT hairpin to the operator's own PCP mapping, a transient routing loop
(measured), a stateless per-packet balancer. A per-connection balancer with unequal paths
(mwan3 style) reads far about half the time per family (lab: 11 of 20, 10 of 20) and, since the
connection takes a new port (the owner's decision), reaches the near host over the short path on
some connections: 4 of 13 and 8 of 17 in two lab runs (round 3's prototype: 12 of 15); with the probe's port
reused it was 0 of 18 (0 of 19). A documented residual, as before the S3 review.

**Availability.** Home paths whose hop 2 sends Time Exceeded (this Mac's and its Linux VM's): no
change, 61 of 61 addresses decided at start hop 2 (S3 18 of 18). Measured by starting the probes
deeper to stand in for silent first hops: hops 2-3 silent, non-S3 destinations about 93 %
(AWS-hosted ones lost); hops 2-5 silent, about 49 % (CDNs lost). Corporate edges and cloud
networks that filter ICMP (EC2: AWS-internal hops 4 to 9 silent): refused, every destination; the
witness broker's endpoints alike. Windows: unchanged (refused). LTE/5G: not measured.

**S3.** S3 now works by distance, like any other server, on paths whose first hops send ICMP
(18 of 18 S3 endpoints from the home paths). An identity path for ICMP-silent paths (S3 admitted
by a TLS 1.3 connection pinned to Amazon's roots with a constant SNI, a different promise: "an
Amazon-keyed S3 front end", not "not near") was designed and deferred by the owner; it is not
implemented. Cloud servers (EC2 and the like, whose provider hops send no ICMP) are out of scope
for now.

**Decided: no port reuse.** Reusing the far probe's local port for the real connection was
implemented first and measured to fail on this Mac's IPv4 home path (hop 1 the home NAT router,
hop 2 the ISP's carrier-grade NAT): the real SYN got no answer whenever it followed the probe's by
more than about 20 ms, for at least 125 s, while a new port connected at once (in the Linux VM
behind the Mac's NAT too; Linux-conntrack-only paths reused fine). A stateful NAT keeps the
probe's session with its sequence number and drops a second SYN on its 4-tuple. Every IPv4
connection after a far verdict failed there, so the owner chose to pin the source address,
interface and flow label only, and to document the per-connection balancer residual above.

**Fixed on the way.** `ProbeGate::enter_until` (and the IPv6 gate) built the gate with
`then_some`, so a caller that timed out or was shed gave back a turn it never held, and more
rounds could be in flight than `PROBES_AT_ONCE` (seen on the Linux VM); now the gate is made only
once given, with a regression test (`a_caller_without_a_turn_gives_none_back`).
