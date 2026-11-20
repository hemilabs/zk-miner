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
a bare FIN, on a path whose first hops send no ICMP (unchanged decision). The third probe attempt
and the gate add latency to a probe without an answer (worst case 3.5 s before the check
connection, from 1.5 s), and a name's addresses are probed one after another (one per family
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
- **Windows and ICMP time exceeded** (the probe lens's suspicion): whether Windows surfaces an
  ICMP "time exceeded" for a SYN in `SYN-SENT` as a failed connect (`WSAEHOSTUNREACH` /
  `WSAENETUNREACH`) at all is unverified; if it does not, every probe times out there and, with no
  check connection on Windows, every public host is refused. It needs a Windows runner: probe a
  far public host with hop limit 2 and see whether the connect fails fast.
- **CLAT detection** is by address and interface name; a CLAT numbered otherwise is not seen
  (its host then admits `<NSP>::10.x` until the prefix is learned, as before).
- **A flapping or spoofed gateway MAC** now makes the Linux guard learn its public addresses
  again on each change (it fails closed; round 4 had debounced it).
- **Probe pacing** (6, then 3 a second) adds latency only past a burst: a redirect chain of many
  dual-stack hosts may wait for tokens.
- Unchanged from round 4: S3 behind first hops without ICMP; caps that refuse IPv6 on a network
  naming more NAT64 prefixes than the guard holds (now cleared as soon as the source names what
  fits).
