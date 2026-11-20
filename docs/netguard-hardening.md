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
   put (a dual-stack host with an unreachable IPv6 router keeps its IPv4 address confirmed). A
   neighbour dump that fails fails the facts read.
4. **Only an acknowledged FIN answers the check connection.** One `confirm_once` for Linux,
   Android and macOS, deciding from a platform-neutral `TcpState`: `FIN_WAIT_2` / `TIME_WAIT`
   (this side's FIN acknowledged) is near; a peer that closed or reset first is a failed check,
   never near and never far. Linux never shows `TIME_WAIT` on the socket (it hands the
   connection to a timewait mini-socket and the socket reads `TCP_CLOSE`), so `TCP_CLOSE` with
   no pending error (`SO_ERROR` 0) reads as acknowledged-and-closed, with one (`ECONNRESET`,
   `EPIPE`, …) as reset. Before, Linux read every state but `FIN_WAIT1` as near.
5. **IPv4-mapped addresses are unmapped inside the probe and the check connection**, on every
   platform (Windows' probe too).
6. **Each connection is checked again once made**, before any request byte is written (new on
   every platform). `NetPolicy::vet_path` vets as before and then records the source address the
   kernel chooses for the connection (a UDP socket connected to it: nothing sent);
   `NetPolicy::recheck_connected` requires the connection's own peer and source (`getpeername`,
   `getsockname`) to be the vetted ones (`connected_as_vetted`, pure) and admits the destination
   again on the facts in force with no cached kernel verdict, so the kernel is asked how it
   routes now. A mismatch is `Denied::PathChanged` (new variant); a refused route is the usual
   refusal; either way the connection is dropped. The guarded client installs this as a reqwest
   connector layer, reading the addresses from hyper-util's `HttpInfo`; for `https` the TLS
   handshake (its ClientHello names the host) runs inside reqwest's connector, before the check.
   The witness broker's connector checks its sockets the same way before handing them over.
7. **NAT64 prefixes are learned per network.** The facts compute the uplink signature once per
   read and hand it to public-address discovery and to `nat64::ensure_discovered_on`: a changed
   signature starts a round at once, an IPv6-only host that found nothing asks again every 15 s,
   one round runs at a time. Until the round for a new signature has finished, a host with IPv6
   and no IPv4 route refuses every IPv6 destination (`Denied::Nat64Unsettled`, now on every
   platform). The servers in use are asked first (macOS: configd's global resolvers; elsewhere
   the `resolv.conf` files' `nameserver` lines in file order, `/etc/resolv.conf` first), servers
   of an unrouted family are skipped, and the list is cut to 8 only after ordering. Linux also
   reads PREF64 (RFC 8781), below. Before, Linux learned at startup and every 300 s from the
   first 8 of the sorted list, IPv4 first.
8. **A default-like kernel answer must be a default route the facts hold** (family, hop,
   interface), or it is refused as off the default path, a refusal that rests on the facts (the
   policy reads them again at once and judges once more). Before, Linux admitted any default-like
   route of an ordinary table until the next facts read.
9. **The positive control, and a second probe attempt.** A FIN unacknowledged within the hop
   limit is far only if the peer acknowledges its retransmission once the default hop limit is
   restored; otherwise a failed check, refused. The probe is asked twice within its 1.5 s (1 s,
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
   cut before it named anything). Dropping the control is a one-line change in
   `fin_after_control_deadline` if S3-hosted programs matter more than a near device that never
   acknowledges a bare FIN and drops the probe's SYN.
10. **CI.** `.github/workflows/netguard-linux.yml` runs the suite with `ZKMINER_CI_STRICT=1`
    (`ZKMINER_CI_ALLOW_SKIP="IPv6,[::1]"`: GitHub's runners have no IPv6) and clippy
    `--all-targets -D warnings`; the macOS half is the diff below.

### PREF64 on Linux

The kernel hands a router advertisement's "user options" (RDNSS, DNSSL, captive portal, and
PREF64 since Linux 5.8: `ndisc_is_useropt`) to the `RTNLGRP_ND_USEROPT` netlink group as
`RTM_NEWNDUSEROPT` messages, and any process may join it (rtnetlink is `NL_CFG_F_NONROOT_RECV`).
`nat64::pref64` starts a listener thread on the first NAT64 round and learns every PREF64 it
sees (for the life of the process, as RFC 7050 prefixes are). There is no table to read: only
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
gateway 192.168.64.1, then the home router), IPv6 only a ULA prefix (no global IPv6), so the
IPv6 paths that need the internet skip there, as on GitHub's runners. Windows ran nothing: it is
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

