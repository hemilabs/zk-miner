#!/bin/bash
# Tests for install-metal-aot.sh (W7-M11) on a fake archive set and a fake worker; no GPU.
# usage: scripts/mac/test-install-metal-aot.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/aot-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail=0
check() { if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3 (got $1, want $2)"; fail=1; fi; }

mkdir -p "$T/set" "$T/inst"
printf '#!/bin/sh\necho applegpu_g17s\n' > "$T/inst/worker"; chmod +x "$T/inst/worker"
(cd "$T/set" && echo one > k-applegpu_g17s-a.binarchive && echo x > k-applegpu_g13s-a.binarchive \
  && echo old > k-applegpu_g17s-a.binarchive.old \
  && shasum -a 256 k-applegpu_g17s-a.binarchive k-applegpu_g17s-a.binarchive.old \
     k-applegpu_g13s-a.binarchive > SHA256SUMS && rm k-applegpu_g17s-a.binarchive.old)

# A SHA256SUMS line for a longer name with this name as a prefix must not be selected.
bash "$here/install-metal-aot.sh" "$T/set" "$T/inst/worker" >/dev/null 2>&1; check $? 0 "prefix-named sum line ignored"
check "$(ls "$T/inst/metal-aot" | grep -c binarchive)" 1 "only this Mac's architecture copied"
check "$(wc -l < "$T/inst/metal-aot/SHA256SUMS" | tr -d ' ')" 1 "one checksum line installed"

# An archive with no checksum line is refused, and the installed set is left as it was.
echo two > "$T/set/k-applegpu_g17s-b.binarchive"
bash "$here/install-metal-aot.sh" "$T/set" "$T/inst/worker" >/dev/null 2>&1; check $? 1 "archive without a sum refused"
check "$(ls "$T/inst/metal-aot" | grep -c binarchive)" 1 "previous set kept on refusal"
rm "$T/set/k-applegpu_g17s-b.binarchive"

# A corrupted archive is refused.
echo corrupt > "$T/set/k-applegpu_g17s-a.binarchive"
bash "$here/install-metal-aot.sh" "$T/set" "$T/inst/worker" >/dev/null 2>&1; check $? 1 "checksum mismatch refused"

# Another architecture installs nothing and succeeds.
printf '#!/bin/sh\necho applegpu_g99x\n' > "$T/inst/worker"
rm -rf "$T/inst/metal-aot"
bash "$here/install-metal-aot.sh" "$T/set" "$T/inst/worker" >/dev/null 2>&1; check $? 0 "unvalidated arch: exit 0"
check "$([ -e "$T/inst/metal-aot" ] && echo yes || echo no)" no "unvalidated arch: nothing installed"

# A reinstall that installs nothing removes the previous install's set (it was built for another
# worker): for an unvalidated architecture, and for a set with no archives for this one.
printf '#!/bin/sh\necho applegpu_g17s\n' > "$T/inst/worker"
mkdir -p "$T/inst/metal-aot" && echo stale > "$T/inst/metal-aot/k-applegpu_g17s-z.binarchive"
bash "$here/install-metal-aot.sh" "$T/set" "$T/inst/worker" applegpu_g99x >/dev/null 2>&1; check $? 0 "unvalidated arch over a stale set: exit 0"
check "$([ -e "$T/inst/metal-aot" ] && echo yes || echo no)" no "unvalidated arch: stale set removed"
mkdir -p "$T/inst/metal-aot" "$T/empty" && echo stale > "$T/inst/metal-aot/k-applegpu_g17s-z.binarchive"
: > "$T/empty/SHA256SUMS"
bash "$here/install-metal-aot.sh" "$T/empty" "$T/inst/worker" >/dev/null 2>&1; check $? 0 "no archives over a stale set: exit 0"
check "$([ -e "$T/inst/metal-aot" ] && echo yes || echo no)" no "no archives: stale set removed"
exit $fail
