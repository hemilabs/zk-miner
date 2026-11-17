#!/bin/bash
# Tests for install-metal-aot.sh (W7-M11, P31-M9b) and build-metal-aot.sh (P31-M9b) on fake archive
# sets, fake workers and a fake risc0 tree; no GPU, no metal-tt.
# usage: scripts/mac/test-install-metal-aot.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/aot-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail=0
# The W7-M11 cases below use a fake worker without embedded metallibs: no digest check for them.
export AOT_SKIP_DIGEST_CHECK=1
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

# ---- P31-M9b: digests ----
unset AOT_SKIP_DIGEST_CHECK
# A fake worker: a shell script followed by two fake metallibs (MTLB header, size, section table).
mkfake() { # $1 = path, $2.. = payload tags
  printf '#!/bin/sh\necho applegpu_g17s\nexit 0\n' > "$1"
  shift_path=$1; shift
  python3 -I - "$@" >> "$shift_path" <<'PY'
import struct, sys
out = b''
for tag in sys.argv[1:]:
    body = tag.encode().ljust(16, b'.')
    size = 0x58 + len(body)
    hdr = b'MTLB' + b'\0' * 12 + struct.pack('<Q', size) + struct.pack('<8Q', 0x58, 4, 0x5c, 4, 0x60, 4, 0x64, 4)
    out += b'junk' + hdr + body
sys.stdout.buffer.write(out + b'tail')
PY
  chmod +x "$shift_path"
}
mkfake "$T/inst/worker" libone libtwo
digests=$(bash "$here/build-metal-aot.sh" --worker-digests "$T/inst/worker")
check "$(echo "$digests" | wc -l | tr -d ' ')" 2 "--worker-digests finds both embedded metallibs"
d1=$(echo "$digests" | head -1)
check "${#d1}" 24 "a digest is 24 hex digits"
mkdir -p "$T/dset" && (cd "$T/dset" && echo a > "zkp-$d1-applegpu_g17s-macos27-0000.binarchive" \
  && shasum -a 256 *.binarchive > SHA256SUMS)
rm -rf "$T/inst/metal-aot"
bash "$here/install-metal-aot.sh" "$T/dset" "$T/inst/worker" >/dev/null 2>&1; check $? 0 "a set of the worker's digests installs"
check "$(ls "$T/inst/metal-aot" | grep -c binarchive)" 1 "digest-matched archive installed"
(cd "$T/dset" && echo b > "zkp-0123456789abcdef01234567-applegpu_g17s-macos27-0001.binarchive" \
  && shasum -a 256 *.binarchive > SHA256SUMS)
bash "$here/install-metal-aot.sh" "$T/dset" "$T/inst/worker" >/dev/null 2>"$T/err"; check $? 1 "an archive of another worker's metallib is refused"
check "$(grep -c 'digest mismatch' "$T/err")" 1 "the refusal names the digest mismatch"
check "$(ls "$T/inst/metal-aot" | grep -c binarchive)" 1 "previous set kept on a digest refusal"
mkfake "$T/inst/worker" libone libthree   # a rebuilt worker: libtwo changed
bash "$here/build-metal-aot.sh" --worker-digests "$T/inst/worker" | grep -qx "$d1"; check $? 0 "an unchanged metallib keeps its digest"

# ---- P31-M9b: build-metal-aot.sh without metal-tt work ----
mkdir -p "$T/r0/tools/metal_aot" "$T/tc/usr/bin" && : > "$T/r0/tools/metal_aot/build_archive.py"
printf '#!/bin/sh\nexit 0\n' > "$T/tc/usr/bin/metal-tt"; chmod +x "$T/tc/usr/bin/metal-tt"
export RISC0_DIR="$T/r0" METAL_TC="$T/tc" AOT_DUMP_TARGET="$T/dumps" AOT_MACOS_MIN=27.0
# A set already built for this worker and these arches is reused without any work.
mkdir -p "$T/set2" && : > "$T/set2/SHA256SUMS"
echo "worker_sha256=$(shasum -a 256 "$T/inst/worker" | cut -d' ' -f1) arches=applegpu_g17s macos_min=27.0" > "$T/set2/WORKER"
out=$(bash "$here/build-metal-aot.sh" "$T/inst/worker" "$T/set2" 2>&1); check $? 0 "a set built for this worker is reused"
check "$(echo "$out" | grep -c reused)" 1 "reuse is reported"
# A dump (kernel names) whose metallib the worker does not embed: nothing is built.
digs=$(bash "$here/build-metal-aot.sh" --worker-digests "$T/inst/worker" | sort | tr '\n' ' ')
key=$(echo "$digs" | shasum -a 256 | cut -c1-16)
mkdir -p "$T/dumps/dump-$key" && echo other > "$T/dumps/dump-$key/zkp.metallib"
echo '{"unit": "zkp", "metallib": "zkp.metallib", "names": ["k"], "fc": null}' > "$T/dumps/dump-$key/units.jsonl"
bash "$here/build-metal-aot.sh" "$T/inst/worker" "$T/set3" >/dev/null 2>"$T/err"; check $? 1 "a dump of another risc0 tree is refused"
check "$(grep -c 'not the tree the worker was built from' "$T/err")" 1 "the refusal says why"
check "$([ -e "$T/set3" ] && echo yes || echo no)" no "nothing built on that refusal"
exit $fail
