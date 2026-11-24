#!/bin/bash
# Build the offline (AOT) Metal binary archive set for one built Metal worker (P31-M9b), with risc0's
# tools/metal_aot (W7-Z1), so `make -f Makefile.mac mac-install-worker` can install it beside the worker
# (scripts/mac/install-metal-aot.sh) and its first start loads the GPU pipelines instead of compiling
# them (a cold first start of `BENCH_ONLY=fibonacci --benchmark`: 76-81 s -> 2.3 s on an M5 Max, P31-M9b note).
#
# usage: build-metal-aot.sh <worker binary> <out dir> [arch ...]
#        build-metal-aot.sh --worker-digests <worker binary>
#
#   <worker binary>  e.g. target/release/zkminer-prove-risc0-metal
#   <out dir>        receives *.binarchive, manifest.jsonl, SHA256SUMS and WORKER (what it was built
#                    for); replaced in one rename. Reused as is when WORKER matches the worker and the
#                    arches (a re-install builds nothing).
#   arch             metal-tt GPU families; default: this Mac's (`<worker> --metal-arch`).
#   --worker-digests prints the archive digest (risc0 `archive::parallel_digest`, first 24 hex digits) of
#                    every metallib the worker embeds, one per line, and exits (install-metal-aot.sh
#                    refuses archives of any other digest).
#
# Inputs:
#   - the metallibs: extracted from the worker binary itself (the exact bytes it loads, so the digests
#     match by construction);
#   - the kernel names of each archive unit: risc0's `w7z1_dump_aot_inputs` tests (zkp, rv32im,
#     keccak, groth16-sys), built in $RISC0_DIR with CARGO_TARGET_DIR=$AOT_DUMP_TARGET (default
#     <zk-miner>/target/aot-dump, never the risc0 checkout's own target) and run once per set of worker
#     digests (cached; the ~5 GB test build is deleted afterwards unless AOT_KEEP_DUMP_BUILD=1). The
#     dump tests load each library on the Metal device (no GPU work). Every metallib a dump writes must be byte-identical to one the worker embeds,
#     else the risc0 tree is not the one the worker was built from and nothing is built. recursion has
#     no dump test: its units come from its sys crate's lib.rs and the worker's recursion metallib.
# Environment: RISC0_DIR (default <zk-miner>/../deps/risc0-3.1), AOT_DUMP_TARGET, AOT_JOBS (units built
# at once, default 3; ~2.2 GB of RAM for the rv32im one), AOT_MACOS_MIN (default this Mac's major.0).
# Needs metal-tt (the Metal toolchain; source env.sh) and python3. Units built: everything but
# keccakstrict and the recursion revert variants (knob paths; they still compile at first use).
# Cost on an M5 Max (applegpu_g17s): 11 archives, 165 MiB; 77 s with the dump cached, ~6 min the first
# time per risc0 kernel set (the dump tests' build); a reuse is a checksum of the worker.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

py_extract() {
  # $1 = worker, $2 = out dir (or "-" to print digests only)
  python3 -I - "$1" "$2" <<'PY'
import hashlib, os, struct, sys
CHUNK = 1 << 20
def digest(b):
    h = hashlib.sha256(struct.pack('<Q', len(b)))
    for i in range(0, len(b), CHUNK):
        h.update(hashlib.sha256(b[i:i + CHUNK]).digest())
    return h.hexdigest()
data = open(sys.argv[1], 'rb').read()
out = sys.argv[2]
seen = {}
pos = data.find(b'MTLB')
while pos >= 0:
    step = 4
    if pos + 0x58 <= len(data):
        (size,) = struct.unpack_from('<Q', data, pos + 0x10)
        if 0x58 < size <= len(data) - pos:
            offs = struct.unpack_from('<8Q', data, pos + 0x18)
            # function list, public/private metadata and bitcode sections inside the file
            if all(o + s <= size for o, s in zip(offs[0::2], offs[1::2])) and offs[0] >= 0x58:
                lib = data[pos:pos + size]
                d = digest(lib)[:24]
                seen.setdefault(d, lib)
                step = size
    pos = data.find(b'MTLB', pos + step)
if not seen:
    sys.exit('no embedded metallib found in ' + sys.argv[1])
for d, lib in sorted(seen.items()):
    if out == '-':
        print(d)
    else:
        open(os.path.join(out, d + '.metallib'), 'wb').write(lib)
        print(d, len(lib))
PY
}

if [ "${1:-}" = --worker-digests ]; then
  w=${2:?usage: build-metal-aot.sh --worker-digests <worker binary>}
  py_extract "$w" -
  exit 0
fi

worker=${1:?usage: build-metal-aot.sh <worker binary> <out dir> [arch ...]}
out=${2:?usage: build-metal-aot.sh <worker binary> <out dir> [arch ...]}
shift 2
[ -x "$worker" ] || { echo "build-metal-aot: $worker is not an executable" >&2; exit 1; }
worker=$(cd "$(dirname "$worker")" && pwd)/$(basename "$worker")
arches=("$@")
if [ ${#arches[@]} = 0 ]; then
  a=$("$worker" --metal-arch 2>/dev/null) || { echo "build-metal-aot: $worker --metal-arch failed" >&2; exit 1; }
  arches=("$a")
fi
RISC0_DIR=${RISC0_DIR:-$(cd "$repo/.." && pwd)/deps/risc0-3.1}
AOT_DUMP_TARGET=${AOT_DUMP_TARGET:-$repo/target/aot-dump}
AOT_JOBS=${AOT_JOBS:-3}
AOT_MACOS_MIN=${AOT_MACOS_MIN:-$(sw_vers -productVersion | cut -d. -f1).0}
worker_sha=$(shasum -a 256 "$worker" | cut -d' ' -f1)
stamp="worker_sha256=$worker_sha arches=${arches[*]} macos_min=$AOT_MACOS_MIN"
if [ -f "$out/WORKER" ] && [ "$(cat "$out/WORKER")" = "$stamp" ] && [ -f "$out/SHA256SUMS" ]; then
  echo "build-metal-aot: $out is already the set of this worker (${arches[*]}): reused"
  exit 0
fi
tools="$RISC0_DIR/tools/metal_aot"
[ -f "$tools/build_archive.py" ] || { echo "build-metal-aot: no $tools/build_archive.py (RISC0_DIR=$RISC0_DIR)" >&2; exit 1; }
command -v metal-tt >/dev/null || [ -x "${METAL_TC:-/nonexistent}/usr/bin/metal-tt" ] \
  || { echo "build-metal-aot: metal-tt not found (source env.sh: the Metal toolchain)" >&2; exit 1; }


t0=$(date +%s)
work=$(mktemp -d "${TMPDIR:-/tmp}/metal-aot-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/libs" "$work/out"
echo "build-metal-aot: metallibs embedded in $worker:"
py_extract "$worker" "$work/libs" | sed 's/^/  /'
digests=$(ls "$work/libs" | sed 's/\.metallib$//' | sort | tr '\n' ' ')

# Kernel names per unit: the dump tests, cached per set of worker digests.
key=$(echo "$digests" | shasum -a 256 | cut -c1-16)
dump="$AOT_DUMP_TARGET/dump-$key"
if [ ! -f "$dump/units.jsonl" ]; then
  echo "build-metal-aot: building risc0's dump tests (CARGO_TARGET_DIR=$AOT_DUMP_TARGET; once per risc0 kernel set)"
  rm -rf "$dump.tmp"; mkdir -p "$dump.tmp"
  locked=; [ -f "$RISC0_DIR/Cargo.lock" ] && locked=--locked
  for spec in risc0-zkp:hal::metal::tests_z16::w7z1_dump_aot_inputs \
              risc0-circuit-rv32im:prove::hal::metal::eval_check::ef_tests::w7z1_dump_aot_inputs \
              risc0-circuit-keccak:prove::hal::metal::archive::tests::w7z1_dump_aot_inputs \
              risc0-groth16-sys:metal::pipelines::tests::w7z1_dump_aot_inputs; do
    pkg=${spec%%:*}; test=${spec#*:}
    exe=$(cd "$RISC0_DIR" && CARGO_TARGET_DIR="$AOT_DUMP_TARGET" cargo test $locked -p "$pkg" --features metal --lib \
          --no-run --message-format=json 2>"$work/cargo-$pkg.log" \
          | python3 -I -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["kind"] == ["lib"]:
        print(m["executable"])' | tail -1) || true
    [ -n "$exe" ] || { echo "build-metal-aot: building the $pkg lib tests failed:" >&2; tail -20 "$work/cargo-$pkg.log" >&2; exit 1; }
    W7Z1_DUMP="$dump.tmp" "$exe" --ignored --exact "$test" -q >"$work/dump-$pkg.log" 2>&1 \
      || { echo "build-metal-aot: $pkg $test failed:" >&2; tail -20 "$work/dump-$pkg.log" >&2; exit 1; }
  done
  rm -rf "$dump"; mv "$dump.tmp" "$dump"
  # The test build (~5 GB) is only needed again after a risc0 kernel change; keep just the dump
  # unless AOT_KEEP_DUMP_BUILD=1 (a later rebuild then reuses it).
  if [ "${AOT_KEEP_DUMP_BUILD:-0}" != 1 ]; then
    for d in debug release riscv-guest tmp .rustc_info.json .future-incompat-report.json CACHEDIR.TAG; do rm -rf "${AOT_DUMP_TARGET:?}/$d"; done
  fi
fi

# Every dumped metallib must be one the worker embeds; build from the worker's bytes.
python3 -I - "$dump" "$work/libs" "$work/units.jsonl" "$RISC0_DIR/risc0/circuit/recursion-sys/src/lib.rs" "$tools" <<'PY'
import hashlib, json, os, re, struct, subprocess, sys
dump, libs, out, rec_lib_rs, tools = sys.argv[1:]
CHUNK = 1 << 20
def digest(b):
    h = hashlib.sha256(struct.pack('<Q', len(b)))
    for i in range(0, len(b), CHUNK):
        h.update(hashlib.sha256(b[i:i + CHUNK]).digest())
    return h.hexdigest()[:24]
worker = {f[:-len('.metallib')] for f in os.listdir(libs) if f.endswith('.metallib')}
units, used, bad = [], set(), []
for line in open(os.path.join(dump, 'units.jsonl')):
    if not line.strip():
        continue
    u = json.loads(line)
    d = digest(open(os.path.join(dump, u['metallib']), 'rb').read())
    if d not in worker:
        bad.append(f"{u['unit']} ({u['metallib']} digest {d})")
        continue
    used.add(d)
    if u['unit'] == 'keccakstrict':
        continue
    u['metallib'] = os.path.join(libs, d + '.metallib')
    units.append(u)
if bad:
    sys.exit('build-metal-aot: the dump tests of this risc0 tree built metallibs the worker does not embed: '
             + ', '.join(bad) + ' -- RISC0_DIR is not the tree the worker was built from (rebuild the worker, '
             'or point RISC0_DIR at its tree); nothing built')
# recursion: the remaining metallib whose functions are the recursion kernels.
src = open(rec_lib_rs).read()
body = src.split('pub const METAL_KERNEL_NAMES: &[&str] = &[', 1)[1].split('];', 1)[0]
body = '\n'.join(l.split('//', 1)[0] for l in body.splitlines())
names = re.findall(r'"([A-Za-z0-9_]+)"', body)
rec = None
for d in sorted(worker - used):
    path = os.path.join(libs, d + '.metallib')
    listed = subprocess.run([sys.executable, '-I', os.path.join(tools, 'metallib_extract.py'), '--list', path],
                            capture_output=True, text=True).stdout.split()
    if names and all(n in listed for n in names):
        rec = path
if rec is None:
    sys.exit('build-metal-aot: no embedded metallib holds the recursion kernels of ' + rec_lib_rs)
is_eval = lambda n: n == 'eval_check' or n.startswith('ec_')
units.append({'unit': 'recursion', 'metallib': rec, 'names': [n for n in names if not is_eval(n)], 'fc': None})
units.append({'unit': 'recursion_splitrg', 'metallib': rec, 'names': [n for n in names if n.startswith('ec_rg_part_')], 'fc': None})
with open(out, 'w') as f:
    for u in units:
        f.write(json.dumps(u) + '\n')
print('build-metal-aot: units ' + ', '.join(u['unit'] for u in units))
PY

echo "build-metal-aot: building ${arches[*]} (macOS $AOT_MACOS_MIN, $AOT_JOBS units at once)"
archargs=(); for a in "${arches[@]}"; do archargs+=(--arch "$a"); done
python3 -I - "$work/units.jsonl" "$tools/build_archive.py" "$work/out" "$AOT_MACOS_MIN" "$AOT_JOBS" "${archargs[@]}" <<'PY'
import concurrent.futures, json, os, subprocess, sys, time
units_file, build, out, macos_min, jobs = sys.argv[1:6]
archs = sys.argv[6:]
units = [json.loads(l) for l in open(units_file) if l.strip()]
# Largest first, so the long rv32im / keccak builds start at once.
units.sort(key=lambda u: -os.path.getsize(u['metallib']) * len(u['names']))
def one(u):
    t = time.time()
    cmd = [sys.executable, '-I', build, '--metallib', u['metallib'], '--unit', u['unit'], '--names', ','.join(u['names']),
           '--out', out, '--macos-min', macos_min, '--manifest', os.path.join(out, f".manifest.{u['unit']}")] + archs
    if u.get('fc'):
        cmd += ['--fc', u['fc']]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return u['unit'], r.returncode, time.time() - t, (r.stdout + r.stderr)[-1500:]
failed = []
with concurrent.futures.ThreadPoolExecutor(int(jobs)) as ex:
    for unit, rc, secs, log in ex.map(one, units):
        print(f"  {unit}: {'ok' if rc == 0 else 'FAILED'} in {secs:.0f} s", flush=True)
        if rc:
            print(log, file=sys.stderr); failed.append(unit)
with open(os.path.join(out, 'manifest.jsonl'), 'w') as m:
    for f in sorted(os.listdir(out)):
        if f.startswith('.manifest.'):
            m.write(open(os.path.join(out, f)).read()); os.remove(os.path.join(out, f))
if failed:
    sys.exit('build-metal-aot: failed units: ' + ', '.join(failed))
PY
(cd "$work/out" && shasum -a 256 *.binarchive > SHA256SUMS)
echo "$stamp" > "$work/out/WORKER"
mkdir -p "$(dirname "$out")"
rm -rf "$out.old"; [ -e "$out" ] && mv "$out" "$out.old"
mv "$work/out" "$out"; rm -rf "$out.old"
n=$(ls "$out" | grep -c '\.binarchive$')
echo "build-metal-aot: $n archives, $(du -sk "$out" | cut -f1 | awk '{printf "%d MiB", $1/1024}') in $out ($(( $(date +%s) - t0 )) s)"
