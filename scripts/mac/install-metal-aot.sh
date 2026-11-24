#!/bin/bash
# Install risc0 W7-Z1's offline (AOT) Metal binary archives beside the installed Metal worker
# (W7-M11), so its first start on this Mac loads its GPU pipelines instead of compiling them
# (65-85 s on a cold OS shader cache). The worker finds them itself: when <worker dir>/metal-aot
# holds archives it sets RISC0_METAL_AOT_DIR to it (ZKMINER_METAL_AOT=0 turns that off).
#
# usage: install-metal-aot.sh <archive set dir> <installed worker> [validated arch ...]
#
#   <archive set dir>  the output of risc0's tools/metal_aot/build_all.py: *.binarchive files,
#                      manifest.jsonl and SHA256SUMS (risc0 tools/metal_aot/README.md)
#   <installed worker> e.g. ~/.zkminer/provers/zkminer-prove-risc0-metal; asked for this Mac's GPU
#                      architecture (--metal-arch), and the archives go to its directory/metal-aot
#   validated arch     the GPU families whose archives were validated on hardware (README); a Mac
#                      of any other family keeps compiling at first start. Default: applegpu_g17s.
#
# Only this Mac's architecture is copied (~170 MB of the 1.7 GB set). Every file is checked against
# SHA256SUMS, and its metallib digest against the worker's embedded metallibs (P31-M9b; a set built
# for another worker is refused). The new set replaces the old one in one rename, so a running worker never sees a
# half-copied directory. Exit 0 also when nothing is installed (another arch, no archives); a
# previous install's set is then removed, since it was built for another worker.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=${1:?usage: install-metal-aot.sh <archive set dir> <installed worker> [validated arch ...]}
worker=${2:?usage: install-metal-aot.sh <archive set dir> <installed worker> [validated arch ...]}
shift 2
validated=("$@")
[ ${#validated[@]} -gt 0 ] || validated=(applegpu_g17s)

[ -d "$src" ] || { echo "install-metal-aot: $src is not a directory" >&2; exit 1; }
[ -f "$src/SHA256SUMS" ] || { echo "install-metal-aot: $src/SHA256SUMS missing" >&2; exit 1; }
[ -x "$worker" ] || { echo "install-metal-aot: $worker is not an executable" >&2; exit 1; }

arch=$("$worker" --metal-arch 2>/dev/null) || { echo "install-metal-aot: $worker --metal-arch failed" >&2; exit 1; }
case "$arch" in applegpu_*) ;; *) echo "install-metal-aot: unexpected architecture '$arch'" >&2; exit 1;; esac
dest_dir=$(cd "$(dirname "$worker")" && pwd)
dest="$dest_dir/metal-aot"

# Nothing to install: drop a previous install's set (built for another worker), then exit 0.
remove_stale() {
  if [ -e "$dest" ]; then
    rm -rf "$dest"
    echo "install-metal-aot: removed the previous install's $dest"
  fi
}

ok=0
for a in "${validated[@]}"; do [ "$a" = "$arch" ] && ok=1; done
if [ $ok = 0 ]; then
  echo "install-metal-aot: this Mac is $arch; archives are validated only for ${validated[*]}: none installed (the first start compiles its pipelines)"
  remove_stale
  exit 0
fi

files=()
while IFS= read -r f; do files+=("$f"); done < <(cd "$src" && ls -1 | grep -E -- "-${arch}-.*\.binarchive$" || true)
if [ ${#files[@]} = 0 ]; then
  echo "install-metal-aot: $src has no archives for $arch: none installed"
  remove_stale
  exit 0
fi

# P31-M9b: every archive must be of a metallib this worker embeds (the digest field of its name,
# `<unit>-<digest24>-<arch>-...`). A set built for another worker (any risc0 kernel change) is refused:
# its files would only be clean misses, so installing it would hide that the first start compiles.
# AOT_SKIP_DIGEST_CHECK=1 skips this (tests with a fake worker).
if [ "${AOT_SKIP_DIGEST_CHECK:-0}" != 1 ]; then
  digests=$("$here/build-metal-aot.sh" --worker-digests "$worker") \
    || { echo "install-metal-aot: cannot read the metallib digests of $worker" >&2; exit 1; }
  stale=()
  for f in "${files[@]}"; do
    d=$(echo "$f" | cut -d- -f2)
    grep -qx "$d" <<<"$digests" || stale+=("$f")
  done
  if [ ${#stale[@]} -gt 0 ]; then
    echo "install-metal-aot: refused: ${#stale[@]} of ${#files[@]} archives in $src were built for metallibs $worker does not embed (digest mismatch; first: ${stale[0]}); rebuild the set for this worker (make -f Makefile.mac mac-build-aot)" >&2
    exit 1
  fi
fi

tmp="$dest_dir/.metal-aot.tmp.$$"
rm -rf "$tmp"; mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
bytes=0
for f in "${files[@]}"; do
  cp "$src/$f" "$tmp/$f"
  # Exact name match on the file-name field ("<sha256>  <name>"), not a substring: "x.binarchive"
  # must not also select a line for "x.binarchive.old".
  awk -v f="$f" 'substr($0, index($0, "  ") + 2) == f' "$src/SHA256SUMS" > "$tmp/.sum"
  [ "$(wc -l < "$tmp/.sum" | tr -d ' ')" = 1 ] || { echo "install-metal-aot: $f is not in SHA256SUMS exactly once" >&2; exit 1; }
  (cd "$tmp" && shasum -a 256 -c .sum >/dev/null) || { echo "install-metal-aot: checksum mismatch for $f" >&2; exit 1; }
  cat "$tmp/.sum" >> "$tmp/SHA256SUMS"
  bytes=$((bytes + $(stat -f %z "$tmp/$f")))
done
rm -f "$tmp/.sum"
[ -f "$src/manifest.jsonl" ] && grep -F "\"arch\": \"$arch\"" "$src/manifest.jsonl" > "$tmp/manifest.jsonl" || true

old="$dest_dir/.metal-aot.old.$$"
[ -e "$dest" ] && mv "$dest" "$old"
mv "$tmp" "$dest"
trap - EXIT
rm -rf "$old"
echo "install-metal-aot: installed ${#files[@]} archives for $arch ($((bytes >> 20)) MiB) into $dest"
