#!/usr/bin/env bash
# Assemble one vendor's Windows zip from build-windows.yml's parts, in the layout the miner runs
# from: zkminer.exe with the workers beside it (each worker's DLLs beside it too), and the SP1
# server the SP1 worker installs, with sp1gnark.dll and `<server>-lib/`, beside that.
#
# Usage: package.sh <nvidia|amd|intel> <parts dir> <out dir>
set -euo pipefail
vendor=$1 parts=$2 out=$3

case "$vendor" in
  nvidia) server=sp1-gpu-server ;;
  amd)    server=sp1-gpu-server-hip ;;
  intel)  server=sp1-gpu-server-sycl ;;
  *) echo "unknown vendor $vendor" >&2; exit 2 ;;
esac

# A vendor whose builds this run skipped or lost gets no zip, rather than one without workers.
for part in "part-cli" "part-sp1-worker" "part-risc0-$vendor" "part-sp1-server-$vendor"; do
  if [ ! -d "$parts/$part" ]; then
    echo "::warning title=$vendor package::$part is missing; no $vendor zip"
    exit 0
  fi
done

name="zkminer-windows-$vendor-x86_64"
dir="$out/$name"
mkdir -p "$dir/LICENSES"

# Copy a part's files into the package. A file two parts both ship (the MSVC runtime) must be the
# same file in each.
merge() {
  local from=$1
  (cd "$from" && find . -type f) | while read -r f; do
    local to="$dir/${f#./}"
    if [ -e "$to" ]; then
      cmp -s "$from/$f" "$to" || { echo "$f differs between parts" >&2; exit 1; }
    else
      mkdir -p "$(dirname "$to")"
      cp "$from/$f" "$to"
    fi
  done
}

cp "$parts/part-cli/zkminer.exe" "$dir/"
merge "$parts/part-risc0-$vendor"
merge "$parts/part-sp1-worker"
merge "$parts/part-sp1-server-$vendor"
cp LICENSE "$dir/LICENSES/zkminer-LICENSE"

test -f "$dir/$server.exe"
test -f "$dir/zkminer-prove-sp1.exe"
ls "$dir"/zkminer-prove-risc0-*.exe > /dev/null

(cd "$dir" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS && cat SHA256SUMS)
(cd "$out" && zip -qr "$name.zip" "$name")
ls -l "$out/$name.zip"
