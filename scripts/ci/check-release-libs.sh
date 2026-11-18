#!/usr/bin/env bash
# Checks, without a GPU, that every binary and library in a release loads on a stock distribution:
#
#   check-release-libs.sh <release dir> [image...]
#
# Unpacks the release as a host installs it (unpack-provers.sh) and, in each image (default: Ubuntu
# 22.04 and 24.04, Fedora), runs ldd on everything, with the library path each is given at run time:
# none for the workers (their RPATH finds what they ship), the shipped directory for the SP1 servers
# (the SP1 worker sets it). The only library allowed to be missing is the NVIDIA driver's libcuda.so.1:
# a host's driver provides it. Anything else missing, or a glibc too old, fails the check. Needs docker.
#
# The macOS kit (zkminer-*-macos-arm64.tar.gz, B9-CI) holds Mach-O programs, which neither ldd nor a
# Linux image can load: check-macos-kit.py reads their load commands instead (arm64 only, only
# /usr/lib and /System/Library libraries, the kit's minimum macOS, a code signature), on this host.
# A release without a macOS kit fails, and so does a Mach-O file anywhere else in the release.
set -euo pipefail
release=$(readlink -f "${1:?usage: $0 <release dir> [image...]}")
shift
images=("$@")
[ ${#images[@]} -gt 0 ] || images=(docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04 \
  registry.fedoraproject.org/fedora:43)
ci=$(dirname "$(readlink -f "$0")")
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
"$ci/unpack-provers.sh" "$release" "$root/provers" >/dev/null

fail=0
echo "== macOS kit (Mach-O)"
shopt -s nullglob
macs=("$release"/zkminer-*-macos-arm64.tar.gz)
shopt -u nullglob
if [ ${#macs[@]} -ne 1 ]; then
  echo "FAIL want one zkminer-<version>-macos-arm64.tar.gz in $release, found ${#macs[@]}"
  fail=1
else
  python3 -I "$ci/check-macos-kit.py" "${macs[0]}" || fail=1
fi
# Nothing else in the release may be a Mach-O file (a macOS binary shipped by mistake as a Linux one).
while IFS= read -r -d '' f; do
  case $(od -An -tx1 -N4 "$f" | tr -d ' \n') in
    cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|bebafeca)
      case $f in "${macs[0]:-}") ;; *) echo "FAIL ${f#"$release"/} is a Mach-O file outside the macOS kit"; fail=1 ;; esac ;;
  esac
done < <(find "$release" -maxdepth 1 -type f -print0)

for image in "${images[@]}"; do
  echo "== $image"
  docker run --rm --network none -v "$root:/z:ro" -v "$ci:/ci:ro" "$image" \
    bash /ci/check-release-libs-inside.sh /z/provers || fail=1
done
exit $fail
