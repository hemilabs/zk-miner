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
for image in "${images[@]}"; do
  echo "== $image"
  docker run --rm --network none -v "$root:/z:ro" -v "$ci:/ci:ro" "$image" \
    bash /ci/check-release-libs-inside.sh /z/provers || fail=1
done
exit $fail
