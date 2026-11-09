#!/usr/bin/env bash
# What building hemilabs/sp1's `sp1-gpu-server` needs on top of a Rust image, for any GPU backend
# (Dockerfile.build's sp1-server stages run it as root):
# - libprotobuf-dev: sp1-prover-types' protos import google/protobuf/empty.proto, which Ubuntu ships
#   there (protobuf-compiler only recommends it).
# - CMake 3.30 or later for sp1-gpu-sys (Ubuntu 22.04 has 3.22): Kitware's build, into /usr/local,
#   which comes first on PATH.
# - Go, for gnark's Groth16/PLONK provers, which are linked into the server through cgo. The image sets
#   GOPROXY (see the Dockerfile).
set -euo pipefail

CMAKE_VERSION=3.31.6
CMAKE_SHA256=5a1133ff103c71eb5120e2cc3de922733e7d8a26a98ae716397e8676adb367bf
GO_VERSION=1.24.13
GO_SHA256=1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730

apt-get update
apt-get install -y --no-install-recommends libprotobuf-dev protobuf-compiler curl ca-certificates
rm -rf /var/lib/apt/lists/*

curl -fsSL -o /tmp/cmake.tgz \
  "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz"
echo "${CMAKE_SHA256}  /tmp/cmake.tgz" | sha256sum -c -
tar -C /usr/local --strip-components=1 -xzf /tmp/cmake.tgz
rm /tmp/cmake.tgz
cmake --version | head -n 1

curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c -
tar -C /usr/local -xzf /tmp/go.tgz
rm /tmp/go.tgz
/usr/local/go/bin/go version
