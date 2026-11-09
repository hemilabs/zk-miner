# shellcheck shell=bash
# Shared by build-intel-igc.sh and build-intel-gpu-runtime.sh, which build Intel's GPU compute stack
# from source for the release's Intel workers, in two Dockerfile stages (intel-igc,
# intel-gpu-runtime) so that the long one, IGC with LLVM, stays in the build cache while the other
# changes. Sourced, with the install prefix as $1.
#
# Built here because Intel's own packages of these versions need glibc 2.38 (Ubuntu 24.04), and the
# release runs on glibc 2.35 (Ubuntu 22.04). The versions are the ones zkminer's Intel workers were
# validated with on an Arc B580: compute runtime 26.05.37020.3 with IGC 2.28.4 (the pair Intel
# released together) and Level Zero loader 1.32.0. Each source is pinned to a commit, checked after
# the fetch. Licenses go to PREFIX/share/licenses/<project>/.

prefix=${1:?usage: $0 <prefix>}
src=${SRC_DIR:-/tmp/intel-gpu-src}
jobs=${JOBS:-$(nproc)}
mkdir -p "$src" "$prefix"
# opencl-clang applies its clang and SPIR-V translator patches with `git am`, which needs an
# identity, and ignores its failure: without one, every patch is skipped and the build goes on.
export GIT_AUTHOR_NAME=zkminer-build GIT_AUTHOR_EMAIL=build@zkminer.invalid
export GIT_COMMITTER_NAME=zkminer-build GIT_COMMITTER_EMAIL=build@zkminer.invalid

# <dir> <repository> <commit> [<tag or branch to fetch shallowly>]
fetch() {
  local dir=$1 repo=$2 commit=$3 ref=${4:-}
  if [ ! -d "$dir/.git" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "https://github.com/$repo"
  fi
  # A tag fetches shallowly by name; a bare commit by its hash (GitHub serves both).
  git -C "$dir" fetch -q --depth 1 origin "${ref:-$commit}"
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
  local got
  got=$(git -C "$dir" rev-parse HEAD)
  [ "$got" = "$commit" ] || { echo "$repo: expected $commit, fetched $got" >&2; exit 1; }
}

cmake_build() { # <source dir> <build dir> [cmake args...]
  local s=$1 b=$2
  shift 2
  cmake -S "$s" -B "$b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib "$@"
  cmake --build "$b" -j "$jobs"
  cmake --install "$b"
}

license() { # <project> <files...>
  local p=$1
  shift
  mkdir -p "$prefix/share/licenses/$p"
  cp "$@" "$prefix/share/licenses/$p/"
}

cd "$src"
