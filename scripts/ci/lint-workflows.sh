#!/usr/bin/env bash
# Lints every GitHub Actions workflow with actionlint, with this repository's self-hosted runner
# labels (actionlint.yaml). When ShellCheck is on PATH, actionlint also checks the run: scripts:
#
#   lint-workflows.sh [actionlint binary]
#
# actionlint: the official release binary (https://github.com/rhysd/actionlint/releases; B9-CI used
# 1.7.12, checked against the release's checksums file).
# Then test-workflow-expressions.py evaluates build-macos.yml's expressions per event (actionlint
# checks their syntax and types, not what they evaluate to).
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$ci/../.." && pwd)
al=${1:-$(command -v actionlint || true)}
[ -n "$al" ] && [ -x "$al" ] || { echo "lint-workflows: no actionlint (pass its path)" >&2; exit 2; }
"$al" -version | head -1
command -v shellcheck > /dev/null && echo "shellcheck $(shellcheck --version | sed -n 's/^version: //p')" || echo "no shellcheck on PATH: run: scripts are not checked"
cd "$repo"
"$al" -color=false -config-file "$ci/actionlint.yaml" .github/workflows/*.yml
python3 -I "$ci/test-workflow-expressions.py"
echo "lint-workflows: ok"
