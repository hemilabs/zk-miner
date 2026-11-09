#!/usr/bin/env bash
# One-time setup, as root, of the self-hosted runner that checks zkminer's release binaries on real
# GPUs: the `validate` job in .github/workflows/release.yml.
#
#   sudo scripts/ci/setup-gpu-runner.sh
#
# Each step is skipped when it is already done, so the script can be run again.
#
# 1. Installs rootless Podman (podman, crun, uidmap, passt). The validation runs the release in stock
#    distribution images (Ubuntu 22.04 and 24.04, Fedora), passing in only the GPU device nodes and
#    the NVIDIA driver's own libraries. That is what shows a host needs nothing but its GPU driver:
#    no CUDA toolkit, ROCm or oneAPI install.
# 2. Creates the user the jobs run as, `zkminer-ci` (CI_USER), in the `render` and `video` groups
#    (for /dev/kfd and /dev/dri), with subordinate IDs for its containers and lingering on, so they
#    run without a login. Never your own account: the repository is public, a job runs whatever its
#    workflow says, and your home holds keys. Its memory is capped (CI_MEMORY_MAX, default 80G), so
#    a runaway job cannot take the host down.
# 3. Downloads the GitHub Actions runner (the version and SHA-256 pinned below), registers it with
#    hemilabs/zk-miner under the single label `zkminer-gpu`, without the default `self-hosted` labels,
#    and starts it as a systemd user service of that user.
#
# The registration token is RUNNER_TOKEN if set, or else asked of `gh` as the user who ran sudo,
# who must be an admin of the repository.
set -euo pipefail

REPO=hemilabs/zk-miner
CI_USER=${CI_USER:-zkminer-ci}
LABEL=zkminer-gpu
NAME=${RUNNER_NAME:-$LABEL-$(hostname -s)}
MEMORY_MAX=${CI_MEMORY_MAX:-80G}
# https://github.com/actions/runner/releases/tag/v2.338.2
RUNNER_VERSION=2.338.2
RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40

[ "$(id -u)" = 0 ] || { echo "run this as root: sudo $0" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

step "1. rootless Podman"
DEBIAN_FRONTEND=noninteractive apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q podman crun uidmap passt curl ca-certificates
podman --version

step "2. the CI user, $CI_USER"
if ! id "$CI_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --comment "zkminer GPU CI runner" "$CI_USER"
fi
usermod -aG render,video "$CI_USER"
chmod 0750 "/home/$CI_USER"
# Subordinate IDs for rootless containers. useradd normally allocates them; a user made earlier
# may have none.
for f in /etc/subuid /etc/subgid; do
  if ! grep -q "^$CI_USER:" "$f"; then
    start=$(awk -F: '{ e = $2 + $3; if (e > m) m = e } END { print (m > 100000 ? m : 100000) }' "$f")
    flag=--add-subuids; [ "$f" = /etc/subgid ] && flag=--add-subgids
    usermod "$flag" "$start-$((start + 65535))" "$CI_USER"
  fi
done
uid=$(id -u "$CI_USER")
install -d -m 0755 "/etc/systemd/system/user-$uid.slice.d"
cat > "/etc/systemd/system/user-$uid.slice.d/50-zkminer-ci-memory.conf" <<EOF
# Written by zkminer's scripts/ci/setup-gpu-runner.sh: everything $CI_USER runs, its containers
# included, shares this cap, so a runaway job is killed instead of freezing the host.
[Slice]
MemoryMax=$MEMORY_MAX
MemorySwapMax=0
EOF
systemctl daemon-reload
loginctl enable-linger "$CI_USER"
for _ in $(seq 30); do [ -S "/run/user/$uid/bus" ] && break; sleep 1; done
[ -S "/run/user/$uid/bus" ] || { echo "the user manager of $CI_USER did not start" >&2; exit 1; }
as_ci() {
  sudo -u "$CI_USER" -H env XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$@"
}
id "$CI_USER"

step "3. the Actions runner $RUNNER_VERSION"
dir=/home/$CI_USER/actions-runner
if [ ! -x "$dir/run.sh" ]; then
  tgz=$(mktemp --suffix=.tar.gz)
  curl -fsSL -o "$tgz" \
    "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz"
  echo "$RUNNER_SHA256  $tgz" | sha256sum -c -
  chmod 0644 "$tgz"
  install -d -o "$CI_USER" -g "$CI_USER" -m 0750 "$dir"
  as_ci tar -xzf "$tgz" -C "$dir"
  rm -f "$tgz"
fi
if [ ! -f "$dir/.runner" ]; then
  token=${RUNNER_TOKEN:-}
  if [ -z "$token" ] && [ -n "${SUDO_USER:-}" ]; then
    token=$(sudo -u "$SUDO_USER" -H gh api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token)
  fi
  [ -n "$token" ] || { echo "no registration token: set RUNNER_TOKEN, or log in to gh as a repo admin" >&2; exit 1; }
  as_ci env RUNNER_TOKEN="$token" bash -c "cd '$dir' && ./config.sh --unattended \
    --url 'https://github.com/$REPO' --token \"\$RUNNER_TOKEN\" --name '$NAME' \
    --labels '$LABEL' --no-default-labels --work _work --replace"
fi
units=/home/$CI_USER/.config/systemd/user
as_ci mkdir -p "$units"
cat > "$units/zkminer-gpu-runner.service" <<EOF
[Unit]
Description=GitHub Actions runner for $REPO ($LABEL)
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=$dir
ExecStart=$dir/run.sh
Restart=always
RestartSec=10
# Let a running job finish its step on stop rather than being killed mid-proof.
KillMode=process
TimeoutStopSec=5min

[Install]
WantedBy=default.target
EOF
chown "$CI_USER:$CI_USER" "$units/zkminer-gpu-runner.service"
as_ci systemctl --user daemon-reload
as_ci systemctl --user enable --now zkminer-gpu-runner.service

step "check: rootless Podman reaches the GPUs as $CI_USER"
as_ci podman info --format 'runtime {{.Host.OCIRuntime.Name}}, rootless {{.Host.Security.Rootless}}'
devices=(--device /dev/kfd --device /dev/dri)
for d in /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia[0-9]*; do [ -e "$d" ] && devices+=(--device "$d"); done
as_ci podman run --rm --group-add keep-groups "${devices[@]}" docker.io/library/ubuntu:22.04 \
  sh -c 'test -r /dev/kfd && test -w /dev/kfd && ls /dev/dri && ls /dev | grep -c "^nvidia"' \
  && echo "ok: /dev/kfd, /dev/dri and the NVIDIA nodes are usable inside a container"
sleep 3
as_ci systemctl --user --no-pager status zkminer-gpu-runner.service | head -5
echo
echo "Done. The runner shows as '$NAME' (label $LABEL) under"
echo "https://github.com/$REPO/settings/actions/runners"
