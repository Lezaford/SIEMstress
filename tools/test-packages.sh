#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install the built packages on a fresh system with systemd running (rootless podman)
# and check them end to end: the hardened service starts, an alert raised through the
# syslog listener reaches an analyst in the siemstress group, and doctor passes.
#
#   tools/build-packages.sh && tools/test-packages.sh [fedora|debian|arch ...]
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A BASE=(
  [fedora]="registry.fedoraproject.org/fedora:44"
  [debian]="docker.io/library/debian:trixie"
  [arch]="docker.io/library/archlinux:latest"
)
declare -A INSTALL=(
  [fedora]="dnf -y -q install systemd util-linux procps-ng /pkgs/*.noarch.rpm && dnf clean all"
  [debian]="apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y systemd systemd-sysv bsdutils /pkgs/*.deb"
  [arch]="pacman -Syu --noconfirm >/dev/null && pacman -U --noconfirm /pkgs/*.pkg.tar.zst >/dev/null && systemd-machine-id-setup"
)

CHECKS='
set -euo pipefail
until systemctl is-system-running --wait >/dev/null 2>&1 || [ "$(systemctl is-system-running)" = degraded ]; do sleep 1; done
systemctl enable --now siemstress >/dev/null 2>&1
sleep 3
echo "service:     $(systemctl is-active siemstress)"
echo "account:     $(id siemstress)"
echo "config:      $(stat -c "%U:%G %a" /etc/siemstress/config.toml)"
echo "state dir:   $(stat -c "%U:%G %a" /var/lib/siemstress)"
useradd -m -G siemstress analyst
logger -n 127.0.0.1 -P 5514 -T -t sshd "Accepted password for root from 203.0.113.9 port 40100 ssh2"
sleep 4
echo "database:    $(stat -c "%U:%G %a" /var/lib/siemstress/events.db)"
echo "--- analyst: siemstress alerts, then acknowledge one"
runuser -u analyst -- siemstress alerts
runuser -u analyst -- siemstress ack 1
echo "--- analyst: siemstress doctor"
runuser -u analyst -- siemstress doctor || true
echo "--- hardening"
systemd-analyze security siemstress --no-pager | tail -1
if ! systemctl is-active -q siemstress; then journalctl -u siemstress --no-pager | tail -20; exit 1; fi
'

for distro in ${@:-fedora debian arch}; do
  echo "===== $distro"
  image="localhost/siemstress-test-$distro"
  podman build -q -t "$image" -f - "dist/packages/$distro" >/dev/null <<CONTAINERFILE
FROM ${BASE[$distro]}
COPY . /pkgs/
RUN ${INSTALL[$distro]}
CMD ["/sbin/init"]
CONTAINERFILE
  name="siemstress-test-$distro"
  podman rm -f "$name" >/dev/null 2>&1 || true
  podman run -d --name "$name" --systemd=always "$image" >/dev/null
  podman exec "$name" bash -c "$CHECKS"
  podman rm -f "$name" >/dev/null
done
