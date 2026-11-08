#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build distro packages in clean containers (rootless podman), running the test
# suite as part of each build:
#
#   tools/build-packages.sh               # fedora, debian and arch
#   tools/build-packages.sh fedora        # just one
#
# Packages end up in dist/packages/<distro>/.
set -euo pipefail
cd "$(dirname "$0")/.."

FEDORA_IMAGE=registry.fedoraproject.org/fedora:44
DEBIAN_IMAGE=docker.io/library/debian:trixie
ARCH_IMAGE=docker.io/library/archlinux:latest

version=$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
tarball=siemstress-$version.tar.gz

rm -f dist/siemstress-*.tar.gz
.venv/bin/python -m build --sdist --outdir dist >/dev/null
echo "source: dist/$tarball"

in_container() {  # image, distro, script
  rm -rf "dist/packages/$2" && mkdir -p "dist/packages/$2"
  podman run --rm -v "$PWD/dist:/dist:Z" -e VERSION="$version" "$1" bash -euo pipefail -c "$3"
  echo "$2: $(cd "dist/packages/$2" && ls | tr '\n' ' ')"
}

build_fedora() {
  in_container "$FEDORA_IMAGE" fedora '
    dnf -y -q install rpm-build python3-devel pyproject-rpm-macros systemd-rpm-macros \
        python3-pytest python3-hatchling openssl >/dev/null
    mkdir -p ~/rpmbuild/SOURCES
    cp /dist/siemstress-$VERSION.tar.gz ~/rpmbuild/SOURCES/
    tar -xzf ~/rpmbuild/SOURCES/siemstress-$VERSION.tar.gz -O \
        siemstress-$VERSION/packaging/fedora/siemstress.spec > /tmp/siemstress.spec
    rpmbuild -ba /tmp/siemstress.spec >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
    cp ~/rpmbuild/RPMS/noarch/*.rpm ~/rpmbuild/SRPMS/*.rpm /dist/packages/fedora/'
}

build_debian() {
  in_container "$DEBIAN_IMAGE" debian '
    apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
        build-essential debhelper dh-python pybuild-plugin-pyproject python3-all \
        python3-hatchling python3-pytest openssl >/dev/null
    mkdir /build && cd /build
    cp /dist/siemstress-$VERSION.tar.gz siemstress_$VERSION.orig.tar.gz
    tar -xzf siemstress_$VERSION.orig.tar.gz && cd siemstress-$VERSION
    cp -r packaging/debian debian
    dpkg-buildpackage -us -uc -b >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
    cp ../*.deb /dist/packages/debian/'
}

build_arch() {
  in_container "$ARCH_IMAGE" arch '
    pacman -Syu --noconfirm --needed base-devel python-build python-installer \
        python-hatchling python-pytest openssl >/dev/null
    useradd -m builder
    install -d -o builder /build
    cp /dist/siemstress-$VERSION.tar.gz /build/
    tar -xzf /build/siemstress-$VERSION.tar.gz -O siemstress-$VERSION/packaging/arch/PKGBUILD \
        > /build/PKGBUILD
    chown -R builder /build
    su builder -c "cd /build && makepkg --noconfirm >/tmp/build.log 2>&1" \
        || { tail -40 /tmp/build.log; exit 1; }
    cp /build/*.pkg.tar.zst /dist/packages/arch/'
}

for distro in ${@:-fedora debian arch}; do
  "build_$distro"
done
