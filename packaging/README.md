# Packaging

Distro packages are built and tested in clean containers with rootless podman:

```sh
tools/build-packages.sh          # dist/packages/{fedora,debian,arch}/, test suite runs in each build
tools/test-packages.sh           # install on a fresh systemd system and check end to end
```

`test-packages.sh` boots each distro with systemd, enables the service, raises an alert
through the syslog listener and one from the journal, then as an ordinary member of the
`siemstress` group lists and acknowledges alerts and runs `siemstress doctor`. It
finishes with the service's `systemd-analyze security` score.

Every distro ships three packages: `siemstress` (collector, CLI, service), and the
optional `siemstress-gui` (Qt) and `siemstress-tui` (Textual) dashboards, so headless
servers don't pull in a GUI toolkit.

## What a package installs

| Path | Purpose |
|---|---|
| `/usr/bin/siemstress` | the command |
| `/usr/lib/systemd/system/siemstress.service` | hardened system service |
| `/usr/lib/sysusers.d/siemstress.conf` | `siemstress` user and group; journal and `adm` access |
| `/usr/lib/tmpfiles.d/siemstress.conf` | `/etc/siemstress` readable by root and the group only |
| `/etc/siemstress/config.toml` | configuration (kept on upgrade) |
| `/etc/siemstress/rules/` | local rules |
| `/var/lib/siemstress/` | database, created by systemd (`StateDirectory`), mode 2770 |
| `/usr/share/man/man1/siemstress.1` | man page |
| `/usr/share/applications`, `/usr/share/icons/hicolor` | desktop entry and icons (gui package) |

After installing:

```sh
sudo systemctl enable --now siemstress
sudo usermod -aG siemstress $USER    # to use the dashboards; log out and back in
siemstress doctor
```

## Publishing

All three need a public home for the release tarball first. Replace
`https://github.com/Lezaford/siemstress` in `fedora/siemstress.spec`,
`arch/PKGBUILD` and `debian/{control,copyright}` with the real URL, tag a release
and attach `dist/siemstress-<version>.tar.gz` to it.

### Fedora, RHEL-likes: COPR

```sh
copr-cli create siemstress --chroot fedora-44-x86_64 --chroot fedora-rawhide-x86_64
copr-cli build siemstress dist/packages/fedora/siemstress-*.src.rpm
```

Users: `sudo dnf copr enable <you>/siemstress && sudo dnf install siemstress siemstress-gui`.

### Arch: AUR

Point `source=()` in the PKGBUILD at the release tarball, then:

```sh
updpkgsums                              # fill in sha256sums
makepkg --printsrcinfo > .SRCINFO
git clone ssh://aur@aur.archlinux.org/siemstress.git   # then add both files, commit, push
```

Users: `yay -S siemstress siemstress-gui` (or any AUR helper).

### Debian, Ubuntu

Two common routes:

- **Launchpad PPA** (Ubuntu): build a signed source package
  (`dpkg-buildpackage -S -sa` with `debian/` copied in) and upload it with `dput`.
- **openSUSE Build Service** (OBS): one project can build Debian, Ubuntu, Fedora and
  openSUSE repositories from the same sources, which is the least work for wide
  coverage.

## Versions and changelogs

Bump the version in `pyproject.toml`, `src/siemstress/__init__.py`,
`fedora/siemstress.spec`, `arch/PKGBUILD` and `packaging/siemstress.1`, and add an
entry to the spec's `%changelog` and `debian/changelog` (`dch -v <version>-1`).
