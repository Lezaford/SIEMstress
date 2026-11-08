# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Who and where: this machine's stable name, and uid-to-username lookups."""

import pwd
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

HOSTNAME_FILE = Path("/etc/hostname")
MACHINE_ID_FILE = Path("/etc/machine-id")
OS_RELEASE_FILE = Path("/etc/os-release")


@dataclass(frozen=True, slots=True)
class LocalHost:
    name: str
    machine_id: str | None
    # True when no name was configured or set as the static hostname, so `name`
    # is a distro default ("fedora") that other machines may share.
    generic: bool = False


def _read_first_line(path: Path) -> str | None:
    try:
        line = path.read_text().strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return None
    return line or None


def _default_hostname() -> str:
    try:
        for line in OS_RELEASE_FILE.read_text().splitlines():
            key, _, value = line.partition("=")
            if key == "DEFAULT_HOSTNAME":
                return value.strip("\"'") or "localhost"
    except OSError:
        pass
    return "localhost"


def local_host(configured_name: str | None = None) -> LocalHost:
    """This machine's identity.

    The name deliberately ignores the transient (DHCP or reverse-DNS) hostname,
    which can change while the machine runs and would split one host into several.
    """
    machine_id = _read_first_line(MACHINE_ID_FILE)
    if name := configured_name or _read_first_line(HOSTNAME_FILE):
        return LocalHost(name, machine_id)
    return LocalHost(_default_hostname(), machine_id, generic=True)


def is_person(uid: int | str) -> bool:
    """root or a regular login account (UID_MIN..UID_MAX in login.defs), not a service."""
    try:
        uid = int(uid)
    except ValueError:
        return False
    return uid == 0 or 1000 <= uid < 60000


@lru_cache(maxsize=512)
def username(uid: int | str) -> str:
    """Name for a uid on this machine, or the number itself if it has no account."""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)
