# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Where configuration and data live, for system-wide and per-user installs.

A packaged install runs the collector as a system service with its config in
/etc/siemstress and its database in /var/lib/siemstress. A per-user install (pip,
or running from a checkout) keeps both under the user's XDG directories. Commands
pick whichever exists, preferring the user's own; SIEMSTRESS_CONFIG and
SIEMSTRESS_DB override both.
"""

import os
from pathlib import Path

SYSTEM_CONFIG = Path("/etc/siemstress/config.toml")
SYSTEM_DB = Path("/var/lib/siemstress/events.db")

CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
DATA_HOME = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
USER_CONFIG = CONFIG_HOME / "siemstress" / "config.toml"
USER_DB = DATA_HOME / "siemstress" / "events.db"


def default_config() -> Path:
    if env := os.environ.get("SIEMSTRESS_CONFIG"):
        return Path(env)
    if USER_CONFIG.exists() or not SYSTEM_CONFIG.exists():
        return USER_CONFIG
    return SYSTEM_CONFIG


def default_db() -> Path:
    if env := os.environ.get("SIEMSTRESS_DB"):
        return Path(env)
    if USER_DB.exists():
        return USER_DB
    # A system install: its database may not exist yet, or be unreadable to users
    # outside the siemstress group, which `siemstress doctor` explains.
    if SYSTEM_DB.parent.exists() or SYSTEM_CONFIG.exists():
        return SYSTEM_DB
    return USER_DB
