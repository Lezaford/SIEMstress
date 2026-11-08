# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""`siemstress doctor`: check an installation end to end and say how to fix problems."""

import importlib.util
import os
import platform
import shutil
import sqlite3
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siemstress import __version__
from siemstress.config import ConfigError, Settings, load_settings
from siemstress.detect import RuleError, load_rules
from siemstress.paths import SYSTEM_DB
from siemstress.store import MIGRATIONS
from siemstress.timeutil import from_us

OK, WARN, FAIL = "ok", "warn", "fail"
MARKS = {OK: "✔", WARN: "!", FAIL: "✘"}
STALE_AFTER = timedelta(minutes=15)


@dataclass(frozen=True, slots=True)
class Check:
    status: str
    title: str
    detail: str = ""
    fix: str = ""


def _run(*cmd: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def check_config(path: Path) -> tuple[Check, Settings | None]:
    if not path.exists():
        return Check(WARN, "Config", f"{path} not found, using defaults"), Settings()
    try:
        return Check(OK, "Config", str(path)), load_settings(path)
    except ConfigError as exc:
        return Check(FAIL, "Config", str(exc), "fix the setting named above"), None
    except PermissionError:
        return Check(
            FAIL, "Config", f"can't read {path}", "run as root or fix its permissions"
        ), None


def check_rules(config: Path, settings: Settings) -> Check:
    try:
        rules = load_rules(config.parent / "rules", settings.disabled_rules)
    except RuleError as exc:
        return Check(FAIL, "Rules", str(exc), "fix the rule file named above")
    return Check(OK, "Rules", f"{len(rules)} active")


def check_database(path: Path) -> tuple[Check, sqlite3.Connection | None]:
    group_fix = (
        "add yourself to the siemstress group (sudo usermod -aG siemstress $USER), "
        "then log out and back in"
    )
    if not path.exists():
        if (
            path == SYSTEM_DB
            and SYSTEM_DB.parent.exists()
            and not os.access(SYSTEM_DB.parent, os.X_OK)
        ):
            return Check(FAIL, "Database", f"no access to {path.parent}", group_fix), None
        return Check(
            WARN,
            "Database",
            f"{path} doesn't exist yet",
            "start the collector: sudo systemctl enable --now siemstress",
        ), None
    try:
        db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        version = db.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.Error:
        return Check(FAIL, "Database", f"can't open {path}", group_fix), None
    if version != len(MIGRATIONS):
        db.close()  # tables may not match this version; don't query them
        return Check(
            FAIL,
            "Database",
            f"schema v{version}, this version expects v{len(MIGRATIONS)}",
            "restart the collector to upgrade it",
        ), None
    writable = os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
    if not writable:
        return Check(
            WARN,
            "Database",
            f"{path} is read-only for you; you can view alerts but not work them",
            group_fix,
        ), db
    return Check(OK, "Database", str(path)), db


def check_collector(db: sqlite3.Connection | None) -> Iterator[Check]:
    states = {
        scope: _run("systemctl", *flags, "is-active", "siemstress").stdout.strip()
        for scope, flags in (("system", ()), ("user", ("--user",)))
    }
    running = [scope for scope, state in states.items() if state == "active"]
    fresh = None
    if db:
        newest = db.execute("SELECT MAX(received) FROM events").fetchone()[0]
        fresh = newest is not None and datetime.now(UTC) - from_us(newest) <= STALE_AFTER
    if running:
        yield Check(OK, "Collector", f"running as a {' and a '.join(running)} service")
    elif not any(states.values()) and fresh:
        # systemctl couldn't be asked (no D-Bus for this account), but events are flowing.
        yield Check(OK, "Collector", "receiving events (couldn't ask systemd)")
    else:
        yield Check(
            WARN,
            "Collector",
            "no siemstress service is running",
            "sudo systemctl enable --now siemstress",
        )
    if db:
        if newest is None:
            yield Check(WARN, "Events", "none stored yet")
        elif not fresh:
            age = datetime.now(UTC) - from_us(newest)
            yield Check(
                WARN,
                "Events",
                f"newest arrived {int(age.total_seconds() // 60)} minutes ago",
                "check the collector's log: journalctl -u siemstress",
            )
        else:
            yield Check(OK, "Events", "arriving")


def check_journal(settings: Settings, system_install: bool) -> Check:
    if not settings.journal:
        return Check(OK, "Journal", "turned off in config")
    if system_install:
        return Check(OK, "Journal", "read by the siemstress service account")
    if not shutil.which("journalctl"):
        return Check(WARN, "Journal", "journalctl not found; journal source idle")
    # A system-wide message only a journal reader with access can see.
    result = _run("journalctl", "--system", "-n", "1", "-q", "--no-pager", "-o", "cat")
    if result.returncode == 0 and result.stdout.strip():
        return Check(OK, "Journal", "readable")
    return Check(
        WARN,
        "Journal",
        "this account can't read the system journal (the service account can)",
        "only matters for per-user installs: add yourself to the systemd-journal group",
    )


def check_syslog(settings: Settings) -> Iterator[Check]:
    s = settings.syslog
    if s.listen:
        host, port = s.listen
        local = host in ("127.0.0.1", "::1", "localhost")
        who = (
            "this machine"
            if local
            else (
                f"{len(s.senders)} allowlisted sender entries" if s.senders else "this machine only"
            )
        )
        yield Check(OK, "Syslog", f"{host}:{port} ({'udp+tcp' if s.udp else 'tcp'}), from {who}")
        if not local and not s.senders:
            yield Check(
                WARN,
                "Syslog senders",
                "listening on the network but nobody is allowed",
                "add hosts under [syslog.senders]",
            )
    else:
        yield Check(OK, "Syslog", "plain listener off")
    if s.tls:
        from siemstress.sources.syslog import tls_context

        try:
            tls_context(s.tls.cert, s.tls.key, s.tls.ca)
            yield Check(OK, "Syslog TLS", f"{s.tls.listen[0]}:{s.tls.listen[1]}, certificates load")
        except (OSError, ValueError) as exc:
            yield Check(FAIL, "Syslog TLS", str(exc), "check tls_cert, tls_key and tls_ca")


def check_sources(settings: Settings) -> Iterator[Check]:
    if sock := settings.docker_socket:
        if not sock.exists():
            yield Check(OK, "Docker", f"{sock} not present (skipped)")
        elif os.access(sock, os.R_OK | os.W_OK):
            yield Check(OK, "Docker", str(sock))
        else:
            yield Check(
                WARN,
                "Docker",
                f"{sock} exists but this account can't use it",
                "add the collector's account to the docker group",
            )
    for path in settings.log_files:
        if not path.exists():
            yield Check(OK, "Log file", f"{path} not present (skipped)")
        elif not os.access(path, os.R_OK):
            yield Check(WARN, "Log file", f"{path} not readable by this account")
        else:
            yield Check(OK, "Log file", str(path))


def check_extras(settings: Settings) -> Iterator[Check]:
    if settings.ntfy:
        yield Check(OK, "Notifications", f"ntfy topic on {settings.ntfy.server}")
    else:
        yield Check(WARN, "Notifications", "none configured", "add an [ntfy] section to config")
    for name, module, package in (
        ("Desktop app", "PySide6", "siemstress-gui"),
        ("Terminal app", "textual", "siemstress-tui"),
    ):
        if importlib.util.find_spec(module):
            yield Check(OK, name, f"{module} installed")
        else:
            yield Check(WARN, name, f"{module} not installed", f"install {package}")


def run_checks(config: Path, db_path: Path) -> list[Check]:
    checks = [Check(OK, "SIEMstress", f"{__version__} on Python {platform.python_version()}")]
    config_check, settings = check_config(config)
    checks.append(config_check)
    if settings is None:
        return checks
    checks.append(check_rules(config, settings))
    database, db = check_database(db_path)
    checks.append(database)
    checks += check_collector(db)
    checks.append(check_journal(settings, db_path == SYSTEM_DB))
    checks += check_syslog(settings)
    checks += check_sources(settings)
    checks += check_extras(settings)
    if db:
        db.close()
    return checks


def report(checks: list[Check]) -> str:
    width = max(len(c.title) for c in checks)
    lines = []
    for c in checks:
        lines.append(f"{MARKS[c.status]} {c.title:<{width}}  {c.detail}")
        if c.fix and c.status != OK:
            lines.append(f"  {'':<{width}}  → {c.fix}")
    return "\n".join(lines) + "\n"
