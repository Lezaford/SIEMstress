# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
from datetime import UTC, datetime

import pytest

from siemstress import doctor, paths
from siemstress.event import Event
from siemstress.store import Store


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """Point the user and system locations at a scratch filesystem."""
    for name, rel in (("USER_CONFIG", "home/.config/siemstress/config.toml"),
                      ("USER_DB", "home/.local/share/siemstress/events.db"),
                      ("SYSTEM_CONFIG", "etc/siemstress/config.toml"),
                      ("SYSTEM_DB", "var/lib/siemstress/events.db")):  # fmt: skip
        monkeypatch.setattr(paths, name, tmp_path / rel)
    monkeypatch.delenv("SIEMSTRESS_CONFIG", raising=False)
    monkeypatch.delenv("SIEMSTRESS_DB", raising=False)
    return tmp_path


def touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()


def test_fresh_machine_uses_user_locations(layout):
    assert paths.default_config() == paths.USER_CONFIG
    assert paths.default_db() == paths.USER_DB


def test_system_install_is_used_when_present(layout):
    touch(paths.SYSTEM_CONFIG)
    assert paths.default_config() == paths.SYSTEM_CONFIG
    assert paths.default_db() == paths.SYSTEM_DB  # even before the collector created it


def test_user_files_win_and_environment_overrides(layout, monkeypatch):
    touch(paths.SYSTEM_CONFIG)
    touch(paths.USER_CONFIG)
    touch(paths.USER_DB)
    assert (paths.default_config(), paths.default_db()) == (paths.USER_CONFIG, paths.USER_DB)
    monkeypatch.setenv("SIEMSTRESS_DB", str(layout / "elsewhere.db"))
    assert paths.default_db() == layout / "elsewhere.db"


def by_title(checks: list[doctor.Check]) -> dict[str, doctor.Check]:
    return {c.title: c for c in checks}


def test_doctor_on_a_working_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_run", lambda *cmd: doctor.subprocess.CompletedProcess(
        cmd, 0, "active\n" if "is-active" in cmd else "some line\n", ""))  # fmt: skip
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    config, db = tmp_path / "config.toml", tmp_path / "events.db"
    config.write_text('[ntfy]\ntopic = "t"\n')
    with Store(db) as store:
        store.insert([Event(ts=datetime.now(UTC), source="t", message="recent")])
    checks = by_title(doctor.run_checks(config, db))
    assert all(c.status != doctor.FAIL for c in checks.values())
    assert checks["Database"].status == doctor.OK
    assert checks["Collector"].detail == "running as a system and a user service"
    optional = {"Desktop app", "Terminal app"}  # depend on what this machine has installed
    assert [
        c.title for c in checks.values() if c.status != doctor.OK and c.title not in optional
    ] == []


def test_doctor_explains_problems(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_run", lambda *cmd: doctor.subprocess.CompletedProcess(
        cmd, 1, "", ""))  # fmt: skip
    config, db = tmp_path / "config.toml", tmp_path / "events.db"

    config.write_text('[scope]\nexclude_ips = ["nope"]\n')
    checks = by_title(doctor.run_checks(config, db))
    assert checks["Config"].status == doctor.FAIL and "nope" in checks["Config"].detail

    config.write_text('[syslog]\nlisten = "0.0.0.0:5514"\n')
    sqlite3.connect(db).execute("PRAGMA user_version = 2").connection.close()
    checks = by_title(doctor.run_checks(config, db))
    assert checks["Database"].status == doctor.FAIL
    assert "restart the collector" in checks["Database"].fix
    assert checks["Collector"].status == doctor.WARN
    assert checks["Syslog senders"].status == doctor.WARN
    text = doctor.report(list(checks.values()))
    assert "✘ Database" in text and "→ restart the collector" in text


def test_doctor_points_to_the_siemstress_group(tmp_path, monkeypatch):
    locked = tmp_path / "lib"
    locked.mkdir(mode=0o700)
    monkeypatch.setattr(doctor, "SYSTEM_DB", locked / "events.db")
    monkeypatch.setattr(doctor.os, "access", lambda *a: False)
    check, _ = doctor.check_database(locked / "events.db")
    assert check.status == doctor.FAIL
    assert "usermod -aG siemstress" in check.fix


def test_doctor_uses_event_freshness_when_systemd_cant_be_asked(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_run", lambda *cmd: doctor.subprocess.CompletedProcess(
        cmd, 1, "", "Failed to connect to bus"))  # fmt: skip
    db = tmp_path / "events.db"
    with Store(db) as store:
        store.insert([Event(ts=datetime.now(UTC), source="t", message="recent")])
    connection = sqlite3.connect(db)
    [collector, events] = doctor.check_collector(connection)
    assert (collector.status, collector.detail) == (
        doctor.OK, "receiving events (couldn't ask systemd)"
    )  # fmt: skip
    assert events.status == doctor.OK
