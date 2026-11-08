# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
from datetime import timedelta

import pytest

from siemstress.cli import bind_address, duration, severity
from siemstress.event import Severity


def test_duration():
    assert duration("15m") == timedelta(minutes=15)
    assert duration("7d") == timedelta(days=7)
    with pytest.raises(argparse.ArgumentTypeError):
        duration("7 days")


def test_severity():
    assert severity("warning") is Severity.WARNING
    assert severity("3") is Severity.ERR
    with pytest.raises(argparse.ArgumentTypeError):
        severity("9")


def test_bind_address():
    assert bind_address("0.0.0.0:514") == ("0.0.0.0", 514)
    assert bind_address(":5514") == ("0.0.0.0", 5514)
    assert bind_address("off") == "off"
    with pytest.raises(argparse.ArgumentTypeError):
        bind_address("5514")


def test_case_commands(tmp_path, capsys):
    from datetime import UTC, datetime

    from siemstress.cli import main
    from siemstress.event import Alert, Level
    from siemstress.store import Store

    db = tmp_path / "events.db"
    with Store(db) as store:
        store.insert([], alerts=[Alert(datetime.now(UTC), "r", Level.HIGH, "bad thing")])

    def run(*args: str) -> str:
        main(["--db", str(db), *args])
        return capsys.readouterr().out

    assert "1 alert(s) acknowledged" in run("ack", "1")
    assert "note added" in run("note", "1", "looked", "at", "it")
    with pytest.raises(SystemExit, match="summary"):
        run("resolve", "1", "--disposition", "false-positive", "--action", "tuned-rule")
    out = run("resolve", "1", "--disposition", "false-positive", "--action", "tuned-rule",
              "--summary", "Matched a backup job")  # fmt: skip
    assert "resolved as false positive" in out
    assert "bad thing" not in run("alerts")
    assert "[False positive]" in run("alerts", "--status", "resolved")

    case = run("case", "1")
    assert "| Disposition | False positive |" in case
    assert "looked at it" in case and "Matched a backup job" in case
    assert "| False positive | 1 | 100% |" in run("report")
    assert "1 alert(s) reopened" in run("reopen", "1", "--reason", "it happened again")


def test_install_desktop(tmp_path, monkeypatch, capsys):
    from siemstress import cli

    monkeypatch.setattr(cli, "DATA_HOME", tmp_path)
    cli.main(["install-desktop"])
    entry = (tmp_path / "applications" / "siemstress.desktop").read_text()
    assert "Icon=siemstress" in entry and '" gui' in entry
    assert (tmp_path / "icons/hicolor/48x48/apps/siemstress.png").stat().st_size > 0
    assert (tmp_path / "icons/hicolor/scalable/apps/siemstress.svg").is_file()
