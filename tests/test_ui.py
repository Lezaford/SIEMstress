# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import os
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from siemstress.event import ACKNOWLEDGED, FAILURE, OPEN, RESOLVED, Alert, Event, Level
from siemstress.store import Store, StoreError
from siemstress.triage import ACTIONS
from siemstress.ui import ago, describe_bucket, parse_query

NOW = datetime.now(UTC)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "events.db"
    with Store(path) as store:
        store.insert(
            [
                Event(ts=NOW - timedelta(hours=3), source="journald", message="boot", host="quiet"),
                Event(
                    ts=NOW - timedelta(minutes=5),
                    source="syslog",
                    message="Failed password for root from 203.0.113.9 port 22 ssh2",
                    host="web",
                    app="sshd",
                    action="ssh.login",
                    outcome=FAILURE,
                    user="root",
                    src_ip="203.0.113.9",
                ),
            ],
            alerts=[
                Alert(ts=NOW - timedelta(minutes=5), rule="r1", level=Level.HIGH, title="bad"),
                Alert(ts=NOW - timedelta(days=3), rule="r2", level=Level.LOW, title="old"),
            ],
        )
    return path


def test_parse_query():
    assert parse_query('action:ssh ip:10.0.0.9 "failed password" nope:x') == {
        "action": "ssh",
        "src_ip": "10.0.0.9",
        "text": "failed password nope:x",
    }
    assert parse_query("") == {}
    assert parse_query('unbalanced "quote') == {"text": 'unbalanced "quote'}


def test_ago_and_describe_bucket():
    assert ago(NOW - timedelta(seconds=30), NOW) == "just now"
    assert ago(NOW - timedelta(minutes=90), NOW) == "1h ago"
    assert ago(NOW - timedelta(days=2, hours=5), NOW) == "2d ago"
    assert describe_bucket(timedelta(hours=1)) == "hour"
    assert describe_bucket(timedelta(hours=7)) == "7 hours"
    assert describe_bucket(timedelta(minutes=2, seconds=30)) == "2 min"


def test_viewer_works_cases_alongside_collector(db_path, tmp_path):
    with pytest.raises(StoreError, match="does not exist"):
        Store(tmp_path / "missing.db", viewer=True)
    with Store(db_path) as collector, Store(db_path, viewer=True) as viewer:
        bad = next(a for a in viewer.alerts() if a.rule == "r1")
        assert viewer.acknowledge([bad.id], "alice") == 1
        collector.insert([Event(ts=NOW, source="x", message="still writing")])
        assert collector.alert(bad.id).status == ACKNOWLEDGED

        viewer.resolve([bad.id], "alice", "benign-positive", ["none"], "Owner was testing a key")
        o = viewer.overview(NOW - timedelta(days=7))
        assert o.unresolved_by_level[Level.HIGH] == 0


def test_readonly_store_rejects_old_schema(tmp_path):
    path = tmp_path / "old.db"
    sqlite3.connect(path).execute("PRAGMA user_version = 1").connection.close()
    with pytest.raises(StoreError, match="schema v1"):
        Store(path, viewer=True)


def test_overview(db_path):
    with Store(db_path, viewer=True) as store:
        o = store.overview(NOW - timedelta(hours=24), buckets=24)
    assert o.events == 2 == sum(o.timeline)
    assert len(o.timeline) == 24
    assert o.unresolved_by_level == {
        Level.LOW: 0,
        Level.MEDIUM: 0,
        Level.HIGH: 1,
        Level.CRITICAL: 0,
    }
    assert o.auth_failures == 1
    assert o.top_failing_ips == [("203.0.113.9", 1)]
    assert [(h.host, h.recent_events, h.users) for h in o.hosts] == [
        ("web", 1, ()),  # only a failed attempt: not a user of the host
        ("quiet", 1, ()),
    ]


def test_alerts_after_id(db_path):
    with Store(db_path, viewer=True) as store:
        low, high = sorted(a.id for a in store.alerts())
        assert [a.id for a in store.alerts(after_id=low)] == [high]


def test_tui_case_workflow(db_path):
    pytest.importorskip("textual")
    from textual.widgets import Select, SelectionList, Static, TextArea

    from siemstress.ui.tui import CaseScreen, Dashboard, PromptScreen, ResolveScreen

    async def scenario(store: Store) -> None:
        app = Dashboard(store, splash=False)
        async with app.run_test(size=(130, 45)) as pilot:
            await pilot.pause()
            assert app.query_one("#alerts").row_count == 1
            await pilot.press("a")  # acknowledge (and take) the selected alert
            await pilot.pause()
            [alert] = store.alerts(statuses=(ACKNOWLEDGED,))
            assert alert.assignee

            await pilot.press("enter")  # open the case
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            await pilot.press("n")
            await pilot.pause()
            assert isinstance(app.screen, PromptScreen)
            await pilot.press(*"blocked at the router", "enter")
            await pilot.pause()
            assert store.activity(alert.id)[-1].text == "blocked at the router"

            await pilot.press("r")
            await pilot.pause()
            form = app.screen
            assert isinstance(form, ResolveScreen)
            await pilot.click("#ok")  # incomplete: refused, form stays open
            await pilot.pause()
            assert app.screen is form
            assert "disposition" in str(form.query_one("#error", Static).render())
            form.query_one("#disposition", Select).value = "true-positive"
            form.query_one("#actions", SelectionList).select("blocked-source")
            form.query_one("#summary", TextArea).text = "Scanner blocked; no logins succeeded"
            await pilot.pause(0.3)  # let the first press's animation finish
            await pilot.click("#ok")
            await pilot.pause()
            resolved = store.alert(alert.id)
            assert (resolved.status, resolved.disposition, resolved.actions) == (
                RESOLVED, "true-positive", ("blocked-source",)
            )  # fmt: skip

            await pilot.press("escape")  # back to the dashboard
            await pilot.pause()
            assert app.query_one("#alerts").row_count == 0  # resolved alerts hidden
            await pilot.press("h")
            await pilot.pause()
            assert app.query_one("#alerts").row_count == 1
            await pilot.press("slash", *"ip:203.0.113.9", "enter")
            await pilot.pause()
            assert app.query_one("#events").row_count == 1
            await pilot.press("w")
            assert app.window == "7d"

    with Store(db_path, viewer=True) as store:
        asyncio.run(scenario(store))


def test_gui_smoke(db_path, monkeypatch):
    pytest.importorskip("PySide6")
    monkeypatch.setitem(os.environ, "QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from siemstress.ui import gui
    from siemstress.ui.gui import MainWindow

    app = QApplication.instance() or QApplication([])
    with Store(db_path, viewer=True) as store:
        window = MainWindow(store)
        assert not window.windowIcon().isNull()
        assert window.alert_model.rowCount() == 1
        assert window.cards["failures"].value.text() == "1"
        window.search.setText("action:ssh")
        window.refresh_events()
        assert window.event_model.rowCount() == 1
        window.window_box.setCurrentText("7d")
        assert window.alert_model.rowCount() == 2
        window.alert_table.selectAll()
        window.acknowledge_selected()
        assert {a.status for a in window.alert_model.records} == {ACKNOWLEDGED}

        window.alert_table.selectRow(0)
        window.add_note("checked the source address")
        assert window.case.tabText(2) == "Activity (2)"  # acknowledged + note

        def fill(dialog):
            dialog.disposition.setCurrentIndex(dialog.disposition.findData("false-positive"))
            dialog.accept()  # no actions or summary yet: refused
            assert "actions" in dialog.error.text()
            dialog.actions.item(list(ACTIONS).index("tuned-rule")).setCheckState(
                Qt.CheckState.Checked
            )
            dialog.summary.setPlainText("Rule matched a scheduled backup job")
            dialog.accept()
            return dialog.result()

        monkeypatch.setattr(gui.ResolveDialog, "exec", fill)
        window.alert_table.selectAll()
        window.resolve_selected()
        assert window.alert_model.rowCount() == 0
        window.show_resolved.setChecked(True)
        assert [a.disposition for a in window.alert_model.records] == ["false-positive"] * 2

        monkeypatch.setattr(gui.QInputDialog, "getText", lambda *a: ("new evidence", True))
        window.alert_table.selectRow(0)
        window.reopen_selected()
        assert window.alert_model.records[0].status == OPEN
        window.close()
    app.processEvents()


def test_tui_splash_shows_when_wide_and_any_key_closes_it(db_path):
    pytest.importorskip("textual")
    from siemstress.ui.tui import LOGO_WIDTH, Dashboard, Splash

    async def scenario(store: Store, width: int) -> bool:
        async with Dashboard(store).run_test(size=(width, 40)) as pilot:
            await pilot.pause()
            shown = isinstance(pilot.app.screen, Splash)
            if shown:
                await pilot.press("x")
                await pilot.pause()
                assert not isinstance(pilot.app.screen, Splash)
                await pilot.press("question_mark")  # About brings it back
                await pilot.pause()
                assert isinstance(pilot.app.screen, Splash)
            return shown

    with Store(db_path, viewer=True) as store:
        assert asyncio.run(scenario(store, LOGO_WIDTH + 20))
        assert not asyncio.run(scenario(store, LOGO_WIDTH - 20))


def test_assets_present():
    from siemstress.ui import ASSETS, ICON_SIZES

    for name in ["icon.svg", "logo.svg", "logo.png", "logo.txt"] + [
        f"icon-{size}.png" for size in ICON_SIZES
    ]:
        assert (ASSETS / name).is_file(), name


def test_gui_reports_missing_database_in_a_dialog(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    monkeypatch.setitem(os.environ, "QT_QPA_PLATFORM", "offscreen")
    from siemstress.ui import gui

    shown = []
    monkeypatch.setattr(gui.QMessageBox, "critical", lambda *args: shown.append(args[2]))
    with pytest.raises(SystemExit):
        gui.run(tmp_path / "missing.db", 5)
    assert "start the collector first" in shown[0]
