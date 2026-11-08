# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from siemstress import casefile
from siemstress.detect import Engine, load_rules
from siemstress.event import ACKNOWLEDGED, OPEN, RESOLVED, Alert, Event, Level
from siemstress.store import MIGRATIONS, Store
from siemstress.triage import TriageError, check_resolution

NOW = datetime.now(UTC)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "events.db") as s:
        yield s


def raise_alert(store: Store, **context: str) -> int:
    store.insert([], alerts=[Alert(NOW, "ssh-brute-force", Level.HIGH, "t", "web",
                                   context=context)])  # fmt: skip
    return max(a.id for a in store.alerts(limit=1000))


@pytest.mark.parametrize(
    ("disposition", "actions", "summary", "error"),
    [
        ("maybe", ["none"], "long enough text", "choose a disposition"),
        ("false-positive", [], "long enough text", "actions taken"),
        ("false-positive", ["reboot"], "long enough text", "unknown actions"),
        ("false-positive", ["none", "tuned-rule"], "long enough text", "can't be combined"),
        ("false-positive", [], "long enough text", "No action needed"),
        ("true-positive", ["none"], "long enough text", "containment"),
        ("benign-positive", ["none"], "too short", "summary"),
    ],
)
def test_incomplete_resolutions_are_refused(disposition, actions, summary, error):
    with pytest.raises(TriageError, match=error):
        check_resolution(disposition, actions, summary)


def test_complete_resolutions_are_accepted():
    check_resolution("true-positive", ["blocked-source", "reset-credentials"], "Attacker blocked")
    check_resolution("false-positive", ["tuned-rule"], "Matched a backup job")
    check_resolution("undetermined", ["none"], "Logs rotated before review")


def test_case_lifecycle_and_audit_trail(store):
    alert_id = raise_alert(store)
    assert store.acknowledge([alert_id], "alice") == 1
    assert store.acknowledge([alert_id], "alice") == 0  # already acknowledged: no log entry
    assert store.assign([alert_id], "bob", "alice") == 1
    assert store.add_note([alert_id], "bob", "  checked the router logs  ") == 1
    assert store.add_note([9999], "bob", "no such alert") == 0
    with pytest.raises(TriageError):
        store.add_note([alert_id], "bob", "   ")

    with pytest.raises(TriageError):
        store.resolve([alert_id], "bob", "true-positive", ["none"], "nothing done")
    assert store.alert(alert_id).status == ACKNOWLEDGED  # refused close changed nothing

    store.resolve([alert_id], "bob", "true-positive", ["blocked-source"], "Blocked at the router")
    a = store.alert(alert_id)
    assert (a.status, a.assignee, a.disposition, a.actions) == (
        RESOLVED, "bob", "true-positive", ("blocked-source",)
    )  # fmt: skip
    assert a.created <= a.acknowledged_at <= a.resolved_at

    with pytest.raises(TriageError, match="why"):
        store.reopen([alert_id], "alice", "")
    assert store.reopen([alert_id], "alice", "the same IP is back") == 1
    a = store.alert(alert_id)
    assert (a.status, a.disposition, a.actions, a.summary, a.resolved_at) == (
        OPEN, None, (), None, None
    )  # fmt: skip

    log = store.activity(alert_id)
    assert [(e.author, e.kind) for e in log] == [
        ("alice", "acknowledged"), ("alice", "assigned"), ("bob", "note"),
        ("bob", "resolved"), ("alice", "reopened"),
    ]  # fmt: skip
    assert log[2].text == "checked the router logs"
    assert "True positive; actions: Blocked the source. Blocked at the router" in log[3].text


def test_resolving_an_open_alert_acknowledges_and_assigns_it(store):
    alert_id = raise_alert(store)
    store.resolve([alert_id], "alice", "benign-positive", ["none"], "My own test login")
    a = store.alert(alert_id)
    assert (a.assignee, a.acknowledged_at) == ("alice", a.resolved_at)


def test_upgrade_keeps_existing_alert_status(tmp_path):
    path = tmp_path / "events.db"
    db = sqlite3.connect(path)
    db.executescript(
        "".join(f"{sql};" for sql in MIGRATIONS[:4]) + "PRAGMA user_version = 4;"
        "INSERT INTO alerts (ts, created, rule, level, title, count, status, status_by, status_at)"
        " VALUES (1, 1, 'r', 3, 't', 1, 'resolved', 'alice', 5);"
    )
    db.close()
    with Store(path) as store:
        [a] = store.alerts()
        assert (a.status, a.resolved_at, a.disposition) == (RESOLVED, a.status_at, None)
        assert store.activity(a.id) == []


def test_related_events_share_host_time_and_address_or_user(store):
    def event(minutes: int, **kw: str) -> Event:
        return Event(ts=NOW + timedelta(minutes=minutes), source="t", message="m",
                     host=kw.pop("host", "web"), **kw)  # fmt: skip

    store.insert([
        event(-5, src_ip="203.0.113.9", action="ssh.login", outcome="failure"),
        event(1, user="root"),
        event(2, src_ip="203.0.113.9", host="other-host"),  # different machine
        event(90, src_ip="203.0.113.9"),  # outside the window
        event(3, user="alice"),  # unrelated user
    ])  # fmt: skip
    alert_id = raise_alert(store, src_ip="203.0.113.9", user="root")
    related = store.related_events(store.alert(alert_id))
    assert [(e.src_ip, e.user) for e in related] == [("203.0.113.9", None), (None, "root")]


def test_report_metrics(store):
    ids = [raise_alert(store) for _ in range(4)]
    store.resolve(ids[:3], "alice", "false-positive", ["tuned-rule"], "Backup job at 2am")
    store.acknowledge([ids[3]], "alice")
    report = store.report(NOW - timedelta(days=1))
    assert report.alerts == 4
    assert report.by_status == {OPEN: 0, ACKNOWLEDGED: 1, RESOLVED: 3}
    assert report.by_disposition == {"false-positive": 3}
    assert report.median_time_to_resolve is not None
    assert report.oldest_unresolved.id == ids[3]
    text = casefile.report(report)
    assert "| ssh-brute-force | 4 | 3 | 1 |" in text
    assert "Tuning candidates** (mostly false positives): ssh-brute-force" in text


def test_alerts_carry_attack_techniques():
    engine = Engine(load_rules())
    event = Event(ts=NOW, source="t", message="m", action="audit.disable")
    [alert] = engine.process(event)
    assert alert.context["mitre"] == "T1562.012"
