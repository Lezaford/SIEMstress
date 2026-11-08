# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from siemstress.event import Event
from siemstress.store import MIGRATIONS, Store

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "events.db") as s:
        yield s


def event(minutes: int, **kw) -> Event:
    return Event(
        ts=T0 + timedelta(minutes=minutes), source="test", message=kw.pop("message", "msg"), **kw
    )


def test_migrations_applied_once(tmp_path):
    path = tmp_path / "events.db"
    Store(path).close()
    with Store(path) as s:
        assert s.db.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)


def test_roundtrip(store):
    original = event(
        0, host="h", app="sshd", pid=1, severity=4, facility=4, extra={"sender_ip": "10.0.0.1"}
    )
    store.insert([original])
    [loaded] = store.search()
    assert loaded == original


def test_search_filters_and_order(store):
    store.insert(
        [
            event(0, app="sshd", message="Failed password", severity=6),
            event(1, app="sudo", message="session opened", severity=6),
            event(2, app="sshd", message="Accepted password", severity=6),
            event(3, app="kernel", message="oops", severity=2),
        ]
    )
    assert [e.message for e in store.search(app="sshd")] == ["Failed password", "Accepted password"]
    assert [e.message for e in store.search(text="password", limit=1)] == ["Accepted password"]
    assert [e.message for e in store.search(max_severity=3)] == ["oops"]
    assert len(store.search(since=T0 + timedelta(minutes=2))) == 2


def test_state_saved_with_batch(store):
    store.insert([event(0)], {"cursor": "a"})
    store.insert([event(1)], {"cursor": "b"})
    assert store.get_state("cursor") == "b"
    assert store.get_state("missing") is None


def test_prune(store):
    store.insert([event(0), event(10)])
    assert store.prune(T0 + timedelta(minutes=5)) == 1
    assert len(store.search()) == 1


def test_stats(store):
    store.insert([event(0, host="a", app="x"), event(1, host="a", app="x"), event(2, host="b")])
    stats = store.stats(T0)
    assert stats.total == 3
    assert stats.oldest == T0
    assert stats.by_host == [("a", "test", 2), ("b", "test", 1)]
    assert stats.by_app == [("x", 2), ("?", 1)]


def test_upgrade_from_v1_keeps_events(tmp_path):
    path = tmp_path / "events.db"
    db = sqlite3.connect(path)
    db.executescript(f"{MIGRATIONS[0]}; PRAGMA user_version = 1;")
    db.execute(
        "INSERT INTO events (ts, received, source, message) VALUES (0, 0, 'journald', 'old')"
    )
    db.commit()
    db.close()

    with Store(path) as s:
        [old] = s.search()
        assert (old.message, old.action) == ("old", None)
        s.insert([event(0, action="ssh.login", outcome="failure", src_ip="10.0.0.9")])
        assert [e.message for e in s.search(action="ssh")] == ["msg"]


def test_search_normalized_fields(store):
    store.insert(
        [
            event(0, action="ssh.login", outcome="failure", user="root", src_ip="10.0.0.9"),
            event(1, action="ssh.login", outcome="success", user="alice", src_ip="10.0.0.2"),
            event(2, action="sudo.exec", outcome="success", user="alice", target_user="root"),
            event(3, action="sshfs.mount"),
        ]
    )

    def minutes(**kw):
        return [int((e.ts - T0).total_seconds() // 60) for e in store.search(**kw)]

    assert minutes(action="ssh") == [0, 1]
    assert minutes(action="ssh.login", outcome="failure") == [0]
    assert minutes(user="root") == [0, 2]
    assert minutes(src_ip="10.0.0.2") == [1]
    assert ("ssh.login", "failure", 1) in store.stats(T0).by_action


def test_database_is_group_writable_in_a_shared_directory(tmp_path):
    shared = tmp_path / "state"
    shared.mkdir()
    shared.chmod(0o2770)
    with Store(shared / "events.db") as s:
        s.insert([event(0)])
    assert (shared / "events.db").stat().st_mode & 0o777 == 0o660

    private = tmp_path / "private"
    private.mkdir()
    Store(private / "events.db").close()
    assert (private / "events.db").stat().st_mode & 0o060 != 0o060  # left alone


def test_private_database_is_owner_only(tmp_path):
    path = tmp_path / "data" / "events.db"
    with Store(path) as s:
        s.db.execute("CREATE TABLE IF NOT EXISTS t (x)")
        s.db.commit()
    path.chmod(0o644)
    with Store(path):
        pass
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
