# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import logging
import os
import signal
from datetime import UTC, datetime

import pytest

from siemstress import collector
from siemstress.collector import Config, Pipeline
from siemstress.config import SyslogSettings
from siemstress.detect import Engine, load_rules
from siemstress.event import Alert, Event
from siemstress.sources.journald import CURSOR_KEY
from siemstress.store import Store

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)


def make_event(n: int) -> Event:
    return Event(ts=T0, source="journald", message=f"m{n}", checkpoint=(CURSOR_KEY, f"c{n}"))


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "events.db") as s:
        yield s


def ssh_failure(second: int) -> Event:
    return Event(
        ts=T0.replace(second=second),
        source="syslog",
        app="sshd",
        message="Failed password for root from 203.0.113.9 port 22 ssh2",
    )


def test_writer_flushes_pending_events_on_cancel(tmp_path):
    async def scenario(store: Store) -> None:
        queue: asyncio.Queue[Event] = asyncio.Queue()
        writer = asyncio.create_task(collector._write(Pipeline(store, Engine([])), queue))
        for n in range(3):
            queue.put_nowait(make_event(n))
        await asyncio.sleep(0)
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)

    with Store(tmp_path / "events.db") as store:
        asyncio.run(scenario(store))
        assert [e.message for e in store.search()] == ["m0", "m1", "m2"]
        assert store.get_state(CURSOR_KEY) == "c2"


def test_run_stops_cleanly_on_sigterm(tmp_path, monkeypatch):
    received_cursor = []

    async def fake_follow(queue, cursor, backfill, local):
        received_cursor.append(cursor)
        await queue.put(make_event(len(received_cursor)))
        await asyncio.Event().wait()

    async def run_then_terminate(config: Config) -> None:
        task = asyncio.create_task(collector.run(config))
        await asyncio.sleep(0.1)
        os.kill(os.getpid(), signal.SIGTERM)
        await task

    monkeypatch.setattr(collector.journald, "follow", fake_follow)
    config = Config(db_path=tmp_path / "events.db", syslog=SyslogSettings(listen=None))
    asyncio.run(run_then_terminate(config))
    asyncio.run(run_then_terminate(config))

    # Second run resumed from the cursor saved by the first.
    assert received_cursor == [None, "c1"]
    with Store(config.db_path) as store:
        assert [e.message for e in store.search()] == ["m1", "m2"]


def test_flush_normalizes_events(store):
    Pipeline(store, Engine([])).flush([ssh_failure(0)])
    [stored] = store.search(action="ssh.login")
    assert (stored.outcome, stored.src_ip) == ("failure", "203.0.113.9")


def test_flush_stores_and_queues_alerts(store):
    queue: asyncio.Queue[Alert] = asyncio.Queue()
    Pipeline(store, Engine(load_rules()), queue).flush([ssh_failure(s) for s in range(10)])

    [stored] = store.alerts()
    assert stored.rule == "ssh-brute-force"
    assert stored.title == "SSH brute force from 203.0.113.9 (10 failures)"
    assert queue.get_nowait().rule == "ssh-brute-force"


def test_processing_crash_keeps_raw_event(store, monkeypatch):
    def broken(event):
        raise RuntimeError("bug")

    monkeypatch.setattr(collector, "normalize", broken)
    Pipeline(store, Engine([])).flush([make_event(1)])
    assert [e.message for e in store.search()] == ["m1"]


def test_duplicate_account_records_raise_one_alert(store):
    usermod = Event(
        ts=T0, source="journald", app="usermod", host="h", message="add 'eve' to group 'wheel'"
    )
    audit = Event(
        ts=T0,
        source="syslog",
        app="audit",
        host="h",
        message="AUDIT1102 pid=1 uid=0 auid=1000 ses=3 msg='op=add-user-to-group "
        'grp="wheel" acct="eve" exe="/usr/sbin/usermod" res=success\'',
    )
    sysusers = Event(ts=T0, source="syslog", app="audit", host="h",
                     message="AUDIT1114 pid=2 uid=0 auid=4294967295 msg='op=adding-user "
                             "acct=\"gluster\" exe=\"systemd-sysusers\" res=success'")  # fmt: skip
    Pipeline(store, Engine(load_rules())).flush([usermod, audit, sysusers])
    assert [a.rule for a in store.alerts()] == ["privileged-group-member"]


def test_absent_optional_sources_stay_quiet(tmp_path, monkeypatch, caplog):
    async def fake_follow(queue, cursor, backfill, local):
        await asyncio.Event().wait()

    async def run_briefly(config: Config) -> None:
        task = asyncio.create_task(collector.run(config))
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)
        await task

    monkeypatch.setattr(collector.journald, "follow", fake_follow)
    caplog.set_level(logging.INFO)
    config = Config(
        db_path=tmp_path / "events.db",
        syslog=SyslogSettings(listen=None),
        docker_socket=tmp_path / "docker.sock",
        log_files=(tmp_path / "pihole.log", tmp_path / "other.log"),
    )
    asyncio.run(run_briefly(config))
    messages = [r.getMessage() for r in caplog.records]
    assert not [m for m in messages if "docker" in m.lower() or ".log" in m]
