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
from siemstress.config import ConfigError, SyslogSettings, load_settings
from siemstress.detect import Engine, load_rules
from siemstress.event import Event
from siemstress.scope import Scope
from siemstress.store import Store

NOW = datetime.now(UTC)


def event(host: str, src_ip: str | None = None, sender: str | None = None, **kw) -> Event:
    extra = {"sender_ip": sender} if sender else {}
    kw.setdefault("message", "m")
    return Event(ts=NOW, source="t", host=host, src_ip=src_ip, extra=extra, **kw)


def test_empty_scope_keeps_everything():
    assert not Scope()
    assert Scope().allows(event("anything", "203.0.113.9"))


def test_host_patterns_are_case_insensitive():
    scope = Scope.parse(hosts=["web*", "server1"], exclude_hosts=["web-test"])
    assert scope.allows(event("WEB-01"))
    assert scope.allows(event("server1"))
    assert not scope.allows(event("web-test"))
    assert not scope.allows(event("nas"))
    assert not scope.allows(event(None))


def test_excluded_addresses_match_source_or_sender():
    scope = Scope.parse(exclude_ips=["192.168.1.250", "10.9.0.0/16", "2001:db8::/32"])
    assert not scope.allows(event("web", src_ip="192.168.1.250"))  # e.g. the vuln scanner
    assert not scope.allows(event("printer", sender="10.9.4.2"))
    assert not scope.allows(event("web", src_ip="2001:db8::7"))
    assert scope.allows(event("web", src_ip="192.168.1.251", sender="192.168.1.40"))


def test_scope_settings(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[sources]\njournal = false\n[scope]\nhosts = ["web*"]\nexclude_ips = ["10.0.0.0/8"]\n'
    )
    settings = load_settings(path)
    assert not settings.journal
    assert settings.scope.describe() == "only hosts web*; not addresses 10.0.0.0/8"

    for bad, error in (
        ('[scope]\nexclude_ips = ["not-an-ip"]\n', "not an address"),
        ('[scope]\nhosts = "web*"\n', "must be a list"),
        ('[scope]\ninclude = ["x"]\n', "unknown keys"),
    ):
        path.write_text(bad)
        with pytest.raises(ConfigError, match=error):
            load_settings(path)


def test_out_of_scope_events_are_dropped_but_sources_move_on(tmp_path):
    scanner = event("web", app="sshd", checkpoint=("file:/log", "1:100"),
                    message="Failed password for root from 192.168.1.250 port 1 ssh2")  # fmt: skip
    attacker = event("web", app="sshd", checkpoint=("file:/log", "1:200"),
                     message="Accepted password for root from 203.0.113.9 port 1 ssh2")  # fmt: skip
    scope = Scope.parse(exclude_ips=["192.168.1.250"])
    with Store(tmp_path / "events.db") as store:
        Pipeline(store, Engine(load_rules()), scope=scope).flush([scanner, attacker])
        [kept] = store.search()
        assert kept.src_ip == "203.0.113.9"  # normalized before the scope check
        assert [a.rule for a in store.alerts()] == ["ssh-root-login"]
        assert store.get_state("file:/log") == "1:200"


def test_startup_warns_when_this_machine_is_out_of_scope(tmp_path, monkeypatch, caplog):
    followed = []

    async def fake_follow(queue, cursor, backfill, local):
        followed.append(local.name)
        await asyncio.Event().wait()

    async def run_briefly(config: Config) -> None:
        task = asyncio.create_task(collector.run(config))
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)
        await task

    monkeypatch.setattr(collector.journald, "follow", fake_follow)
    caplog.set_level(logging.INFO)
    base = {"db_path": tmp_path / "events.db", "hostname": "desk",
            "syslog": SyslogSettings(listen=None)}  # fmt: skip

    asyncio.run(run_briefly(Config(**base, scope=Scope.parse(hosts=["web*"]))))
    assert "this machine (desk) is outside [scope]" in caplog.text
    assert "scope: only hosts web*" in caplog.text
    assert followed == ["desk"]

    asyncio.run(run_briefly(Config(**base, journal=False)))
    assert followed == ["desk"]  # journal source not started the second time
