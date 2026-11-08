# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from siemstress import notify
from siemstress.config import ConfigError, NtfySettings, load_settings
from siemstress.event import Alert, Level


def alert(level: Level = Level.HIGH, age: timedelta = timedelta(0)) -> Alert:
    return Alert(
        ts=datetime.now(UTC) - age,
        rule="ssh-brute-force",
        level=level,
        title="SSH brute force from 203.0.113.9 (10 failures)",
        host="desk",
        context={"src_ip": "203.0.113.9"},
    )


def test_ntfy_request(monkeypatch):
    sent = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

    def fake_urlopen(request, timeout):
        sent.append(request)
        return Response()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    notify.Ntfy(NtfySettings(topic="t0p1c", server="https://ntfy.example", token="tk")).send(
        alert()
    )

    [request] = sent
    body = json.loads(request.data)
    assert request.full_url == "https://ntfy.example"
    assert request.get_header("Authorization") == "Bearer tk"
    assert (body["topic"], body["priority"]) == ("t0p1c", 4)
    assert body["title"].startswith("SSH brute force")
    assert "src_ip: 203.0.113.9" in body["message"]


def test_deliver_filters_low_level_and_stale_alerts():
    class Recorder:
        settings = NtfySettings(topic="t", min_level=Level.MEDIUM)

        def __init__(self):
            self.sent: list[Alert] = []

        def send(self, a: Alert) -> None:
            self.sent.append(a)

    async def scenario(recorder: Recorder) -> None:
        queue: asyncio.Queue[Alert] = asyncio.Queue()
        for a in (
            alert(Level.LOW),
            alert(Level.HIGH, age=timedelta(hours=2)),
            alert(Level.MEDIUM),
        ):
            queue.put_nowait(a)
        task = asyncio.create_task(notify.deliver(queue, recorder))
        while not queue.empty():
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        task.cancel()

    recorder = Recorder()
    asyncio.run(scenario(recorder))
    assert [a.level for a in recorder.sent] == [Level.MEDIUM]


def test_load_settings(tmp_path):
    assert load_settings(tmp_path / "missing.toml").ntfy is None

    path = tmp_path / "config.toml"
    path.write_text(
        'disabled_rules = ["user-deleted"]\n\n[ntfy]\ntopic = "abc"\n'
        'server = "https://ntfy.example/"\nmin_level = "high"\n'
    )
    settings = load_settings(path)
    assert settings.disabled_rules == {"user-deleted"}
    assert settings.ntfy == NtfySettings(
        topic="abc", server="https://ntfy.example", min_level=Level.HIGH
    )

    path.write_text('[ntfy]\ntopic = "only-a-topic"\n')
    assert load_settings(path).ntfy == NtfySettings(topic="only-a-topic")  # server defaults

    path.write_text('[ntfy]\nserver = "https://ntfy.example"\n')
    with pytest.raises(ConfigError, match="topic"):
        load_settings(path)


@pytest.mark.parametrize(
    "server",
    ["https://ntfy.sh", "http://localhost:8080", "http://127.0.0.1", "http://[::1]:80"],
)
def test_ntfy_server_accepted(tmp_path, server):
    config = tmp_path / "config.toml"
    config.write_text(f'[ntfy]\ntopic = "t"\nserver = "{server}"\n')
    assert load_settings(config).ntfy.server == server


@pytest.mark.parametrize(
    "server",
    ["http://ntfy.example", "ftp://ntfy.example", "file:///etc/passwd", "ntfy.sh", "https://"],
)
def test_ntfy_server_rejected(tmp_path, server):
    config = tmp_path / "config.toml"
    config.write_text(f'[ntfy]\ntopic = "t"\nserver = "{server}"\n')
    with pytest.raises(ConfigError, match=r"ntfy\.server"):
        load_settings(config)


def test_ntfy_plain_http_needs_opt_in(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[ntfy]\ntopic = "t"\nserver = "http://ntfy.lan"\nallow_insecure = true\n')
    assert load_settings(config).ntfy.server == "http://ntfy.lan"
