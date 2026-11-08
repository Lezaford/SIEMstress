# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine

import pytest

from siemstress.config import load_settings
from siemstress.event import Event
from siemstress.sources import docker, journald, logfile

LINE = "Sep 22 18:00:01 dnsmasq[5]: query[A] example.com from 192.168.1.20\n"


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch):
    monkeypatch.setattr(logfile, "POLL_INTERVAL", 0.01)
    monkeypatch.setattr(logfile, "RECHECK_INTERVAL", 0.01)
    monkeypatch.setattr(docker, "RECHECK_INTERVAL", 0.01)
    monkeypatch.setattr(docker, "RECONNECT_DELAY", 0.01)


async def collect(
    start: Callable[[asyncio.Queue[Event]], Coroutine],
    while_running: Callable[[], None] | None = None,
    seconds: float = 0.1,
) -> list[Event]:
    """Run a source for a moment (optionally changing the world halfway) and return its events."""
    queue: asyncio.Queue[Event] = asyncio.Queue()
    task = asyncio.create_task(start(queue))
    await asyncio.sleep(seconds)
    if while_running:
        while_running()
        await asyncio.sleep(seconds)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return [queue.get_nowait() for _ in range(queue.qsize())]


def no_logs_above_debug(caplog) -> bool:
    return not [r for r in caplog.records if r.levelno >= logging.INFO]


def test_missing_file_is_silent_then_picked_up(tmp_path, caplog):
    path = tmp_path / "pihole.log"
    caplog.set_level(logging.DEBUG)

    events = asyncio.run(collect(lambda q: logfile.follow(q, path, None, "h")))
    assert events == []
    assert no_logs_above_debug(caplog)

    # Created while running: read from the start.
    events = asyncio.run(
        collect(lambda q: logfile.follow(q, path, None, "h"), lambda: path.write_text(LINE * 2))
    )
    assert [e.action for e in events] == [None, None]  # normalized later, in the pipeline
    assert events[0].app == "dnsmasq"
    assert events[0].extra == {"path": str(path)}


def test_existing_file_starts_at_end_and_resumes_from_checkpoint(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("old line\n")

    def append(text: str) -> Callable[[], None]:
        return lambda: path.open("a").write(text)

    events = asyncio.run(collect(lambda q: logfile.follow(q, path, None, "h"), append("new 1\n")))
    assert [e.message for e in events] == ["new 1"]

    # Written while we were stopped, picked up from the saved checkpoint.
    path.open("a").write("new 2\nnew 3\n")
    checkpoint = events[-1].checkpoint[1]
    events = asyncio.run(collect(lambda q: logfile.follow(q, path, checkpoint, "h")))
    assert [e.message for e in events] == ["new 2", "new 3"]


def test_rotation_and_partial_lines(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("")

    def rotate() -> None:
        path.open("a").write("before rotate\npartial")
        path.rename(tmp_path / "app.log.1")
        path.write_text("after rotate\n")

    events = asyncio.run(collect(lambda q: logfile.follow(q, path, None, "h"), rotate))
    assert [e.message for e in events] == ["before rotate", "after rotate"]


def test_unreadable_file_warns_once(tmp_path, caplog):
    path = tmp_path / "secret.log"
    path.write_text("x\n")
    path.chmod(0)
    try:
        path.open("rb").close()
        pytest.skip("running with permission to read everything")
    except PermissionError:
        pass
    asyncio.run(collect(lambda q: logfile.follow(q, path, None, "h"), seconds=0.1))
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "no permission" in warnings[0].getMessage()


def test_missing_docker_socket_is_silent(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    events = asyncio.run(collect(lambda q: docker.follow(q, tmp_path / "docker.sock", None, "h")))
    assert events == []
    assert no_logs_above_debug(caplog)


def test_missing_journalctl_is_silent(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(journald.shutil, "which", lambda _: None)
    events = asyncio.run(collect(lambda q: journald.follow(q, None, "1h")))
    assert events == []
    assert no_logs_above_debug(caplog)


DOCKER_EVENTS = [
    {
        "Type": "container",
        "Action": "exec_start: /bin/sh -c id",
        "Actor": {"ID": "abc123def4567890", "Attributes": {"name": "web", "image": "nginx"}},
        "time": 1790000000,
        "timeNano": 1790000000123456789,
    },
    {
        "Type": "container",
        "Action": "die",
        "Actor": {"ID": "abc123def4567890", "Attributes": {"name": "web", "exitCode": "137"}},
        "timeNano": 1790000001000000000,
    },
    {"Type": "network", "Action": "connect", "Actor": {}, "timeNano": 1790000002000000000},
]


def test_docker_parse():
    exec_event, die_event = (docker.parse(obj, "host") for obj in DOCKER_EVENTS[:2])
    assert exec_event.action == "docker.container.exec_start"
    assert exec_event.extra == {"name": "web", "image": "nginx", "id": "abc123def456",
                                "command": "/bin/sh -c id"}  # fmt: skip
    assert (die_event.action, die_event.outcome, die_event.extra["exit_code"]) == (
        "docker.container.die", "failure", "137",
    )  # fmt: skip
    assert docker.parse(DOCKER_EVENTS[2], "host") is None


def test_docker_stream_from_fake_daemon(tmp_path):
    sock = tmp_path / "docker.sock"
    requests: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        requests.append((await reader.readline()).decode())
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n")  # fmt: skip
        for obj in DOCKER_EVENTS:
            data = json.dumps(obj).encode() + b"\n"
            writer.write(b"%x\r\n%s\r\n" % (len(data), data))
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def scenario() -> list[Event]:
        server = await asyncio.start_unix_server(handle, path=str(sock))
        async with server:
            return await collect(lambda q: docker.follow(q, sock, "1789999999.5", "h"), seconds=0.2)

    events = asyncio.run(scenario())
    assert [e.action for e in events[:2]] == ["docker.container.exec_start", "docker.container.die"]
    assert "since=1789999999.500001" in requests[0]
    # After the stream ended it reconnected from the last event it saw.
    assert any("since=1790000001.000001" in r for r in requests[1:])


def test_source_settings(tmp_path):
    path = tmp_path / "config.toml"
    assert load_settings(path).docker_socket is not None  # watched by default

    path.write_text('[sources]\ndocker = false\nfiles = ["~/app.log"]\n')
    settings = load_settings(path)
    assert settings.docker_socket is None
    assert [p.name for p in settings.log_files] == ["app.log"]
