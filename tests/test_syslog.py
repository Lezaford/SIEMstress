# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from datetime import UTC, datetime

import pytest

from siemstress.sources.syslog import parse, read_frames

NOW = datetime(2026, 9, 22, 18, 0, tzinfo=UTC)


def test_rfc3164_debian_rsyslog():
    e = parse(
        b"<38>Sep 22 17:59:01 deb sshd[812]: Failed password for root from 10.0.0.9\n",
        "10.0.0.5",
        NOW,
    )
    assert (e.host, e.app, e.pid) == ("deb", "sshd", 812)
    assert (e.facility, e.severity) == (4, 6)
    assert e.message == "Failed password for root from 10.0.0.9"
    assert e.extra["sender_ip"] == "10.0.0.5"


def test_rfc3164_padded_day_without_pid():
    e = parse(b"<13>Sep  2 08:00:00 pi cron: job done", "10.0.0.6", NOW)
    assert (e.host, e.app, e.pid, e.message) == ("pi", "cron", None, "job done")


def test_rfc3164_year_rollover():
    new_year = datetime(2027, 1, 1, 12, tzinfo=UTC)
    e = parse(b"<13>Dec 31 23:59:00 pi app: hi", "10.0.0.6", new_year)
    assert e.ts.astimezone().year == 2026


def test_rfc5424():
    e = parse(
        b'<165>1 2026-09-22T17:30:00.123Z web nginx 42 ID47 [meta a="1"] \xef\xbb\xbfGET /',
        "10.0.0.7",
        NOW,
    )
    assert e.ts == datetime(2026, 9, 22, 17, 30, 0, 123000, tzinfo=UTC)
    assert (e.host, e.app, e.pid, e.message) == ("web", "nginx", 42, "GET /")
    assert e.extra["structured_data"] == '[meta a="1"]'


def test_unstructured_line_is_kept():
    e = parse(b"hello there", "10.0.0.8", NOW)
    assert (e.host, e.message, e.severity) == ("10.0.0.8", "hello there", None)


def test_blank_is_ignored():
    assert parse(b"\r\n", "10.0.0.8", NOW) is None


async def _frames(data: bytes) -> list[bytes]:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return [f async for f in read_frames(reader)]


def test_tcp_framing_mixed():
    frames = asyncio.run(_frames(b"<13>one\n5 <13>2<13>three\n"))
    assert frames == [b"<13>one\n", b"<13>2", b"<13>three\n"]


def test_tcp_oversized_frame_rejected():
    with pytest.raises(ValueError):
        asyncio.run(_frames(b"99999999 x"))
