# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from datetime import UTC, datetime

from siemstress.sources.journald import parse


def test_parse_entry():
    e = parse(
        json.dumps(
            {
                "__CURSOR": "s=abc",
                "__REALTIME_TIMESTAMP": "1790119390849463",
                "_HOSTNAME": "desk",
                "SYSLOG_IDENTIFIER": "sudo",
                "_PID": "3949",
                "PRIORITY": "5",
                "_UID": "1000",
                "MESSAGE": "pam_unix(sudo:session): session opened for user root",
            }
        )
    )
    assert e.ts == datetime(2026, 9, 22, 23, 23, 10, 849463, tzinfo=UTC)
    assert (e.host, e.app, e.pid, e.severity) == ("desk", "sudo", 3949, 5)
    assert e.checkpoint == ("journald.cursor", "s=abc")
    assert e.extra == {"_UID": "1000"}


def test_binary_message_is_decoded():
    e = parse(json.dumps({"__REALTIME_TIMESTAMP": "1", "MESSAGE": list(b"a\x00b")}))
    assert e.message == "a\x00b"


def test_falls_back_to_comm():
    e = parse(json.dumps({"__REALTIME_TIMESTAMP": "1", "_COMM": "kthread", "MESSAGE": "x"}))
    assert e.app == "kthread"


def test_skips_empty_and_invalid():
    assert parse(json.dumps({"__REALTIME_TIMESTAMP": "1", "MESSAGE": ""})) is None
    assert parse("not json") is None


def test_repeated_field_keeps_first_value():
    e = parse(
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "1",
                "MESSAGE": "x",
                "SYSLOG_IDENTIFIER": ["app", "other"],
                "_COMM": [list(b"bin\xff"), "y"],
            }
        )
    )
    assert e.app == "app"
    assert e.extra["_COMM"] == "bin�"
