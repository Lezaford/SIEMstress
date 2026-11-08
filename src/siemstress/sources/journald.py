# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging
import shutil

from siemstress.event import Event
from siemstress.identity import LocalHost, is_person, username
from siemstress.timeutil import from_us

log = logging.getLogger(__name__)

EXTRA_FIELDS = ("_SYSTEMD_UNIT", "_UID", "_COMM", "_EXE", "_TRANSPORT")
FIELDS = (
    "MESSAGE",
    "_HOSTNAME",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "PRIORITY",
    "SYSLOG_FACILITY",
    "_MACHINE_ID",
    *EXTRA_FIELDS,
)
RESTART_DELAY = 5
CURSOR_KEY = "journald.cursor"


def _text(value: object) -> str | None:
    # journalctl emits non-UTF-8 values as a list of byte values, and fields that
    # occur more than once as a list of values (we keep the first).
    if isinstance(value, list):
        if value and all(isinstance(b, int) for b in value):
            return bytes(value).decode("utf-8", "replace")
        return _text(value[0]) if value else None
    return value  # type: ignore[return-value]


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def parse(line: str | bytes, local: LocalHost | None = None) -> Event | None:
    """Turn one `journalctl -o json` line into an event.

    Entries written on this machine (matched by machine ID) are labeled with its
    stable name and, when it's a person or root rather than a service account, the
    user whose process logged them.
    """
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not (message := _text(entry.get("MESSAGE"))):
        return None

    def get(key: str) -> str | None:
        return _text(entry.get(key))

    is_local = local is not None and get("_MACHINE_ID") == local.machine_id
    uid = get("_UID")
    return Event(
        ts=from_us(int(entry["__REALTIME_TIMESTAMP"])),
        source="journald",
        message=message,
        host=local.name if is_local else get("_HOSTNAME"),
        user=username(uid) if is_local and uid and is_person(uid) else None,
        app=get("SYSLOG_IDENTIFIER") or get("_COMM"),
        pid=_int(get("_PID")),
        severity=_int(get("PRIORITY")),
        facility=_int(get("SYSLOG_FACILITY")),
        extra={k: v for k in EXTRA_FIELDS if (v := get(k)) is not None},
        checkpoint=(CURSOR_KEY, cursor) if (cursor := entry.get("__CURSOR")) else None,
    )


async def follow(
    queue: asyncio.Queue[Event], cursor: str | None, backfill: str, local: LocalHost | None = None
) -> None:
    """Stream journal entries into `queue`, resuming after `cursor` if given."""
    if not shutil.which("journalctl"):
        log.debug("journalctl not found; journal source disabled")
        return
    while True:
        cmd = ["journalctl", "--follow", "--output=json", f"--output-fields={','.join(FIELDS)}"]
        cmd.append(f"--after-cursor={cursor}" if cursor else f"--since=-{backfill}")
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, limit=2**20
        )
        try:
            async for line in proc.stdout:
                if event := parse(line, local):
                    cursor = event.checkpoint[1] if event.checkpoint else cursor
                    await queue.put(event)
        finally:
            if proc.returncode is None:
                proc.terminate()
            await proc.wait()
        log.warning("journalctl exited (%s), restarting in %ss", proc.returncode, RESTART_DELAY)
        await asyncio.sleep(RESTART_DELAY)
