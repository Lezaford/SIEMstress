# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Follow local log files, like `tail -F`.

A file that doesn't exist yet is waited for quietly, so optional inputs (e.g. a
Pi-hole log on a machine without Pi-hole) cost nothing and produce no log noise.
"""

import asyncio
import logging
import os
from pathlib import Path

from siemstress.event import Event
from siemstress.sources import syslog

log = logging.getLogger(__name__)

POLL_INTERVAL = 1.0
RECHECK_INTERVAL = 30.0
READ_SIZE = 64 * 1024


def state_key(path: Path) -> str:
    return f"file:{path}"


def _parse_checkpoint(value: str | None) -> tuple[int | None, int]:
    inode, _, offset = (value or "").partition(":")
    return (int(inode), int(offset)) if inode.isdigit() and offset.isdigit() else (None, 0)


async def follow(
    queue: asyncio.Queue[Event], path: Path, checkpoint: str | None, host: str
) -> None:
    """Stream new lines from `path`, resuming from `checkpoint` ("inode:offset")."""
    key = state_key(path)
    saved_inode, saved_offset = _parse_checkpoint(checkpoint)
    first_open = True
    reported: str | None = None  # last problem logged, to avoid repeating it

    while True:
        try:
            handle = path.open("rb")
        except FileNotFoundError:
            if reported != "missing":
                log.debug("%s does not exist; will pick it up if it appears", path)
                reported = "missing"
            first_open = False  # a file created later is read from its start
            await asyncio.sleep(RECHECK_INTERVAL)
            continue
        except PermissionError:
            if reported != "denied":
                log.warning("no permission to read %s; skipping until it is readable", path)
                reported = "denied"
            await asyncio.sleep(RECHECK_INTERVAL)
            continue

        with handle:
            inode = os.fstat(handle.fileno()).st_ino
            size = os.fstat(handle.fileno()).st_size
            if inode == saved_inode and saved_offset <= size:
                offset = saved_offset
            elif first_open and saved_inode is None:
                offset = size  # first run: only new lines, not the whole history
            else:
                offset = 0  # rotated or replaced since we last read it
            handle.seek(offset)
            first_open, reported = False, None
            log.info("following %s", path)

            buffer = b""
            while True:
                if chunk := handle.read(READ_SIZE):
                    buffer += chunk
                    *lines, buffer = buffer.split(b"\n")
                    for line in lines:
                        offset += len(line) + 1
                        if event := syslog.parse(line, host, source="file"):
                            event.extra = {"path": str(path)}
                            event.checkpoint = (key, f"{inode}:{offset}")
                            await queue.put(event)
                    continue

                try:
                    current = os.stat(path)
                except FileNotFoundError:
                    current = None
                if current is None or current.st_ino != inode:
                    break  # rotated: reopen the new file
                if current.st_size < offset:
                    handle.seek(0)  # truncated in place
                    offset, buffer = 0, b""
                await asyncio.sleep(POLL_INTERVAL)
            saved_inode = None
