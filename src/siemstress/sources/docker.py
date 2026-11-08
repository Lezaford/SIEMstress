# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Container and image events from the Docker API socket (Podman's compatible socket works too).

No socket means no Docker on this host: the source waits quietly and connects if
one appears later.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from siemstress.event import FAILURE, SUCCESS, Event

log = logging.getLogger(__name__)

STATE_KEY = "docker.since"
TYPES = ("container", "image")
RECHECK_INTERVAL = 60.0  # while the socket is missing or refused
RECONNECT_DELAY = 5.0  # after a stream we were receiving ends


def parse(obj: dict, host: str) -> Event | None:
    kind, action = obj.get("Type"), obj.get("Action") or obj.get("status")
    if kind not in TYPES or not action:
        return None
    actor = obj.get("Actor") or {}
    attrs = actor.get("Attributes") or {}
    # Exec actions carry the command: "exec_start: /bin/sh -c id".
    verb, _, command = action.partition(":")
    name = attrs.get("name") or (actor.get("ID") or "")[:12]
    extra = {"name": name, "image": attrs.get("image", ""), "id": (actor.get("ID") or "")[:12]}
    if command.strip():
        extra["command"] = command.strip()
    outcome = None
    if verb == "die":
        extra["exit_code"] = str(attrs.get("exitCode", ""))
        outcome = SUCCESS if extra["exit_code"] == "0" else FAILURE

    if "timeNano" in obj:
        ts = datetime.fromtimestamp(obj["timeNano"] / 1e9, UTC)
    else:
        ts = datetime.fromtimestamp(obj.get("time", 0), UTC)
    return Event(
        ts=ts,
        source="docker",
        message=f"{kind} {action} {name}".strip(),
        host=host,
        app="docker",
        action=f"docker.{kind}.{verb}",
        outcome=outcome,
        extra={k: str(v) for k, v in extra.items() if v},
        checkpoint=(STATE_KEY, f"{ts.timestamp():.6f}"),
    )


async def _read_events(socket_path: Path, since: str | None) -> AsyncIterator[dict]:
    """Stream decoded JSON objects from the API's /events endpoint (HTTP/1.1 over a unix socket)."""
    reader, writer = await asyncio.open_unix_connection(str(socket_path), limit=2**20)
    try:
        params = {"filters": json.dumps({"type": list(TYPES)})}
        if since:
            # `since` is inclusive; step past the last event we already stored.
            params["since"] = f"{float(since) + 1e-6:.6f}"
        writer.write(f"GET /events?{urlencode(params)} HTTP/1.1\r\nHost: docker\r\n\r\n".encode())
        await writer.drain()

        status = await reader.readline()
        if b" 200 " not in status:
            raise ConnectionError(f"events request failed: {status.decode().strip()}")
        chunked = False
        while (header := await reader.readline()) not in (b"\r\n", b""):
            name, _, value = header.decode().partition(":")
            chunked |= name.lower() == "transfer-encoding" and "chunked" in value.lower()

        buffer = b""
        while True:
            if chunked:
                size = int((await reader.readline()).split(b";")[0], 16)
                if size == 0:
                    return
                buffer += await reader.readexactly(size)
                await reader.readexactly(2)  # CRLF after each chunk
            elif not (data := await reader.read(65536)):
                return
            else:
                buffer += data
            *lines, buffer = buffer.split(b"\n")
            for line in lines:
                if line.strip():
                    yield json.loads(line)
    finally:
        writer.close()


async def follow(
    queue: asyncio.Queue[Event], socket_path: Path, since: str | None, host: str
) -> None:
    reported: str | None = None
    while True:
        if not socket_path.exists():
            if reported != "missing":
                log.debug("%s not found; Docker source idle until it appears", socket_path)
                reported = "missing"
            await asyncio.sleep(RECHECK_INTERVAL)
            continue
        try:
            async for obj in _read_events(socket_path, since):
                if reported != "connected":
                    log.info("receiving Docker events from %s", socket_path)
                    reported = "connected"
                if event := parse(obj, host):
                    since = event.checkpoint[1] if event.checkpoint else since
                    await queue.put(event)
        except PermissionError:
            if reported != "denied":
                log.warning("no permission for %s; add this user to the docker group", socket_path)
                reported = "denied"
        except (OSError, ConnectionError, ValueError, asyncio.IncompleteReadError) as exc:
            # Daemon stopped or restarting: not worth more than a debug line.
            log.debug("Docker event stream ended: %s", exc)
            if reported == "connected":
                reported = None
        await asyncio.sleep(RECONNECT_DELAY if reported == "connected" else RECHECK_INTERVAL)
