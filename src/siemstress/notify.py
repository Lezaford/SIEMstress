# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging
import urllib.request
from datetime import UTC, datetime, timedelta

from siemstress.config import NtfySettings
from siemstress.event import Alert, Level

log = logging.getLogger(__name__)

# Alerts on older events (e.g. from the first-run backfill) are stored but not pushed.
MAX_AGE = timedelta(minutes=15)
TIMEOUT = 10

_PRIORITY = {Level.LOW: 2, Level.MEDIUM: 3, Level.HIGH: 4, Level.CRITICAL: 5}
_TAG = {Level.LOW: "information_source", Level.MEDIUM: "warning",
        Level.HIGH: "rotating_light", Level.CRITICAL: "skull"}  # fmt: skip


class Ntfy:
    def __init__(self, settings: NtfySettings):
        self.settings = settings

    def send(self, alert: Alert) -> None:
        lines = [f"{alert.host or '?'} at {alert.ts.astimezone():%Y-%m-%d %H:%M:%S}"]
        lines += [f"{k}: {v}" for k, v in alert.context.items()]
        payload = {
            "topic": self.settings.topic,
            "title": alert.title,
            "message": "\n".join(lines),
            "priority": _PRIORITY[alert.level],
            "tags": [_TAG[alert.level], alert.rule],
        }
        headers = {"Content-Type": "application/json"}
        if self.settings.token:
            headers["Authorization"] = f"Bearer {self.settings.token}"
        # ntfy accepts JSON at the server root; this avoids non-ASCII header issues.
        request = urllib.request.Request(
            self.settings.server, data=json.dumps(payload).encode(), headers=headers
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT):
            pass


async def deliver(queue: asyncio.Queue[Alert], notifier: Ntfy) -> None:
    min_level = notifier.settings.min_level
    while True:
        alert = await queue.get()
        if alert.level < min_level:
            continue
        if datetime.now(UTC) - alert.ts > MAX_AGE:
            log.debug("not pushing stale alert %s from %s", alert.rule, alert.ts)
            continue
        try:
            await asyncio.to_thread(notifier.send, alert)
        except OSError as exc:
            log.warning("failed to send %s notification: %s", alert.rule, exc)
