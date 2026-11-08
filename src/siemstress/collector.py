# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import logging
import signal
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siemstress import notify
from siemstress.config import NtfySettings, SyslogSettings
from siemstress.detect import Engine, Rule
from siemstress.event import Alert, Event
from siemstress.identity import local_host
from siemstress.parsers import normalize
from siemstress.scope import Scope
from siemstress.sources import docker, journald, logfile, syslog
from siemstress.store import Store

log = logging.getLogger(__name__)

QUEUE_SIZE = 10_000
ALERT_QUEUE_SIZE = 1_000
FLUSH_INTERVAL = 1.0
PRUNE_INTERVAL = 3600


@dataclass(frozen=True, slots=True)
class Config:
    db_path: Path
    hostname: str | None = None
    syslog: SyslogSettings = field(default_factory=SyslogSettings)
    backfill: str = "24h"
    retention: timedelta = timedelta(days=30)
    rules: list[Rule] = field(default_factory=list)
    ntfy: NtfySettings | None = None
    journal: bool = True
    docker_socket: Path | None = None
    log_files: tuple[Path, ...] = ()
    scope: Scope = field(default_factory=Scope)


class Pipeline:
    """Normalize, detect and store one batch of events at a time."""

    def __init__(
        self,
        store: Store,
        engine: Engine,
        alerts: asyncio.Queue[Alert] | None = None,
        scope: Scope | None = None,
    ):
        self.store = store
        self.engine = engine
        self.alerts = alerts
        self.scope = scope or Scope()

    def flush(self, batch: list[Event]) -> None:
        if not batch:
            return
        kept: list[Event] = []
        found: list[Alert] = []
        for event in batch:
            # A parser or rule bug must never cost us the raw event.
            try:
                normalize(event)
            except Exception:
                log.exception("failed to normalize %r", event.message)
            if not self.scope.allows(event):
                continue
            kept.append(event)
            try:
                found += self.engine.process(event)
            except Exception:
                log.exception("failed to evaluate rules for %r", event.message)
        if dropped := len(batch) - len(kept):
            log.debug("dropped %d events outside the configured scope", dropped)

        # Sources resume after dropped events too. Last checkpoint per source wins.
        state = dict(e.checkpoint for e in batch if e.checkpoint)
        self.store.insert(kept, state, alerts=found)

        for alert in found:
            log.warning("alert [%s] %s", alert.rule, alert.title)
            if self.alerts is None:
                continue
            try:
                self.alerts.put_nowait(alert)
            except asyncio.QueueFull:
                log.error("notification queue full, dropping %s", alert.rule)


async def _write(pipeline: Pipeline, queue: asyncio.Queue[Event]) -> None:
    # Batching turns thousands of per-line transactions into one per second.
    batch: list[Event] = []
    try:
        while True:
            batch.append(await queue.get())
            await asyncio.sleep(FLUSH_INTERVAL)
            while not queue.empty():
                batch.append(queue.get_nowait())
            pipeline.flush(batch)
            batch.clear()
    finally:
        while not queue.empty():
            batch.append(queue.get_nowait())
        pipeline.flush(batch)


async def _prune(store: Store, retention: timedelta) -> None:
    while True:
        if removed := store.prune(datetime.now(UTC) - retention):
            log.info("pruned %d events older than %s", removed, retention)
        await asyncio.sleep(PRUNE_INTERVAL)


async def run(config: Config) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=QUEUE_SIZE)
    alerts: asyncio.Queue[Alert] | None = (
        asyncio.Queue(maxsize=ALERT_QUEUE_SIZE) if config.ntfy else None
    )
    local = local_host(config.hostname)
    if local.generic:
        log.warning(
            "this machine has no static hostname, so its events are labeled %r; set one with "
            "`sudo hostnamectl set-hostname NAME` or `hostname = ...` in config.toml",
            local.name,
        )
    if config.scope:
        log.info("scope: %s", config.scope.describe())
    if config.journal and not config.scope.includes_host(local.name):
        log.warning("this machine (%s) is outside [scope], so its journal is dropped", local.name)
    with Store(config.db_path) as store:
        log.info("%s: writing to %s with %d rules", local.name, config.db_path, len(config.rules))
        pipeline = Pipeline(store, Engine(config.rules), alerts, config.scope)
        async with asyncio.TaskGroup() as tg:
            consumers = [tg.create_task(_write(pipeline, queue))]
            if config.ntfy and alerts:
                consumers.append(tg.create_task(notify.deliver(alerts, notify.Ntfy(config.ntfy))))
            producers = [tg.create_task(_prune(store, config.retention))]
            if config.journal:
                cursor = store.get_state(journald.CURSOR_KEY)
                producers.append(
                    tg.create_task(journald.follow(queue, cursor, config.backfill, local))
                )
            server = syslog.SyslogServer(queue, syslog.Senders(config.syslog.senders, local.name))
            if listen := config.syslog.listen:
                producers.append(tg.create_task(server.serve(*listen, udp=config.syslog.udp)))
            if tls := config.syslog.tls:
                context = syslog.tls_context(tls.cert, tls.key, tls.ca)
                producers.append(tg.create_task(server.serve_tls(*tls.listen, context)))
            if config.docker_socket:
                since = store.get_state(docker.STATE_KEY)
                producers.append(
                    tg.create_task(docker.follow(queue, config.docker_socket, since, local.name))
                )
            for path in config.log_files:
                checkpoint = store.get_state(logfile.state_key(path))
                producers.append(
                    tg.create_task(logfile.follow(queue, path, checkpoint, local.name))
                )

            await stop.wait()
            log.info("shutting down")
            # Stop producers, then the writer (whose final flush may raise alerts),
            # then the notifier.
            for task in (*producers, *consumers):
                task.cancel()
                await asyncio.wait([task])
