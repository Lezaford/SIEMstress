# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

SUCCESS = "success"
FAILURE = "failure"

# Alert lifecycle: new alerts are open until someone acknowledges or resolves them.
OPEN = "open"
ACKNOWLEDGED = "acknowledged"
RESOLVED = "resolved"
STATUSES = (OPEN, ACKNOWLEDGED, RESOLVED)


class Severity(IntEnum):
    EMERG = 0
    ALERT = 1
    CRIT = 2
    ERR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


@dataclass(slots=True)
class Event:
    ts: datetime
    source: str
    message: str
    host: str | None = None
    app: str | None = None
    pid: int | None = None
    severity: int | None = None
    facility: int | None = None
    extra: dict[str, str] = field(default_factory=dict)
    # Normalized fields, filled in by siemstress.parsers for events they recognize.
    action: str | None = None
    outcome: str | None = None
    user: str | None = None
    target_user: str | None = None
    src_ip: str | None = None
    # Source position (state key, value) saved with the batch so a restart resumes
    # after this event. Not persisted with the event itself.
    checkpoint: tuple[str, str] | None = None


class Level(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(slots=True)
class Alert:
    ts: datetime  # time of the event that triggered it
    rule: str
    level: Level
    title: str
    host: str | None = None
    count: int = 1
    context: dict[str, str] = field(default_factory=dict)
    id: int | None = None  # assigned by the store
    status: str = OPEN
    status_by: str | None = None
    status_at: datetime | None = None
    # Case handling (see siemstress.triage)
    assignee: str | None = None
    disposition: str | None = None
    actions: tuple[str, ...] = ()
    summary: str | None = None
    created: datetime | None = None
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Activity:
    """One entry in an alert's append-only case log."""

    ts: datetime
    author: str
    kind: str  # note, acknowledged, assigned, resolved, reopened
    text: str
