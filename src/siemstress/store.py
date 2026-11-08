# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sqlite3
import stat
from collections import Counter
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siemstress.event import (
    ACKNOWLEDGED,
    OPEN,
    RESOLVED,
    STATUSES,
    Activity,
    Alert,
    Event,
    Level,
)
from siemstress.timeutil import from_us, to_us
from siemstress.triage import (
    FALSE_POSITIVE,
    TriageError,
    check_resolution,
    describe,
)

# Each entry upgrades the schema by one version (tracked in PRAGMA user_version).
# Never edit a released migration; append a new one.
MIGRATIONS = [
    """
    CREATE TABLE events (
        id       INTEGER PRIMARY KEY,
        ts       INTEGER NOT NULL,  -- unix microseconds, UTC
        received INTEGER NOT NULL,
        source   TEXT NOT NULL,
        host     TEXT,
        app      TEXT,
        pid      INTEGER,
        severity INTEGER,
        facility INTEGER,
        message  TEXT NOT NULL,
        extra    TEXT               -- JSON object
    );
    CREATE INDEX events_ts ON events (ts);
    CREATE INDEX events_host_ts ON events (host, ts);
    CREATE INDEX events_app_ts ON events (app, ts);

    CREATE TABLE state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    """
    ALTER TABLE events ADD COLUMN action TEXT;
    ALTER TABLE events ADD COLUMN outcome TEXT;
    ALTER TABLE events ADD COLUMN user TEXT;
    ALTER TABLE events ADD COLUMN target_user TEXT;
    ALTER TABLE events ADD COLUMN src_ip TEXT;
    -- Partial indexes: only the small fraction of events that were normalized.
    CREATE INDEX events_action_ts ON events (action, ts) WHERE action IS NOT NULL;
    CREATE INDEX events_user_ts ON events (user, ts) WHERE user IS NOT NULL;
    CREATE INDEX events_src_ip_ts ON events (src_ip, ts) WHERE src_ip IS NOT NULL;
    """,
    """
    CREATE TABLE alerts (
        id      INTEGER PRIMARY KEY,
        ts      INTEGER NOT NULL,  -- triggering event time, unix microseconds
        created INTEGER NOT NULL,
        rule    TEXT NOT NULL,
        level   INTEGER NOT NULL,
        title   TEXT NOT NULL,
        host    TEXT,
        count   INTEGER NOT NULL,
        context TEXT               -- JSON object
    );
    CREATE INDEX alerts_ts ON alerts (ts);
    """,
    """
    ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
    ALTER TABLE alerts ADD COLUMN status_by TEXT;
    ALTER TABLE alerts ADD COLUMN status_at INTEGER;
    """,
    """
    ALTER TABLE alerts ADD COLUMN assignee TEXT;
    ALTER TABLE alerts ADD COLUMN disposition TEXT;
    ALTER TABLE alerts ADD COLUMN actions TEXT;      -- JSON list of triage action codes
    ALTER TABLE alerts ADD COLUMN summary TEXT;
    ALTER TABLE alerts ADD COLUMN acknowledged_at INTEGER;
    ALTER TABLE alerts ADD COLUMN resolved_at INTEGER;
    UPDATE alerts SET resolved_at = status_at WHERE status = 'resolved';
    UPDATE alerts SET acknowledged_at = status_at WHERE status = 'acknowledged';
    CREATE INDEX alerts_status ON alerts (status, ts);

    -- Append-only case log: notes and every change to an alert, with who and when.
    CREATE TABLE alert_activity (
        id       INTEGER PRIMARY KEY,
        alert_id INTEGER NOT NULL REFERENCES alerts (id),
        ts       INTEGER NOT NULL,
        author   TEXT NOT NULL,
        kind     TEXT NOT NULL,
        text     TEXT NOT NULL
    );
    CREATE INDEX alert_activity_alert ON alert_activity (alert_id, ts);
    """,
]

# Event fields persisted as columns, in a fixed order shared by INSERT and SELECT.
_COLUMNS = (
    "ts", "source", "message", "host", "app", "pid", "severity", "facility", "extra",
    "action", "outcome", "user", "target_user", "src_ip",
)  # fmt: skip
_TS, _EXTRA = _COLUMNS.index("ts"), _COLUMNS.index("extra")
_INSERT = (
    f"INSERT INTO events (received, {', '.join(_COLUMNS)})"
    f" VALUES ({', '.join('?' * (len(_COLUMNS) + 1))})"
)


def _to_row(e: Event) -> list:
    row = [getattr(e, c) for c in _COLUMNS]
    row[_TS] = to_us(e.ts)
    row[_EXTRA] = json.dumps(e.extra) if e.extra else None
    return row


_ALERT_COLUMNS = (
    "ts, rule, level, title, host, count, context, id, status, status_by, status_at,"
    " assignee, disposition, actions, summary, created, acknowledged_at, resolved_at"
)


def _alert_from_row(row: tuple) -> Alert:
    (ts, rule, level, title, host, count, context, id, status, by, at,
     assignee, disposition, actions, summary, created, acked, resolved) = row  # fmt: skip

    def when(us: int | None) -> datetime | None:
        return None if us is None else from_us(us)

    return Alert(
        from_us(ts), rule, Level(level), title, host, count,
        json.loads(context) if context else {}, id, status, by, when(at),
        assignee, disposition, tuple(json.loads(actions)) if actions else (), summary,
        when(created), when(acked), when(resolved),
    )  # fmt: skip


def _from_row(row: tuple) -> Event:
    fields = dict(zip(_COLUMNS, row, strict=True))
    fields["ts"] = from_us(fields["ts"])
    fields["extra"] = json.loads(fields["extra"]) if fields["extra"] else {}
    return Event(**fields)


class StoreError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class HostStatus:
    host: str
    last_seen: datetime
    recent_events: int
    users: tuple[str, ...] = ()  # accounts seen in the window, busiest first


@dataclass(frozen=True, slots=True)
class Overview:
    since: datetime
    bucket: timedelta
    events: int
    timeline: list[int]  # event counts per bucket, oldest first
    unresolved_by_level: dict[Level, int]
    auth_failures: int
    top_failing_ips: list[tuple[str, int]]
    hosts: list[HostStatus]


@dataclass(frozen=True, slots=True)
class RuleReport:
    rule: str
    alerts: int
    false_positives: int
    unresolved: int


@dataclass(frozen=True, slots=True)
class Report:
    """Alert-handling metrics over a period, for triage review and tuning."""

    since: datetime
    alerts: int
    by_level: dict[Level, int]
    by_status: dict[str, int]
    by_disposition: dict[str, int]
    by_rule: list[RuleReport]
    median_time_to_acknowledge: timedelta | None
    median_time_to_resolve: timedelta | None
    oldest_unresolved: Alert | None


def _median(values: list[timedelta]) -> timedelta | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


@dataclass(slots=True)
class Stats:
    total: int
    oldest: datetime | None
    by_host: list[tuple[str, str, int]]
    by_app: list[tuple[str, int]]
    by_action: list[tuple[str, str, int]]


class Store:
    def __init__(self, path: Path, *, viewer: bool = False):
        """Open the database.

        The collector (default) creates and migrates it. Viewers (dashboards, alert
        commands) never create or migrate the collector's database; they only read it
        and update alert status, waiting briefly if the collector holds the write lock.
        """
        self.path = path
        if viewer:
            if not path.exists():
                raise StoreError(f"{path} does not exist; start the collector first")
            self.db = sqlite3.connect(path, timeout=5)
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version != len(MIGRATIONS):
                raise StoreError(
                    f"{path} is at schema v{version}, expected v{len(MIGRATIONS)};"
                    " run the collector once to upgrade it"
                )
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA synchronous = NORMAL")
        self._share_with_group()
        self._migrate()

    def _share_with_group(self) -> None:
        """Make the database group-writable in a shared (setgid) directory.

        Packaged installs keep it in /var/lib/siemstress, owned by the siemstress group,
        whose members work alerts from the dashboards. SQLite creates files 0644 minus
        the umask, which would leave them read-only; its -wal and -shm files copy the
        main file's mode.

        Anywhere else (a per-user install) the database holds logins, addresses and
        commands, so it is kept private to its owner.
        """
        shared = bool(self.path.parent.stat().st_mode & stat.S_ISGID)
        for suffix in ("", "-wal", "-shm"):
            file = self.path.with_name(self.path.name + suffix)
            if not file.exists():
                continue
            mode = file.stat().st_mode & 0o777
            if shared and mode & 0o060 != 0o060:
                file.chmod(0o660)
            elif not shared and mode & 0o077:
                file.chmod(0o600)

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()

    def _migrate(self) -> None:
        current = self.db.execute("PRAGMA user_version").fetchone()[0]
        for version, sql in enumerate(MIGRATIONS[current:], start=current + 1):
            self.db.executescript(f"BEGIN; {sql}; PRAGMA user_version = {version}; COMMIT;")

    def insert(
        self,
        events: Iterable[Event],
        state: dict[str, str] | None = None,
        *,
        alerts: Iterable[Alert] = (),
    ) -> None:
        now = to_us(datetime.now(UTC))
        with self.db:
            self.db.executemany(_INSERT, ([now, *_to_row(e)] for e in events))
            self.db.executemany(
                "INSERT INTO alerts (ts, created, rule, level, title, host, count, context)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (to_us(a.ts), now, a.rule, a.level, a.title, a.host, a.count,
                     json.dumps(a.context) if a.context else None)
                    for a in alerts
                ),
            )  # fmt: skip
            if state:
                self.db.executemany(
                    "INSERT INTO state (key, value) VALUES (?, ?)"
                    " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    state.items(),
                )

    def get_state(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def prune(self, before: datetime) -> int:
        with self.db:
            return self.db.execute("DELETE FROM events WHERE ts < ?", (to_us(before),)).rowcount

    def search(
        self,
        *,
        since: datetime | None = None,
        host: str | None = None,
        app: str | None = None,
        text: str | None = None,
        max_severity: int | None = None,
        action: str | None = None,
        outcome: str | None = None,
        user: str | None = None,
        src_ip: str | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Return the newest `limit` matching events in chronological order."""
        filters = {
            "ts >= ?": since and to_us(since),
            "host LIKE ?": host and f"%{host}%",
            "app = ?": app,
            "message LIKE ?": text and f"%{text}%",
            "severity <= ?": max_severity,
            # "ssh" matches ssh.login, ssh.invalid_user, ...
            "(action = ? OR action LIKE ? || '.%')": action,
            "outcome = ?": outcome,
            "(user = ? OR target_user = ?)": user,
            "src_ip = ?": src_ip,
        }
        clauses, args = [], []
        for sql, arg in filters.items():
            if arg is not None:
                clauses.append(sql)
                args.extend([arg] * sql.count("?"))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM events {where} ORDER BY ts DESC, id DESC LIMIT ?",
            [*args, limit],
        ).fetchall()
        return [_from_row(row) for row in reversed(rows)]

    def iter_events(self, since: datetime | None = None) -> Iterator[Event]:
        """Yield stored events in chronological order without loading them all."""
        cursor = self.db.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM events WHERE ts >= ? ORDER BY ts, id",
            (to_us(since) if since else 0,),
        )
        for row in cursor:
            yield _from_row(row)

    def alerts(
        self,
        *,
        since: datetime | None = None,
        rule: str | None = None,
        min_level: Level | None = None,
        statuses: Collection[str] = STATUSES,
        after_id: int = 0,
        limit: int = 50,
    ) -> list[Alert]:
        """Return the newest `limit` matching alerts in chronological order."""
        rows = self.db.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts"
            " WHERE ts >= ? AND (? IS NULL OR rule = ?) AND level >= ? AND id > ?"
            f" AND status IN ({', '.join('?' * len(statuses))})"
            " ORDER BY ts DESC, id DESC LIMIT ?",
            (to_us(since) if since else 0, rule, rule, min_level or 0, after_id, *statuses, limit),
        ).fetchall()
        return [_alert_from_row(row) for row in reversed(rows)]

    def alert(self, alert_id: int) -> Alert | None:
        row = self.db.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return row and _alert_from_row(row)

    def activity(self, alert_id: int) -> list[Activity]:
        return [
            Activity(from_us(ts), author, kind, text)
            for ts, author, kind, text in self.db.execute(
                "SELECT ts, author, kind, text FROM alert_activity WHERE alert_id = ? ORDER BY id",
                (alert_id,),
            )
        ]

    # Case handling. Each change and its log entry are written in one transaction, so
    # the activity log is a complete audit trail of the alert.

    def _change(self, ids: Iterable[int], sql: str, params: dict, by: str, kind: str,
                text: str) -> int:  # fmt: skip
        """Run `sql` (named parameters; :id, :now and :by are provided) for each alert
        and log the change for each one it actually modified."""
        now = to_us(datetime.now(UTC))
        changed = []
        with self.db:
            for alert_id in ids:
                args = {**params, "id": alert_id, "now": now, "by": by}
                returning = "" if sql.startswith("SELECT") else " RETURNING id"
                if self.db.execute(sql + returning, args).fetchone():
                    changed.append(alert_id)
            self.db.executemany(
                "INSERT INTO alert_activity (alert_id, ts, author, kind, text)"
                " VALUES (?, ?, ?, ?, ?)",
                [(alert_id, now, by, kind, text) for alert_id in changed],
            )
        return len(changed)

    def acknowledge(self, ids: Iterable[int], by: str) -> int:
        """Mark open alerts as being worked on, taking ownership of unowned ones."""
        return self._change(
            ids,
            "UPDATE alerts SET status = :acknowledged, status_by = :by, status_at = :now,"
            " assignee = COALESCE(assignee, :by), acknowledged_at = COALESCE(acknowledged_at, :now)"
            " WHERE id = :id AND status = :open",
            {"acknowledged": ACKNOWLEDGED, "open": OPEN},
            by, "acknowledged", "Acknowledged",
        )  # fmt: skip

    def assign(self, ids: Iterable[int], assignee: str, by: str) -> int:
        return self._change(
            ids,
            "UPDATE alerts SET assignee = :assignee, status_by = :by, status_at = :now"
            " WHERE id = :id AND assignee IS NOT :assignee",
            {"assignee": assignee},
            by, "assigned", f"Assigned to {assignee}",
        )  # fmt: skip

    def add_note(self, ids: Iterable[int], by: str, text: str) -> int:
        if not text.strip():
            raise TriageError("a note needs some text")
        return self._change(ids, "SELECT id FROM alerts WHERE id = :id", {}, by, "note",
                            text.strip())  # fmt: skip

    def resolve(self, ids: Iterable[int], by: str, disposition: str, actions: list[str],
                summary: str) -> int:  # fmt: skip
        """Close alerts with a disposition, the actions taken and a summary."""
        check_resolution(disposition, actions, summary)
        summary = summary.strip()
        return self._change(
            ids,
            "UPDATE alerts SET status = :resolved, status_by = :by, status_at = :now,"
            " disposition = :disposition, actions = :actions, summary = :summary,"
            " assignee = COALESCE(assignee, :by), resolved_at = :now,"
            " acknowledged_at = COALESCE(acknowledged_at, :now)"
            " WHERE id = :id AND status != :resolved",
            {"resolved": RESOLVED, "disposition": disposition, "actions": json.dumps(actions),
             "summary": summary},
            by, "resolved", f"Resolved: {describe(disposition, tuple(actions))}. {summary}",
        )  # fmt: skip

    def reopen(self, ids: Iterable[int], by: str, reason: str) -> int:
        if len(reason.strip()) < 3:
            raise TriageError("say why the alert is being reopened")
        return self._change(
            ids,
            "UPDATE alerts SET status = :open, status_by = :by, status_at = :now,"
            " disposition = NULL, actions = NULL, summary = NULL, resolved_at = NULL"
            " WHERE id = :id AND status = :resolved",
            {"open": OPEN, "resolved": RESOLVED},
            by, "reopened", f"Reopened: {reason.strip()}",
        )  # fmt: skip

    def related_events(
        self, alert: Alert, window: timedelta = timedelta(minutes=30), limit: int = 200
    ) -> list[Event]:
        """Events on the alert's host around its time that share its address or users."""
        people = {alert.context.get(k) for k in ("user", "target_user")} - {None}
        ip = alert.context.get("src_ip")
        if not ip and not people:
            return []
        marks = ", ".join("?" * len(people)) or "NULL"
        rows = self.db.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM events"
            " WHERE ts BETWEEN ? AND ? AND host IS ?"
            f" AND (src_ip = ? OR user IN ({marks}) OR target_user IN ({marks}))"
            " ORDER BY ts LIMIT ?",
            (to_us(alert.ts - window), to_us(alert.ts + window), alert.host, ip,
             *people, *people, limit),
        ).fetchall()  # fmt: skip
        return [_from_row(row) for row in rows]

    def report(self, since: datetime) -> Report:
        alerts = self.alerts(since=since, limit=1_000_000)
        by_rule: dict[str, list[Alert]] = {}
        for a in alerts:
            by_rule.setdefault(a.rule, []).append(a)

        unresolved = [a for a in alerts if a.status != RESOLVED]
        rules = [
            RuleReport(
                rule,
                alerts=len(group),
                false_positives=sum(a.disposition == FALSE_POSITIVE for a in group),
                unresolved=sum(a.status != RESOLVED for a in group),
            )
            for rule, group in by_rule.items()
        ]
        return Report(
            since=since,
            alerts=len(alerts),
            by_level={lv: sum(a.level == lv for a in alerts) for lv in Level},
            by_status={s: sum(a.status == s for a in alerts) for s in STATUSES},
            by_disposition=dict(Counter(a.disposition for a in alerts if a.disposition)),
            by_rule=sorted(rules, key=lambda r: (-r.alerts, r.rule)),
            median_time_to_acknowledge=_median(
                [a.acknowledged_at - a.created for a in alerts if a.acknowledged_at and a.created]
            ),
            median_time_to_resolve=_median(
                [a.resolved_at - a.created for a in alerts if a.resolved_at and a.created]
            ),
            oldest_unresolved=min(unresolved, key=lambda a: a.ts, default=None),
        )

    def overview(self, since: datetime, buckets: int = 24) -> Overview:
        """Everything a dashboard's summary view needs, for events since `since`."""
        start = to_us(since)
        bucket_us = max(1, (to_us(datetime.now(UTC)) - start) // buckets)
        timeline = [0] * buckets
        for index, count in self.db.execute(
            "SELECT (ts - ?) / ?, COUNT(*) FROM events WHERE ts >= ? GROUP BY 1",
            (start, bucket_us, start),
        ):
            timeline[min(index, buckets - 1)] += count
        by_level = dict(
            self.db.execute(
                "SELECT level, COUNT(*) FROM alerts WHERE ts >= ? AND status != ? GROUP BY level",
                (start, RESOLVED),
            ).fetchall()
        )
        auth_failures = self.db.execute(
            "SELECT COUNT(*) FROM events"
            " WHERE action IS NOT NULL AND outcome = 'failure' AND ts >= ?",
            (start,),
        ).fetchone()[0]
        top_ips = self.db.execute(
            "SELECT src_ip, COUNT(*) AS n FROM events"
            " WHERE src_ip IS NOT NULL AND outcome = 'failure' AND ts >= ?"
            " GROUP BY src_ip ORDER BY n DESC LIMIT 10",
            (start,),
        ).fetchall()
        users: dict[str, list[str]] = {}
        for host, user in self.db.execute(
            # Failed attempts name accounts an attacker guessed, not users of the host.
            "SELECT host, user FROM events"
            " WHERE ts >= ? AND host IS NOT NULL AND user IS NOT NULL"
            " AND outcome IS NOT 'failure'"
            " GROUP BY host, user ORDER BY COUNT(*) DESC",
            (start,),
        ):
            users.setdefault(host, []).append(user)
        hosts = [
            HostStatus(host, from_us(last), recent, tuple(users.get(host, ())))
            for host, last, recent in self.db.execute(
                "SELECT host, MAX(ts), SUM(ts >= ?) FROM events WHERE host IS NOT NULL"
                " GROUP BY host ORDER BY MAX(ts) DESC",
                (start,),
            )
        ]
        return Overview(
            since=since,
            bucket=from_us(bucket_us) - from_us(0),
            events=sum(timeline),
            timeline=timeline,
            unresolved_by_level={lv: by_level.get(lv.value, 0) for lv in Level},
            auth_failures=auth_failures,
            top_failing_ips=top_ips,
            hosts=hosts,
        )

    def stats(self, since: datetime) -> Stats:
        total, oldest = self.db.execute("SELECT COUNT(*), MIN(ts) FROM events").fetchone()
        since_us = to_us(since)

        def query(sql: str) -> list[tuple]:
            return self.db.execute(sql, (since_us,)).fetchall()

        return Stats(
            total=total,
            oldest=oldest and from_us(oldest),
            by_host=query(
                "SELECT COALESCE(host, '?'), source, COUNT(*) AS n FROM events WHERE ts >= ?"
                " GROUP BY host, source ORDER BY n DESC"
            ),
            by_app=query(
                "SELECT COALESCE(app, '?'), COUNT(*) AS n FROM events WHERE ts >= ?"
                " GROUP BY app ORDER BY n DESC LIMIT 15"
            ),
            by_action=query(
                "SELECT action, COALESCE(outcome, '-'), COUNT(*) AS n FROM events"
                " WHERE ts >= ? AND action IS NOT NULL"
                " GROUP BY action, outcome ORDER BY n DESC"
            ),
        )
