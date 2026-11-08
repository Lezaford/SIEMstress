# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Detection rules: loading from TOML and evaluating against the event stream."""

import logging
import re
import tomllib
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from siemstress.event import Alert, Event, Level
from siemstress.timeutil import parse_duration

log = logging.getLogger(__name__)

DEFAULT_RULES = files("siemstress") / "default_rules.toml"
FIELDS = frozenset(
    {"source", "host", "app", "message", "action", "outcome", "user", "target_user", "src_ip"}
)
_RULE_KEYS = frozenset(
    {"id", "title", "level", "description", "match", "exclude", "group_by", "threshold", "after",
     "cooldown", "mitre"}
)  # fmt: skip
_CONTEXT_FIELDS = ("action", "outcome", "user", "target_user", "src_ip")
_TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
_GC_EVERY = 10_000


class RuleError(ValueError):
    pass


def _get(event: Event, name: str) -> str | None:
    if name.startswith("extra."):
        return event.extra.get(name.removeprefix("extra."))
    value = getattr(event, name)
    return None if value is None else str(value)


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    patterns: tuple[str, ...]  # shell-style globs; any may match

    def test(self, event: Event) -> bool:
        value = _get(event, self.field)
        return value is not None and any(fnmatchcase(value, p) for p in self.patterns)


@dataclass(frozen=True, slots=True)
class Threshold:
    count: int
    window: timedelta


@dataclass(frozen=True, slots=True)
class After:
    """Only fire if `count` events matching `match` came from the same group within `window`."""

    match: tuple[Condition, ...]
    count: int
    window: timedelta

    def matches(self, event: Event) -> bool:
        return all(c.test(event) for c in self.match)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    level: Level
    match: tuple[Condition, ...]
    exclude: tuple[Condition, ...] = ()
    group_by: tuple[str, ...] = ()
    threshold: Threshold | None = None
    after: After | None = None
    cooldown: timedelta = timedelta(0)
    description: str = ""
    mitre: tuple[str, ...] = ()  # ATT&CK technique IDs

    def matches(self, event: Event) -> bool:
        if not all(c.test(event) for c in self.match):
            return False
        return not (self.exclude and all(c.test(event) for c in self.exclude))


class _Defaults(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def _render(template: str, event: Event, count: int) -> str:
    values = _Defaults({f: _get(event, f) or "?" for f in FIELDS})
    values.update(count=count, extra=_Defaults(event.extra))
    return template.format_map(values)


class Engine:
    """Stateful rule evaluation. Feed events in (roughly) chronological order."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._hits: dict[tuple, deque[datetime]] = {}
        self._preceding: dict[tuple, deque[datetime]] = {}
        self._quiet_until: dict[tuple, datetime] = {}
        windows = [r.threshold.window for r in rules if r.threshold]
        windows += [r.after.window for r in rules if r.after]
        self._max_window = max(windows, default=timedelta(0))
        self._processed = 0

    def process(self, event: Event) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if rule.after and rule.after.matches(event):
                self._remember_preceding(rule, event)
            if rule.matches(event) and (alert := self._evaluate(rule, event)):
                alerts.append(alert)
        self._processed += 1
        if self._processed % _GC_EVERY == 0:
            self._gc(event.ts)
        return alerts

    def _remember_preceding(self, rule: Rule, event: Event) -> None:
        key = (rule.id, tuple(_get(event, f) for f in rule.group_by))
        seen = self._preceding.setdefault(key, deque())
        seen.append(event.ts)
        while rule.after and event.ts - seen[0] > rule.after.window:
            seen.popleft()

    def _evaluate(self, rule: Rule, event: Event) -> Alert | None:
        group = tuple(_get(event, f) for f in rule.group_by)
        key = (rule.id, group)
        if (quiet := self._quiet_until.get(key)) and event.ts < quiet:
            return None

        count = 1
        if rule.threshold:
            hits = self._hits.setdefault(key, deque())
            hits.append(event.ts)
            while event.ts - hits[0] > rule.threshold.window:
                hits.popleft()
            if len(hits) < rule.threshold.count:
                return None
            count = len(hits)
            del self._hits[key]

        if rule.after:
            seen = self._preceding.get(key, deque())
            recent = [ts for ts in seen if event.ts - ts <= rule.after.window]
            if len(recent) < rule.after.count:
                return None
            count = len(recent)
            del self._preceding[key]

        if rule.cooldown:
            self._quiet_until[key] = event.ts + rule.cooldown
        # A threshold alert sums many events; only the grouped-by fields are true of all
        # of them. Details like the user of the last attempt would be misleading.
        shared = _CONTEXT_FIELDS if not rule.threshold else ("action", "outcome")
        context = {f: v for f in shared if (v := _get(event, f))}
        context.update((f, v) for f, v in zip(rule.group_by, group, strict=True) if v)
        context["last message" if rule.threshold else "message"] = event.message
        if rule.mitre:
            context["mitre"] = ", ".join(rule.mitre)
        return Alert(
            ts=event.ts,
            rule=rule.id,
            level=rule.level,
            title=_render(rule.title, event, count),
            host=event.host,
            count=count,
            context=context,
        )

    def _gc(self, now: datetime) -> None:
        self._quiet_until = {k: t for k, t in self._quiet_until.items() if t > now}
        self._hits = {k: h for k, h in self._hits.items() if now - h[-1] <= self._max_window}
        self._preceding = {
            k: h for k, h in self._preceding.items() if now - h[-1] <= self._max_window
        }


def _conditions(table: object, where: str) -> tuple[Condition, ...]:
    if not isinstance(table, dict):
        raise RuleError(f"{where}: expected a table of field = pattern(s)")
    conditions = []
    for name, value in table.items():
        # Unquoted `extra.group = ...` in TOML arrives as a nested table.
        if name == "extra" and isinstance(value, dict):
            conditions += _conditions({f"extra.{k}": v for k, v in value.items()}, where)
            continue
        if name not in FIELDS and not name.startswith("extra."):
            raise RuleError(f"{where}: unknown field {name!r}")
        patterns = value if isinstance(value, list) else [value]
        conditions.append(Condition(name, tuple(str(p) for p in patterns)))
    return tuple(conditions)


def parse_rule(data: dict, source: str) -> Rule:
    rule_id = data.get("id")
    where = f"{source}: rule {rule_id or '<missing id>'}"
    if unknown := data.keys() - _RULE_KEYS:
        raise RuleError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("id", "title", "level", "match"):
        if key not in data:
            raise RuleError(f"{where}: missing {key!r}")
    if not data["match"]:
        raise RuleError(f"{where}: match must not be empty")
    level = str(data["level"]).upper()
    if level not in Level.__members__:
        names = ", ".join(lv.name.lower() for lv in Level)
        raise RuleError(f"{where}: level must be one of {names}")
    t = data.get("threshold")
    if t is not None and (not isinstance(t, dict) or t.keys() != {"count", "window"}):
        raise RuleError(f'{where}: threshold must be {{ count = N, window = "5m" }}')
    a = data.get("after")
    if a is not None and (not isinstance(a, dict) or a.keys() != {"match", "count", "window"}):
        raise RuleError(
            f'{where}: after must be {{ match = {{ ... }}, count = N, window = "30m" }}'
        )
    if t and a:
        raise RuleError(f"{where}: use either threshold or after, not both")
    try:
        threshold = t and Threshold(int(t["count"]), parse_duration(t["window"]))
        after = a and After(
            _conditions(a["match"], f"{where} after"), int(a["count"]), parse_duration(a["window"])
        )
        default_cooldown = threshold.window if threshold else timedelta(0)
        cooldown = parse_duration(data["cooldown"]) if "cooldown" in data else default_cooldown
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{where}: {exc}") from None

    mitre = tuple(data.get("mitre", ()))
    if bad := [t for t in mitre if not _TECHNIQUE.fullmatch(str(t))]:
        raise RuleError(f"{where}: mitre expects ATT&CK technique IDs like T1110.001, got {bad}")
    group_by = tuple(data.get("group_by", ()))
    if bad := [f for f in group_by if f not in FIELDS and not f.startswith("extra.")]:
        raise RuleError(f"{where}: unknown group_by fields {bad}")
    rule = Rule(
        id=rule_id,
        title=data["title"],
        level=Level[level],
        match=_conditions(data["match"], where),
        exclude=_conditions(data.get("exclude", {}), where),
        group_by=group_by,
        threshold=threshold or None,
        after=after or None,
        cooldown=cooldown,
        description=data.get("description", ""),
        mitre=mitre,
    )
    try:
        _render(rule.title, Event(ts=datetime.now(), source="check", message=""), 1)
    except (KeyError, IndexError, ValueError, AttributeError) as exc:
        raise RuleError(f"{where}: bad title template: {exc}") from None
    return rule


def _load_file(path: Traversable | Path) -> list[Rule]:
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"{path}: {exc}") from None
    rules = [parse_rule(entry, str(path)) for entry in data.get("rule", [])]
    ids = [r.id for r in rules]
    if dupes := {i for i in ids if ids.count(i) > 1}:
        raise RuleError(f"{path}: duplicate rule ids {sorted(dupes)}")
    return rules


def load_rules(user_dir: Path | None = None, disabled: frozenset[str] = frozenset()) -> list[Rule]:
    """Built-in rules, overridden or extended by *.toml files in `user_dir`."""
    rules = {r.id: r for r in _load_file(DEFAULT_RULES)}
    if user_dir and user_dir.is_dir():
        for path in sorted(user_dir.glob("*.toml")):
            rules.update((r.id, r) for r in _load_file(path))
    if unknown := disabled - rules.keys():
        log.warning("disabled rules not found: %s", ", ".join(sorted(unknown)))
    return [r for r in rules.values() if r.id not in disabled]
