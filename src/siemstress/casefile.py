# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Markdown renderings of an alert's case file and of the alert-handling report."""

from datetime import datetime, timedelta

from siemstress.event import RESOLVED, Activity, Alert, Event, Level
from siemstress.store import Report
from siemstress.triage import ACTIONS, DISPOSITIONS

# Rules closed as false positive at least this often, over at least this many alerts,
# are listed as tuning candidates.
TUNING_FP_RATE = 0.5
TUNING_MIN_ALERTS = 3


def when(ts: datetime | None) -> str:
    return f"{ts.astimezone():%Y-%m-%d %H:%M:%S}" if ts else "-"


def duration(delta: timedelta | None) -> str:
    if delta is None:
        return "-"
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if hours < 48 else f"{hours // 24}d {hours % 24}h"


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def case(alert: Alert, activity: list[Activity], related: list[Event]) -> str:
    rule = alert.rule + (f" (ATT&CK {alert.context['mitre']})" if "mitre" in alert.context else "")
    rows = [
        ("Status", alert.status),
        ("Level", alert.level.name),
        ("Rule", rule),
        ("Host", alert.host or "?"),
        ("Event time", when(alert.ts)),
        ("Raised", when(alert.created)),
        ("Assignee", alert.assignee or "unassigned"),
        ("Acknowledged", _since_raised(alert.acknowledged_at, alert.created)),
        ("Resolved", _since_raised(alert.resolved_at, alert.created)),
    ]
    if alert.status == RESOLVED and alert.disposition:
        rows.append(("Disposition", DISPOSITIONS[alert.disposition].label))
        rows.append(("Actions taken", ", ".join(ACTIONS[a].label for a in alert.actions)))
    lines = [f"# Alert #{alert.id}: {alert.title}", "", "| | |", "|---|---|"]
    lines += [f"| {name} | {_cell(value)} |" for name, value in rows]
    if alert.summary:
        lines += ["", "## Resolution summary", "", alert.summary]

    lines += ["", "## Evidence", ""]
    lines += [f"- **{key}**: {value}" for key, value in alert.context.items() if key != "mitre"]

    lines += ["", f"## Related events ({len(related)})", ""]
    if related:
        lines += [
            "| Time | Host | User | Program | Action | Message |",
            "|---|---|---|---|---|---|",
        ]
        lines += [
            f"| {when(e.ts)} | {_cell(e.host or '')} | {_cell(e.user or '')} "
            f"| {_cell(e.app or '')} | {_cell(f'{e.action} {e.outcome}' if e.action else '')} "
            f"| {_cell(e.message)} |"
            for e in related
        ]
    else:
        lines.append("None on this host with the same address or user.")

    lines += ["", "## Activity", ""]
    lines += [f"- {when(a.ts)} **{a.author}** ({a.kind}): {a.text}" for a in activity] or [
        "No activity yet."
    ]
    return "\n".join(lines) + "\n"


def _since_raised(ts: datetime | None, created: datetime | None) -> str:
    if not ts:
        return "-"
    return f"{when(ts)} (+{duration(ts - created)})" if created else when(ts)


def report(r: Report) -> str:
    unresolved = r.by_status["open"] + r.by_status["acknowledged"]
    lines = [
        f"# Alert report since {when(r.since)}",
        "",
        f"- **Alerts:** {r.alerts} ({unresolved} unresolved)",
        f"- **Median time to acknowledge:** {duration(r.median_time_to_acknowledge)}",
        f"- **Median time to resolve:** {duration(r.median_time_to_resolve)}",
    ]
    if r.oldest_unresolved:
        a = r.oldest_unresolved
        lines.append(f"- **Oldest unresolved:** #{a.id} {a.title} ({when(a.ts)})")

    lines += ["", "## By level", "", "| Level | Alerts |", "|---|---|"]
    lines += [f"| {level.name} | {r.by_level[level]} |" for level in reversed(Level)]

    resolved = sum(r.by_disposition.values())
    lines += ["", f"## Dispositions ({resolved} resolved)", "", "| Disposition | Alerts | Share |",
              "|---|---|---|"]  # fmt: skip
    for code, choice in DISPOSITIONS.items():
        n = r.by_disposition.get(code, 0)
        lines.append(f"| {choice.label} | {n} | {n / resolved:.0%} |" if resolved else
                     f"| {choice.label} | 0 | - |")  # fmt: skip

    lines += ["", "## By rule", "", "| Rule | Alerts | False positives | Unresolved |",
              "|---|---|---|---|"]  # fmt: skip
    lines += [
        f"| {x.rule} | {x.alerts} | {x.false_positives} | {x.unresolved} |" for x in r.by_rule
    ]
    tuning = [
        x.rule
        for x in r.by_rule
        if x.alerts >= TUNING_MIN_ALERTS and x.false_positives / x.alerts >= TUNING_FP_RATE
    ]
    if tuning:
        lines += ["", f"**Tuning candidates** (mostly false positives): {', '.join(tuning)}"]
    return "\n".join(lines) + "\n"
