# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import getpass
import importlib
import logging
import shutil
import socket
import sys
import types
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siemstress import __version__, casefile, doctor
from siemstress.collector import Config, run
from siemstress.config import (
    ConfigError,
    Settings,
    load_settings,
    parse_bind,
)
from siemstress.detect import Engine, Rule, RuleError, load_rules
from siemstress.event import (
    ACKNOWLEDGED,
    FAILURE,
    OPEN,
    RESOLVED,
    STATUSES,
    SUCCESS,
    Alert,
    Event,
    Level,
    Severity,
)
from siemstress.notify import Ntfy
from siemstress.parsers import normalize
from siemstress.paths import (
    DATA_HOME,
    SYSTEM_CONFIG,
    SYSTEM_DB,
    USER_CONFIG,
    USER_DB,
    default_config,
    default_db,
)
from siemstress.store import Store, StoreError
from siemstress.timeutil import parse_duration
from siemstress.triage import ACTIONS, DISPOSITIONS, TriageError, check_resolution
from siemstress.ui import ASSETS, ICON_SIZES, STATUS_MARKERS


def duration(text: str) -> timedelta:
    try:
        return parse_duration(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def severity(text: str) -> Severity:
    try:
        return Severity(int(text)) if text.isdigit() else Severity[text.upper()]
    except (KeyError, ValueError):
        names = ", ".join(s.name.lower() for s in Severity)
        raise argparse.ArgumentTypeError(f"invalid severity {text!r} (0-7 or {names})") from None


def level(text: str) -> Level:
    try:
        return Level[text.upper()]
    except KeyError:
        names = ", ".join(lv.name.lower() for lv in Level)
        raise argparse.ArgumentTypeError(f"invalid level {text!r} ({names})") from None


def bind_address(text: str) -> tuple[str, int] | str:
    try:
        return parse_bind(text) or "off"
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def format_event(e: Event) -> str:
    sev = Severity(e.severity).name.lower() if e.severity is not None else "-"
    host = (e.host or "?").split(".")[0]
    app = f"{e.app or '?'}[{e.pid}]" if e.pid else e.app or "?"
    tag = ""
    if e.action:
        labels = (
            e.action,
            e.outcome,
            e.user and f"user={e.user}",
            e.target_user and f"target={e.target_user}",
            e.src_ip and f"src={e.src_ip}",
        )
        tag = f"[{' '.join(filter(None, labels))}] "
    user = e.user or "-"
    return (
        f"{e.ts.astimezone():%Y-%m-%d %H:%M:%S}  {sev:<7}  {host:<14}  {user:<10}"
        f"  {app}: {tag}{e.message}"
    )


def format_alert(a: Alert) -> str:
    host = (a.host or "?").split(".")[0]
    user = a.context.get("user", "-")
    ident = f"#{a.id:<5} {STATUS_MARKERS[a.status]} " if a.id else ""
    owner = f"  [{a.assignee}]" if a.assignee and a.status != RESOLVED else ""
    closed = f"  [{DISPOSITIONS[a.disposition].label}]" if a.disposition else ""
    return (
        f"{ident}{a.ts.astimezone():%Y-%m-%d %H:%M:%S}  {a.level.name:<8}  {host:<14}"
        f"  {user:<10}  {a.title}{owner}{closed}"
    )


def load(args: argparse.Namespace) -> tuple[Settings, list[Rule]]:
    settings = load_settings(args.config)
    rules = load_rules(args.config.parent / "rules", settings.disabled_rules)
    return settings, rules


def cmd_run(args: argparse.Namespace) -> None:
    settings, rules = load(args)
    config = Config(
        db_path=args.db,
        hostname=settings.hostname,
        syslog=settings.syslog
        if args.syslog is None
        else replace(settings.syslog, listen=None if args.syslog == "off" else args.syslog),
        backfill=args.backfill,
        retention=timedelta(days=args.retention_days),
        rules=rules,
        ntfy=settings.ntfy,
        journal=settings.journal,
        docker_socket=settings.docker_socket,
        log_files=settings.log_files,
        scope=settings.scope,
    )
    asyncio.run(run(config))


STATUS_FILTERS = {
    "unresolved": (OPEN, ACKNOWLEDGED),
    "open": (OPEN,),
    "acknowledged": (ACKNOWLEDGED,),
    "resolved": (RESOLVED,),
    "all": STATUSES,
}


def cmd_alerts(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        alerts = store.alerts(
            since=args.since and datetime.now(UTC) - args.since,
            rule=args.rule,
            min_level=args.level,
            statuses=STATUS_FILTERS[args.status],
            limit=args.limit,
        )
    if not alerts:
        print("no matching alerts", file=sys.stderr)
    for alert in alerts:
        print(format_alert(alert))


def _choose(title: str, choices: dict, many: bool = False) -> list[str]:
    """Numbered menu on the terminal; returns the chosen codes."""
    print(title)
    codes = list(choices)
    for n, code in enumerate(codes, start=1):
        print(f"  {n:>2}. {choices[code].label:<20} {choices[code].help}")
    prompt = "numbers, separated by spaces: " if many else "number: "
    while True:
        answer = input(prompt).split()
        valid = all(a.isdigit() and 1 <= int(a) <= len(codes) for a in answer)
        if answer and valid and (many or len(answer) == 1):
            return [codes[int(a) - 1] for a in answer]
        print("  not a valid choice")


def cmd_ack(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        changed = store.acknowledge(args.ids, getpass.getuser())
    print(f"{changed} alert(s) acknowledged")


def cmd_assign(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        changed = store.assign(args.ids, args.to or getpass.getuser(), getpass.getuser())
    print(f"{changed} alert(s) assigned")


def cmd_note(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        if not store.add_note([args.id], getpass.getuser(), " ".join(args.text)):
            sys.exit(f"error: no alert #{args.id}")
    print(f"note added to #{args.id}")


def cmd_resolve(args: argparse.Namespace) -> None:
    interactive = sys.stdin.isatty()
    disposition = args.disposition
    actions = args.action or []
    summary = args.summary
    if interactive:
        disposition = disposition or _choose("Disposition:", DISPOSITIONS)[0]
        actions = actions or _choose("Actions taken:", ACTIONS, many=True)
        summary = summary or input("Resolution summary: ")
    check_resolution(disposition or "", actions, summary or "")  # clear message if incomplete
    with Store(args.db, viewer=True) as store:
        changed = store.resolve(args.ids, getpass.getuser(), disposition, actions, summary)
    print(f"{changed} alert(s) resolved as {DISPOSITIONS[disposition].label.lower()}")


def cmd_reopen(args: argparse.Namespace) -> None:
    reason = args.reason or (input("Why reopen? ") if sys.stdin.isatty() else "")
    with Store(args.db, viewer=True) as store:
        changed = store.reopen(args.ids, getpass.getuser(), reason)
    print(f"{changed} alert(s) reopened")


def cmd_case(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        if not (alert := store.alert(args.id)):
            sys.exit(f"error: no alert #{args.id}")
        text = casefile.case(alert, store.activity(args.id), store.related_events(alert))
    print(text, end="")


def cmd_report(args: argparse.Namespace) -> None:
    with Store(args.db, viewer=True) as store:
        print(casefile.report(store.report(datetime.now(UTC) - args.since)), end="")


def cmd_rules(args: argparse.Namespace) -> None:
    _, rules = load(args)
    for r in rules:
        if r.threshold:
            kind = f"{r.threshold.count} in {r.threshold.window}"
        elif r.after:
            kind = f"after {r.after.count} in {r.after.window}"
        else:
            kind = "match"
        print(f"{r.id:<26}  {r.level.name:<8}  {kind:<14}  {r.title}")


def cmd_hunt(args: argparse.Namespace) -> None:
    _, rules = load(args)
    if args.rule:
        rules = [r for r in rules if r.id in args.rule]
    engine = Engine(rules)
    fired: Counter[str] = Counter()
    with Store(args.db) as store:
        for event in store.iter_events(args.since and datetime.now(UTC) - args.since):
            if event.action is None:
                normalize(event)  # stored before its parser existed
            for alert in engine.process(event):
                fired[alert.rule] += 1
                print(format_alert(alert))
    print(f"\n{sum(fired.values())} alerts", end="")
    print(f": {', '.join(f'{rule} x{n}' for rule, n in fired.most_common())}" if fired else "")


def _dashboard(module: str, package: str, extra: str) -> "types.ModuleType":
    try:
        return importlib.import_module(f"siemstress.ui.{module}")
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.split(".")[0] == package:
            sys.exit(
                f"error: this needs {package}; install it with: pip install 'siemstress[{extra}]'"
            )
        raise


def cmd_gui(args: argparse.Namespace) -> None:
    _dashboard("gui", "PySide6", "gui").run(args.db, args.refresh)


def cmd_tui(args: argparse.Namespace) -> None:
    _dashboard("tui", "textual", "tui").run(args.db, args.refresh)


DESKTOP_ENTRY = """\
[Desktop Entry]
Type=Application
Name=SIEMstress
GenericName=Security Dashboard
Comment=Alerts and logs from your homelab
Exec="{exe}" gui
Icon=siemstress
Terminal=false
Categories=System;Security;Monitor;
"""


def cmd_install_desktop(args: argparse.Namespace) -> None:
    """Add the desktop app to this user's application menu, with its icon."""
    icons = DATA_HOME / "icons" / "hicolor"
    for size in ICON_SIZES:
        target = icons / f"{size}x{size}" / "apps" / "siemstress.png"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ASSETS / f"icon-{size}.png").read_bytes())
    scalable = icons / "scalable" / "apps" / "siemstress.svg"
    scalable.parent.mkdir(parents=True, exist_ok=True)
    scalable.write_bytes((ASSETS / "icon.svg").read_bytes())

    exe = shutil.which("siemstress") or str(Path(sys.argv[0]).absolute())
    entry = DATA_HOME / "applications" / "siemstress.desktop"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(DESKTOP_ENTRY.format(exe=exe))
    print(f"installed {entry}\n  runs {exe} gui\n  icons in {icons}")


def cmd_doctor(args: argparse.Namespace) -> None:
    checks = doctor.run_checks(args.config, args.db)
    print(doctor.report(checks), end="")
    if any(c.status == doctor.FAIL for c in checks):
        sys.exit(1)


def cmd_notify_test(args: argparse.Namespace) -> None:
    settings, _ = load(args)
    if not settings.ntfy:
        sys.exit(f"error: no [ntfy] section in {args.config}")
    alert = Alert(
        ts=datetime.now(UTC),
        rule="test",
        level=Level.HIGH,
        title="SIEMstress test notification",
        host=socket.gethostname(),
    )
    Ntfy(settings.ntfy).send(alert)
    print(f"sent to {settings.ntfy.server}/{settings.ntfy.topic}")


def cmd_search(args: argparse.Namespace) -> None:
    with Store(args.db) as store:
        events = store.search(
            since=args.since and datetime.now(UTC) - args.since,
            host=args.host,
            app=args.app,
            text=args.grep,
            max_severity=args.severity,
            action=args.action,
            outcome=args.outcome,
            user=args.user,
            src_ip=args.ip,
            limit=args.limit,
        )
    if not events:
        print("no matching events", file=sys.stderr)
    for event in events:
        print(format_event(event))


def cmd_stats(args: argparse.Namespace) -> None:
    start = datetime.now(UTC) - args.since
    with Store(args.db) as store:
        stats = store.stats(start)
    size = sum(
        p.stat().st_size for p in (args.db, args.db.with_name(f"{args.db.name}-wal")) if p.exists()
    )
    oldest = f"{stats.oldest.astimezone():%Y-%m-%d %H:%M}" if stats.oldest else "-"
    print(f"{args.db} ({size / 2**20:.1f} MiB)")
    print(f"{stats.total:,} events, oldest {oldest}")
    window = f"since {start.astimezone():%Y-%m-%d %H:%M}"
    print(f"\nhosts {window}:")
    for host, source, count in stats.by_host:
        print(f"  {count:>9,}  {host} ({source})")
    print(f"\nprograms {window}:")
    for app, count in stats.by_app:
        print(f"  {count:>9,}  {app}")
    print(f"\nactions {window}:")
    for action, outcome, count in stats.by_action:
        print(f"  {count:>9,}  {action} ({outcome})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="siemstress", description="Lightweight homelab SIEM.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--db", type=Path, help=f"database (default: {USER_DB} if it exists, else {SYSTEM_DB})"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=f"config file (default: {USER_CONFIG} if it exists, else {SYSTEM_CONFIG})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="collect events until stopped")
    p.add_argument(
        "--syslog",
        type=bind_address,
        metavar="HOST:PORT",
        help="plain syslog listen address, or 'off' (default: from config, else 127.0.0.1:5514)",
    )
    p.add_argument(
        "--backfill", default="24h", help="journal history to import on first run (%(default)s)"
    )
    p.add_argument(
        "--retention-days", type=int, default=30, help="delete events older than this (%(default)s)"
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("search", help="search stored events")
    p.add_argument("--since", type=duration, help="e.g. 15m, 2h, 7d")
    p.add_argument("--host", help="host name contains")
    p.add_argument("--app", help="exact program name")
    p.add_argument("--grep", help="message contains")
    p.add_argument("--severity", type=severity, help="this severity or worse, e.g. warning")
    p.add_argument("--action", help="normalized action or prefix, e.g. ssh or ssh.login")
    p.add_argument("--outcome", choices=(SUCCESS, FAILURE))
    p.add_argument("--user", help="acting or target user")
    p.add_argument("--ip", help="source IP address")
    p.add_argument("-n", "--limit", type=int, default=50, help="max results (%(default)s)")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("stats", help="summarize collected events")
    p.add_argument("--since", type=duration, default="24h", help="window (%(default)s)")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("alerts", help="list stored alerts")
    p.add_argument("--since", type=duration, help="e.g. 1h, 7d")
    p.add_argument("--rule", help="rule id")
    p.add_argument("--level", type=level, help="this level or higher, e.g. high")
    p.add_argument("--status", choices=STATUS_FILTERS, default="unresolved", help="(%(default)s)")
    p.add_argument("-n", "--limit", type=int, default=50, help="max results (%(default)s)")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("case", help="an alert's full case file: evidence, related events, log")
    p.add_argument("id", type=int, metavar="ID")
    p.set_defaults(func=cmd_case)

    p = sub.add_parser("ack", help="acknowledge alerts: seen and being worked on (takes them)")
    p.add_argument("ids", type=int, nargs="+", metavar="ID")
    p.set_defaults(func=cmd_ack)

    p = sub.add_parser("assign", help="give alerts to someone (default: you)")
    p.add_argument("ids", type=int, nargs="+", metavar="ID")
    p.add_argument("--to", metavar="USER")
    p.set_defaults(func=cmd_assign)

    p = sub.add_parser("note", help="add a note to an alert's case log")
    p.add_argument("id", type=int, metavar="ID")
    p.add_argument("text", nargs="+")
    p.set_defaults(func=cmd_note)

    p = sub.add_parser(
        "resolve",
        help="close alerts with a disposition, the actions taken and a summary",
        description="Prompts for anything left out when run in a terminal.",
    )
    p.add_argument("ids", type=int, nargs="+", metavar="ID")
    p.add_argument("--disposition", choices=DISPOSITIONS)
    p.add_argument("--action", choices=ACTIONS, action="append", help="repeatable")
    p.add_argument("--summary")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("reopen", help="reopen resolved alerts, with a reason")
    p.add_argument("ids", type=int, nargs="+", metavar="ID")
    p.add_argument("--reason")
    p.set_defaults(func=cmd_reopen)

    p = sub.add_parser("report", help="alert-handling metrics, as Markdown")
    p.add_argument("--since", type=duration, default="30d", help="period (%(default)s)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("rules", help="list active detection rules")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("hunt", help="run rules over stored events without saving alerts")
    p.add_argument("--since", type=duration, help="e.g. 7d (default: everything)")
    p.add_argument("--rule", action="append", help="only this rule id (repeatable)")
    p.set_defaults(func=cmd_hunt)

    for name, func, what in (("gui", cmd_gui, "desktop"), ("tui", cmd_tui, "terminal")):
        p = sub.add_parser(name, help=f"open the {what} dashboard (read-only)")
        p.add_argument(
            "--refresh", type=float, default=5.0, help="seconds between updates (%(default)s)"
        )
        p.set_defaults(func=func)

    p = sub.add_parser("doctor", help="check the installation and explain how to fix problems")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("install-desktop", help="add the desktop app to your app menu")
    p.set_defaults(func=cmd_install_desktop)

    p = sub.add_parser("notify-test", help="send a test notification")
    p.set_defaults(func=cmd_notify_test)

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.db = args.db or default_db()
    args.config = args.config or default_config()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        args.func(args)
    except (ConfigError, RuleError, StoreError, TriageError) as exc:
        sys.exit(f"error: {exc}")
