# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import getpass
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from rich.cells import cell_len
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    SelectionList,
    Sparkline,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from siemstress import __version__
from siemstress.event import ACKNOWLEDGED, OPEN, RESOLVED, STATUSES, Alert, Event, Level
from siemstress.store import Overview, Store
from siemstress.triage import ACTIONS, DISPOSITIONS, TriageError, check_resolution
from siemstress.ui import (
    AMBER,
    ASSETS,
    GRAY,
    GREEN,
    HOST_STATE_COLORS,
    LEVEL_COLORS,
    OUTCOME_COLORS,
    RED,
    STATUS_MARKERS,
    WINDOWS,
    ago,
    describe_bucket,
    host_state,
    local_time,
    parse_query,
    severity_color,
    short_host,
    status_color,
    users_text,
)

LOGO = Text.from_markup((ASSETS / "logo.txt").read_text().rstrip("\n"))
LOGO_WIDTH = max(cell_len(line) for line in LOGO.plain.splitlines())
EVENT_LIMIT = 500
ALERT_LIMIT = 500
CASE_KEYS: list[BindingType] = [
    Binding("a", "case('acknowledge')", "Acknowledge"),
    Binding("t", "case('take')", "Take"),
    Binding("n", "case('note')", "Note"),
    Binding("r", "case('resolve')", "Resolve"),
    Binding("o", "case('reopen')", "Reopen"),
]


def styled(value: str, color: str | None) -> Text:
    return Text(value, style=color or "")


def alert_row(a: Alert) -> tuple[Text, ...]:
    muted = a.status == RESOLVED
    plain = GRAY if muted else None
    return (
        styled(STATUS_MARKERS[a.status], status_color(a)),
        styled(local_time(a.ts), plain),
        styled(a.level.name, GRAY if muted else LEVEL_COLORS[a.level]),
        styled(short_host(a.host), plain),
        styled(a.context.get("user", ""), plain),
        styled(a.rule, plain),
        styled(a.assignee or "", plain),
        styled(DISPOSITIONS[a.disposition].label if a.disposition else "", plain),
        styled(a.title, plain),
    )


def event_row(e: Event) -> tuple[Text | str, ...]:
    action = f"{e.action} {e.outcome or ''}".strip() if e.action else ""
    return (
        local_time(e.ts),
        short_host(e.host),
        e.user or "",
        e.app or "",
        styled(action, OUTCOME_COLORS.get(e.outcome or "")),
        styled(e.message, severity_color(e.severity)),
    )


class AlertTable(DataTable):
    BINDINGS: ClassVar[list[BindingType]] = CASE_KEYS

    def action_case(self, kind: str) -> None:
        app: Dashboard = self.app  # type: ignore[assignment]
        if (key := app._selected_key(self)) and key in app.alerts:
            app.case_action(kind, [int(key)])


class PromptScreen(ModalScreen[str | None]):
    """One line of text, e.g. a note or the reason for reopening."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, title: str):
        super().__init__()
        self.title_text = title

    def compose(self) -> ComposeResult:
        with Vertical(classes="form"):
            yield Label(self.title_text, classes="form-title")
            yield Input(id="prompt")
            yield Static(f"[{GRAY}]enter to save · esc to cancel[/]")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


class ResolveScreen(ModalScreen[tuple[str, list[str], str] | None]):
    """Close-out form: disposition, actions taken and a summary, all required."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, count: int):
        super().__init__()
        self.count = count

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="form"):
            yield Label(f"Resolve {self.count} alert{'s' if self.count > 1 else ''}",
                        classes="form-title")  # fmt: skip
            yield Select(
                [(c.label, code) for code, c in DISPOSITIONS.items()],
                prompt="Disposition",
                id="disposition",
            )
            yield Static("", id="disposition-help")
            yield Label("Actions taken (space to tick)")
            yield SelectionList(*((c.label, code) for code, c in ACTIONS.items()), id="actions")
            yield Label("Summary: what happened, how you know, what was done")
            yield TextArea(id="summary")
            yield Static("", id="error")
            with Horizontal(id="buttons"):
                yield Button("Resolve", variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    def on_select_changed(self, event: Select.Changed) -> None:
        help_text = DISPOSITIONS[event.value].help if event.value in DISPOSITIONS else ""
        self.query_one("#disposition-help", Static).update(Text(help_text, GRAY))

    def values(self) -> tuple[str, list[str], str]:
        disposition = self.query_one("#disposition", Select).value
        return (
            disposition if isinstance(disposition, str) else "",
            list(self.query_one("#actions", SelectionList).selected),
            self.query_one("#summary", TextArea).text,
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            check_resolution(*self.values())
        except TriageError as exc:
            self.query_one("#error", Static).update(Text(str(exc).capitalize(), RED))
            return
        self.dismiss(self.values())


class CaseScreen(Screen[None]):
    """An alert's case: details, related events and the activity log."""

    BINDINGS: ClassVar[list[BindingType]] = [
        *CASE_KEYS,
        Binding("escape,q", "app.pop_screen", "Back"),
    ]

    def __init__(self, alert_id: int):
        super().__init__()
        self.alert_id = alert_id

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Static(id="case-details")
            yield Label("", id="related-title", classes="section")
            yield DataTable(id="related", cursor_type="row", zebra_stripes=True)
            yield Label("Activity", classes="section")
            yield Static(id="case-log")
        yield Footer()

    def on_mount(self) -> None:
        related = self.query_one("#related", DataTable)
        for label, width in (("time", 19), ("user", 10), ("app", 14), ("action", 26),
                             ("message", None)):  # fmt: skip
            related.add_column(label, width=width)
        self.reload()

    def reload(self) -> None:
        store = self.app.store  # type: ignore[attr-defined]
        if not (a := store.alert(self.alert_id)):
            return
        self.sub_title = f"alert #{a.id}"
        body = Text.assemble(
            (f"{STATUS_MARKERS[a.status]} {a.status}  ", status_color(a)),
            (a.level.name, f"bold {LEVEL_COLORS[a.level]}"),
            "\n",
            (a.title, "bold"),
            "\n\n",
        )
        fields = {
            "rule": a.rule,
            "event time": f"{local_time(a.ts)} ({ago(a.ts)})",
            "host": a.host or "?",
            "assignee": a.assignee or "unassigned",
        }
        if a.disposition:
            fields["disposition"] = DISPOSITIONS[a.disposition].label
            fields["actions taken"] = ", ".join(ACTIONS[x].label for x in a.actions)
            fields["summary"] = a.summary or ""
        fields |= a.context
        for key, value in fields.items():
            body.append(f"{key:<14}", GRAY)
            body.append(f"{value}\n")
        self.query_one("#case-details", Static).update(body)

        events = store.related_events(a)
        self.query_one("#related-title", Label).update(f"Related events ({len(events)})")
        table = self.query_one("#related", DataTable)
        table.clear()
        for e in events:
            table.add_row(*event_row(e)[:1], *event_row(e)[2:])

        log = Text()
        for entry in store.activity(a.id):
            log.append(f"{local_time(entry.ts)}  ", GRAY)
            log.append(f"{entry.author} ", "bold")
            log.append(f"{entry.kind}\n", GRAY)
            log.append(f"  {entry.text}\n")
        self.query_one("#case-log", Static).update(log or Text("No activity yet.", GRAY))

    def action_case(self, kind: str) -> None:
        self.app.case_action(kind, [self.alert_id], self.reload)  # type: ignore[attr-defined]


class Splash(ModalScreen[None]):
    """The braille logo. Closes on any key, or by itself when given a timeout."""

    def __init__(self, timeout: float | None = None):
        super().__init__()
        self.timeout = timeout

    def compose(self) -> ComposeResult:
        with Vertical(id="splash"):
            yield Static(LOGO)
            yield Static(
                Text.assemble(
                    (f"SIEMstress {__version__}", "bold"),
                    "  ·  a lightweight SIEM for homelabs  ·  ",
                    ("press any key", GRAY),
                ),
                id="tagline",
            )

    def on_mount(self) -> None:
        self.query_one("#splash").styles.width = LOGO_WIDTH + 8  # 2 border + 6 padding
        if self.timeout:
            self.set_timer(self.timeout, self.close)

    def on_key(self, event: Key) -> None:
        event.stop()
        self.close()

    def close(self) -> None:
        if self.is_current:
            self.dismiss()


class Dashboard(App[None]):
    TITLE = "SIEMstress"
    CSS = """
    #cards { height: 5; }
    .card { width: 1fr; height: 5; border: round $panel; content-align: center middle;
             text-align: center; }
    #timeline { height: 5; border: round $panel; border-title-color: $text-muted; padding: 0 1; }
    TabbedContent, ContentSwitcher, TabPane { height: 1fr; }
    #filter { margin: 0 0 1 0; }
    DataTable { height: 1fr; }
    Splash, PromptScreen, ResolveScreen { align: center middle; }
    .form { width: 80; max-width: 100%; height: auto; max-height: 90%; border: thick $accent;
            background: $surface; padding: 1 2; }
    .form-title { text-style: bold; margin-bottom: 1; }
    #actions { height: 14; }
    #summary { height: 6; }
    #buttons { height: auto; margin-top: 1; }
    .section { text-style: bold; margin-top: 1; }
    #related { height: auto; max-height: 14; }
    #splash { height: auto; border: round $panel; background: $surface; padding: 1 3; }
    #splash Static { width: 100%; height: auto; }
    #tagline { width: 100%; text-align: center; margin-top: 1; }
    #detail { width: 80%; max-width: 110; height: auto; max-height: 80%;
              border: thick $accent; background: $surface; padding: 1 2; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit"),
        Binding("f5", "refresh", "Refresh"),
        Binding("w", "cycle_window", "Window"),
        Binding("h", "toggle_resolved", "Resolved"),
        Binding("slash", "focus_filter", "Search"),
        Binding("question_mark", "about", "About"),
        *(Binding(str(n), f"show_tab('{tab}')", show=False)
          for n, tab in enumerate(("alerts", "events", "hosts", "ips"), start=1)),
    ]  # fmt: skip

    def __init__(self, store: Store, refresh_seconds: float = 5.0, splash: bool = True):
        super().__init__()
        self.store = store
        self.splash = splash
        self.refresh_seconds = refresh_seconds
        self.window = "24h"
        self.show_resolved = False
        self.alerts: dict[str, Alert] = {}
        self.last_alert_id: int | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="cards"):
            for card in ("events", "alerts", "failures", "hosts"):
                yield Static(id=f"card-{card}", classes="card")
        yield Sparkline([], id="timeline")
        with TabbedContent():
            with TabPane("Alerts", id="tab-alerts"):
                yield AlertTable(id="alerts", cursor_type="row", zebra_stripes=True)
            with TabPane("Events", id="tab-events"):
                yield Input(
                    placeholder="search: words, action:ssh user:root ip:1.2.3.4 host:… app:…",
                    id="filter",
                )
                yield DataTable(id="events", cursor_type="row", zebra_stripes=True)
            with TabPane("Hosts", id="tab-hosts"):
                yield DataTable(id="hosts", cursor_type="row")
            with TabPane("Failing IPs", id="tab-ips"):
                yield DataTable(id="ips", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        columns = {
            "alerts": [("", 1), ("time", 19), ("level", 8), ("host", 14), ("user", 10),
                       ("rule", 22), ("owner", 10), ("outcome", 15), ("alert", None)],
            "events": [("time", 19), ("host", 14), ("user", 10), ("app", 16), ("action", 22),
                       ("message", None)],
            "hosts": [("host", 24), ("state", 7), ("last seen", 10), ("events", 9),
                      ("users", None)],
            "ips": [("source ip", 40), ("failures", 10)],
        }  # fmt: skip
        for table_id, specs in columns.items():
            table = self.query_one(f"#{table_id}", DataTable)
            for label, width in specs:
                table.add_column(label, width=width)
        self.query_one("#alerts", DataTable).focus()
        self.action_refresh()
        self.set_interval(self.refresh_seconds, self.refresh_live)
        if self.splash and self.size.width >= LOGO_WIDTH + 10:
            self.push_screen(Splash(timeout=2.5))

    def action_about(self) -> None:
        self.push_screen(Splash())

    def action_refresh(self) -> None:
        self.refresh_live()
        self.refresh_events()

    def action_cycle_window(self) -> None:
        names = list(WINDOWS)
        self.window = names[(names.index(self.window) + 1) % len(names)]
        self.action_refresh()

    def action_toggle_resolved(self) -> None:
        self.show_resolved = not self.show_resolved
        self.notify("showing resolved alerts" if self.show_resolved else "hiding resolved alerts")
        self.refresh_live()

    def action_show_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = f"tab-{tab}"
        self.query_one(f"#{tab}", DataTable).focus()

    def action_focus_filter(self) -> None:
        self.query_one(TabbedContent).active = "tab-events"
        self.query_one("#filter", Input).focus()

    def case_action(
        self, kind: str, ids: list[int], then: Callable[[], None] | None = None
    ) -> None:
        """Run a case action on alerts, asking for input first where it needs some."""
        me = getpass.getuser()

        def apply(change: Callable[[], int], done: str) -> None:
            try:
                changed = change()
            except TriageError as exc:
                self.notify(str(exc).capitalize(), severity="error", timeout=6)
                return
            self.notify(f"{changed} alert(s) {done}", timeout=3)
            self.refresh_live()
            if then:
                then()

        def noted(text: str | None) -> None:
            if text is not None:
                apply(lambda: self.store.add_note(ids, me, text), "noted")

        def resolved(values: tuple[str, list[str], str] | None) -> None:
            if values:
                apply(lambda: self.store.resolve(ids, me, *values), "resolved")

        def reopened(reason: str | None) -> None:
            if reason is not None:
                apply(lambda: self.store.reopen(ids, me, reason), "reopened")

        match kind:
            case "acknowledge":
                apply(lambda: self.store.acknowledge(ids, me), "acknowledged")
            case "take":
                apply(lambda: self.store.assign(ids, me, me), f"assigned to {me}")
            case "note":
                self.push_screen(PromptScreen("Add a note to the case log"), noted)
            case "resolve":
                self.push_screen(ResolveScreen(len(ids)), resolved)
            case "reopen":
                self.push_screen(PromptScreen("Why is this being reopened?"), reopened)

    def refresh_live(self) -> None:
        since = datetime.now(UTC) - WINDOWS[self.window]
        overview = self.store.overview(since)
        self.sub_title = f"last {self.window}" + (" · incl. resolved" if self.show_resolved else "")
        timeline = self.query_one("#timeline", Sparkline)
        timeline.border_title = f"events per {describe_bucket(overview.bucket)}"
        timeline.data = overview.timeline
        self._show_cards(overview)
        statuses = STATUSES if self.show_resolved else (OPEN, ACKNOWLEDGED)
        self._show_alerts(self.store.alerts(since=since, statuses=statuses, limit=ALERT_LIMIT))
        self._show_hosts(overview)
        ips = self.query_one("#ips", DataTable)
        ips.clear()
        for ip, count in overview.top_failing_ips:
            ips.add_row(ip, styled(f"{count:,}", RED))

    def refresh_events(self) -> None:
        filters = parse_query(self.query_one("#filter", Input).value)
        since = datetime.now(UTC) - WINDOWS[self.window]
        events = self.store.search(since=since, limit=EVENT_LIMIT, **filters)
        table = self.query_one("#events", DataTable)
        table.clear()
        for e in reversed(events):
            table.add_row(*event_row(e))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.refresh_events()
        self.query_one("#events", DataTable).focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "alerts" and event.row_key.value in self.alerts:
            self.push_screen(CaseScreen(int(event.row_key.value)))

    def _show_cards(self, o: Overview) -> None:
        unresolved = sum(o.unresolved_by_level.values())
        worst = next((lv for lv in reversed(Level) if o.unresolved_by_level[lv]), None)
        states = [host_state(h.last_seen) for h in o.hosts]
        quiet, silent = states.count("quiet"), states.count("silent")
        host_note = ", ".join(f"{n} {s}" for n, s in ((silent, "silent"), (quiet, "quiet")) if n)
        cards = {
            "events": (f"{o.events:,}", "events", ""),
            "alerts": (f"{unresolved:,}", "unresolved alerts",
                       LEVEL_COLORS[worst] if worst else GREEN),
            "failures": (f"{o.auth_failures:,}", "failed logins", AMBER if o.auth_failures else ""),
            "hosts": (f"{len(o.hosts)}", f"hosts, {host_note}" if host_note else "hosts",
                      RED if silent else AMBER if quiet else GREEN),
        }  # fmt: skip
        for name, (value, label, style) in cards.items():
            text = Text.assemble((value, f"bold {style}".strip()), "\n", (label, GRAY))
            self.query_one(f"#card-{name}", Static).update(text)

    def _show_alerts(self, alerts: list[Alert]) -> None:
        newest = max((a.id or 0 for a in alerts), default=0)
        if self.last_alert_id is not None:
            for a in alerts:
                if (a.id or 0) > self.last_alert_id and a.level >= Level.MEDIUM:
                    severity = "error" if a.level >= Level.HIGH else "warning"
                    self.notify(a.title, title=a.level.name, severity=severity, timeout=10)
        self.last_alert_id = max(newest, self.last_alert_id or 0)

        table = self.query_one("#alerts", DataTable)
        selected = self._selected_key(table)
        table.clear()
        self.alerts = {str(a.id): a for a in alerts}
        for a in reversed(alerts):
            table.add_row(*alert_row(a), key=str(a.id))
        if selected in self.alerts:
            table.move_cursor(row=table.get_row_index(selected))

    def _show_hosts(self, o: Overview) -> None:
        table = self.query_one("#hosts", DataTable)
        table.clear()
        now = datetime.now(UTC)
        for h in o.hosts:
            state = host_state(h.last_seen, now)
            table.add_row(
                h.host,
                styled(state, HOST_STATE_COLORS[state]),
                ago(h.last_seen, now),
                f"{h.recent_events:,}",
                users_text(h.users, shown=6),
            )

    @staticmethod
    def _selected_key(table: DataTable) -> str | None:
        if not table.row_count:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value


def run(db_path: Path, refresh_seconds: float) -> None:
    with Store(db_path, viewer=True) as store:
        Dashboard(store, refresh_seconds).run()
