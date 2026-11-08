# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import getpass
import html
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QRectF,
    QSize,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QIcon,
    QKeySequence,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QSystemTrayIcon,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QToolBar,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from siemstress import __version__
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
from siemstress.store import Overview, Store, StoreError
from siemstress.triage import ACTIONS, DISPOSITIONS, TriageError, check_resolution
from siemstress.ui import (
    AMBER,
    ASSETS,
    GRAY,
    GREEN,
    HOST_STATE_COLORS,
    ICON_SIZES,
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

EVENT_LIMIT = 1000
ALERT_LIMIT = 1000

Index = QModelIndex | QPersistentModelIndex
Column = tuple[str, Callable[[Any], str]]
ColorFn = Callable[[Any], str | None]


class RecordModel(QAbstractTableModel):
    """Read-only table over a list of records, one accessor per column.

    `colors` gives some columns their own color; rows for which `muted` is true are
    drawn gray everywhere else.
    """

    def __init__(
        self,
        columns: list[Column],
        colors: dict[int, ColorFn] | None = None,
        muted: Callable[[Any], bool] | None = None,
    ):
        super().__init__()
        self.columns = columns
        self.colors = colors or {}
        self.muted = muted
        self.records: list[Any] = []

    def set_records(self, records: Sequence[Any]) -> None:
        self.beginResetModel()
        self.records = list(records)
        self.endResetModel()

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        record = self.records[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return self.columns[index.column()][1](record)
        if role == Qt.ItemDataRole.ForegroundRole:
            color_fn = self.colors.get(index.column())
            if color := color_fn and color_fn(record):
                return QColor(color)
            if self.muted and self.muted(record):
                return QColor(GRAY)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = 0) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.columns[section][0]
        return None


def make_table(model: RecordModel, multi_select: bool = False) -> QTableView:
    table = QTableView()
    table.setModel(model)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(
        QAbstractItemView.SelectionMode.ExtendedSelection
        if multi_select
        else QAbstractItemView.SelectionMode.SingleSelection
    )
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.verticalHeader().hide()
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    header.setStretchLastSection(True)
    return table


def is_resolved(alert: Alert) -> bool:
    return alert.status == RESOLVED


def level_color(alert: Alert) -> str | None:
    return None if is_resolved(alert) else LEVEL_COLORS[alert.level]


def alert_columns(*, when_as_ago: bool = False) -> list[Column]:
    return [
        ("", lambda a: STATUS_MARKERS[a.status]),
        ("When" if when_as_ago else "Time", (lambda a: ago(a.ts)) if when_as_ago
         else (lambda a: local_time(a.ts))),
        ("Level", lambda a: a.level.name),
        ("Host", lambda a: short_host(a.host)),
        ("User", lambda a: a.context.get("user", "")),
        ("Alert", lambda a: a.title),
    ]  # fmt: skip


def app_icon() -> QIcon:
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addFile(str(ASSETS / f"icon-{size}.png"), QSize(size, size))
    return icon


class StatCard(QFrame):
    def __init__(self, caption: str):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.value = QLabel("-")
        font = self.value.font()
        font.setPointSizeF(font.pointSizeF() * 2.2)
        font.setBold(True)
        self.value.setFont(font)
        self.caption = QLabel(caption)
        self.caption.setEnabled(False)  # palette's muted text
        layout = QVBoxLayout(self)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)

    def set(self, value: str, color: str | None = None, caption: str | None = None) -> None:
        self.value.setText(value)
        self.value.setStyleSheet(f"color: {color}" if color else "")
        if caption:
            self.caption.setText(caption)


class TimelineChart(QWidget):
    """Bar chart of event counts per time bucket, with hover tooltips."""

    def __init__(self):
        super().__init__()
        self.counts: list[int] = []
        self.start = datetime.now(UTC)
        self.bucket = timedelta(hours=1)
        self.setMinimumHeight(140)
        self.setMouseTracking(True)

    def set_data(self, counts: list[int], start: datetime, bucket: timedelta) -> None:
        self.counts, self.start, self.bucket = counts, start, bucket
        self.update()

    def _plot_rect(self) -> QRectF:
        metrics = self.fontMetrics()
        return QRectF(self.rect()).adjusted(4, metrics.height() + 4, -4, -metrics.height() - 6)

    def paintEvent(self, event: QPaintEvent) -> None:
        if not self.counts:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        plot = self._plot_rect()
        peak = max(self.counts) or 1
        slot = plot.width() / len(self.counts)
        gap = min(4.0, slot * 0.2)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(palette.highlight())
        for i, count in enumerate(self.counts):
            if count:
                height = max(2.0, plot.height() * count / peak)
                painter.drawRoundedRect(
                    QRectF(plot.left() + i * slot + gap / 2, plot.bottom() - height,
                           slot - gap, height), 2, 2,
                )  # fmt: skip

        painter.setPen(palette.placeholderText().color())
        painter.drawLine(plot.bottomLeft(), plot.bottomRight())
        height = self.fontMetrics().height()
        below = QRectF(plot.left(), plot.bottom() + 4, plot.width(), height)
        painter.drawText(
            QRectF(plot.left(), 0, plot.width(), height),
            Qt.AlignmentFlag.AlignLeft,
            f"peak {peak:,} per {describe_bucket(self.bucket)}",
        )
        painter.drawText(below, Qt.AlignmentFlag.AlignLeft, local_time(self.start)[:16])
        painter.drawText(below, Qt.AlignmentFlag.AlignRight, "now")

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        plot = self._plot_rect()
        x = event.position().x() - plot.left()
        if not self.counts or not 0 <= x < plot.width():
            QToolTip.hideText()
            return
        i = int(x / plot.width() * len(self.counts))
        start = self.start + self.bucket * i
        QToolTip.showText(
            event.globalPosition().toPoint(),
            f"{local_time(start)[:16]} to {local_time(start + self.bucket)[11:16]}\n"
            f"{self.counts[i]:,} events",
            self,
        )


def _section(title: str, widget: QWidget) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(QLabel(f"<b>{html.escape(title)}</b>"))
    layout.addWidget(widget)
    return box


def _rows_html(rows: dict[str, str]) -> str:
    return (
        "<table>"
        + "".join(
            f"<tr><td style='padding-right:16px;color:{GRAY}'>{html.escape(k)}</td>"
            f"<td>{html.escape(v)}</td></tr>"
            for k, v in rows.items()
        )
        + "</table>"
    )


def case_html(a: Alert) -> str:
    handling = {
        "status": f"{STATUS_MARKERS[a.status]} {a.status}",
        "assignee": a.assignee or "unassigned",
        "raised": f"{local_time(a.created)} ({ago(a.created)})" if a.created else "-",
    }
    if a.acknowledged_at:
        handling["acknowledged"] = f"{local_time(a.acknowledged_at)} ({ago(a.acknowledged_at)})"
    if a.status == RESOLVED and a.disposition:
        handling["resolved"] = (
            f"{local_time(a.resolved_at)} by {a.status_by}" if a.resolved_at else ""
        )
        handling["disposition"] = DISPOSITIONS[a.disposition].label
        handling["actions taken"] = ", ".join(ACTIONS[x].label for x in a.actions)
    evidence = {"rule": a.rule, "event time": local_time(a.ts), "host": a.host or "?",
                "count": str(a.count), **a.context}  # fmt: skip
    summary = f"<p><b>Resolution:</b> {html.escape(a.summary)}</p>" if a.summary else ""
    return (
        f"<h3><span style='color:{LEVEL_COLORS[a.level]}'>{a.level.name}</span>"
        f"&nbsp; {html.escape(a.title)}</h3>"
        f"<p style='color:{status_color(a)}'>{STATUS_MARKERS[a.status]} {a.status}</p>"
        f"{summary}<h4>Handling</h4>{_rows_html(handling)}<h4>Evidence</h4>{_rows_html(evidence)}"
    )


class ResolveDialog(QDialog):
    """Close-out form: disposition, actions taken and a summary, all required."""

    def __init__(self, parent: QWidget, count: int):
        super().__init__(parent)
        self.setWindowTitle(f"Resolve {count} alert{'s' if count > 1 else ''}")
        self.disposition = QComboBox()
        for code, choice in DISPOSITIONS.items():
            self.disposition.addItem(choice.label, code)
        self.disposition_help = QLabel()
        self.disposition_help.setWordWrap(True)
        self.disposition_help.setEnabled(False)
        self.disposition.currentIndexChanged.connect(self._explain)
        self._explain()

        self.actions = QListWidget()
        for code, choice in ACTIONS.items():
            item = QListWidgetItem(choice.label)
            item.setData(Qt.ItemDataRole.UserRole, code)
            item.setToolTip(choice.help)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.actions.addItem(item)
        rows = self.actions.sizeHintForRow(0) * self.actions.count()
        self.actions.setMinimumHeight(rows + 2 * self.actions.frameWidth())
        self.summary = QPlainTextEdit()
        self.summary.setPlaceholderText("What happened, how you know, and what was done.")
        self.error = QLabel()
        self.error.setStyleSheet(f"color: {RED}")
        self.error.setWordWrap(True)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Resolve")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form = QFormLayout(self)
        form.addRow("Disposition", self.disposition)
        form.addRow("", self.disposition_help)
        form.addRow("Actions taken", self.actions)
        form.addRow("Summary", self.summary)
        form.addRow(self.error)
        form.addRow(buttons)
        self.resize(560, 520)

    def _explain(self) -> None:
        self.disposition_help.setText(DISPOSITIONS[self.disposition.currentData()].help)

    def values(self) -> tuple[str, list[str], str]:
        checked = [
            self.actions.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.actions.count())
            if self.actions.item(i).checkState() == Qt.CheckState.Checked
        ]
        return self.disposition.currentData(), checked, self.summary.toPlainText()

    def accept(self) -> None:
        try:
            check_resolution(*self.values())
        except TriageError as exc:
            self.error.setText(str(exc).capitalize())
            return
        super().accept()


class CasePanel(QTabWidget):
    """The selected alert's case: details, related events and the activity log."""

    def __init__(self, add_note: Callable[[str], None]):
        super().__init__()
        self.shown: tuple | None = None
        self.details = QTextBrowser()
        self.details.setPlaceholderText("Select an alert to open its case.")
        self.related = RecordModel(
            [
                ("Time", lambda e: local_time(e.ts)),
                ("User", lambda e: e.user or ""),
                ("App", lambda e: e.app or ""),
                ("Action", lambda e: f"{e.action} {e.outcome or ''}".strip() if e.action else ""),
                ("Message", lambda e: e.message),
            ],
            {3: lambda e: OUTCOME_COLORS.get(e.outcome or "")},
        )
        self.log = QTextBrowser()
        self.note = QLineEdit()
        self.note.setPlaceholderText("Add a note to the case log and press Enter")
        self.note.returnPressed.connect(lambda: self._submit(add_note))
        activity = QWidget()
        layout = QVBoxLayout(activity)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.log, stretch=1)
        layout.addWidget(self.note)
        self.addTab(self.details, "Case")
        self.addTab(make_table(self.related), "Related events")
        self.addTab(activity, "Activity")

    def _submit(self, add_note: Callable[[str], None]) -> None:
        if text := self.note.text().strip():
            add_note(text)
            self.note.clear()

    def show_case(self, alert: Alert, activity: list[Activity], related: list[Event]) -> None:
        key = (alert.id, alert.status, alert.status_at, len(activity))
        if key == self.shown:
            return  # unchanged: keep scroll positions
        self.shown = key
        self.details.setHtml(case_html(alert))
        self.related.set_records(related)
        self.setTabText(1, f"Related events ({len(related)})")
        self.setTabText(2, f"Activity ({len(activity)})")
        self.log.setHtml("".join(
            f"<p><span style='color:{GRAY}'>{local_time(a.ts)}</span> <b>{html.escape(a.author)}"
            f"</b> <i>{a.kind}</i><br>{html.escape(a.text)}</p>"
            for a in activity
        ) or f"<p style='color:{GRAY}'>No activity yet.</p>")  # fmt: skip

    def clear_case(self) -> None:
        self.shown = None
        self.details.clear()
        self.related.set_records([])
        self.log.clear()


class MainWindow(QMainWindow):
    def __init__(self, store: Store, refresh_seconds: float = 5.0):
        super().__init__()
        self.store = store
        self.last_alert_id: int | None = None
        self.setWindowTitle("SIEMstress")
        self.setWindowIcon(app_icon())
        self.resize(1280, 820)

        self.window_box = QComboBox()
        self.window_box.addItems(WINDOWS)
        self.window_box.setCurrentText("24h")
        self.window_box.currentTextChanged.connect(self.refresh_all)
        refresh = QAction("Refresh", self, shortcut=QKeySequence.StandardKey.Refresh)
        refresh.triggered.connect(self.refresh_all)
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        toolbar.addWidget(QLabel(" Show last "))
        toolbar.addWidget(self.window_box)
        toolbar.addAction(refresh)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)
        about = QAction("About", self)
        about.triggered.connect(self.show_about)
        toolbar.addAction(about)

        self.alert_model = RecordModel(
            [
                *alert_columns()[:5],
                ("Rule", lambda a: a.rule),
                ("Owner", lambda a: a.assignee or ""),
                ("Outcome", lambda a: DISPOSITIONS[a.disposition].label if a.disposition else ""),
                alert_columns()[5],
            ],
            {0: status_color, 2: level_color},
            muted=is_resolved,
        )
        self.recent_model = RecordModel(
            alert_columns(when_as_ago=True), {0: status_color, 2: level_color}
        )
        self.event_model = RecordModel(
            [
                ("Time", lambda e: local_time(e.ts)),
                ("Host", lambda e: short_host(e.host)),
                ("User", lambda e: e.user or ""),
                ("App", lambda e: e.app or ""),
                ("Action", lambda e: f"{e.action} {e.outcome or ''}".strip() if e.action else ""),
                ("Message", lambda e: e.message),
            ],
            {
                4: lambda e: OUTCOME_COLORS.get(e.outcome or ""),
                5: lambda e: severity_color(e.severity),
            },
        )
        self.host_model = RecordModel(
            [
                ("Host", lambda h: h.host),
                ("State", lambda h: host_state(h.last_seen)),
                ("Last seen", lambda h: ago(h.last_seen)),
                ("Events", lambda h: f"{h.recent_events:,}"),
                ("Users", lambda h: users_text(h.users, shown=8)),
            ],
            {1: lambda h: HOST_STATE_COLORS[host_state(h.last_seen)]},
        )
        self.ip_model = RecordModel(
            [("Source IP", lambda r: r[0]), ("Failed logins", lambda r: f"{r[1]:,}")],
            {1: lambda _: RED},
        )

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.addTab(self._overview_tab(), "Overview")
        tabs.addTab(self._alerts_tab(), "Alerts")
        tabs.addTab(self._events_tab(), "Events")
        tabs.addTab(make_table(self.host_model), "Hosts")
        self.setCentralWidget(tabs)

        self.tray: QSystemTrayIcon | None = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(app_icon(), self)
            self.tray.setToolTip("SIEMstress")
            self.tray.activated.connect(self._bring_to_front)
            self.tray.show()

        self.refresh_all()
        self.timer = QTimer(self, interval=int(refresh_seconds * 1000))
        self.timer.timeout.connect(self.refresh_live)
        self.timer.start()

    def _overview_tab(self) -> QWidget:
        self.cards = {
            "events": StatCard("events"),
            "alerts": StatCard("unresolved alerts"),
            "failures": StatCard("failed logins"),
            "hosts": StatCard("hosts"),
        }
        cards = QHBoxLayout()
        for card in self.cards.values():
            cards.addWidget(card)
        self.chart = TimelineChart()
        bottom = QSplitter()
        bottom.addWidget(_section("Unresolved alerts", make_table(self.recent_model)))
        bottom.addWidget(_section("Most failed logins by source IP", make_table(self.ip_model)))
        bottom.setSizes([800, 300])

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addLayout(cards)
        layout.addWidget(_section("Activity", self.chart))
        layout.addWidget(bottom, stretch=1)
        return page

    def _alerts_tab(self) -> QWidget:
        self.alert_table = make_table(self.alert_model, multi_select=True)
        self.alert_table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        actions = QToolBar()
        for label, key, handler, tip in (
            (f"{STATUS_MARKERS[ACKNOWLEDGED]}  Acknowledge", "A", self.acknowledge_selected,
             "Seen and being worked on; takes unowned alerts"),
            ("Assign to me", "M", self.assign_selected, "Make yourself the owner"),
            ("Add note…", "N", self.note_current, "Add a note to the case log"),
            (f"{STATUS_MARKERS[RESOLVED]}  Resolve…", "R", self.resolve_selected,
             "Close with a disposition, the actions taken and a summary"),
            (f"{STATUS_MARKERS[OPEN]}  Reopen…", "O", self.reopen_selected,
             "Reopen resolved alerts, with a reason"),
        ):  # fmt: skip
            action = QAction(label, self, shortcut=key)
            action.setToolTip(f"{tip} ({key})")
            action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            action.triggered.connect(handler)
            actions.addAction(action)
            self.alert_table.addAction(action)
        self.show_resolved = QCheckBox("Show resolved")
        self.show_resolved.toggled.connect(self.refresh_live)
        actions.addSeparator()
        actions.addWidget(self.show_resolved)

        self.case = CasePanel(self.add_note)
        self.alert_table.selectionModel().currentRowChanged.connect(self._show_alert)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.alert_table)
        splitter.addWidget(self.case)
        splitter.setSizes([420, 330])

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(actions)
        layout.addWidget(splitter, stretch=1)
        page.addActions(self.alert_table.actions())  # shortcuts work anywhere on the tab
        return page

    def _events_tab(self) -> QWidget:
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search: words, action:ssh user:root ip:1.2.3.4 host:… app:…  (Enter to run)"
        )
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(self.refresh_events)
        self.event_count = QLabel()
        self.event_count.setEnabled(False)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self.search)
        layout.addWidget(make_table(self.event_model), stretch=1)
        layout.addWidget(self.event_count)
        return page

    @property
    def since(self) -> datetime:
        return datetime.now(UTC) - WINDOWS[self.window_box.currentText()]

    def refresh_all(self) -> None:
        self.refresh_live()
        self.refresh_events()

    def refresh_live(self) -> None:
        since = self.since
        overview = self.store.overview(since)
        statuses = STATUSES if self.show_resolved.isChecked() else (OPEN, ACKNOWLEDGED)
        alerts = self.store.alerts(since=since, statuses=statuses, limit=ALERT_LIMIT)
        self._notify_new(alerts)
        self._show_overview(overview)
        self.recent_model.set_records([a for a in reversed(alerts) if not is_resolved(a)][:20])
        self.host_model.set_records(overview.hosts)
        self.ip_model.set_records(overview.top_failing_ips)

        selected = self._selected_ids()
        current = self._current_id()
        self.alert_model.set_records(alerts[::-1])
        for row, alert in enumerate(self.alert_model.records):
            if alert.id in selected:
                self.alert_table.selectionModel().select(
                    self.alert_model.index(row, 0),
                    self.alert_table.selectionModel().SelectionFlag.Select
                    | self.alert_table.selectionModel().SelectionFlag.Rows,
                )
            if alert.id == current:
                self._load_case(alert)
        self.statusBar().showMessage(f"Updated {datetime.now():%H:%M:%S}  ·  {self.store.path}")

    def refresh_events(self) -> None:
        events: list[Event] = self.store.search(
            since=self.since, limit=EVENT_LIMIT, **parse_query(self.search.text())
        )
        self.event_model.set_records(events[::-1])
        more = " (limit reached, narrow the search)" if len(events) == EVENT_LIMIT else ""
        self.event_count.setText(f"{len(events):,} events{more}")

    def _act(self, change: Callable[[], int], done: str) -> None:
        try:
            changed = change()
        except TriageError as exc:
            QMessageBox.warning(self, "SIEMstress", str(exc).capitalize())
            return
        self.statusBar().showMessage(f"{changed} alert(s) {done}", 5000)
        self.refresh_live()

    def acknowledge_selected(self) -> None:
        if ids := self._selected_ids():
            self._act(lambda: self.store.acknowledge(ids, getpass.getuser()), "acknowledged")

    def assign_selected(self) -> None:
        if ids := self._selected_ids():
            me = getpass.getuser()
            self._act(lambda: self.store.assign(ids, me, me), f"assigned to {me}")

    def resolve_selected(self) -> None:
        if not (ids := self._selected_ids()):
            return
        dialog = ResolveDialog(self, len(ids))
        if dialog.exec():
            values = dialog.values()
            self._act(lambda: self.store.resolve(ids, getpass.getuser(), *values), "resolved")

    def reopen_selected(self) -> None:
        if not (ids := self._selected_ids()):
            return
        reason, ok = QInputDialog.getText(self, "Reopen", "Why is this being reopened?")
        if ok:
            self._act(lambda: self.store.reopen(ids, getpass.getuser(), reason), "reopened")

    def note_current(self) -> None:
        if self._current_id() is None:
            return
        self.case.setCurrentIndex(2)
        self.case.note.setFocus()

    def add_note(self, text: str) -> None:
        if (alert_id := self._current_id()) is not None:
            self.store.add_note([alert_id], getpass.getuser(), text)
            self.refresh_live()

    def _load_case(self, alert: Alert) -> None:
        self.case.show_case(alert, self.store.activity(alert.id), self.store.related_events(alert))

    def _show_overview(self, o: Overview) -> None:
        unresolved = sum(o.unresolved_by_level.values())
        worst = next((lv for lv in reversed(Level) if o.unresolved_by_level[lv]), None)
        states = [host_state(h.last_seen) for h in o.hosts]
        quiet, silent = states.count("quiet"), states.count("silent")
        host_note = ", ".join(f"{n} {s}" for n, s in ((silent, "silent"), (quiet, "quiet")) if n)
        self.cards["events"].set(f"{o.events:,}")
        self.cards["alerts"].set(f"{unresolved:,}", LEVEL_COLORS[worst] if worst else GREEN)
        self.cards["failures"].set(f"{o.auth_failures:,}", AMBER if o.auth_failures else None)
        self.cards["hosts"].set(
            str(len(o.hosts)),
            RED if silent else AMBER if quiet else GREEN,
            f"hosts, {host_note}" if host_note else "hosts",
        )
        self.chart.set_data(o.timeline, o.since, o.bucket)

    def _selected_ids(self) -> set[int]:
        rows = {index.row() for index in self.alert_table.selectionModel().selectedRows()}
        return {self.alert_model.records[r].id for r in rows if self.alert_model.records[r].id}

    def _current_id(self) -> int | None:
        index = self.alert_table.currentIndex()
        return self.alert_model.records[index.row()].id if index.isValid() else None

    def _show_alert(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid():
            self._load_case(self.alert_model.records[current.row()])
        else:
            self.case.clear_case()

    def show_about(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("About SIEMstress")
        logo = QLabel()
        logo.setPixmap(
            QPixmap(str(ASSETS / "logo.png")).scaledToWidth(
                520, Qt.TransformationMode.SmoothTransformation
            )
        )
        text = QLabel(
            f"<b>SIEMstress {__version__}</b><br>A lightweight SIEM for homelabs: it stitches"
            " logs from your machines together and flags what's worth a look."
        )
        text.setWordWrap(True)
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout = QVBoxLayout(dialog)
        layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text)
        layout.addWidget(buttons)
        dialog.exec()

    def _bring_to_front(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _notify_new(self, alerts: list[Alert]) -> None:
        newest = max((a.id or 0 for a in alerts), default=0)
        if self.last_alert_id is not None and self.tray:
            fresh = [
                a for a in alerts if (a.id or 0) > self.last_alert_id and a.level >= Level.MEDIUM
            ]
            for a in fresh[-3:]:
                icon = (
                    QSystemTrayIcon.MessageIcon.Critical
                    if a.level >= Level.HIGH
                    else QSystemTrayIcon.MessageIcon.Warning
                )
                self.tray.showMessage(f"SIEMstress: {a.level.name}", a.title, icon, 10_000)
        self.last_alert_id = max(newest, self.last_alert_id or 0)


def run(db_path: Path, refresh_seconds: float) -> None:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("SIEMstress")
    app.setDesktopFileName("siemstress")
    app.setWindowIcon(app_icon())
    try:
        store = Store(db_path, viewer=True)
    except StoreError as exc:
        # Launched from the app menu there's no terminal to print to.
        QMessageBox.critical(None, "SIEMstress", f"Can't open the event database.\n\n{exc}")
        raise SystemExit(1) from None
    with store:
        window = MainWindow(store, refresh_seconds)
        window.show()
        app.exec()
