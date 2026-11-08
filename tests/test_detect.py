# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import UTC, datetime, timedelta

import pytest

from siemstress.detect import Engine, RuleError, load_rules, parse_rule
from siemstress.event import Event, Level

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)


def event(seconds: float = 0, **kw) -> Event:
    return Event(ts=T0 + timedelta(seconds=seconds), source="test", message="m", **kw)


def rule(**kw) -> dict:
    return {"id": "r", "title": "t", "level": "high", "match": {"action": "x"}} | kw


def run(rules: list[dict], events: list[Event]) -> list:
    engine = Engine([parse_rule(r, "test") for r in rules])
    return [alert for e in events for alert in engine.process(e)]


def test_match_rule_with_globs_and_extra():
    r = rule(match={"action": "group.*", "extra": {"group": ["wheel", "sudo"]}})
    alerts = run(
        [r],
        [
            event(action="group.add_member", extra={"group": "wheel"}),
            event(action="group.add_member", extra={"group": "users"}),
            event(action="user.create", extra={"group": "wheel"}),
        ],
    )
    assert len(alerts) == 1


def test_exclude_requires_all_conditions():
    r = rule(exclude={"user": "backup", "src_ip": "10.*"})
    alerts = run(
        [r],
        [
            event(action="x", user="backup", src_ip="10.0.0.1"),  # excluded
            event(action="x", user="backup", src_ip="1.2.3.4"),
            event(action="x", user="alice", src_ip="10.0.0.1"),
        ],
    )
    assert len(alerts) == 2


def test_threshold_is_per_group_and_sliding():
    r = rule(group_by=["src_ip"], threshold={"count": 3, "window": "1m"}, title="{src_ip} {count}")
    events = [
        event(0, action="x", src_ip="a"),
        event(10, action="x", src_ip="b"),
        event(20, action="x", src_ip="a"),
        event(70, action="x", src_ip="a"),  # first hit has slid out of the window
        event(80, action="x", src_ip="a"),  # three within 60s: alert
    ]
    [alert] = run([r], events)
    assert (alert.title, alert.count, alert.ts) == ("a 3", 3, T0 + timedelta(seconds=80))
    assert alert.context["src_ip"] == "a"


def test_threshold_context_only_has_shared_fields():
    r = rule(group_by=["src_ip"], threshold={"count": 2, "window": "1m"})
    events = [
        event(0, action="x", src_ip="a", user="admin"),
        event(1, action="x", src_ip="a", user="pi"),
    ]
    [alert] = run([r], events)
    assert "user" not in alert.context
    assert alert.context["src_ip"] == "a" and alert.context["last message"] == "m"


def test_cooldown_suppresses_repeats_per_group():
    r = rule(group_by=["user"], cooldown="10m")
    events = [
        event(0, action="x", user="a"),
        event(60, action="x", user="a"),  # suppressed
        event(60, action="x", user="b"),
        event(601, action="x", user="a"),
    ]
    assert [a.context["user"] for a in run([r], events)] == ["a", "b", "a"]


def test_threshold_cooldown_defaults_to_window():
    r = rule(threshold={"count": 2, "window": "1m"})
    events = [event(s, action="x") for s in (0, 1, 2, 3, 61, 62)]
    assert [a.ts.second for a in run([r], events)] == [1, 2]


def test_title_placeholders_for_missing_values():
    [alert] = run([rule(title="{user} on {host} via {extra[nope]}")], [event(action="x")])
    assert alert.title == "? on ? via ?"


@pytest.mark.parametrize(
    ("data", "error"),
    [
        (rule(level="severe"), "level must be one of low, medium, high, critical"),
        (rule(threshold={"count": 2}), "threshold must be"),
        (rule(match={"usr": "x"}), "unknown field 'usr'"),
        (rule(treshold={"count": 1}), "unknown keys"),
        (rule(threshold={"count": 2, "window": "5 min"}), "invalid duration"),
        (rule(group_by=["nope"]), "unknown group_by"),
        (rule(title="{user.nope}"), "bad title"),
        ({"id": "r", "level": "low", "match": {}}, "missing 'title'"),
        (rule(match={}), "match must not be empty"),
    ],
)
def test_invalid_rules(data, error):
    with pytest.raises(RuleError, match=error):
        parse_rule(data, "test")


def test_default_rules_load():
    rules = load_rules()
    assert len({r.id for r in rules}) == len(rules) >= 10


def test_user_rules_override_and_disable(tmp_path):
    (tmp_path / "local.toml").write_text(
        '[[rule]]\nid = "ssh-root-login"\ntitle = "custom"\nlevel = "critical"\n'
        'match = { action = "ssh.login" }\n\n'
        '[[rule]]\nid = "my-rule"\ntitle = "mine"\nlevel = "low"\nmatch = { app = "cron" }\n'
    )
    rules = {r.id: r for r in load_rules(tmp_path, frozenset({"user-deleted"}))}
    assert rules["ssh-root-login"].level is Level.CRITICAL
    assert "my-rule" in rules
    assert "user-deleted" not in rules


def test_duplicate_ids_in_one_file(tmp_path):
    block = '[[rule]]\nid = "dup"\ntitle = "t"\nlevel = "low"\nmatch = { app = "x" }\n'
    (tmp_path / "dup.toml").write_text(block * 2)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def after_rule(**kw) -> dict:
    return (
        rule(
            match={"action": "login", "outcome": "success"},
            group_by=["src_ip"],
            after={"match": {"action": "login", "outcome": "failure"}, "count": 3, "window": "10m"},
        )
        | kw
    )


def login(seconds: float, outcome: str, ip: str = "a") -> Event:
    return event(seconds, action="login", outcome=outcome, src_ip=ip, user="alice")


def test_after_needs_enough_recent_preceding_events_from_the_same_group():
    events = [
        login(0, "failure"),  # slides out of the 10 minute window
        login(400, "failure"),
        login(410, "failure", ip="b"),  # other address, doesn't count
        login(420, "failure"),
        login(620, "success"),  # only 2 recent failures from a
        login(630, "failure"),
        login(640, "success"),  # 3 recent failures: alert
        login(650, "success"),  # counter was reset by the alert
    ]
    [alert] = run([after_rule(cooldown="0s")], events)
    assert (alert.ts, alert.count) == (T0 + timedelta(seconds=640), 3)
    assert alert.context["user"] == "alice"  # the success's own details are accurate


@pytest.mark.parametrize(
    ("data", "error"),
    [
        (after_rule(threshold={"count": 2, "window": "1m"}), "either threshold or after"),
        (after_rule(after={"count": 3, "window": "1m"}), "after must be"),
        (after_rule(after={"match": {"nope": "x"}, "count": 3, "window": "1m"}), "unknown field"),
    ],
)
def test_invalid_after(data, error):
    with pytest.raises(RuleError, match=error):
        parse_rule(data, "test")
