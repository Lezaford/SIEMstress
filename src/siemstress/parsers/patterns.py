# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import ipaddress
import re
from dataclasses import dataclass

from siemstress.event import Event

_FIELDS = ("user", "target_user")


@dataclass(frozen=True, slots=True)
class Pattern:
    """A message regex and what a match means.

    Named groups `user`, `target_user` and `src_ip` fill the matching Event
    fields; any other named group that matched is stored in `extra`.
    """

    regex: re.Pattern[str]
    action: str
    outcome: str | None = None


def pattern(regex: str, action: str, outcome: str | None = None) -> Pattern:
    return Pattern(re.compile(regex), action, outcome)


def clean_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def apply(event: Event, patterns: tuple[Pattern, ...], text: str | None = None) -> bool:
    """Normalize `event` using the first pattern matching `text` (default: the message)."""
    text = event.message if text is None else text
    for p in patterns:
        if not (m := p.regex.match(text)):
            continue
        groups = {k: v for k, v in m.groupdict().items() if v}
        event.action, event.outcome = p.action, p.outcome
        # Only overwrite what the message names; otherwise keep what the source knew
        # (e.g. the journal's process owner).
        for name in _FIELDS:
            if value := groups.pop(name, None):
                setattr(event, name, value)
        if host := groups.pop("src_ip", None):
            # PAM's rhost may be a hostname rather than an address.
            if ip := clean_ip(host):
                event.src_ip = ip
            else:
                event.extra["rhost"] = host
        event.extra.update(groups)
        return True
    return False
