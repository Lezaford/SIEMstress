# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize raw events into action/outcome/user/target_user/src_ip fields."""

from collections.abc import Callable

from siemstress.event import Event
from siemstress.parsers import accounts, audit, firewall, pam, pihole, ssh, su, sudo
from siemstress.parsers.patterns import Pattern, apply

Parser = Callable[[Event], bool]


def _table(patterns: tuple[Pattern, ...]) -> Parser:
    return lambda event: apply(event, patterns)


_BY_APP: dict[str, Parser] = {
    **dict.fromkeys(("sshd", "sshd-session", "sshd-auth"), _table(ssh.PATTERNS)),
    "sudo": _table(sudo.PATTERNS),
    "su": _table(su.PATTERNS),
    **dict.fromkeys(
        ("useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd"),
        _table(accounts.PATTERNS),
    ),
    **dict.fromkeys(("audit", "audispd", "audisp-syslog"), audit.parse),
    "kernel": firewall.parse_netfilter,
    "filterlog": firewall.parse_filterlog,
    **dict.fromkeys(("dnsmasq", "pihole-FTL"), _table(pihole.PATTERNS)),
}


def normalize(event: Event) -> bool:
    """Fill in normalized fields if the event is recognized. Returns whether it was."""
    if event.message.startswith("pam_"):
        return pam.parse(event)
    parser = _BY_APP.get(event.app or "")
    return parser is not None and parser(event)
