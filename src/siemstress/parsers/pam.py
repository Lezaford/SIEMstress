# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAM module messages, logged under whichever program called PAM (sudo, sshd, kde, login...)."""

import re

from siemstress.event import FAILURE, SUCCESS, Event
from siemstress.parsers.patterns import apply, pattern

_PREFIX = re.compile(r"pam_(?P<module>\w+)\((?P<service>[^:]+):(?P<type>\w+)\): ")

PATTERNS = (
    pattern(
        r"authentication failure;.*? rhost=(?P<src_ip>\S*)(?:\s+user=(?P<user>\S+))?",
        "auth",
        FAILURE,
    ),
    # The session owner is the target; "by" is whoever opened it (empty for system services).
    pattern(
        r"session opened for user (?P<target_user>[^(\s]+)\(uid=\d+\) by (?P<user>[^(\s]*)",
        "session.open",
        SUCCESS,
    ),
    pattern(r"session closed for user (?P<target_user>\S+)", "session.close", SUCCESS),
    pattern(r"password changed for (?P<target_user>\S+)", "password.change", SUCCESS),
    pattern(
        r"Consecutive login failures for user (?P<target_user>\S+) account temporarily locked",
        "account.lock",
        SUCCESS,
    ),
)


def parse(event: Event) -> bool:
    if not (m := _PREFIX.match(event.message)):
        return False
    if apply(event, PATTERNS, event.message[m.end() :]):
        event.extra["pam_service"] = m["service"]
        return True
    return False
