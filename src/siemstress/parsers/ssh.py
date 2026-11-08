# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from siemstress.event import FAILURE, SUCCESS
from siemstress.parsers.patterns import pattern

_FROM = r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"

PATTERNS = (
    pattern(rf"Accepted (?P<method>\S+) for (?P<user>.+?) {_FROM}", "ssh.login", SUCCESS),
    pattern(
        rf"Failed (?P<method>\S+) for (?:(?P<invalid_user>invalid) user )?(?P<user>.*?) {_FROM}",
        "ssh.login",
        FAILURE,
    ),
    pattern(rf"Invalid user (?P<user>.*?) {_FROM}", "ssh.invalid_user", FAILURE),
    pattern(
        rf"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*?) "
        rf"{_FROM}",
        "ssh.max_attempts",
        FAILURE,
    ),
)
