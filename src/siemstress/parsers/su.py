# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from siemstress.event import FAILURE, SUCCESS
from siemstress.parsers.patterns import pattern

_BODY = r"\(to (?P<target_user>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"

PATTERNS = (
    pattern(rf"FAILED SU {_BODY}", "su.switch", FAILURE),
    pattern(_BODY, "su.switch", SUCCESS),
)
