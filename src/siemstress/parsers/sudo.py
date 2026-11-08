# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from siemstress.event import FAILURE, SUCCESS
from siemstress.parsers.patterns import pattern

# "  alice : [reason ; ]TTY=pts/0 ; PWD=/home/alice ; USER=root ; [KEY=value ; ]COMMAND=..."
_FIELDS = (
    r"(?:TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>.*?) ; USER=(?P<target_user>\S+) ; "
    r"(?:[A-Z]+=\S* ; )*COMMAND=(?P<command>.*)"
)

PATTERNS = (
    # Denials put a reason (no "=") before the fields, e.g. "3 incorrect password attempts".
    pattern(rf"\s*(?P<user>\S+) : (?P<reason>[^=;]+?) ; {_FIELDS}", "sudo.exec", FAILURE),
    pattern(rf"\s*(?P<user>\S+) : {_FIELDS}", "sudo.exec", SUCCESS),
)
