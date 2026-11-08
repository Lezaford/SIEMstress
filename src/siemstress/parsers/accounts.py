# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""shadow-utils: useradd, userdel, usermod, groupadd, groupdel, gpasswd."""

from siemstress.event import SUCCESS
from siemstress.parsers.patterns import pattern

PATTERNS = (
    pattern(r"new user: name=(?P<target_user>[^,]+), UID=(?P<uid>\d+)", "user.create", SUCCESS),
    pattern(r"delete user '(?P<target_user>[^']+)'", "user.delete", SUCCESS),
    pattern(r"new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)", "group.create", SUCCESS),
    pattern(r"group '(?P<group>[^']+)' removed$", "group.delete", SUCCESS),
    # usermod/useradd also log a "to shadow group" twin of this line; it deliberately won't match.
    pattern(
        r"add '(?P<target_user>[^']+)' to group '(?P<group>[^']+)'", "group.add_member", SUCCESS
    ),
    pattern(
        r"delete '(?P<target_user>[^']+)' from group '(?P<group>[^']+)'",
        "group.remove_member",
        SUCCESS,
    ),
    pattern(
        r"user (?P<target_user>\S+) added by (?P<user>\S+) to group (?P<group>\S+)",
        "group.add_member",
        SUCCESS,
    ),
    pattern(
        r"user (?P<target_user>\S+) removed by (?P<user>\S+) from group (?P<group>\S+)",
        "group.remove_member",
        SUCCESS,
    ),
    pattern(r"change user '(?P<target_user>[^']+)' password", "password.change", SUCCESS),
    pattern(r"lock user '(?P<target_user>[^']+)' password", "account.lock", SUCCESS),
    pattern(r"unlock user '(?P<target_user>[^']+)' password", "account.unlock", SUCCESS),
)
