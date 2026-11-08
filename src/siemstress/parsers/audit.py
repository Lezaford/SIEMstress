# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Linux audit records, from the journal or from audit.log-style lines forwarded over syslog.

journald writes user-space record types by number (AUDIT1123), the kernel ones by
name (AVC). Only security-relevant types are normalized; routine records such as
SERVICE_START or CRED_ACQ are left as raw events.
"""

import re

from siemstress.event import FAILURE, SUCCESS, Event
from siemstress.identity import username
from siemstress.parsers.patterns import clean_ip

TYPES = {
    1100: "USER_AUTH", 1101: "USER_ACCT", 1102: "USER_MGMT", 1103: "CRED_ACQ",
    1104: "CRED_DISP", 1105: "USER_START", 1106: "USER_END", 1107: "USER_AVC",
    1108: "USER_CHAUTHTOK", 1109: "USER_ERR", 1110: "CRED_REFR", 1112: "USER_LOGIN",
    1113: "USER_LOGOUT", 1114: "ADD_USER", 1115: "DEL_USER", 1116: "ADD_GROUP",
    1117: "DEL_GROUP", 1123: "USER_CMD", 1127: "SYSTEM_BOOT", 1128: "SYSTEM_SHUTDOWN",
    1132: "GRP_MGMT", 1135: "ACCT_LOCK", 1136: "ACCT_UNLOCK", 1138: "SOFTWARE_UPDATE",
    1400: "AVC", 1404: "MAC_STATUS", 1700: "ANOM_PROMISCUOUS", 1701: "ANOM_ABEND",
}  # fmt: skip

# "USER_CMD pid=..." (journal) or "type=USER_CMD msg=audit(1690000000.123:42): pid=..." (audit.log)
_HEADER = re.compile(
    r"(?:type=)?(?P<type>AUDIT\d+|[A-Z][A-Z_]+)(?: msg=audit\([\d.:]+\):)? ?(?P<body>.*)", re.S
)
_KV = re.compile(r"""([\w-]+)=("[^"]*"|'[^']*'|\S*)""")
_AVC = re.compile(r"avc:\s+(?P<result>denied|granted)\s+\{ (?P<perms>[^}]+) \}")
_HEX = re.compile(r"(?:[0-9A-F]{2})+")
# Fields that audit hex-encodes when they contain spaces or other special characters.
_MAYBE_HEX = frozenset({"cmd", "proctitle", "acct", "exe", "comm", "name", "grp", "cwd"})
_UNSET = frozenset({"4294967295", "-1", "unset", "?"})


def _fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in _KV.findall(body):
        if value.startswith("'"):  # msg='...' holds a nested key=value list
            fields.update(_fields(value[1:-1]))
        elif value.startswith('"'):
            fields[key] = value[1:-1]
        elif key in _MAYBE_HEX and _HEX.fullmatch(value):
            fields[key] = bytes.fromhex(value).decode("utf-8", "replace").replace("\x00", " ")
        else:
            fields[key] = value
    return fields


def _account(uid: str | None, local: bool) -> str | None:
    """Map a numeric uid to a name. Only safe for this machine's own records."""
    if uid is None or uid in _UNSET:
        return None
    return username(uid) if local else None


def _outcome(res: str | None) -> str | None:
    if res is None:
        return None
    return SUCCESS if res in ("success", "1", "yes") else FAILURE


def parse(event: Event) -> bool:
    if not (m := _HEADER.match(event.message)):
        return False
    kind = m["type"]
    if kind.startswith("AUDIT") and kind[5:].isdigit():
        kind = TYPES.get(int(kind[5:]), kind)
    f = _fields(m["body"])
    actor = _account(f.get("auid"), local=event.source == "journald")
    account = f.get("acct") if f.get("acct") not in _UNSET else None
    extra = {"audit_type": kind}
    if f.get("auid") and f["auid"] not in _UNSET:
        extra["auid"] = f["auid"]

    def done(
        action: str,
        *,
        user: str | None = actor,
        target: str | None = None,
        outcome: str | None = _outcome(f.get("res")),
        **details: str | None,
    ) -> bool:
        event.action, event.outcome, event.target_user = action, outcome, target
        event.user = user or event.user
        if (addr := f.get("addr")) and addr not in _UNSET:
            event.src_ip = clean_ip(addr)
        event.extra.update(extra)
        event.extra.update({k: v for k, v in details.items() if v})
        return True

    match kind:
        case "USER_AUTH":
            return done("audit.auth", user=account, exe=f.get("exe"), terminal=f.get("terminal"))
        case "USER_LOGIN":
            return done("audit.login", user=account or actor, terminal=f.get("terminal"))
        case "USER_CMD":
            return done(
                "audit.command", command=f.get("cmd"), cwd=f.get("cwd"), terminal=f.get("terminal")
            )
        case "ADD_USER":
            return done("user.create", target=account or f.get("id"), exe=f.get("exe"))
        case "DEL_USER":
            return done("user.delete", target=account or f.get("id"), exe=f.get("exe"))
        case "ADD_GROUP":
            return done("group.create", group=account or f.get("grp"), exe=f.get("exe"))
        case "DEL_GROUP":
            return done("group.delete", group=account or f.get("grp"), exe=f.get("exe"))
        case "USER_MGMT" | "GRP_MGMT":
            op = f.get("op", "")
            if "shadow" in op:  # the /etc/gshadow twin of a group change
                return False
            if "group" in op and ("add" in op or "delete" in op or "remove" in op):
                action = "group.add_member" if "add" in op else "group.remove_member"
                return done(action, target=account, group=f.get("grp"), op=op)
            return done("audit.account_change", target=account, op=op)
        case "USER_CHAUTHTOK":
            return done("password.change", target=account, op=f.get("op"))
        case "ACCT_LOCK" | "ACCT_UNLOCK":
            return done(f"account.{kind[5:].lower()}", target=account)
        case "SOFTWARE_UPDATE":
            op = f.get("op", "change")
            return done(f"software.{op}", package=f.get("sw"), tool=f.get("comm"))
        case "SYSTEM_BOOT" | "SYSTEM_SHUTDOWN":
            return done(f"system.{kind[7:].lower()}", user=None)
        case "MAC_STATUS":
            return done(
                "selinux.mode", enforcing=f.get("enforcing"), old_enforcing=f.get("old_enforcing")
            )
        case "AVC" | "USER_AVC":
            if not (avc := _AVC.search(m["body"])) or avc["result"] != "denied":
                return False
            return done(
                "selinux.denied",
                outcome=FAILURE,
                perms=avc["perms"].strip(),
                comm=f.get("comm"),
                tclass=f.get("tclass"),
                scontext=f.get("scontext"),
                tcontext=f.get("tcontext"),
                permissive=f.get("permissive"),
            )
        case "CONFIG_CHANGE":
            # Turning auditing off, or deleting its rules, is how an attacker hides
            # what comes next. auditd also changes config at boot, without an auid.
            if f.get("audit_enabled") == "0":
                return done("audit.disable", old=f.get("old"))
            if f.get("op") == "remove_rule":
                return done("audit.rule_remove", key=f.get("key"), list=f.get("list"))
            return False
        case "ANOM_PROMISCUOUS":
            return done("network.promiscuous", outcome=None, dev=f.get("dev"), prom=f.get("prom"))
        case "ANOM_ABEND":
            return done(
                "process.crash",
                outcome=FAILURE,
                comm=f.get("comm"),
                exe=f.get("exe"),
                sig=f.get("sig"),
            )
    return False
