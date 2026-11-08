# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Detection replay: realistic log lines for each threat, run through the real parsers
and the built-in rules, plus benign look-alikes that must stay quiet.

Each scenario lists the alerts it must raise, and no others.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

from siemstress.detect import Engine, load_rules
from siemstress.event import Event
from siemstress.parsers import normalize
from siemstress.sources import docker, journald, syslog

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)
ATTACKER, OTHER = "203.0.113.50", "198.51.100.23"


def log(at: float, program: str, message: str, host: str = "web") -> Event:
    """A syslog line from `host`, as the collector would receive it, `at` seconds in."""
    event = syslog.parse(f"<38>Sep 22 12:00:00 {host} {program}: {message}".encode(), "10.0.0.5")
    event.ts = T0 + timedelta(seconds=at)
    return event


def audit(at: float, record: str) -> Event:
    """An audit record as this machine's journal delivers it."""
    line = json.dumps(
        {"__REALTIME_TIMESTAMP": "0", "MESSAGE": record, "SYSLOG_IDENTIFIER": "audit"}
    )
    event = journald.parse(line)
    event.ts = T0 + timedelta(seconds=at)
    event.host = "web"  # same machine as the syslog lines in a scenario
    return event


def container(at: float, action: str, name: str = "web", **attributes: str) -> Event:
    attrs = {"name": name, "image": "nginx", **attributes}
    obj = {
        "Type": "container",
        "Action": action,
        "timeNano": 0,
        "Actor": {"ID": "c0ffee", "Attributes": attrs},
    }
    event = docker.parse(obj, "web")
    event.ts = T0 + timedelta(seconds=at)
    return event


def failed_ssh(at: float, ip: str = ATTACKER, user: str = "root") -> Event:
    return log(
        at,
        f"sshd[{900 + int(at)}]",
        f"Failed password for {user} from {ip} port 4{int(at):04d} ssh2",
    )


def pam_failure(at: float, user: str = "alice") -> Event:
    message = (
        f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        f"ruser= rhost={OTHER}  user={user}"
    )
    return log(at, "sshd[1]", message)


def sudo_denied(at: float, reason: str) -> Event:
    message = f"  alice : {reason} ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/id"
    return log(at, "sudo", message)


def ufw_block(at: float, port: int, ip: str = ATTACKER) -> Event:
    message = (
        f"[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC={ip} DST=192.168.1.10 LEN=44 PROTO=TCP "
        f"SPT=40000 DPT={port} WINDOW=1024 SYN URGP=0"
    )
    return log(at, "kernel", message)


def avc(at: float, comm: str = "httpd") -> Event:
    record = (
        f'AVC avc:  denied  {{ read }} for  pid=4242 comm="{comm}" name="shadow" '
        "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 "
        "tclass=file permissive=0"
    )
    return audit(at, record)


SCENARIOS = {
    # --- Initial access: guessing passwords over SSH (ATT&CK T1110) ---
    "ssh password guessing, 12 tries in 2 minutes": (
        [failed_ssh(i * 10) for i in range(12)],
        {"ssh-brute-force"},
    ),
    "ssh username spraying with invalid users": (
        [
            log(i * 5, "sshd", f"Invalid user {u} from {OTHER} port 5{i:04d}")
            for i, u in enumerate(
                [
                    "admin",
                    "oracle",
                    "test",
                    "pi",
                    "git",
                    "ftp",
                    "deploy",
                    "guest",
                    "ubuntu",
                    "postgres",
                ]
            )
        ],
        {"ssh-brute-force"},
    ),
    "benign: owner mistypes their ssh password 3 times": (
        [failed_ssh(i * 20, "192.168.1.20", "alice") for i in range(3)],
        set(),
    ),
    "benign: 9 failures from each of two IPs stay under the threshold": (
        [failed_ssh(i * 10, ip) for ip in (ATTACKER, OTHER) for i in range(9)],
        set(),
    ),
    # --- Valid accounts: direct root login (T1078) ---
    "ssh root login": (
        [log(0, "sshd", f"Accepted password for root from {ATTACKER} port 40100 ssh2")],
        {"ssh-root-login"},
    ),
    "benign: normal user logs in with a key": (
        [log(0, "sshd-session", "Accepted publickey for alice from 192.168.1.20 port 50022 ssh2")],
        set(),
    ),
    # --- The guessing worked: success right after failures (T1110 -> T1078) ---
    "ssh login succeeds right after a brute-force burst from the same IP": (
        [
            *(failed_ssh(i * 5, user="alice") for i in range(6)),
            log(40, "sshd", f"Accepted password for alice from {ATTACKER} port 40100 ssh2"),
        ],
        {"login-after-failures"},
    ),
    "full compromise: brute force that ends in a root login": (
        [
            *(failed_ssh(i * 5) for i in range(12)),
            log(70, "sshd", f"Accepted password for root from {ATTACKER} port 40100 ssh2"),
        ],
        {"ssh-brute-force", "ssh-root-login", "login-after-failures"},
    ),
    "benign: owner mistypes twice, then logs in": (
        [
            *(failed_ssh(i * 10, "192.168.1.20", "alice") for i in range(2)),
            log(30, "sshd", "Accepted password for alice from 192.168.1.20 port 50022 ssh2"),
        ],
        set(),
    ),
    "benign: success from a different address than the failures": (
        [
            *(failed_ssh(i * 5) for i in range(6)),
            log(40, "sshd", "Accepted publickey for alice from 192.168.1.20 port 50022 ssh2"),
        ],
        set(),
    ),
    # --- Password guessing against any PAM service ---
    "5 failed logins for one account in 10 minutes": (
        [pam_failure(i * 60) for i in range(5)],
        {"login-failures"},
    ),
    "benign: lock-screen typos spread over the day": (
        [pam_failure(i * 3600) for i in range(6)],
        set(),
    ),
    # --- Privilege escalation via sudo (T1548.003) ---
    "sudo password guessing": (
        [
            sudo_denied(0, "3 incorrect password attempts"),
            sudo_denied(90, "3 incorrect password attempts"),
        ],
        {"sudo-password-failures"},
    ),
    "sudo by an account without rights": (
        [sudo_denied(0, "user NOT in sudoers")],
        {"sudo-not-permitted"},
    ),
    "benign: one sudo typo, then success": (
        [
            sudo_denied(0, "1 incorrect password attempt"),
            log(
                10,
                "sudo",
                "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/dnf upgrade",
            ),
        ],
        set(),
    ),
    "failed su to root": (
        [log(0, "su", "FAILED SU (to root) alice on pts/1")],
        {"su-failure"},
    ),
    # --- Persistence: new accounts and privileged groups (T1136.001, T1098) ---
    "backdoor account added to sudo, logged by shadow-utils and audit": (
        [
            log(
                0,
                "useradd",
                "new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup, "
                "shell=/bin/bash, from=/dev/pts/0",
            ),
            audit(
                0,
                "AUDIT1114 pid=1 uid=0 auid=1000 ses=3 msg='op=adding-user "
                'acct="svc-backup" exe="/usr/sbin/useradd" res=success\'',
            ),
            log(5, "usermod", "add 'svc-backup' to group 'sudo'"),
            audit(
                5,
                "AUDIT1102 pid=2 uid=0 auid=1000 ses=3 msg='op=add-user-to-group "
                'grp="sudo" acct="svc-backup" exe="/usr/sbin/usermod" res=success\'',
            ),
        ],
        {"user-created", "privileged-group-member"},
    ),
    "account added to the docker group (root-equivalent)": (
        [log(0, "gpasswd", "user eve added by root to group docker")],
        {"privileged-group-member"},
    ),
    "benign: package installs a system account": (
        [
            audit(
                0,
                'AUDIT1114 pid=1 uid=0 auid=4294967295 msg=\'op=adding-user acct="gluster" '
                'exe="systemd-sysusers" res=success\'',
            )
        ],
        set(),
    ),
    "benign: user added to an unprivileged group": (
        [log(0, "usermod", "add 'alice' to group 'video'")],
        set(),
    ),
    "account deleted": (
        [log(0, "userdel", "delete user 'bob'")],
        {"user-deleted"},
    ),
    "root password changed": (
        [log(0, "passwd", "pam_unix(passwd:chauthtok): password changed for root")],
        {"root-password-changed"},
    ),
    "benign: user changes their own password": (
        [log(0, "passwd", "pam_unix(passwd:chauthtok): password changed for alice")],
        set(),
    ),
    "account locked after failures": (
        [
            log(
                0,
                "sshd",
                "pam_faillock(sshd:auth): Consecutive login failures for user alice "
                "account temporarily locked",
            )
        ],
        {"account-locked"},
    ),
    # --- Defense evasion: SELinux (T1562.001) ---
    "SELinux switched to permissive": (
        [
            audit(
                0,
                "MAC_STATUS enforcing=0 old_enforcing=1 auid=1000 ses=3 enabled=1 "
                "old-enabled=1 lsm=selinux res=1",
            )
        ],
        {"selinux-permissive"},
    ),
    "benign: SELinux switched back to enforcing": (
        [
            audit(
                0,
                "MAC_STATUS enforcing=1 old_enforcing=0 auid=1000 ses=3 enabled=1 "
                "old-enabled=1 lsm=selinux res=1",
            )
        ],
        set(),
    ),
    "burst of SELinux denials for a web server": (
        [avc(i * 5) for i in range(12)],
        {"selinux-denials"},
    ),
    "benign: an occasional SELinux denial": (
        [avc(i * 600) for i in range(4)],
        set(),
    ),
    # --- Defense evasion: blinding the audit system (T1562.012) ---
    "audit logging turned off": (
        [audit(0, "CONFIG_CHANGE op=set audit_enabled=0 old=1 auid=1000 ses=3 res=1")],
        {"audit-disabled"},
    ),
    "audit rules deleted by a person": (
        [
            audit(i, f"CONFIG_CHANGE auid=1000 ses=3 op=remove_rule key=watch{i} list=4 res=1")
            for i in range(3)
        ],
        {"audit-rules-removed"},
    ),
    "benign: auditd enables auditing and reloads its rules at boot": (
        [
            audit(
                0, "CONFIG_CHANGE op=set audit_enabled=1 old=1 auid=4294967295 ses=4294967295 res=1"
            ),
            audit(
                1,
                "CONFIG_CHANGE auid=4294967295 ses=4294967295 op=remove_rule "
                "key=(null) list=4 res=1",
            ),
        ],
        set(),
    ),
    # --- Discovery and collection (T1040, T1046) ---
    "physical NIC put into promiscuous mode": (
        [audit(0, "ANOM_PROMISCUOUS dev=eth0 prom=256 old_prom=0 auid=1000 uid=0 gid=0 ses=3")],
        {"promiscuous-interface"},
    ),
    "benign: VM and container interfaces, and promiscuous mode turned off": (
        [
            audit(0, "ANOM_PROMISCUOUS dev=vnet0 prom=256 old_prom=0 auid=4294967295 uid=0 gid=0"),
            audit(1, "ANOM_PROMISCUOUS dev=veth3a1 prom=256 old_prom=0 auid=4294967295 uid=0"),
            audit(2, "ANOM_PROMISCUOUS dev=eth0 prom=0 old_prom=256 auid=1000 uid=0 gid=0 ses=3"),
        ],
        set(),
    ),
    "port scan: 40 blocked ports from one IP in 20 seconds": (
        [ufw_block(i * 0.5, 1000 + i) for i in range(40)],
        {"firewall-scan"},
    ),
    "benign: a few blocked packets from internet noise": (
        [ufw_block(i * 30, 23) for i in range(5)],
        set(),
    ),
    # --- Containers (T1609) ---
    "shell opened inside a container": (
        [container(0, "exec_start: /bin/sh -c id")],
        {"container-exec"},
    ),
    "container crash loop": (
        [container(i * 60, "die", exitCode="1") for i in range(5)],
        {"container-restart-loop"},
    ),
    "benign: containers stopped cleanly for an update": (
        [container(i * 60, "die", name=f"app{i}", exitCode="0") for i in range(5)],
        set(),
    ),
}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_detection(scenario):
    events, expected = SCENARIOS[scenario]
    engine = Engine(load_rules())
    fired = []
    for event in sorted(events, key=lambda e: e.ts):
        normalize(event)
        fired += engine.process(event)
    assert {a.rule for a in fired} == expected
    assert len(fired) == len(expected), [a.title for a in fired]  # duplicates folded


def test_every_rule_has_a_scenario():
    covered = set().union(*(expected for _, expected in SCENARIOS.values()))
    assert {r.id for r in load_rules()} <= covered
