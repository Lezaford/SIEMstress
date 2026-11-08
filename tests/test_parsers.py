# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import UTC, datetime

import pytest

from siemstress.event import Event
from siemstress.parsers import normalize
from siemstress.parsers.patterns import clean_ip

FIELDS = ("action", "outcome", "user", "target_user", "src_ip")


def normalized(app: str, message: str) -> Event:
    event = Event(ts=datetime.now(UTC), source="test", app=app, message=message)
    normalize(event)
    return event


def fields(event: Event) -> tuple:
    return tuple(getattr(event, f) for f in FIELDS)


@pytest.mark.parametrize(
    ("app", "message", "expected", "extra"),
    [
        (
            "sshd-session",
            "Accepted publickey for alice from 192.168.1.20 port 50022 ssh2: ED25519 SHA256:abc",
            ("ssh.login", "success", "alice", None, "192.168.1.20"),
            {"method": "publickey", "src_port": "50022"},
        ),
        (
            "sshd",
            "Failed password for root from 203.0.113.9 port 4242 ssh2",
            ("ssh.login", "failure", "root", None, "203.0.113.9"),
            {"method": "password"},
        ),
        (
            "sshd-auth",
            "Failed password for invalid user admin from 2001:db8::1 port 4242 ssh2",
            ("ssh.login", "failure", "admin", None, "2001:db8::1"),
            {"invalid_user": "invalid"},
        ),
        (
            "sshd",
            "Invalid user oracle from ::ffff:198.51.100.7 port 36000",
            ("ssh.invalid_user", "failure", "oracle", None, "198.51.100.7"),
            {},
        ),
        (
            "sshd",
            "error: maximum authentication attempts exceeded for root from 203.0.113.9 "
            "port 4242 ssh2 [preauth]",
            ("ssh.max_attempts", "failure", "root", None, "203.0.113.9"),
            {},
        ),
        (
            "sudo",
            "  alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/dnf upgrade",
            ("sudo.exec", "success", "alice", "root", None),
            {"tty": "pts/1", "command": "/usr/bin/dnf upgrade"},
        ),
        (
            "sudo",
            "  alice : a password is required ; PWD=/home/alice ; USER=root ; COMMAND=/bin/id",
            ("sudo.exec", "failure", "alice", "root", None),
            {"reason": "a password is required", "command": "/bin/id"},
        ),
        (
            "sudo",
            "bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/tmp ; USER=root ; "
            "TSID=000001 ; COMMAND=/bin/sh -c 'a ; b'",
            ("sudo.exec", "failure", "bob", "root", None),
            {"reason": "3 incorrect password attempts", "command": "/bin/sh -c 'a ; b'"},
        ),
        (
            "su",
            "FAILED SU (to root) alice on pts/2",
            ("su.switch", "failure", "alice", "root", None),
            {"tty": "pts/2"},
        ),
        (
            "su",
            "(to root) alice on pts/2",
            ("su.switch", "success", "alice", "root", None),
            {},
        ),
        (
            "kde",
            "pam_unix(kde:auth): authentication failure; logname=alice uid=1000 euid=1000 "
            "tty= ruser= rhost=  user=alice",
            ("auth", "failure", "alice", None, None),
            {"pam_service": "kde"},
        ),
        (
            "sshd",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost=203.0.113.9  user=root",
            ("auth", "failure", "root", None, "203.0.113.9"),
            {"pam_service": "sshd"},
        ),
        (
            "sudo",
            "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
            ("session.open", "success", "alice", "root", None),
            {"pam_service": "sudo"},
        ),
        (
            "plasmalogin",
            "pam_unix(plasmalogin-greeter:session): session opened for user plasmalogin(uid=964)"
            " by (uid=0)",
            ("session.open", "success", None, "plasmalogin", None),
            {"pam_service": "plasmalogin-greeter"},
        ),
        (
            "login",
            "pam_unix(login:session): session closed for user alice",
            ("session.close", "success", None, "alice", None),
            {},
        ),
        (
            "passwd",
            "pam_unix(passwd:chauthtok): password changed for bob",
            ("password.change", "success", None, "bob", None),
            {},
        ),
        (
            "useradd",
            "new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, "
            "from=/dev/pts/0",
            ("user.create", "success", None, "bob", None),
            {"uid": "1001"},
        ),
        (
            "userdel",
            "delete user 'bob'",
            ("user.delete", "success", None, "bob", None),
            {},
        ),
        (
            "usermod",
            "add 'alice' to group 'libvirt'",
            ("group.add_member", "success", None, "alice", None),
            {"group": "libvirt"},
        ),
        (
            "gpasswd",
            "user bob added by root to group wheel",
            ("group.add_member", "success", "root", "bob", None),
            {"group": "wheel"},
        ),
        (
            "groupadd",
            "new group: name=docker, GID=990",
            ("group.create", "success", None, None, None),
            {"group": "docker"},
        ),
    ],
)
def test_recognized(app, message, expected, extra):
    event = normalized(app, message)
    assert fields(event) == expected
    assert extra.items() <= event.extra.items()


@pytest.mark.parametrize(
    ("app", "message"),
    [
        ("usermod", "add 'alice' to shadow group 'libvirt'"),
        ("sudo", "pam_systemd(sudo:session): Failed to check if /run/user/0/bus exists"),
        ("sshd", "Connection closed by 203.0.113.9 port 4242 [preauth]"),
        ("kernel", "Failed password for root from 203.0.113.9 port 22 ssh2"),
        ("sudo", "pam_unix(sudo:auth): conversation failed"),
    ],
)
def test_ignored(app, message):
    event = normalized(app, message)
    assert fields(event) == (None,) * len(FIELDS)
    assert event.extra == {}


def test_hostname_rhost_goes_to_extra():
    event = normalized(
        "sshd",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=scanner.example.net  user=root",
    )
    assert event.src_ip is None
    assert event.extra["rhost"] == "scanner.example.net"


def test_clean_ip():
    assert clean_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert clean_ip("2001:DB8::1") == "2001:db8::1"
    assert clean_ip("example.com") is None


AUDIT_CASES = [
    (
        "AUDIT1123 pid=266092 uid=1000 auid=1000 ses=3 subj=unconfined_u:unconfined_r:"
        'unconfined_t:s0-s0:c0.c1023 msg=\'cwd="/home/alice" '
        'cmd=6E6D6170202D7353202D506E203139322E3136382E312E302F3234 exe="/usr/bin/sudo" '
        "terminal=pts/1 res=success'",
        ("audit.command", "success"),
        {"command": "nmap -sS -Pn 192.168.1.0/24", "cwd": "/home/alice", "auid": "1000"},
    ),
    (
        "AUDIT1102 pid=9168 uid=0 auid=1000 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:"
        's0-s0:c0.c1023 msg=\'op=add-user-to-group grp="libvirt" acct="alice" '
        'exe="/usr/sbin/usermod" hostname=h addr=? terminal=pts/3 res=success\'',
        ("group.add_member", "success"),
        {"group": "libvirt", "op": "add-user-to-group"},
    ),
    (
        "type=USER_LOGIN msg=audit(1790000000.123:456): pid=812 uid=0 auid=4294967295 "
        'ses=4294967295 msg=\'op=login acct="root" exe="/usr/sbin/sshd" hostname=? '
        "addr=203.0.113.9 terminal=ssh res=failed'",
        ("audit.login", "failure"),
        {"audit_type": "USER_LOGIN", "terminal": "ssh"},
    ),
    (
        "AUDIT1138 pid=2698 uid=0 auid=1000 ses=3 msg='op=install sw=\"hashcat-7.1.2-5.fc44."
        'x86_64" sw_type=rpm key_enforce=0 gpg_res=1 root_dir="/" comm="dnf" '
        'exe="/usr/bin/dnf5" hostname=h addr=? terminal=pts/2 res=success\'',
        ("software.install", "success"),
        {"package": "hashcat-7.1.2-5.fc44.x86_64", "tool": "dnf"},
    ),
    (
        "MAC_STATUS enforcing=0 old_enforcing=1 auid=1000 ses=3 enabled=1 old-enabled=1 "
        "lsm=selinux res=1",
        ("selinux.mode", "success"),
        {"enforcing": "0", "old_enforcing": "1"},
    ),
    (
        'AVC avc:  denied  { read } for  pid=1234 comm="httpd" name="shadow" dev="dm-0" '
        "ino=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 "
        "tclass=file permissive=0",
        ("selinux.denied", "failure"),
        {"perms": "read", "comm": "httpd", "tclass": "file", "permissive": "0"},
    ),
    (
        "ANOM_PROMISCUOUS dev=eth0 prom=256 old_prom=0 auid=1000 uid=0 gid=0 ses=3",
        ("network.promiscuous", None),
        {"dev": "eth0", "prom": "256"},
    ),
]


@pytest.mark.parametrize(("message", "expected", "extra"), AUDIT_CASES)
def test_audit(message, expected, extra):
    event = Event(ts=datetime.now(UTC), source="syslog", app="audit", message=message)
    assert normalize(event)
    assert (event.action, event.outcome) == expected
    assert extra.items() <= event.extra.items()


def test_audit_login_address_and_account():
    event = normalized("audispd", AUDIT_CASES[2][0])
    assert (event.user, event.src_ip) == ("root", "203.0.113.9")


def test_audit_actor_resolved_only_for_local_records():
    remote = normalized("audit", AUDIT_CASES[0][0])
    assert remote.user is None
    local = Event(ts=datetime.now(UTC), source="journald", app="audit", message=AUDIT_CASES[0][0])
    normalize(local)
    assert local.user is not None  # uid 1000 resolved (or kept numeric) from this host


@pytest.mark.parametrize(
    "message",
    [
        "SERVICE_START pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=cups res=success'",
        "AUDIT1103 pid=1 uid=0 auid=4294967295 msg='op=PAM:setcred acct=\"alice\" res=success'",
        'AUDIT1102 pid=1 uid=0 auid=1000 msg=\'op=add-to-shadow-group grp="libvirt" '
        'acct="alice" res=success\'',
        "BPF prog-id=167 op=UNLOAD",
    ],
)
def test_audit_noise_ignored(message):
    assert not normalize(Event(ts=datetime.now(UTC), source="test", app="audit", message=message))


@pytest.mark.parametrize(
    ("app", "message", "expected", "extra"),
    [
        (
            "kernel",
            "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=198.51.100.7 DST=192.168.1.10 LEN=44 TOS=0x00 "
            "PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0",
            ("firewall.block", "198.51.100.7"),
            {"dst_port": "22", "proto": "TCP", "interface": "eth0", "rule": "UFW BLOCK"},
        ),
        (
            "kernel",
            "[ 1234.5678] filter_IN_public_REJECT: IN=enp3s0 OUT= SRC=203.0.113.4 "
            "DST=192.168.1.2 PROTO=UDP SPT=5353 DPT=161",
            ("firewall.block", "203.0.113.4"),
            {"dst_port": "161", "rule": "filter_IN_public_REJECT"},
        ),
        (
            "filterlog",
            "5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.9,"
            "192.168.1.1,51514,443,0,S,1,,64240,,mss",
            ("firewall.block", "198.51.100.9"),
            {"dst_port": "443", "proto": "tcp", "interface": "igb0", "direction": "in"},
        ),
        (
            "filterlog",
            "7,,,1000000105,igb1,match,pass,out,6,0x00,0x00000,64,udp,17,72,2001:db8::5,"
            "2001:db8::1,546,547,72",
            ("firewall.allow", "2001:db8::5"),
            {"dst_port": "547", "proto": "udp"},
        ),
        (
            "dnsmasq",
            "query[AAAA] tracker.example.com from 192.168.1.23",
            ("dns.query", "192.168.1.23"),
            {"domain": "tracker.example.com", "qtype": "AAAA"},
        ),
        (
            "pihole-FTL",
            "gravity blocked tracker.example.com is 0.0.0.0",
            ("dns.blocked", None),
            {"domain": "tracker.example.com"},
        ),
    ],
)
def test_network_sources(app, message, expected, extra):
    event = normalized(app, message)
    assert (event.action, event.src_ip) == expected
    assert extra.items() <= event.extra.items()


def test_ordinary_kernel_message_ignored():
    assert not normalize(Event(ts=datetime.now(UTC), source="t", app="kernel", message="usb 1-1"))
