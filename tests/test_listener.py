# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging
import shutil
import socket
import ssl
import subprocess
from pathlib import Path

import pytest

from siemstress import identity
from siemstress.config import ConfigError, load_settings
from siemstress.event import Event
from siemstress.sources import journald
from siemstress.sources.syslog import Senders, SyslogServer, cert_name, tls_context

MAKE_CERTS = Path(__file__).parent.parent / "contrib" / "make-certs.sh"
LINE = b"<38>Sep 22 17:59:01 whoever sshd[812]: Failed password for root from 10.0.0.9 port 1 ssh2"


def test_local_host_prefers_configured_then_static_name(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "MACHINE_ID_FILE", tmp_path / "machine-id")
    monkeypatch.setattr(identity, "HOSTNAME_FILE", tmp_path / "hostname")
    monkeypatch.setattr(identity, "OS_RELEASE_FILE", tmp_path / "os-release")
    (tmp_path / "machine-id").write_text("abc123\n")
    (tmp_path / "os-release").write_text('ID=fedora\nDEFAULT_HOSTNAME="fedora"\n')
    (tmp_path / "hostname").write_text("\n")  # present but empty, as on this laptop

    assert identity.local_host() == identity.LocalHost("fedora", "abc123", generic=True)
    (tmp_path / "hostname").write_text("desk\n")
    assert identity.local_host() == identity.LocalHost("desk", "abc123")
    assert identity.local_host("configured").name == "configured"


def test_journal_entries_labeled_by_machine_id_and_uid():
    local = identity.LocalHost("desk", "abc123")
    entry = {"__REALTIME_TIMESTAMP": "1", "MESSAGE": "m", "_UID": "0",
             "_HOSTNAME": "customer.isp.example", "_MACHINE_ID": "abc123"}  # fmt: skip
    mine = journald.parse(json.dumps(entry), local)
    assert (mine.host, mine.user) == ("desk", "root")
    service = journald.parse(json.dumps(entry | {"_UID": "70"}), local)  # e.g. avahi
    assert (service.host, service.user) == ("desk", None)

    theirs = journald.parse(json.dumps(entry | {"_MACHINE_ID": "other"}), local)
    assert (theirs.host, theirs.user) == ("customer.isp.example", None)


def test_senders_most_specific_match_wins():
    senders = Senders({"192.168.1.0/24": "", "192.168.1.40": "debian-docker"}, "desk")
    assert senders.lookup("192.168.1.40") == (True, "debian-docker")
    assert senders.lookup("192.168.1.41") == (True, None)  # trust reported name
    assert senders.lookup("10.0.0.5") == (False, None)
    assert senders.lookup("127.0.0.1") == (True, "desk")
    assert senders.lookup("::ffff:127.0.0.1") == (True, "desk")


def test_verified_name_replaces_claimed_one():
    server = SyslogServer(asyncio.Queue(), Senders({"192.168.1.40": "debian-docker"}, "desk"))
    event = server.event(LINE, "192.168.1.40", "debian-docker")
    assert event.host == "debian-docker"
    assert event.extra["claimed_host"] == "whoever"
    trusted = server.event(LINE, "192.168.1.41", None)
    assert trusted.host == "whoever" and "claimed_host" not in trusted.extra


def test_rejections_are_logged_once_per_address(caplog):
    server = SyslogServer(asyncio.Queue(), Senders({}, "desk"))
    for _ in range(3):
        assert server.admit("203.0.113.9") == (False, None)
    server.admit("203.0.113.10")
    rejected = [r.getMessage() for r in caplog.records if "rejected" in r.getMessage()]
    assert len(rejected) == 2


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_plain_tcp_from_this_machine_gets_its_name():
    async def scenario() -> Event:
        queue: asyncio.Queue[Event] = asyncio.Queue()
        port = free_port()
        task = asyncio.create_task(
            SyslogServer(queue, Senders({}, "desk")).serve("127.0.0.1", port, udp=False)
        )
        await asyncio.sleep(0.05)
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(LINE + b"\n")
        await writer.drain()
        writer.close()
        event = await asyncio.wait_for(queue.get(), 2)
        task.cancel()
        return event

    event = asyncio.run(scenario())
    assert (event.host, event.app, event.extra["claimed_host"]) == ("desk", "sshd", "whoever")


@pytest.fixture(scope="module")
def certs(tmp_path_factory) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    good, rogue = tmp_path_factory.mktemp("certs"), tmp_path_factory.mktemp("rogue")
    for args in (
        [good, "ca"], [good, "server", "siem", "127.0.0.1"], [good, "client", "debian-docker"],
        [rogue, "ca"], [rogue, "client", "debian-docker"],
    ):  # fmt: skip
        subprocess.run([MAKE_CERTS, *map(str, args)], check=True, capture_output=True)
    (good / "rogue.crt").write_bytes((rogue / "debian-docker.crt").read_bytes())
    (good / "rogue.key").write_bytes((rogue / "debian-docker.key").read_bytes())
    return good


def client_context(certs: Path, name: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=certs / "ca.crt")
    context.check_hostname = False  # server cert names "siem"; we connect to 127.0.0.1
    context.load_cert_chain(certs / f"{name}.crt", certs / f"{name}.key")
    return context


def test_tls_names_host_from_client_certificate(certs):
    async def scenario() -> tuple[Event, bool]:
        queue: asyncio.Queue[Event] = asyncio.Queue()
        port = free_port()
        server = SyslogServer(queue, Senders({}, "desk"))
        context = tls_context(certs / "siem.crt", certs / "siem.key", certs / "ca.crt")
        task = asyncio.create_task(server.serve_tls("127.0.0.1", port, context))
        await asyncio.sleep(0.05)

        _, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(certs, "debian-docker")
        )
        writer.write(b"%d %s" % (len(LINE), LINE))  # RFC 5425 octet counting
        await writer.drain()
        event = await asyncio.wait_for(queue.get(), 2)
        writer.close()

        # A certificate from another CA must not get in.
        rogue_rejected = False
        try:
            _, rogue = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_context(certs, "rogue")
            )
            rogue.write(b"%d %s" % (len(LINE), LINE))
            await rogue.drain()
            await asyncio.sleep(0.1)
            rogue_rejected = queue.empty()
        except (ssl.SSLError, ConnectionError):
            rogue_rejected = True
        task.cancel()
        return event, rogue_rejected

    logging.getLogger("asyncio").setLevel(logging.CRITICAL)  # expected handshake failure noise
    event, rogue_rejected = asyncio.run(scenario())
    assert event.host == "debian-docker"  # from the certificate, not the message header
    assert event.extra["claimed_host"] == "whoever"
    assert rogue_rejected


def test_cert_name():
    assert (
        cert_name({"subjectAltName": (("DNS", "a"),), "subject": ((("commonName", "b"),),)}) == "a"
    )
    assert cert_name({"subject": ((("commonName", "b"),),)}) == "b"
    assert cert_name({}) is None


def test_syslog_settings(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        'hostname = "desk"\n[syslog]\nlisten = "0.0.0.0:5514"\nudp = false\n'
        'tls_listen = ":6514"\ntls_cert = "/c"\ntls_key = "/k"\ntls_ca = "/ca"\n'
        '[syslog.senders]\n"192.168.1.40" = "debian-docker"\n"192.168.1.0/24" = ""\n'
    )
    settings = load_settings(path)
    assert settings.hostname == "desk"
    assert settings.syslog.listen == ("0.0.0.0", 5514)
    assert not settings.syslog.udp
    assert settings.syslog.tls.listen == ("0.0.0.0", 6514)
    assert settings.syslog.senders == {"192.168.1.40": "debian-docker", "192.168.1.0/24": ""}

    path.write_text('[syslog.senders]\n"not-an-ip" = "x"\n')
    with pytest.raises(ConfigError, match="not an address"):
        load_settings(path)
    path.write_text('[syslog]\ntls_listen = ":6514"\n')
    with pytest.raises(ConfigError, match="tls_cert"):
        load_settings(path)


@pytest.mark.parametrize(
    "args",
    [
        ["client", "evil/CN=root"],
        ["client", "a,DNS:victim.example"],
        ["client", "-leading"],
        ["client", "ok", "10.0.0.1"],  # an IP only makes sense for a server certificate
        ["server", "srv", "not-an-ip!"],
    ],
)
def test_make_certs_rejects_bad_names(tmp_path, args):
    subprocess.run([MAKE_CERTS, str(tmp_path), "ca"], check=True, capture_output=True)
    result = subprocess.run([MAKE_CERTS, str(tmp_path), *args], capture_output=True, text=True)
    assert result.returncode != 0
    assert {p.name for p in tmp_path.iterdir()} <= {"ca.key", "ca.crt", "ca.srl"}  # nothing issued
