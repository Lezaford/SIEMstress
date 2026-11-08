# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Syslog receiver (UDP, TCP and TLS) for RFC 3164 and RFC 5424 messages."""

import asyncio
import contextlib
import ipaddress
import logging
import re
import ssl
import time
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siemstress.event import Event

log = logging.getLogger(__name__)

MAX_MESSAGE = 64 * 1024
REJECT_LOG_INTERVAL = 3600.0

_PRI = re.compile(r"<(\d{1,3})>")
_RFC5424 = re.compile(
    r"1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) \S+ "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)",
    re.S,
)
_RFC3164 = re.compile(
    r"(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)",
    re.S,
)
# Local log files (e.g. Pi-hole's dnsmasq log) often omit the hostname.
_RFC3164_NO_HOST = re.compile(
    r"(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) "
    r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)",
    re.S,
)


def _nil(value: str) -> str | None:
    return None if value == "-" else value


def _bsd_timestamp(stamp: str, now: datetime) -> datetime:
    # RFC 3164 has no year or zone: assume the receiver's, and roll back a year
    # for messages that would otherwise land in the future (Dec 31 seen on Jan 1).
    local_now = now.astimezone()
    ts = datetime.strptime(f"{local_now.year} {stamp}", "%Y %b %d %H:%M:%S")
    ts = ts.replace(tzinfo=local_now.tzinfo)
    return ts.replace(year=ts.year - 1) if ts - local_now > timedelta(days=1) else ts


def parse(
    data: bytes, sender: str, now: datetime | None = None, *, source: str = "syslog"
) -> Event | None:
    """Parse a syslog message or log-file line; the <PRI> prefix and hostname are optional."""
    now = now or datetime.now(UTC)
    text = data.decode("utf-8", "replace").strip("\r\n\x00")
    if not text:
        return None
    event = Event(ts=now, source=source, message=text, host=sender, extra={"sender_ip": sender})

    rest = text
    if pri := _PRI.match(text):
        event.facility, event.severity = divmod(int(pri[1]), 8)
        rest = text[pri.end() :]

    if pri and (m := _RFC5424.match(rest)):
        with contextlib.suppress(ValueError):
            event.ts = datetime.fromisoformat(m["ts"]).astimezone()
        event.host = _nil(m["host"]) or sender
        event.app = _nil(m["app"])
        event.pid = int(m["pid"]) if m["pid"].isdigit() else None
        event.message = m["msg"].removeprefix("\ufeff")
        if m["sd"] != "-":
            event.extra["structured_data"] = m["sd"]
    elif m := _RFC3164.match(rest) or _RFC3164_NO_HOST.match(rest):
        with contextlib.suppress(ValueError):
            event.ts = _bsd_timestamp(m["ts"], now)
        event.host = m.groupdict().get("host") or sender
        event.app = m["app"]
        event.pid = int(m["pid"]) if m["pid"] else None
        event.message = m["msg"]
    else:
        event.message = rest
    return event


async def read_frames(reader: asyncio.StreamReader) -> AsyncIterator[bytes]:
    """Split a TCP stream into messages: octet-counted (RFC 6587) or newline-delimited."""
    while first := await reader.read(1):
        if first.isdigit():
            length = int(first + (await reader.readuntil(b" "))[:-1])
            if length > MAX_MESSAGE:
                raise ValueError(f"frame too large: {length}")
            yield await reader.readexactly(length)
        else:
            yield first + await reader.readline()


class Senders:
    """Which hosts may send syslog, and what their events are labeled.

    Entries map an address or network to a host name; an empty name trusts the name
    the sender reports. The most specific network wins. This machine (loopback) is
    always allowed and labeled with its own name.
    """

    def __init__(self, entries: Mapping[str, str], local_name: str):
        networks = [(ipaddress.ip_network(k, strict=False), v or None) for k, v in entries.items()]
        self._networks = sorted(networks, key=lambda entry: entry[0].prefixlen, reverse=True)
        self.local_name = local_name

    def lookup(self, ip: str) -> tuple[bool, str | None]:
        """Return (allowed, host name to use)."""
        address = ipaddress.ip_address(ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback:
            return True, self.local_name
        for network, name in self._networks:
            if address.version == network.version and address in network:
                return True, name
        return False, None


def label(event: Event, name: str | None) -> None:
    """Apply a verified host name, keeping a different self-reported name for reference."""
    if name and event.host != name:
        if event.host and event.host != event.extra.get("sender_ip"):
            event.extra["claimed_host"] = event.host
        event.host = name


def cert_name(cert: dict) -> str | None:
    """Host name from a verified client certificate: first DNS SAN, else the CN."""
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "DNS":
            return value
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def tls_context(cert: Path, key: Path, ca: Path) -> ssl.SSLContext:
    """Server context that only accepts clients with a certificate signed by `ca`."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "SyslogServer"):
        self.server = server
        self.dropped = 0

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        allowed, name = self.server.admit(addr[0])
        if not allowed or not (event := self.server.event(data, addr[0], name)):
            return
        try:
            self.server.queue.put_nowait(event)
        except asyncio.QueueFull:
            # UDP has no back-pressure; drop rather than grow memory unbounded.
            self.dropped += 1
            if self.dropped % 1000 == 1:
                log.warning("queue full, %d syslog messages dropped so far", self.dropped)


class SyslogServer:
    def __init__(self, queue: asyncio.Queue[Event], senders: Senders):
        self.queue = queue
        self.senders = senders
        self._last_rejected: dict[str, float] = {}

    def admit(self, ip: str) -> tuple[bool, str | None]:
        allowed, name = self.senders.lookup(ip)
        if not allowed:
            now = time.monotonic()
            if now - self._last_rejected.get(ip, -REJECT_LOG_INTERVAL) >= REJECT_LOG_INTERVAL:
                self._last_rejected[ip] = now
                log.warning("rejected syslog from %s: not in [syslog.senders]", ip)
        return allowed, name

    def event(self, data: bytes, sender: str, name: str | None) -> Event | None:
        if event := parse(data, sender):
            label(event, name)
        return event

    async def _read(self, reader: asyncio.StreamReader, sender: str, name: str | None) -> None:
        try:
            async for frame in read_frames(reader):
                if event := self.event(frame, sender, name):
                    await self.queue.put(event)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError) as exc:
            log.debug("closing syslog connection from %s: %s", sender, exc)
        except ConnectionError:
            pass

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sender = writer.get_extra_info("peername")[0]
        allowed, name = self.admit(sender)
        try:
            if allowed:
                await self._read(reader, sender, name)
        finally:
            writer.close()

    async def _handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sender = writer.get_extra_info("peername")[0]
        # The handshake already required a certificate from our CA; it names the host.
        name = cert_name(writer.get_extra_info("peercert") or {})
        try:
            await self._read(reader, sender, name)
        finally:
            writer.close()

    async def serve(self, host: str, port: int, *, udp: bool = True) -> None:
        """Plain listener (TCP, and UDP unless disabled) until cancelled."""
        transport = None
        if udp:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _UDPProtocol(self), local_addr=(host, port)
            )
        server = await asyncio.start_server(self._handle_tcp, host, port, limit=MAX_MESSAGE)
        log.info("syslog listening on %s:%d (%s)", host, port, "udp, tcp" if udp else "tcp")
        try:
            async with server:
                await server.serve_forever()
        finally:
            if transport:
                transport.close()

    async def serve_tls(self, host: str, port: int, context: ssl.SSLContext) -> None:
        """TLS listener (RFC 5425) requiring client certificates, until cancelled."""
        server = await asyncio.start_server(
            self._handle_tls, host, port, ssl=context, limit=MAX_MESSAGE
        )
        log.info("syslog listening on %s:%d (tls, client certificates required)", host, port)
        async with server:
            await server.serve_forever()
