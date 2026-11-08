# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from siemstress.event import Level
from siemstress.scope import Scope

# Optional inputs, watched by default. Any that don't exist on this host are skipped quietly.
DEFAULT_DOCKER_SOCKET = Path("/var/run/docker.sock")
DEFAULT_NTFY_SERVER = "https://ntfy.sh"
DEFAULT_LOG_FILES = (Path("/var/log/pihole/pihole.log"), Path("/var/log/pihole.log"))


class ConfigError(ValueError):
    pass


def parse_bind(text: str) -> tuple[str, int] | None:
    """`HOST:PORT` (host may be empty for all interfaces), or `off`."""
    if text == "off":
        return None
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"expected HOST:PORT or 'off', got {text!r}")
    return host or "0.0.0.0", int(port)


def _check_ntfy_server(server: str, allow_insecure: bool) -> None:
    """Alerts carry hostnames, usernames and addresses, and the token is a bearer
    credential: send them only over HTTPS, unless the server is on this machine or
    the owner explicitly opts out with `allow_insecure = true`."""
    parts = urlsplit(server)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname:
        if allow_insecure or parts.hostname in ("localhost", "127.0.0.1", "::1"):
            return
        raise ValueError(
            f"ntfy.server {server!r} is plain http: alerts and the token would cross the "
            "network unencrypted. Use https, or set allow_insecure = true to accept that"
        )
    raise ValueError(f"ntfy.server must be an http(s) URL, got {server!r}")


@dataclass(frozen=True, slots=True)
class NtfySettings:
    topic: str
    server: str = DEFAULT_NTFY_SERVER
    token: str | None = None
    min_level: Level = Level.MEDIUM


@dataclass(frozen=True, slots=True)
class TlsSettings:
    listen: tuple[str, int]
    cert: Path
    key: Path
    ca: Path  # client certificates must be signed by this CA


@dataclass(frozen=True, slots=True)
class SyslogSettings:
    listen: tuple[str, int] | None = ("127.0.0.1", 5514)
    udp: bool = True
    # Address or network -> host name ("" trusts the name the sender reports).
    senders: dict[str, str] = field(default_factory=dict)
    tls: TlsSettings | None = None


@dataclass(frozen=True, slots=True)
class Settings:
    hostname: str | None = None  # this machine's name; default: its static hostname
    disabled_rules: frozenset[str] = frozenset()
    ntfy: NtfySettings | None = None
    syslog: SyslogSettings = field(default_factory=SyslogSettings)
    journal: bool = True
    docker_socket: Path | None = DEFAULT_DOCKER_SOCKET
    log_files: tuple[Path, ...] = DEFAULT_LOG_FILES
    scope: Scope = field(default_factory=Scope)


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _syslog(data: dict) -> SyslogSettings:
    senders = {str(k): str(v) for k, v in data.get("senders", {}).items()}
    for network in senders:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise ValueError(f"syslog.senders: {network!r} is not an address or network") from None
    tls = None
    if "tls_listen" in data:
        missing = [k for k in ("tls_cert", "tls_key", "tls_ca") if k not in data]
        if missing:
            raise ValueError(f"syslog.tls_listen also needs {', '.join(missing)}")
        listen = parse_bind(data["tls_listen"])
        if listen:
            tls = TlsSettings(
                listen, _path(data["tls_cert"]), _path(data["tls_key"]), _path(data["tls_ca"])
            )
    return SyslogSettings(
        listen=parse_bind(data.get("listen", "127.0.0.1:5514")),
        udp=bool(data.get("udp", True)),
        senders=senders,
        tls=tls,
    )


def _scope(data: dict) -> Scope:
    if unknown := data.keys() - {"hosts", "exclude_hosts", "exclude_ips"}:
        raise ValueError(f"scope: unknown keys {sorted(unknown)}")
    for key, value in data.items():
        if not isinstance(value, list):
            raise ValueError(f"scope.{key} must be a list")
    return Scope.parse(**data)


def load_settings(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    try:
        data = tomllib.loads(path.read_text())
        ntfy = None
        if n := data.get("ntfy"):
            server = n.get("server", DEFAULT_NTFY_SERVER).rstrip("/")
            _check_ntfy_server(server, bool(n.get("allow_insecure", False)))
            ntfy = NtfySettings(
                topic=n["topic"],
                server=server,
                token=n.get("token"),
                min_level=Level[n.get("min_level", "medium").upper()],
            )
        sources = data.get("sources", {})
        docker = sources.get("docker", str(DEFAULT_DOCKER_SOCKET))
        if docker is not False and not isinstance(docker, str):
            raise TypeError("sources.docker must be a socket path or false")
        return Settings(
            hostname=data.get("hostname"),
            disabled_rules=frozenset(data.get("disabled_rules", ())),
            ntfy=ntfy,
            syslog=_syslog(data.get("syslog", {})),
            journal=bool(sources.get("journal", True)),
            docker_socket=_path(docker) if docker else None,
            log_files=tuple(_path(p) for p in sources.get("files", map(str, DEFAULT_LOG_FILES))),
            scope=_scope(data.get("scope", {})),
        )
    except (tomllib.TOMLDecodeError, KeyError, AttributeError, TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
