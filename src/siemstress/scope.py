# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Which events SIEMstress keeps, by host and by address."""

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatchcase

from siemstress.event import Event

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class Scope:
    """Events outside the scope are dropped before detection and storage.

    `hosts` and `exclude_hosts` are case-insensitive shell-style patterns matched
    against the event's host; `exclude_networks` match its source address or, for
    network sources, the address that sent it.
    """

    hosts: tuple[str, ...] = ()  # empty: every host
    exclude_hosts: tuple[str, ...] = ()
    exclude_networks: tuple[Network, ...] = ()

    @classmethod
    def parse(cls, hosts=(), exclude_hosts=(), exclude_ips=()) -> "Scope":
        networks = []
        for value in exclude_ips:
            try:
                networks.append(ipaddress.ip_network(str(value), strict=False))
            except ValueError:
                raise ValueError(
                    f"scope.exclude_ips: {value!r} is not an address or network"
                ) from None
        return cls(
            tuple(str(h).lower() for h in hosts),
            tuple(str(h).lower() for h in exclude_hosts),
            tuple(networks),
        )

    def __bool__(self) -> bool:
        return bool(self.hosts or self.exclude_hosts or self.exclude_networks)

    def includes_host(self, host: str | None) -> bool:
        name = (host or "").lower()
        if self.hosts and not any(fnmatchcase(name, p) for p in self.hosts):
            return False
        return not any(fnmatchcase(name, p) for p in self.exclude_hosts)

    def allows(self, event: Event) -> bool:
        if not self.includes_host(event.host):
            return False
        if self.exclude_networks:
            for value in (event.src_ip, event.extra.get("sender_ip")):
                if value and self._excluded(value):
                    return False
        return True

    def _excluded(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address.version == n.version and address in n for n in self.exclude_networks)

    def describe(self) -> str:
        parts = []
        if self.hosts:
            parts.append(f"only hosts {', '.join(self.hosts)}")
        if self.exclude_hosts:
            parts.append(f"not hosts {', '.join(self.exclude_hosts)}")
        if self.exclude_networks:
            parts.append(f"not addresses {', '.join(map(str, self.exclude_networks))}")
        return "; ".join(parts)
