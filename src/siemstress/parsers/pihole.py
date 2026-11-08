# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pi-hole DNS log (dnsmasq / pihole-FTL)."""

from siemstress.parsers.patterns import pattern

PATTERNS = (
    pattern(r"query\[(?P<qtype>\w+)\] (?P<domain>\S+) from (?P<src_ip>\S+)", "dns.query"),
    pattern(
        r"(?:gravity blocked|exactly blocked|regex blacklisted|blacklisted|exactly denied"
        r"|regex denied|special domain) (?P<domain>\S+) is",
        "dns.blocked",
    ),
)
