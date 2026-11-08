# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Firewall logs: Linux netfilter LOG lines (UFW, firewalld, iptables/nftables) and
pfSense/OPNsense `filterlog`."""

import re

from siemstress.event import Event
from siemstress.parsers.patterns import clean_ip

_NETFILTER = re.compile(r"(?:\[\s*\d+\.\d+\]\s*)?(?P<prefix>.*?)\s*\bIN=(?P<fields>.*)", re.S)
_KV = re.compile(r"(\w+)=(\S*)")
_BLOCK = re.compile(r"block|reject|drop|deny", re.I)
_ALLOW = re.compile(r"allow|accept|pass", re.I)


def _verdict(text: str) -> str:
    if _BLOCK.search(text):
        return "block"
    return "allow" if _ALLOW.search(text) else "log"


def _record(event: Event, verdict: str, src: str, **extra: str) -> bool:
    event.action = f"firewall.{verdict}"
    event.src_ip = clean_ip(src)
    event.extra.update({k: v for k, v in extra.items() if v})
    return True


def parse_netfilter(event: Event) -> bool:
    """Kernel lines like `[UFW BLOCK] IN=eth0 OUT= ... SRC=1.2.3.4 DST=... PROTO=TCP DPT=22`."""
    if " SRC=" not in event.message or not (m := _NETFILTER.match(event.message)):
        return False
    f = dict(_KV.findall("IN=" + m["fields"]))
    prefix = m["prefix"].strip(" :[]")
    return _record(
        event, _verdict(prefix), f.get("SRC", ""),
        dst_ip=f.get("DST", ""), proto=f.get("PROTO", ""), src_port=f.get("SPT", ""),
        dst_port=f.get("DPT", ""), interface=f.get("IN", ""), rule=prefix,
    )  # fmt: skip


def parse_filterlog(event: Event) -> bool:
    """pfSense/OPNsense CSV: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,..."""
    f = event.message.split(",")
    if len(f) < 17:
        return False
    if f[8] == "4" and len(f) >= 20:
        proto, src, dst, rest = f[16], f[18], f[19], f[20:]
    elif f[8] == "6":
        proto, src, dst, rest = f[12], f[15], f[16], f[17:]
    else:
        return False
    ports = rest[:2] if proto.lower() in ("tcp", "udp") and len(rest) >= 2 else ["", ""]
    return _record(
        event, _verdict(f[6]), src,
        dst_ip=dst, proto=proto, src_port=ports[0], dst_port=ports[1],
        interface=f[4], direction=f[7], rule=f[0],
    )  # fmt: skip
