# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from datetime import UTC, datetime, timedelta

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_US = timedelta(microseconds=1)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def to_us(dt: datetime) -> int:
    return (dt - _EPOCH) // _US


def from_us(us: int) -> datetime:
    return _EPOCH + us * _US


def parse_duration(text: str) -> timedelta:
    """Parse durations like 30s, 15m, 2h, 7d."""
    if not (m := re.fullmatch(r"(\d+)([smhd])", text)):
        raise ValueError(f"invalid duration {text!r} (examples: 30s, 15m, 2h, 7d)")
    return timedelta(**{_UNITS[m[2]]: int(m[1])})
