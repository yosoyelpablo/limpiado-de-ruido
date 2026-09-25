"""Timestamp and duration helpers. Every datetime inside hushwatch is timezone-aware UTC."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo

UTC = timezone.utc
_MONTHS = {
    m: i
    for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)
}
_SYSLOG_TS = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$")

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*$", re.IGNORECASE)
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
# Wazuh writes offsets without a colon ("+0000"); Python < 3.11 fromisoformat can't parse that.
_OFFSET_NO_COLON = re.compile(r"([+-])(\d{2})(\d{2})$")
_FRACTION = re.compile(r"\.(\d+)")


def parse_duration(value: str | int | float | timedelta) -> timedelta:
    """Parse "90s", "15m", "24h", "7d", "2w" (or a number of seconds) into a timedelta."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError(f"invalid duration {value!r}: use e.g. 30m, 24h, 7d, 2w")
    return timedelta(seconds=float(match.group(1)) * _DURATION_UNITS[match.group(2).lower()])


def parse_ts(value: object, *, naive_tz: tzinfo = UTC, default_year: int | None = None) -> datetime | None:
    """Parse the timestamp formats SIEMs emit. Returns an aware UTC datetime, or None if unparseable.

    Accepts ISO-8601 (``Z``, ``+00:00`` or Wazuh-style ``+0000`` offsets, any fraction length, basic
    ``YYYYMMDD``), epoch seconds / ms / µs / ns (numbers, or numeric strings of at least 10 digits so that
    ``20240101`` is never read as an epoch), classic syslog ``Jan  1 00:00:00`` (needs ``default_year``) and
    datetime objects. Naive timestamps are interpreted in ``naive_tz`` (UTC unless the source says otherwise).
    Callers must COUNT the ``None`` results; never drop them silently.
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        try:
            return value.replace(tzinfo=naive_tz).astimezone(UTC) if value.tzinfo is None else value.astimezone(UTC)
        except OverflowError:
            return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.isdigit():
        if len(text) == 8:  # basic ISO date YYYYMMDD
            text = f"{text[:4]}-{text[4:6]}-{text[6:]}"
        elif len(text) >= 10:
            return _from_epoch(float(text))
        else:
            return None
    elif _looks_like_float(text):
        return _from_epoch(float(text)) if float(text) >= 1e9 else None
    syslog = _SYSLOG_TS.match(text)
    if syslog:
        return _parse_syslog(syslog, naive_tz, default_year)
    if "T" not in text and " " in text:
        text = text.replace(" ", "T", 1)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _OFFSET_NO_COLON.sub(r"\1\2:\3", text)
    # normalise fraction to 6 digits (py3.10 fromisoformat only accepts 3 or 6)
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=naive_tz)
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):  # e.g. 9999-12-31T23:59:59-05:00 overflows when converted to UTC
        return None


def _looks_like_float(text: str) -> bool:
    head, dot, tail = text.partition(".")
    return bool(dot) and head.isdigit() and tail.isdigit()


def _parse_syslog(match: re.Match[str], naive_tz: tzinfo, default_year: int | None) -> datetime | None:
    if default_year is None:
        return None
    month = _MONTHS.get(match.group(1).lower())
    if month is None:
        return None
    micro = int((match.group(6) or "0")[:6].ljust(6, "0"))
    try:
        local = datetime(
            default_year,
            month,
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            micro,
            tzinfo=naive_tz,
        )
    except ValueError:
        return None
    return local.astimezone(UTC)


def _from_epoch(number: float) -> datetime | None:
    if number != number or number < 1e9:  # NaN, or too small to be a plausible epoch (< 2001-09-09)
        return None
    # heuristically detect ms / us epochs
    if number > 1e17:
        number /= 1e9
    elif number > 1e14:
        number /= 1e6
    elif number > 1e11:
        number /= 1e3
    try:
        return datetime.fromtimestamp(number, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def floor_to(ts: datetime, step: timedelta) -> datetime:
    """Floor an aware datetime to a multiple of ``step`` since the epoch."""
    seconds = int(step.total_seconds())
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=UTC)


def iso(ts: datetime | None) -> str | None:
    """Render an aware datetime as compact ISO-8601 UTC (``2026-09-25T10:00:00Z``)."""
    if ts is None:
        return None
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def humanize(delta: timedelta) -> str:
    """``timedelta(hours=26)`` -> ``"1d 2h"``."""
    total = int(delta.total_seconds())
    if total < 0:
        return "-" + humanize(-delta)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m" if minutes and not days else ""]
    out = " ".join(p for p in parts if p)
    return out or f"{seconds}s"
