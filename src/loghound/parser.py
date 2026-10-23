"""Parsers for the log formats LogHound understands.

Three shapes are supported, tried in order:
1. JSON lines with auth-ish keys.
2. Common SSH `auth.log` / `secure` lines.
3. CSV with a header row.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone

from .events import AuthEvent

# e.g. "Jan  5 12:34:56 host sshd[123]: Failed password for root from 10.0.0.1 port 22 ssh2"
SSH_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+\S+?:\s+"
    r"(?P<result>Failed|Accepted|Invalid user)\s+"
    r"(?:password|publickey|none)?\s*"
    # Two shapes: "... for <user> from <ip>" and "Invalid user <user> from <ip>".
    r"(?:for\s+(?:invalid user\s+)?(?P<user_for>\S+)|(?P<user_invalid>\S+))?"
    r".*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# A fixed reference year keeps parsing deterministic; real deployments pass one in.
DEFAULT_YEAR = 2026


def _ssh_timestamp(month: str, day: str, clock: str, year: int) -> float:
    hour, minute, second = (int(p) for p in clock.split(":"))
    dt = datetime(year, MONTHS[month], int(day), hour, minute, second, tzinfo=timezone.utc)
    return dt.timestamp()


def parse_ssh_line(line: str, *, year: int = DEFAULT_YEAR) -> AuthEvent | None:
    match = SSH_RE.search(line)
    if not match:
        return None
    result = match.group("result")
    return AuthEvent(
        timestamp=_ssh_timestamp(match.group("month"), match.group("day"), match.group("time"), year),
        source_ip=match.group("ip"),
        username=match.group("user_for") or match.group("user_invalid") or "unknown",
        success=result == "Accepted",
        method="password",
        raw=line,
    )


def parse_json_line(line: str) -> AuthEvent | None:
    try:
        payload = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    ip = payload.get("ip") or payload.get("source_ip") or payload.get("src_ip")
    user = payload.get("user") or payload.get("username") or payload.get("account")
    if not ip or not user:
        return None
    raw_ts = payload.get("timestamp") or payload.get("time") or payload.get("ts")
    timestamp = _coerce_timestamp(raw_ts)
    if timestamp is None:
        return None
    outcome = payload.get("success")
    if outcome is None:
        outcome = str(payload.get("result", payload.get("status", ""))).lower() in (
            "success", "accepted", "ok", "true",
        )
    return AuthEvent(
        timestamp=timestamp,
        source_ip=str(ip),
        username=str(user),
        success=bool(outcome),
        method=str(payload.get("method", "password")),
        latitude=_as_float(payload.get("latitude") or payload.get("lat")),
        longitude=_as_float(payload.get("longitude") or payload.get("lon") or payload.get("lng")),
        raw=line,
    )


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_timestamp(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def parse_csv(text: str) -> list[AuthEvent]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    fields = {name.lower().strip() for name in reader.fieldnames}
    if not {"ip", "user"} <= fields and not {"source_ip", "username"} <= fields:
        return []
    events: list[AuthEvent] = []
    for row in reader:
        normalised = {k.lower().strip(): v for k, v in row.items() if k}
        ip = normalised.get("ip") or normalised.get("source_ip")
        user = normalised.get("user") or normalised.get("username")
        timestamp = _coerce_timestamp(normalised.get("timestamp") or normalised.get("time"))
        if not ip or not user or timestamp is None:
            continue
        success_raw = str(normalised.get("success", normalised.get("result", ""))).lower()
        events.append(
            AuthEvent(
                timestamp=timestamp,
                source_ip=ip,
                username=user,
                success=success_raw in ("1", "true", "yes", "success", "accepted"),
                latitude=_as_float(normalised.get("latitude") or normalised.get("lat")),
                longitude=_as_float(normalised.get("longitude") or normalised.get("lon")),
            )
        )
    return events


def parse_lines(lines: list[str], *, year: int = DEFAULT_YEAR) -> list[AuthEvent]:
    """Parse a mixed list of lines, auto-detecting the format per line."""
    events: list[AuthEvent] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        event = parse_json_line(stripped) or parse_ssh_line(stripped, year=year)
        if event is not None:
            events.append(event)
    if events:
        return sorted(events, key=lambda e: e.timestamp)
    # Fall back to treating the whole blob as CSV.
    return sorted(parse_csv("\n".join(lines)), key=lambda e: e.timestamp)
