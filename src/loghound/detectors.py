"""The detection rules.

Every detector is a pure function of the event list, which keeps them individually
testable and lets `run_all` compose them without shared state.
"""
from __future__ import annotations

from collections import defaultdict

from .events import AuthEvent
from .findings import ORDER, Finding, Severity
from .geo import haversine_km, implied_speed_kmh

# Defaults, all overridable so a deployment can tune to its own traffic.
BRUTE_FORCE_FAILURES = 5
BRUTE_FORCE_WINDOW = 300.0
SPRAY_ACCOUNTS = 5
SPRAY_WINDOW = 600.0
SPRAY_MAX_PER_ACCOUNT = 3
DISTRIBUTED_SOURCES = 5
DISTRIBUTED_WINDOW = 600.0
LATERAL_USERS = 3
LATERAL_WINDOW = 900.0
IMPOSSIBLE_SPEED_KMH = 900.0
OFF_HOURS_START = 0
OFF_HOURS_END = 5


def _window(events: list[AuthEvent], seconds: float):
    """Yield (event, events_in_the_preceding_window) for a time-sorted list."""
    start = 0
    for index, event in enumerate(events):
        while events[start].timestamp < event.timestamp - seconds:
            start += 1
        yield event, events[start : index + 1]


def detect_brute_force(
    events: list[AuthEvent],
    *,
    threshold: int = BRUTE_FORCE_FAILURES,
    window: float = BRUTE_FORCE_WINDOW,
) -> list[Finding]:
    failures = [e for e in events if not e.success]
    grouped: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in failures:
        grouped[(event.source_ip, event.username)].append(event)

    findings: list[Finding] = []
    for (ip, user), group in grouped.items():
        group.sort(key=lambda e: e.timestamp)
        for event, in_window in _window(group, window):
            if len(in_window) >= threshold:
                findings.append(
                    Finding(
                        detector="brute_force",
                        severity=Severity.HIGH,
                        summary=f"{len(in_window)} failed logins for {user!r} from {ip}",
                        detail=(
                            f"{len(in_window)} failures for account {user!r} from {ip} "
                            f"within {int(window)}s — consistent with password guessing."
                        ),
                        evidence={
                            "source_ip": ip,
                            "username": user,
                            "failures": len(in_window),
                            "window_seconds": window,
                        },
                        first_seen=in_window[0].timestamp,
                        last_seen=event.timestamp,
                    )
                )
                break
    return findings


def detect_password_spray(
    events: list[AuthEvent],
    *,
    accounts: int = SPRAY_ACCOUNTS,
    window: float = SPRAY_WINDOW,
    max_per_account: int = SPRAY_MAX_PER_ACCOUNT,
) -> list[Finding]:
    """One source, few attempts each, across many accounts."""
    failures = [e for e in events if not e.success]
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip].append(event)

    findings: list[Finding] = []
    for ip, group in by_ip.items():
        group.sort(key=lambda e: e.timestamp)
        for event, in_window in _window(group, window):
            per_account: dict[str, int] = defaultdict(int)
            for item in in_window:
                per_account[item.username] += 1
            if len(per_account) < accounts:
                continue
            if max(per_account.values()) > max_per_account:
                continue  # that is brute force, not spraying
            findings.append(
                Finding(
                    detector="password_spray",
                    severity=Severity.HIGH,
                    summary=f"Password spray from {ip} across {len(per_account)} accounts",
                    detail=(
                        f"{ip} tried {len(in_window)} passwords across {len(per_account)} "
                        f"accounts in {int(window)}s, at most {max(per_account.values())} per "
                        f"account — the shape of a spray, not a brute force."
                    ),
                    evidence={
                        "source_ip": ip,
                        "accounts": sorted(per_account),
                        "attempts": len(in_window),
                        "window_seconds": window,
                    },
                    first_seen=in_window[0].timestamp,
                    last_seen=event.timestamp,
                )
            )
            break
    return findings


def detect_distributed_brute_force(
    events: list[AuthEvent],
    *,
    sources: int = DISTRIBUTED_SOURCES,
    window: float = DISTRIBUTED_WINDOW,
) -> list[Finding]:
    """Many sources, one account — a botnet spreading the same attack."""
    failures = [e for e in events if not e.success]
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_user[event.username].append(event)

    findings: list[Finding] = []
    for user, group in by_user.items():
        group.sort(key=lambda e: e.timestamp)
        for event, in_window in _window(group, window):
            distinct = {item.source_ip for item in in_window}
            if len(distinct) < sources:
                continue
            findings.append(
                Finding(
                    detector="distributed_brute_force",
                    severity=Severity.HIGH,
                    summary=f"{len(distinct)} sources attacking {user!r}",
                    detail=(
                        f"{len(distinct)} distinct source addresses failed against {user!r} "
                        f"within {int(window)}s — a distributed attack on one account."
                    ),
                    evidence={
                        "username": user,
                        "sources": sorted(distinct),
                        "window_seconds": window,
                    },
                    first_seen=in_window[0].timestamp,
                    last_seen=event.timestamp,
                )
            )
            break
    return findings


def detect_impossible_travel(
    events: list[AuthEvent],
    *,
    max_speed_kmh: float = IMPOSSIBLE_SPEED_KMH,
) -> list[Finding]:
    """Two successful logins for one user, too far apart, too close in time."""
    successes = [
        e for e in events if e.success and e.latitude is not None and e.longitude is not None
    ]
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in successes:
        by_user[event.username].append(event)

    findings: list[Finding] = []
    for user, group in by_user.items():
        group.sort(key=lambda e: e.timestamp)
        for previous, current in zip(group, group[1:]):
            distance = haversine_km(
                previous.latitude, previous.longitude, current.latitude, current.longitude
            )
            elapsed = current.timestamp - previous.timestamp
            speed = implied_speed_kmh(distance, elapsed)
            if speed <= max_speed_kmh:
                continue
            findings.append(
                Finding(
                    detector="impossible_travel",
                    severity=Severity.CRITICAL,
                    summary=f"Impossible travel for {user!r} ({distance:,.0f} km in {elapsed:,.0f}s)",
                    detail=(
                        f"{user!r} logged in from {previous.source_ip} and then "
                        f"{current.source_ip}, {distance:,.0f} km apart, {elapsed:,.0f}s later. "
                        f"That implies {speed:,.0f} km/h."
                    ),
                    evidence={
                        "username": user,
                        "from_ip": previous.source_ip,
                        "to_ip": current.source_ip,
                        "distance_km": round(distance, 1),
                        "elapsed_seconds": elapsed,
                        "implied_speed_kmh": round(speed, 1),
                    },
                    first_seen=previous.timestamp,
                    last_seen=current.timestamp,
                )
            )
    return findings


def detect_lateral_movement(
    events: list[AuthEvent],
    *,
    users: int = LATERAL_USERS,
    window: float = LATERAL_WINDOW,
) -> list[Finding]:
    """One source successfully authenticating as several distinct users."""
    successes = [e for e in events if e.success]
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in successes:
        by_ip[event.source_ip].append(event)

    findings: list[Finding] = []
    for ip, group in by_ip.items():
        group.sort(key=lambda e: e.timestamp)
        for event, in_window in _window(group, window):
            distinct = {item.username for item in in_window}
            if len(distinct) < users:
                continue
            findings.append(
                Finding(
                    detector="lateral_movement",
                    severity=Severity.CRITICAL,
                    summary=f"{ip} authenticated as {len(distinct)} different users",
                    detail=(
                        f"{ip} successfully logged in as {len(distinct)} distinct accounts "
                        f"within {int(window)}s — consistent with a compromised host pivoting."
                    ),
                    evidence={
                        "source_ip": ip,
                        "usernames": sorted(distinct),
                        "window_seconds": window,
                    },
                    first_seen=in_window[0].timestamp,
                    last_seen=event.timestamp,
                )
            )
            break
    return findings


def detect_off_hours_success(
    events: list[AuthEvent],
    *,
    start_hour: int = OFF_HOURS_START,
    end_hour: int = OFF_HOURS_END,
) -> list[Finding]:
    """Successful logins in the small hours, grouped per user."""
    from datetime import datetime, timezone

    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if not event.success:
            continue
        hour = datetime.fromtimestamp(event.timestamp, tz=timezone.utc).hour
        if start_hour <= hour < end_hour:
            grouped[event.username].append(event)

    findings: list[Finding] = []
    for user, group in grouped.items():
        group.sort(key=lambda e: e.timestamp)
        findings.append(
            Finding(
                detector="off_hours_success",
                severity=Severity.LOW,
                summary=f"{user!r} logged in {len(group)} time(s) between {start_hour:02d}:00 and {end_hour:02d}:00 UTC",
                detail=(
                    f"{len(group)} successful login(s) for {user!r} in the quiet hours. "
                    f"Often benign, but worth confirming against the user's working pattern."
                ),
                evidence={
                    "username": user,
                    "count": len(group),
                    "source_ips": sorted({e.source_ip for e in group}),
                },
                first_seen=group[0].timestamp,
                last_seen=group[-1].timestamp,
            )
        )
    return findings


def run_all(events: list[AuthEvent]) -> list[Finding]:
    """Run every detector and return findings ordered by severity then time."""
    findings: list[Finding] = []
    findings += detect_brute_force(events)
    findings += detect_password_spray(events)
    findings += detect_distributed_brute_force(events)
    findings += detect_impossible_travel(events)
    findings += detect_lateral_movement(events)
    findings += detect_off_hours_success(events)
    return sorted(
        findings,
        key=lambda f: (ORDER[f.severity], f.first_seen or 0.0, f.detector),
    )
