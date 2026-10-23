from loghound.detectors import (
    detect_brute_force,
    detect_distributed_brute_force,
    detect_impossible_travel,
    detect_lateral_movement,
    detect_off_hours_success,
    detect_password_spray,
    run_all,
)
from loghound.events import AuthEvent


def ev(ts, ip, user, success, lat=None, lon=None):
    return AuthEvent(timestamp=ts, source_ip=ip, username=user, success=success, latitude=lat, longitude=lon)


def test_brute_force_detected():
    events = [ev(1000 + i, "10.0.0.1", "root", False) for i in range(6)]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    # The detector reports the first window that crosses the threshold, so it
    # fires at exactly the threshold rather than waiting for the whole burst.
    assert findings[0].evidence["failures"] == 5


def test_brute_force_below_threshold_is_quiet():
    events = [ev(1000 + i, "10.0.0.1", "root", False) for i in range(3)]
    assert detect_brute_force(events) == []


def test_brute_force_outside_window_is_quiet():
    events = [ev(1000 + i * 1000, "10.0.0.1", "root", False) for i in range(6)]
    assert detect_brute_force(events) == []


def test_brute_force_is_per_account():
    events = [ev(1000 + i, "10.0.0.1", f"user{i}", False) for i in range(6)]
    assert detect_brute_force(events) == []


def test_password_spray_detected():
    events = [ev(1000 + i, "10.0.0.1", f"user{i}", False) for i in range(6)]
    findings = detect_password_spray(events)
    assert len(findings) == 1
    assert findings[0].evidence["accounts"] == [f"user{i}" for i in range(5)]


def test_spray_ignores_heavy_attempts_on_one_account():
    events = [ev(1000 + i, "10.0.0.1", "root", False) for i in range(6)]
    assert detect_password_spray(events) == []


def test_distributed_brute_force_detected():
    events = [ev(1000 + i, f"10.0.0.{i}", "root", False) for i in range(6)]
    findings = detect_distributed_brute_force(events)
    assert len(findings) == 1
    assert len(findings[0].evidence["sources"]) == 5


def test_impossible_travel_detected():
    events = [
        ev(1000, "1.1.1.1", "alice", True, lat=51.5074, lon=-0.1278),
        ev(1600, "2.2.2.2", "alice", True, lat=40.7128, lon=-74.0060),
    ]
    findings = detect_impossible_travel(events)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_plausible_travel_is_quiet():
    events = [
        ev(1000, "1.1.1.1", "alice", True, lat=51.5074, lon=-0.1278),
        ev(1000 + 7200, "2.2.2.2", "alice", True, lat=48.8566, lon=2.3522),
    ]
    assert detect_impossible_travel(events) == []


def test_impossible_travel_ignores_events_without_coordinates():
    events = [ev(1000, "1.1.1.1", "alice", True), ev(1001, "2.2.2.2", "alice", True)]
    assert detect_impossible_travel(events) == []


def test_lateral_movement_detected():
    events = [ev(1000 + i, "10.0.0.1", f"user{i}", True) for i in range(4)]
    findings = detect_lateral_movement(events)
    assert len(findings) == 1
    assert len(findings[0].evidence["usernames"]) == 3


def test_lateral_movement_needs_distinct_users():
    events = [ev(1000 + i, "10.0.0.1", "alice", True) for i in range(4)]
    assert detect_lateral_movement(events) == []


def test_off_hours_success_detected():
    # 2026-01-05 02:00:00 UTC
    events = [ev(1767578400, "10.0.0.1", "alice", True)]
    findings = detect_off_hours_success(events)
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_off_hours_ignores_failures():
    events = [ev(1767578400, "10.0.0.1", "alice", False)]
    assert detect_off_hours_success(events) == []


def test_run_all_orders_by_severity():
    events = [ev(1000 + i, "10.0.0.1", "root", False) for i in range(6)]
    events += [ev(1000 + i, "10.0.0.1", f"u{i}", True) for i in range(4)]
    findings = run_all(events)
    severities = [f.severity.value for f in findings]
    order = ["critical", "high", "medium", "low"]
    assert severities == sorted(severities, key=order.index)


def test_run_all_on_empty_input():
    assert run_all([]) == []
