from loghound.parser import parse_csv, parse_json_line, parse_lines, parse_ssh_line


def test_parse_ssh_failure():
    line = "Jan  5 02:14:01 web01 sshd[1001]: Failed password for root from 203.0.113.7 port 51001 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.7"
    assert event.username == "root"
    assert event.success is False


def test_parse_ssh_success():
    line = "Jan  5 09:31:00 web01 sshd[1100]: Accepted password for alice from 198.51.100.20 port 40001 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.success is True
    assert event.username == "alice"


def test_parse_ssh_invalid_user():
    line = "Jan  5 02:20:00 web01 sshd[1200]: Invalid user admin from 203.0.113.9 port 22 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.username == "admin"


def test_parse_ssh_ignores_unrelated_lines():
    assert parse_ssh_line("Jan  5 02:20:00 web01 systemd[1]: Started Session 4.") is None


def test_parse_json_line():
    event = parse_json_line(
        '{"timestamp":"2026-01-05T02:14:01Z","ip":"203.0.113.7","user":"root","success":false}'
    )
    assert event is not None
    assert event.username == "root"
    assert event.success is False


def test_parse_json_line_accepts_alternate_keys():
    event = parse_json_line('{"ts":1767574441,"src_ip":"10.0.0.1","account":"svc","result":"accepted"}')
    assert event is not None
    assert event.success is True


def test_parse_json_line_rejects_missing_fields():
    assert parse_json_line('{"timestamp":1,"ip":"10.0.0.1"}') is None


def test_parse_json_line_rejects_non_json():
    assert parse_json_line("not json at all") is None


def test_parse_csv():
    text = "timestamp,ip,user,success\n2026-01-05 02:14:01,203.0.113.7,root,false\n"
    events = parse_csv(text)
    assert len(events) == 1
    assert events[0].username == "root"


def test_parse_csv_without_expected_columns_returns_empty():
    assert parse_csv("a,b\n1,2\n") == []


def test_parse_lines_sorts_by_time():
    lines = [
        "Jan  5 09:31:00 web01 sshd[1]: Accepted password for alice from 198.51.100.20 port 1 ssh2",
        "Jan  5 02:14:01 web01 sshd[2]: Failed password for root from 203.0.113.7 port 2 ssh2",
    ]
    events = parse_lines(lines)
    assert events[0].timestamp < events[1].timestamp


def test_parse_lines_skips_blank_lines():
    assert parse_lines(["", "   ", "garbage"]) == []
