import json
from pathlib import Path

from loghound.cli import main, render
from loghound.detectors import run_all
from loghound.parser import parse_lines

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "auth.log"


def test_example_log_parses():
    events = parse_lines(EXAMPLE.read_text().splitlines())
    assert len(events) == 10


def test_example_log_yields_findings():
    events = parse_lines(EXAMPLE.read_text().splitlines())
    findings = run_all(events)
    detectors = {f.detector for f in findings}
    assert "brute_force" in detectors
    assert "lateral_movement" in detectors


def test_render_clean():
    assert "No suspicious" in render([], [])


def test_cli_runs_on_the_example(tmp_path):
    out = tmp_path / "f.json"
    code = main([str(EXAMPLE), "--json", str(out)])
    assert code == 1
    payload = json.loads(out.read_text())
    assert payload["events"] == 10
    assert payload["findings"]


def test_cli_missing_file_returns_2():
    assert main(["/nonexistent/path.log"]) == 2
