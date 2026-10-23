"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .detectors import run_all
from .parser import parse_lines

MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". "}


def _stamp(value: float | None) -> str:
    if value is None:
        return "?"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def render(events, findings) -> str:
    lines = [
        f"Parsed {len(events)} auth event(s)",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No suspicious authentication activity detected.")
        return "\n".join(lines)
    for finding in findings:
        lines.append(f"{MARK[finding.severity.value]} [{finding.severity.value.upper()}] {finding.summary}")
        lines.append(f"     {finding.detail}")
        lines.append(f"     window: {_stamp(finding.first_seen)} -> {_stamp(finding.last_seen)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="loghound", description="Authentication log anomaly detector")
    parser.add_argument("path", help="log file to analyse")
    parser.add_argument("--json", metavar="PATH", help="write findings as JSON")
    parser.add_argument("--year", type=int, default=2026, help="year for syslog timestamps")
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        print(f"could not read {args.path}: {exc}", file=sys.stderr)
        return 2

    events = parse_lines(lines, year=args.year)
    findings = run_all(events)
    print(render(events, findings))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "events": len(events),
                    "findings": [f.public() for f in findings],
                },
                handle,
                indent=2,
            )
        print(f"\nJSON report written to {args.json}")

    return 1 if any(f.severity.value in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
