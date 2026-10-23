# LogHound

Reads authentication logs and reports the attacks hiding in them: password brute
force, credential spraying, impossible travel, and lateral movement after a
successful login.

It works on plain log lines, so it takes SSH `auth.log`, an application's JSON
auth events, or a CSV export — no agent, no database, no vendor.

## Detections

| Detector | What it looks for |
|---|---|
| `brute_force` | Many failures from one source against one account inside a window |
| `password_spray` | One source trying a few passwords across many accounts |
| `distributed_brute_force` | Many sources hitting one account — the same attack, spread out |
| `impossible_travel` | Two successful logins for one user from far-apart places too close in time |
| `lateral_movement` | One source successfully authenticating as several distinct users |
| `off_hours_success` | A successful login outside the account's normal hours |

## Why windows and not thresholds alone

A fixed "more than 5 failures" rule fires on a typo-prone user and misses a slow
attacker. Every detector here is a **rate over a sliding window**, and each finding
reports the window it used so an analyst can judge it.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
loghound examples/auth.log
loghound examples/auth.log --json findings.json
loghound examples/auth.log --format json
```

## As a library

```python
from loghound.parser import parse_lines
from loghound.detectors import run_all

events = parse_lines(open("auth.log").read().splitlines())
for finding in run_all(events):
    print(finding.severity, finding.detector, finding.summary)
```

## Tests

```bash
pytest -q
```

## License

MIT — see `LICENSE`.
