"""Finding model."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


@dataclass
class Finding:
    detector: str
    severity: Severity
    summary: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: float | None = None
    last_seen: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "evidence": self.evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
