"""The normalised auth event every parser produces."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthEvent:
    timestamp: float
    source_ip: str
    username: str
    success: bool
    method: str = "password"
    latitude: float | None = None
    longitude: float | None = None
    raw: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "username": self.username,
            "success": self.success,
            "method": self.method,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }
