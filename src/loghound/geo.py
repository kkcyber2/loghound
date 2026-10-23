"""Great-circle distance, used by the impossible-travel detector."""
from __future__ import annotations

import math

EARTH_RADIUS_KM = 6371.0088


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance in kilometres between two points on a sphere."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def implied_speed_kmh(distance_km: float, seconds: float) -> float:
    """Speed needed to cover `distance_km` in `seconds`. Infinite if time is zero."""
    if seconds <= 0:
        return float("inf")
    return distance_km / (seconds / 3600.0)
