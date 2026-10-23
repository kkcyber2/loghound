from loghound.geo import haversine_km, implied_speed_kmh


def test_same_point_is_zero_distance():
    assert haversine_km(51.5, -0.1, 51.5, -0.1) == 0.0


def test_london_to_paris_is_about_344_km():
    distance = haversine_km(51.5074, -0.1278, 48.8566, 2.3522)
    assert 330 < distance < 360


def test_london_to_new_york_is_about_5570_km():
    distance = haversine_km(51.5074, -0.1278, 40.7128, -74.0060)
    assert 5500 < distance < 5650


def test_implied_speed():
    assert abs(implied_speed_kmh(100, 3600) - 100) < 1e-9


def test_implied_speed_with_zero_time_is_infinite():
    assert implied_speed_kmh(10, 0) == float("inf")
