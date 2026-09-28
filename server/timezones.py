"""Windows time zones exposed for branch-managed endpoint configuration."""

WINDOWS_TIME_ZONES = {
    "UTC": "UTC",
    "India (Kolkata)": "India Standard Time",
    "Singapore": "Singapore Standard Time",
    "Dubai": "Arabian Standard Time",
    "Japan (Tokyo)": "Tokyo Standard Time",
    "United Kingdom": "GMT Standard Time",
    "Central Europe": "W. Europe Standard Time",
    "US Eastern": "Eastern Standard Time",
    "US Central": "Central Standard Time",
    "US Mountain": "Mountain Standard Time",
    "US Pacific": "Pacific Standard Time",
    "Australia Eastern": "AUS Eastern Standard Time",
}

WINDOWS_TIME_ZONE_IDS = frozenset(WINDOWS_TIME_ZONES.values())
