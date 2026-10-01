"""Translate branch timezones for Windows without changing stored IANA values.

The vendored Unicode CLDR snapshot includes worldwide mappings and IANA aliases.
Unknown values are not guessed: omitting the policy preserves the device timezone.
No network access or extra dependency is required at heartbeat time.
"""
import json
from pathlib import Path

_DATA = json.loads((Path(__file__).parent / "data" / "windows_timezones.json").read_text(encoding="utf-8"))
_IANA_TO_WINDOWS = _DATA["iana_to_windows"]
_WINDOWS_IDS = {value.casefold(): value for value in _IANA_TO_WINDOWS.values()}


def windows_timezone(value):
    """Return a supported Windows ID, or None rather than an unsafe fallback."""
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 255 or any(ord(char) < 32 for char in name):
        return None
    return _IANA_TO_WINDOWS.get(name) or _WINDOWS_IDS.get(name.casefold())
