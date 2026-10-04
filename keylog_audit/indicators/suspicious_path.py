"""
suspicious_path.py — flags a process whose executable lives in a
location commonly used to drop malware because it's writable by a
normal user and not normally where legitimate installed software runs
from: temp directories, hidden/dot directories, browser download
folders, and similar.

This is a WEAK, informational-strength signal on its own — plenty of
legitimate software (browser updaters, some games, portable apps)
genuinely runs from temp-like locations. It's meant to combine with
other indicators, not to stand alone as a verdict.
"""
from __future__ import annotations
from .base import IndicatorHit, register

INDICATOR_ID = "suspicious_path"

register(
    INDICATOR_ID,
    description="Executable is running from a temp/hidden/user-writable location.",
    platforms=("linux", "macos", "windows"),
)

# Lower-cased substrings checked against the executable's full path.
# Intentionally small and documented rather than an exhaustive list.
SUSPICIOUS_PATH_SUBSTRINGS = {
    "linux": ["/tmp/", "/var/tmp/", "/dev/shm/", "/.cache/", "/downloads/"],
    "macos": ["/private/tmp/", "/tmp/", "/library/caches/", "/downloads/"],
    "windows": ["temp", "appdata", "downloads"],
}


def check(process, os_name: str):
    if not process.exe:
        return None  # no path to evaluate — common for protected/kernel processes, not itself suspicious

    exe_lower = process.exe.lower().replace("\\", "/")
    substrings = SUSPICIOUS_PATH_SUBSTRINGS.get(os_name, [])
    for substring in substrings:
        if substring in exe_lower:
            label = substring.strip("/")
            return IndicatorHit(
                indicator_id=INDICATOR_ID, weight=2,
                reason=f"Running from a path containing {label!r}, a location normal "
                       f"software isn't usually installed to.",
                evidence=process.exe,
            )
    return None
