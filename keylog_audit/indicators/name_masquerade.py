"""
name_masquerade.py — flags a process whose NAME matches a well-known
system process (svchost, launchd, systemd, etc.) but whose executable
path does not live in that process's expected system directory. This
is the classic "masquerading" technique: naming malware after a
trusted process so it blends into a process list at a glance.

The reference table below is intentionally small and illustrative —
see README for why this can never be an exhaustive list, and why a
mismatch here is suspicious but a match is NOT proof of legitimacy (a
name AND path can both be spoofed by something sufficiently determined).
"""
from __future__ import annotations
from .base import IndicatorHit, register

INDICATOR_ID = "name_masquerade"

register(
    INDICATOR_ID,
    description="Process name matches a well-known system process, but its path doesn't match "
                "that process's expected system directory.",
    platforms=("linux", "macos", "windows"),
)

# name (lowercase) -> tuple of acceptable lowercase path prefixes.
KNOWN_SYSTEM_PROCESSES = {
    "linux": {
        "systemd": ("/usr/lib/systemd/", "/lib/systemd/", "/sbin/"),
        "sshd": ("/usr/sbin/", "/sbin/"),
        "dbus-daemon": ("/usr/bin/", "/bin/"),
        "cron": ("/usr/sbin/", "/sbin/"),
    },
    "macos": {
        "launchd": ("/sbin/",),
        "windowserver": ("/system/library/",),
        "loginwindow": ("/system/library/",),
    },
    "windows": {
        "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
        "explorer.exe": ("c:\\windows\\",),
        "csrss.exe": ("c:\\windows\\system32\\",),
        "lsass.exe": ("c:\\windows\\system32\\",),
        "winlogon.exe": ("c:\\windows\\system32\\",),
    },
}


def check(process, os_name: str):
    if not process.exe or not process.name:
        return None

    known = KNOWN_SYSTEM_PROCESSES.get(os_name, {})
    expected_prefixes = known.get(process.name.lower())
    if expected_prefixes is None:
        return None  # not a name we have a reference location for

    exe_lower = process.exe.lower()
    if any(exe_lower.startswith(prefix) for prefix in expected_prefixes):
        return None  # matches a known-good location

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=4,
        reason=f"Process is named {process.name!r}, matching a well-known system process, but "
               f"is running from a location that process doesn't normally run from.",
        evidence=process.exe,
    )
