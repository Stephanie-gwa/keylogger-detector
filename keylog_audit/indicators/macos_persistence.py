"""
macos_persistence.py — macOS only (parsing logic itself is portable and
tested on any OS). Checks whether a process's executable is referenced
by a LaunchAgent or LaunchDaemon .plist — the standard, documented
macOS mechanism for running something automatically at login or boot.
"""
from __future__ import annotations
import os
import plistlib

from .base import IndicatorHit, register

INDICATOR_ID = "macos_persistence"

register(
    INDICATOR_ID,
    description="Executable is referenced by a LaunchAgent or LaunchDaemon plist.",
    platforms=("macos",),
)

DEFAULT_DIRS = (
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
)


def _entries_referencing(exe_path: str, directory: str) -> list:
    """Pure, testable: which .plist files in `directory` have a
    ProgramArguments/Program entry mentioning exe_path?"""
    if not exe_path or not os.path.isdir(directory):
        return []
    matches = []
    try:
        filenames = os.listdir(directory)
    except OSError:
        return []
    for filename in filenames:
        if not filename.endswith(".plist"):
            continue
        full = os.path.join(directory, filename)
        try:
            with open(full, "rb") as f:
                data = plistlib.load(f)
        except (OSError, plistlib.InvalidFileException):
            continue
        args = data.get("ProgramArguments") or []
        program = data.get("Program")
        candidates = list(args) + ([program] if program else [])
        if any(exe_path in str(c) for c in candidates):
            matches.append(filename)
    return matches


def check(process, search_dirs=DEFAULT_DIRS):
    if not process.exe:
        return None

    matches = []
    for d in search_dirs:
        matches += _entries_referencing(process.exe, os.path.expanduser(d))
    if not matches:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=3,
        reason="Executable is registered to launch automatically via a LaunchAgent/LaunchDaemon "
               f"({len(matches)} matching plist file(s)).",
        evidence=", ".join(sorted(set(matches))),
    )
