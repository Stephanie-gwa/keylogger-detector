"""
linux_persistence.py — Linux only. Checks whether a process's
executable is referenced by one of the standard, documented ways
software configures itself to start automatically on Linux:

  - XDG autostart: ~/.config/autostart/*.desktop (Exec= line)
  - systemd user units: ~/.config/systemd/user/*.service (ExecStart=)

By itself, "this program starts automatically" describes the vast
majority of completely legitimate software (browsers, chat apps, cloud
sync clients) — it's only combined with another indicator that
persistence becomes meaningfully suspicious. See scoring.py.
"""
from __future__ import annotations
import os
import re

from .base import IndicatorHit, register

INDICATOR_ID = "linux_persistence"

register(
    INDICATOR_ID,
    description="Executable is registered to start automatically (XDG autostart or a systemd user unit).",
    platforms=("linux",),
)

_EXEC_LINE_RE = re.compile(r"^Exec(Start)?\s*=\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def _entries_referencing(exe_path: str, directory: str) -> list:
    """Pure, testable: given a directory of .desktop/.service files,
    which ones have an Exec/ExecStart line mentioning exe_path?"""
    if not exe_path or not os.path.isdir(directory):
        return []
    matches = []
    try:
        filenames = os.listdir(directory)
    except OSError:
        return []
    for filename in filenames:
        full = os.path.join(directory, filename)
        try:
            with open(full, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        for m in _EXEC_LINE_RE.finditer(content):
            if exe_path in m.group(2):
                matches.append(filename)
                break
    return matches


def check(process, autostart_dir: str = None, systemd_user_dir: str = None):
    if not process.exe:
        return None

    home = os.path.expanduser("~")
    autostart_dir = autostart_dir or os.path.join(home, ".config", "autostart")
    systemd_user_dir = systemd_user_dir or os.path.join(home, ".config", "systemd", "user")

    matches = _entries_referencing(process.exe, autostart_dir) + \
        _entries_referencing(process.exe, systemd_user_dir)
    if not matches:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=3,
        reason="Executable is registered to launch automatically at login "
               f"({len(matches)} matching autostart/systemd entry/entries).",
        evidence=", ".join(sorted(set(matches))),
    )
