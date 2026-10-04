"""
windows_persistence.py — Windows only. Checks the two most common,
documented places Windows software registers to run automatically:
the HKCU\\...\\Run (and RunOnce) registry keys, and the per-user
Startup folder. This is exactly what Task Manager's "Startup apps" tab
and tools like Autoruns show.

The registry read itself (`winreg`, Windows-only stdlib module) is kept
as thin as possible and isolated behind an import guard, so this module
can still be imported (and its pure matching logic tested) on any OS —
only the actual registry/filesystem read is Windows-only.
"""
from __future__ import annotations
import os

from .base import IndicatorHit, register

INDICATOR_ID = "windows_persistence"

register(
    INDICATOR_ID,
    description="Executable is referenced by a Run/RunOnce registry entry or the Startup folder.",
    platforms=("windows",),
)

try:
    import winreg
    HAVE_WINREG = True
except ImportError:
    winreg = None
    HAVE_WINREG = False

RUN_KEY_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


def _matches(exe_path: str, value: str) -> bool:
    """Pure, testable: does this registry value / startup entry string
    reference exe_path? Case-insensitive substring match, which is
    deliberately simple — registry values often wrap the path in quotes
    or append arguments."""
    if not exe_path or not value:
        return False
    return exe_path.lower() in value.lower()


def _read_run_keys() -> list:
    """Returns [(key_path, value_name, value_data), ...]. Windows-only;
    raises RuntimeError if winreg isn't available (i.e. not on Windows)."""
    if not HAVE_WINREG:
        raise RuntimeError("winreg is only available on Windows")
    results = []
    for path in RUN_KEY_PATHS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        results.append((path, name, str(data)))
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    return results


def _list_startup_folder(folder: str) -> list:
    try:
        return os.listdir(folder)
    except OSError:
        return []


def check(process, startup_folder: str = None):
    if not HAVE_WINREG or not process.exe:
        return None  # not on Windows, or nothing to match against

    matches = []
    for path, name, data in _read_run_keys():
        if _matches(process.exe, data):
            matches.append(f"{path}\\{name}")

    startup_folder = startup_folder or os.path.join(
        os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    for entry in _list_startup_folder(startup_folder):
        if _matches(process.exe, entry) or _matches(process.name or "", entry):
            matches.append(f"Startup folder: {entry}")

    if not matches:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=3,
        reason="Executable is registered to launch automatically at login "
               f"({len(matches)} matching entry/entries).",
        evidence=", ".join(sorted(set(matches))),
    )
