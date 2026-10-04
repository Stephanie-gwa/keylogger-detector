"""
platform_support.py — what OS are we on, and which indicators can
actually run here right now? This is deliberately explicit rather than
letting an indicator silently no-op: every indicator's availability is
one of AVAILABLE, WRONG_OS, or NEEDS_PERMISSION, and the CLI/report
show this so a "clean" result is never confused with "this check
didn't actually run."
"""
from __future__ import annotations
import os
import platform
from enum import Enum


class OS(str, Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    OTHER = "other"


def current_os() -> OS:
    system = platform.system().lower()
    if system == "linux":
        return OS.LINUX
    if system == "darwin":
        return OS.MACOS
    if system == "windows":
        return OS.WINDOWS
    return OS.OTHER


class Availability(str, Enum):
    AVAILABLE = "available"
    WRONG_OS = "unavailable — not supported on this operating system"
    NEEDS_PERMISSION = "unavailable — requires a permission this process doesn't have"


def macos_has_full_disk_access() -> bool:
    """Best-effort check: can we read the TCC database at all? There is
    no public API for 'do I have Full Disk Access' — attempting the read
    and catching PermissionError is the documented, standard way tools
    in this category (e.g. Objective-See's utilities) determine this."""
    tcc_path = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    try:
        with open(tcc_path, "rb"):
            return True
    except (PermissionError, FileNotFoundError, OSError):
        return False
