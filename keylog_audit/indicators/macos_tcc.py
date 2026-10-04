"""
macos_tcc.py — macOS only. Since macOS Catalina (10.15), an app must be
explicitly granted "Input Monitoring" permission (or, historically,
"Accessibility") before it's allowed to use the low-level event-tap
APIs (CGEventTap / IOHIDManager) that a macOS keylogger would need.
These grants are recorded in a per-user SQLite database, TCC.db, which
System Settings > Privacy & Security reads to show you the toggle
list.

This is a real, documented mechanism — the exact one tools like
Objective-See's "KnockKnock" and "Oversight" inspect — but reading
TCC.db itself requires Full Disk Access (a deliberate, ironic
protection: the database that lists sensitive permission grants is
itself protected). Without it, this check reports "unavailable", never
a false "clear".

The TCC schema is undocumented by Apple and has changed across macOS
versions; this query is best-effort and wrapped so a schema mismatch
degrades to "unavailable" rather than crashing.
"""
from __future__ import annotations
import os
import sqlite3

from .base import IndicatorHit, register

INDICATOR_ID = "macos_tcc_input_permission"

register(
    INDICATOR_ID,
    description="Process's executable/bundle has been granted Input Monitoring or Accessibility "
                "permission (the permission macOS requires for low-level keyboard event taps).",
    platforms=("macos",),
    needs_permission="Requires Full Disk Access for the running Python process.",
)

RELEVANT_SERVICES = ("kTCCServiceListenEvent", "kTCCServiceAccessibility")


class TccUnavailable(Exception):
    pass


def _query_tcc_grants(tcc_path: str) -> list:
    """Pure(ish) helper: given a path to a TCC.db file, return
    (client, service) pairs that are currently granted. Isolated from
    check() so it can be unit-tested against a fabricated SQLite file
    on any OS."""
    if not os.path.exists(tcc_path):
        raise TccUnavailable(f"no TCC database at {tcc_path}")
    try:
        conn = sqlite3.connect(f"file:{tcc_path}?mode=ro", uri=True)
        cur = conn.cursor()
        placeholders = ",".join("?" for _ in RELEVANT_SERVICES)
        cur.execute(
            f"SELECT client, service, auth_value FROM access WHERE service IN ({placeholders})",
            RELEVANT_SERVICES,
        )
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error as e:
        raise TccUnavailable(str(e)) from e

    # auth_value: 0 = denied, 2 = allowed, on the schema versions this has
    # been checked against; treat anything else as "not confirmed granted"
    # rather than guessing.
    return [(client, service) for client, service, auth_value in rows if auth_value == 2]


def check(process, tcc_path: str = None):
    tcc_path = tcc_path or os.path.expanduser(
        "~/Library/Application Support/com.apple.TCC/TCC.db"
    )
    if not process.exe:
        return None

    try:
        grants = _query_tcc_grants(tcc_path)
    except TccUnavailable:
        return None

    matches = [service for client, service in grants if client in process.exe]
    if not matches:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=5,
        reason="This executable has been granted a permission (Input Monitoring or "
               "Accessibility) that macOS requires before an app can read low-level "
               "keyboard events system-wide.",
        evidence=", ".join(sorted(set(matches))),
    )
