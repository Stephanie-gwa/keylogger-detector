"""
recent_executable.py — flags an executable whose file was recently
created or modified. On its own this is extremely weak (software
updates constantly), but combined with another indicator — especially
autostart persistence — "new AND set to run automatically" is a
genuinely useful pattern worth a human's attention.
"""
from __future__ import annotations
import os
import time

from .base import IndicatorHit, register

INDICATOR_ID = "recent_executable"
DEFAULT_RECENCY_DAYS = 7

register(
    INDICATOR_ID,
    description="Executable file was created or modified within the last few days.",
    platforms=("linux", "macos", "windows"),
)


def check(process, recency_days: int = DEFAULT_RECENCY_DAYS, now: float = None):
    if not process.exe:
        return None
    now = now if now is not None else time.time()
    try:
        mtime = os.path.getmtime(process.exe)
    except OSError:
        return None  # file gone, or we can't read its metadata — not itself suspicious

    age_days = (now - mtime) / 86400
    if age_days < 0 or age_days > recency_days:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=1,
        reason=f"Executable file was last modified {age_days:.1f} day(s) ago — recent enough to "
               f"be worth noting, especially alongside other indicators.",
        evidence=f"mtime={time.strftime('%Y-%m-%d', time.localtime(mtime))}",
    )
