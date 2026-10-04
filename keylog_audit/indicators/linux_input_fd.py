"""
linux_input_fd.py — Linux only. Checks whether a process has an open
file descriptor pointing at a raw kernel input device
(/dev/input/eventN) — the device nodes the kernel exposes keyboard (and
mouse, and other HID) events through. A process reading one of these
directly, outside of the normal windowing/desktop stack, is exactly
the mechanism real evdev-based Linux keyloggers (e.g. the well-known
"logkeys" tool) use.

This is the strongest, most direct signal in this whole project — but
it comes with a real permission limitation: /proc/<pid>/fd is only
readable by the process's own owner or root. For any process owned by
someone else, this check cannot be performed at all, and reports
"unavailable" rather than a false "clear".

It is also not proof by itself: legitimate software has real reasons to
read input devices directly — remote-desktop/screen-sharing tools,
accessibility software, some games and macro tools, display-server
components themselves. See README "False positives".
"""
from __future__ import annotations
import os

from .base import IndicatorHit, register

INDICATOR_ID = "linux_input_fd"

register(
    INDICATOR_ID,
    description="Process has an open file descriptor to a raw keyboard input device (/dev/input/eventN).",
    platforms=("linux",),
    needs_permission="Must own the process (or run as root) to read /proc/<pid>/fd.",
)


class PermissionUnavailable(Exception):
    """Raised internally, caught by check(); exposed so tests can assert on it directly."""


def _list_input_fd_targets(pid: int, proc_root: str = "/proc") -> list:
    fd_dir = os.path.join(proc_root, str(pid), "fd")
    try:
        entries = os.listdir(fd_dir)
    except FileNotFoundError:
        return []  # process exited between enumeration and this check — not an error
    except PermissionError as e:
        raise PermissionUnavailable(str(e)) from e

    targets = []
    for entry in entries:
        try:
            target = os.readlink(os.path.join(fd_dir, entry))
        except OSError:
            continue  # fd closed/raced between listdir and readlink — ignore, not an error
        if "/dev/input/event" in target:
            targets.append(target)
    return targets


def check(process, proc_root: str = "/proc"):
    try:
        targets = _list_input_fd_targets(process.pid, proc_root=proc_root)
    except PermissionUnavailable:
        return None  # could not check — see README: absence here is NOT confirmed-clean

    if not targets:
        return None

    return IndicatorHit(
        indicator_id=INDICATOR_ID, weight=6,
        reason=f"Process has {len(targets)} open file descriptor(s) directly to a raw keyboard "
               f"input device, bypassing the normal desktop input stack.",
        evidence=", ".join(sorted(set(targets))),
    )
