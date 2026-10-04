"""
process_info.py — collects the same process metadata a normal user can
already see in Task Manager / Activity Monitor / `ps`: PID, name,
executable path, command line, parent PID, owning user, and start time.
Uses psutil (the standard, well-established cross-platform library for
exactly this) rather than shelling out to OS tools or requiring any
elevated privilege.

This module only ever reads. It never sends a signal to a process,
never modifies anything, and never needs administrator/root access to
see this information — psutil silently returns None/empty for fields a
normal user genuinely isn't allowed to see (e.g. another user's full
command line on some systems), which this module treats as "unknown",
not as an error.
"""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field
from typing import Optional

import psutil


@dataclass
class ProcessRecord:
    pid: int
    name: str
    exe: Optional[str]
    cmdline: list = field(default_factory=list)
    ppid: Optional[int] = None
    username: Optional[str] = None
    create_time: Optional[float] = None

    @property
    def create_time_iso(self) -> Optional[str]:
        if self.create_time is None:
            return None
        return datetime.datetime.fromtimestamp(
            self.create_time, tz=datetime.timezone.utc
        ).isoformat()

    def to_dict(self) -> dict:
        return {
            "pid": self.pid, "name": self.name, "exe": self.exe,
            "cmdline": self.cmdline, "ppid": self.ppid, "username": self.username,
            "create_time": self.create_time_iso,
        }


def collect_processes() -> list:
    """Returns a ProcessRecord for every process this user can see.
    Processes that vanish mid-iteration, or whose details we're not
    permitted to read, are skipped rather than raising — that's normal,
    expected behavior on a live system, not an error condition."""
    records = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "username", "create_time"]):
        try:
            info = proc.info
            records.append(ProcessRecord(
                pid=info.get("pid"),
                name=info.get("name") or "",
                exe=info.get("exe") or None,
                cmdline=info.get("cmdline") or [],
                ppid=info.get("ppid"),
                username=info.get("username"),
                create_time=info.get("create_time"),
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return records
