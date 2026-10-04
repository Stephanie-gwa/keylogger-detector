"""
sample_data.py — a completely fabricated AuditReport for demonstration
and testing. Nothing here inspects any real process on any real
machine; every PID, path, and username below is invented. This exists
so the project's report format, scoring, and export can be shown and
tested on any operating system, including one where none of the real
platform-specific indicators in indicators/ can run.

The scenarios are deliberately chosen to also teach: a strong
multi-indicator case, a single-strong-indicator case that stays at
"medium" rather than "high", a weak single-indicator case, and — most
importantly — a case demonstrating a well-known FALSE POSITIVE (a
legitimate remote-desktop tool that legitimately reads input devices).
"""
from __future__ import annotations
import datetime

from .engine import AuditReport, Finding
from .indicators.base import IndicatorHit
from .process_info import ProcessRecord
from .scoring import score_hits

SAMPLE_GENERATED_AT = "2026-03-14T09:00:00+00:00"


def _proc(**kw) -> ProcessRecord:
    defaults = dict(pid=0, name="", exe=None, cmdline=[], ppid=1, username="alex", create_time=None)
    defaults.update(kw)
    return ProcessRecord(**defaults)


def build_sample_report() -> AuditReport:
    now = datetime.datetime.fromisoformat(SAMPLE_GENERATED_AT).timestamp()
    day = 86400

    # ---------------------------------------------------------- clean processes (no hits)
    clean_processes = [
        _proc(pid=1188, name="firefox", exe="/usr/lib/firefox/firefox",
              cmdline=["/usr/lib/firefox/firefox"], ppid=1, username="alex", create_time=now - 3 * day),
        _proc(pid=990, name="bash", exe="/usr/bin/bash", cmdline=["bash"], ppid=1,
              username="alex", create_time=now - 30 * day),
    ]

    findings = []

    # ---------------------------------------------------------- scenario 1: high confidence
    p1 = _proc(
        pid=4821, name="svchost.exe",
        exe=r"C:\Users\alex\AppData\Roaming\Updater\svchost.exe",
        cmdline=[r"C:\Users\alex\AppData\Roaming\Updater\svchost.exe"],
        ppid=612, username="alex", create_time=now - 2 * day,
    )
    hits1 = [
        IndicatorHit(
            indicator_id="name_masquerade", weight=4,
            reason="Process is named 'svchost.exe', matching a well-known Windows system process, "
                   "but is running from AppData\\Roaming instead of C:\\Windows\\System32.",
            evidence=p1.exe,
        ),
        IndicatorHit(
            indicator_id="suspicious_path", weight=2,
            reason="Running from a path containing 'appdata', a location normal software isn't "
                   "usually installed to.",
            evidence=p1.exe,
        ),
        IndicatorHit(
            indicator_id="recent_executable", weight=1,
            reason="Executable file was last modified 2.0 day(s) ago — recent enough to be worth "
                   "noting, especially alongside other indicators.",
            evidence="mtime=2026-03-12",
        ),
        IndicatorHit(
            indicator_id="windows_persistence", weight=3,
            reason="Executable is registered to launch automatically at login (1 matching entry).",
            evidence=r"Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        ),
    ]
    findings.append(Finding(process=p1, hits=hits1, confidence=score_hits(hits1)))

    # ---------------------------------------------------------- scenario 2: medium — single strong indicator
    p2 = _proc(
        pid=9931, name="xhelper", exe="/home/alex/.local/share/xhelper/xhelper",
        cmdline=["/home/alex/.local/share/xhelper/xhelper", "--background"],
        ppid=1, username="alex", create_time=now - 45 * day,
    )
    hits2 = [
        IndicatorHit(
            indicator_id="linux_input_fd", weight=6,
            reason="Process has 1 open file descriptor directly to a raw keyboard input device, "
                   "bypassing the normal desktop input stack.",
            evidence="/dev/input/event4",
        ),
    ]
    findings.append(Finding(process=p2, hits=hits2, confidence=score_hits(hits2)))

    # ---------------------------------------------------------- scenario 3: low confidence
    p3 = _proc(
        pid=7744, name="app_updater", exe="/home/alex/.local/bin/app_updater",
        cmdline=["/home/alex/.local/bin/app_updater"], ppid=1,
        username="alex", create_time=now - 1 * day,
    )
    hits3 = [
        IndicatorHit(
            indicator_id="recent_executable", weight=1,
            reason="Executable file was last modified 1.0 day(s) ago — recent enough to be worth "
                   "noting, especially alongside other indicators.",
            evidence="mtime=2026-03-13",
        ),
    ]
    findings.append(Finding(process=p3, hits=hits3, confidence=score_hits(hits3)))

    # ---------------------------------------------------------- scenario 4: known false-positive pattern
    p4 = _proc(
        pid=5502, name="TeamViewer", exe="/opt/teamviewer/tv_bin/TeamViewer",
        cmdline=["/opt/teamviewer/tv_bin/TeamViewer", "--daemon"], ppid=1,
        username="alex", create_time=now - 200 * day,
    )
    hits4 = [
        IndicatorHit(
            indicator_id="linux_input_fd", weight=6,
            reason="Process has 1 open file descriptor directly to a raw keyboard input device. "
                   "NOTE: remote-desktop/screen-sharing software legitimately reads input devices "
                   "directly to support remote control — this is a common, documented "
                   "false-positive source for this specific indicator. See README \"False positives\".",
            evidence="/dev/input/event2",
        ),
    ]
    findings.append(Finding(process=p4, hits=hits4, confidence=score_hits(hits4)))

    findings.sort(key=lambda f: f.confidence.score, reverse=True)

    return AuditReport(
        generated_at=SAMPLE_GENERATED_AT, mode="sample", os_name="sample",
        process_count=len(clean_processes) + len(findings),
        findings=findings,
        unavailable_indicators=[
            {"indicator_id": "macos_tcc_input_permission", "reason": "sample mode — not a real scan"},
            {"indicator_id": "windows_persistence", "reason": "sample mode — not a real scan"},
        ],
    )
