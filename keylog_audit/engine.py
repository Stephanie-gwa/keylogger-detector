"""
engine.py — runs every indicator applicable to the current OS against
every collected process, and turns the results into Findings. This is
the only module that decides WHICH indicators run — each indicator
module itself stays simple and doesn't know about platform gating.
"""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field

from . import process_info
from .indicators import (
    linux_input_fd, linux_persistence, macos_persistence, macos_tcc,
    name_masquerade, recent_executable, suspicious_path, windows_persistence,
)
from .platform_support import OS, current_os, macos_has_full_disk_access
from .scoring import score_hits

DISCLAIMER = (
    "This report lists documented, read-only indicators that MAY be associated with "
    "keylogging activity. It does not capture, log, or inspect any keystroke, and a "
    "flagged process is NOT confirmed to be malicious — every finding needs a human's "
    "manual review. This tool cannot detect every keylogger: kernel-mode drivers, "
    "hardware keyloggers, browser extensions, and techniques that avoid every indicator "
    "checked here are all invisible to this report. See README \"Limitations\"."
)


@dataclass
class Finding:
    process: object          # ProcessRecord
    hits: list                 # list[IndicatorHit]
    confidence: object           # ConfidenceResult

    def to_dict(self) -> dict:
        return {
            "process": self.process.to_dict(),
            "confidence": {"level": self.confidence.level, "score": self.confidence.score},
            "indicators": [h.to_dict() for h in self.hits],
        }


@dataclass
class AuditReport:
    generated_at: str
    mode: str                     # "live" | "sample"
    os_name: str
    process_count: int
    findings: list = field(default_factory=list)     # only processes with >=1 hit
    unavailable_indicators: list = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at, "mode": self.mode, "os_name": self.os_name,
            "process_count": self.process_count,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "unavailable_indicators": self.unavailable_indicators,
            "disclaimer": self.disclaimer,
        }


def _applicable_indicators(os_enum: OS):
    """Returns [(name, check_fn, available: bool, reason_if_not)]."""
    all_indicators = [
        ("suspicious_path", suspicious_path.check, True, None),
        ("name_masquerade", name_masquerade.check, True, None),
        ("recent_executable", recent_executable.check, True, None),
    ]
    if os_enum == OS.LINUX:
        all_indicators.append(("linux_input_fd", linux_input_fd.check, True, None))
        all_indicators.append(("linux_persistence", linux_persistence.check, True, None))
    else:
        all_indicators.append(("linux_input_fd", None, False, "not running on Linux"))
        all_indicators.append(("linux_persistence", None, False, "not running on Linux"))

    if os_enum == OS.MACOS:
        has_fda = macos_has_full_disk_access()
        all_indicators.append((
            "macos_tcc_input_permission", macos_tcc.check, has_fda,
            None if has_fda else "this process doesn't have Full Disk Access",
        ))
        all_indicators.append(("macos_persistence", macos_persistence.check, True, None))
    else:
        all_indicators.append(("macos_tcc_input_permission", None, False, "not running on macOS"))
        all_indicators.append(("macos_persistence", None, False, "not running on macOS"))

    if os_enum == OS.WINDOWS:
        all_indicators.append(("windows_persistence", windows_persistence.check, True, None))
    else:
        all_indicators.append(("windows_persistence", None, False, "not running on Windows"))

    return all_indicators


def run_live_audit() -> AuditReport:
    os_enum = current_os()
    processes = process_info.collect_processes()
    indicators = _applicable_indicators(os_enum)

    unavailable = [
        {"indicator_id": name, "reason": reason}
        for name, _fn, available, reason in indicators if not available
    ]
    active = [(name, fn) for name, fn, available, _ in indicators if available]

    findings = []
    for proc in processes:
        hits = []
        for name, fn in active:
            try:
                if name in ("suspicious_path", "name_masquerade"):
                    hit = fn(proc, os_enum.value)
                else:
                    hit = fn(proc)
            except Exception:
                # A single indicator failing on a single process (e.g. a
                # race where the process exits mid-check) must never take
                # down the whole scan.
                hit = None
            if hit is not None:
                hits.append(hit)
        if hits:
            findings.append(Finding(process=proc, hits=hits, confidence=score_hits(hits)))

    findings.sort(key=lambda f: f.confidence.score, reverse=True)

    return AuditReport(
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        mode="live", os_name=os_enum.value, process_count=len(processes),
        findings=findings, unavailable_indicators=unavailable,
    )
