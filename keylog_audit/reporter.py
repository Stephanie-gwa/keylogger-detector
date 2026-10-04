"""
reporter.py — renders an AuditReport as JSON (for machines) or a
readable text report (for a person) — every export carries the same
disclaimer as the on-screen output, so it travels with the report if
shared or filed away.
"""
from __future__ import annotations
import json

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}


def to_json_string(report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def save_json(report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)


def format_text(report) -> str:
    lines = []
    lines.append(f"Keylog Audit Report — mode: {report.mode}, OS: {report.os_name}")
    lines.append(f"Generated: {report.generated_at}")
    lines.append(f"Processes examined: {report.process_count}   Flagged: {len(report.findings)}")
    lines.append("")

    if report.unavailable_indicators:
        lines.append("Indicators that could NOT run this scan (not a 'clear' result — just not checked):")
        for u in report.unavailable_indicators:
            lines.append(f"  - {u['indicator_id']}: {u['reason']}")
        lines.append("")

    if not report.findings:
        lines.append("No processes were flagged by any indicator in this scan.")
    else:
        for finding in sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.confidence.level, 9)):
            p = finding.process
            lines.append(
                f"[{finding.confidence.level.upper():<6}] PID {p.pid}  {p.name}  "
                f"(score {finding.confidence.score}, {finding.confidence.hit_count} indicator(s))"
            )
            lines.append(f"         path: {p.exe or '(unknown)'}")
            lines.append(f"         user: {p.username or '(unknown)'}   started: {p.create_time_iso or '(unknown)'}")
            for hit in finding.hits:
                lines.append(f"         - [{hit.indicator_id}] {hit.reason}")
                lines.append(f"           evidence: {hit.evidence}")
            lines.append("")

    lines.append(report.disclaimer)
    return "\n".join(lines)
