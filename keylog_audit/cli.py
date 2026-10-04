"""
cli.py — command-line entry point.

    python -m keylog_audit scan --sample-data
    python -m keylog_audit scan                       # live scan of THIS machine
    python -m keylog_audit scan --output report.json
    python -m keylog_audit list-indicators
"""
from __future__ import annotations
import argparse
import sys

from .engine import run_live_audit
from .indicators.base import INDICATOR_CATALOG
from .platform_support import current_os
from .reporter import format_text, save_json, to_json_string
from .sample_data import build_sample_report

# Import every indicator module so INDICATOR_CATALOG is fully populated
# before list-indicators runs (each module registers itself on import).
from .indicators import (  # noqa: F401
    linux_input_fd, linux_persistence, macos_persistence, macos_tcc,
    name_masquerade, recent_executable, suspicious_path, windows_persistence,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keylog-audit",
        description="Read-only audit for documented keylogging indicators on YOUR OWN computer. "
                     "Never logs a keystroke; never installs anything.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run an audit")
    scan.add_argument("--sample-data", action="store_true",
                       help="Use the bundled fabricated sample report instead of scanning this machine "
                            "(works on any OS — use this to see the report format without a live scan)")
    scan.add_argument("--min-confidence", choices=["low", "medium", "high"], default=None,
                       help="Only show findings at or above this confidence level")
    scan.add_argument("--output", "-o", default=None, help="Write the full JSON report to this file")
    scan.add_argument("--json-stdout", action="store_true", help="Print JSON to stdout instead of a table")
    scan.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("list-indicators", help="List every indicator and whether it can run on this OS")

    return p


_LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _apply_min_confidence(report, min_confidence: str):
    if not min_confidence:
        return report
    threshold = _LEVEL_RANK[min_confidence]
    report.findings = [f for f in report.findings if _LEVEL_RANK[f.confidence.level] >= threshold]
    return report


def cmd_scan(args) -> int:
    if not args.quiet and not args.json_stdout:
        mode = "SAMPLE DATA (no real scan performed)" if args.sample_data else "LIVE scan of this machine"
        print(f"Running keylog-audit — {mode}\n", file=sys.stderr)

    report = build_sample_report() if args.sample_data else run_live_audit()
    report = _apply_min_confidence(report, args.min_confidence)

    if args.output:
        save_json(report, args.output)
        if not args.quiet:
            print(f"Full report written to {args.output}", file=sys.stderr)

    if args.json_stdout:
        print(to_json_string(report))
    else:
        print(format_text(report))
    return 0


def cmd_list_indicators(_args) -> int:
    os_name = current_os().value
    print(f"Current OS: {os_name}\n")
    for indicator_id, info in sorted(INDICATOR_CATALOG.items()):
        applicable = os_name in info["platforms"]
        status = "available" if applicable else f"not applicable on {os_name}"
        if applicable and info["needs_permission"]:
            status += f" (needs: {info['needs_permission']})"
        print(f"{indicator_id}")
        print(f"    {info['description']}")
        print(f"    platforms: {', '.join(info['platforms'])} — {status}")
        print()
    return 0


def main(argv: list = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "list-indicators":
        return cmd_list_indicators(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
