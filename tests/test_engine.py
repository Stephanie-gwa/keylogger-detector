from unittest.mock import patch

from keylog_audit.engine import run_live_audit, _applicable_indicators, DISCLAIMER
from keylog_audit.platform_support import OS


def test_live_audit_runs_and_returns_report():
    report = run_live_audit()
    assert report.mode == "live"
    assert report.process_count > 0


def test_live_audit_includes_disclaimer():
    report = run_live_audit()
    assert report.disclaimer == DISCLAIMER


def test_live_audit_findings_only_include_flagged_processes():
    report = run_live_audit()
    for finding in report.findings:
        assert len(finding.hits) > 0
        assert finding.confidence.level != "none"


def test_live_audit_findings_sorted_by_score_descending():
    report = run_live_audit()
    scores = [f.confidence.score for f in report.findings]
    assert scores == sorted(scores, reverse=True)


def test_applicable_indicators_on_linux_includes_linux_specific():
    indicators = _applicable_indicators(OS.LINUX)
    names_available = {name for name, _fn, available, _ in indicators if available}
    assert "linux_input_fd" in names_available
    assert "linux_persistence" in names_available


def test_applicable_indicators_on_linux_excludes_windows_and_macos():
    indicators = _applicable_indicators(OS.LINUX)
    by_name = {name: available for name, _fn, available, _ in indicators}
    assert by_name["windows_persistence"] is False
    assert by_name["macos_tcc_input_permission"] is False
    assert by_name["macos_persistence"] is False


def test_applicable_indicators_unavailable_entries_have_reasons():
    indicators = _applicable_indicators(OS.LINUX)
    for name, _fn, available, reason in indicators:
        if not available:
            assert reason is not None and len(reason) > 0


def test_applicable_indicators_universal_ones_always_available():
    for os_enum in (OS.LINUX, OS.MACOS, OS.WINDOWS):
        indicators = _applicable_indicators(os_enum)
        by_name = {name: available for name, _fn, available, _ in indicators}
        assert by_name["suspicious_path"] is True
        assert by_name["name_masquerade"] is True
        assert by_name["recent_executable"] is True


def test_macos_tcc_unavailable_without_full_disk_access():
    with patch("keylog_audit.engine.macos_has_full_disk_access", return_value=False):
        indicators = _applicable_indicators(OS.MACOS)
        by_name = {name: (available, reason) for name, _fn, available, reason in indicators}
        available, reason = by_name["macos_tcc_input_permission"]
        assert available is False
        assert "Full Disk Access" in reason


def test_macos_tcc_available_with_full_disk_access():
    with patch("keylog_audit.engine.macos_has_full_disk_access", return_value=True):
        indicators = _applicable_indicators(OS.MACOS)
        by_name = {name: available for name, _fn, available, _reason in indicators}
        assert by_name["macos_tcc_input_permission"] is True


def test_a_single_indicator_exception_does_not_crash_the_whole_scan():
    """A single indicator raising on a single process (e.g. a race where
    the process exits mid-check) must not take down the entire audit."""
    with patch("keylog_audit.engine.suspicious_path.check", side_effect=RuntimeError("boom")):
        report = run_live_audit()  # should not raise
        assert report.process_count > 0
