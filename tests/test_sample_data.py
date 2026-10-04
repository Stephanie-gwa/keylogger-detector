from keylog_audit.sample_data import build_sample_report


def test_sample_report_mode_and_os():
    report = build_sample_report()
    assert report.mode == "sample"
    assert report.os_name == "sample"


def test_sample_report_has_expected_finding_count():
    report = build_sample_report()
    assert len(report.findings) == 4


def test_sample_report_process_count_includes_clean_processes():
    report = build_sample_report()
    # 2 clean + 4 flagged = 6
    assert report.process_count == 6


def test_sample_report_includes_a_high_confidence_finding():
    report = build_sample_report()
    levels = {f.confidence.level for f in report.findings}
    assert "high" in levels


def test_sample_report_includes_a_low_confidence_finding():
    report = build_sample_report()
    levels = {f.confidence.level for f in report.findings}
    assert "low" in levels


def test_sample_report_includes_documented_false_positive_example():
    report = build_sample_report()
    teamviewer = next(f for f in report.findings if f.process.name == "TeamViewer")
    assert any("false-positive" in h.reason.lower() or "false positive" in h.reason.lower()
               for h in teamviewer.hits)


def test_sample_report_findings_sorted_by_score():
    report = build_sample_report()
    scores = [f.confidence.score for f in report.findings]
    assert scores == sorted(scores, reverse=True)


def test_sample_report_is_deterministic():
    a = build_sample_report()
    b = build_sample_report()
    assert a.to_dict() == b.to_dict()


def test_sample_report_disclaimer_present():
    report = build_sample_report()
    assert "does not capture" in report.disclaimer.lower() or "keystroke" in report.disclaimer.lower()


def test_every_finding_hit_has_nonempty_reason_and_evidence():
    report = build_sample_report()
    for finding in report.findings:
        for hit in finding.hits:
            assert hit.reason
            assert hit.evidence
