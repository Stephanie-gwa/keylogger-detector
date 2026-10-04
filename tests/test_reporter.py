import json

from keylog_audit.reporter import to_json_string, save_json, format_text
from keylog_audit.sample_data import build_sample_report


def test_to_json_string_is_valid_json():
    report = build_sample_report()
    parsed = json.loads(to_json_string(report))
    assert parsed["mode"] == "sample"
    assert parsed["finding_count"] == 4


def test_save_json_writes_file(tmp_path):
    report = build_sample_report()
    path = tmp_path / "out.json"
    save_json(report, str(path))
    parsed = json.loads(path.read_text())
    assert parsed["finding_count"] == 4


def test_format_text_includes_disclaimer():
    report = build_sample_report()
    text = format_text(report)
    assert report.disclaimer in text


def test_format_text_includes_every_finding_pid():
    report = build_sample_report()
    text = format_text(report)
    for finding in report.findings:
        assert f"PID {finding.process.pid}" in text


def test_format_text_no_findings_message():
    report = build_sample_report()
    report.findings = []
    text = format_text(report)
    assert "No processes were flagged" in text


def test_format_text_shows_unavailable_indicators():
    report = build_sample_report()
    text = format_text(report)
    assert "could NOT run" in text
    assert "macos_tcc_input_permission" in text


def test_format_text_shows_confidence_level_uppercase():
    report = build_sample_report()
    text = format_text(report)
    assert "[HIGH" in text


def test_json_includes_disclaimer_and_indicator_reasons():
    report = build_sample_report()
    d = json.loads(to_json_string(report))
    assert "disclaimer" in d
    first_finding = d["findings"][0]
    assert "reason" in first_finding["indicators"][0]
    assert "evidence" in first_finding["indicators"][0]
