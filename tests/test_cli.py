import json

from keylog_audit import cli


def test_scan_sample_data_exits_zero(capsys):
    rc = cli.main(["scan", "--sample-data", "--quiet"])
    assert rc == 0


def test_scan_sample_data_prints_report(capsys):
    cli.main(["scan", "--sample-data", "--quiet"])
    out = capsys.readouterr().out
    assert "svchost.exe" in out
    assert "does not capture" in out.lower() or "keystroke" in out.lower()


def test_scan_sample_data_json_stdout(capsys):
    cli.main(["scan", "--sample-data", "--quiet", "--json-stdout"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["mode"] == "sample"
    assert data["finding_count"] == 4


def test_scan_sample_data_writes_output_file(tmp_path):
    out_path = tmp_path / "report.json"
    rc = cli.main(["scan", "--sample-data", "--quiet", "--output", str(out_path)])
    assert rc == 0
    data = json.loads(out_path.read_text())
    assert data["mode"] == "sample"


def test_scan_min_confidence_filters_findings(capsys):
    cli.main(["scan", "--sample-data", "--quiet", "--json-stdout", "--min-confidence", "high"])
    data = json.loads(capsys.readouterr().out)
    assert all(f["confidence"]["level"] == "high" for f in data["findings"])
    assert len(data["findings"]) == 1  # only the one high-confidence sample scenario


def test_scan_min_confidence_medium_includes_high_and_medium(capsys):
    cli.main(["scan", "--sample-data", "--quiet", "--json-stdout", "--min-confidence", "medium"])
    data = json.loads(capsys.readouterr().out)
    levels = {f["confidence"]["level"] for f in data["findings"]}
    assert levels <= {"high", "medium"}
    assert len(data["findings"]) == 3  # high(1) + medium(2)


def test_live_scan_runs(capsys):
    rc = cli.main(["scan", "--quiet", "--json-stdout"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "live"


def test_list_indicators_command(capsys):
    rc = cli.main(["list-indicators"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "linux_input_fd" in out
    assert "suspicious_path" in out


def test_no_command_shows_help_and_exits_nonzero():
    import pytest
    with pytest.raises(SystemExit):
        cli.main([])


def test_scan_warns_when_not_using_sample_data(capsys):
    cli.main(["scan", "--sample-data"])  # not quiet
    err = capsys.readouterr().err
    assert "SAMPLE DATA" in err
