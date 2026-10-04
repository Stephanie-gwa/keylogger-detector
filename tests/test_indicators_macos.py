import sqlite3

from keylog_audit.indicators import macos_tcc, macos_persistence


# ---------------------------------------------------------------- macos_tcc

def _make_fake_tcc_db(path, rows):
    """rows: list of (client, service, auth_value)."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE access (client TEXT, service TEXT, auth_value INTEGER)")
    conn.executemany("INSERT INTO access VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()


def test_query_tcc_grants_returns_allowed_rows(tmp_path):
    db_path = tmp_path / "TCC.db"
    _make_fake_tcc_db(db_path, [
        ("/Applications/Sketchy.app", "kTCCServiceListenEvent", 2),
        ("/Applications/Other.app", "kTCCServiceListenEvent", 0),  # denied
        ("/Applications/Sketchy.app", "kTCCServiceCamera", 2),      # irrelevant service
    ])
    grants = macos_tcc._query_tcc_grants(str(db_path))
    assert ("/Applications/Sketchy.app", "kTCCServiceListenEvent") in grants
    assert len(grants) == 1  # denied and irrelevant-service rows excluded


def test_query_tcc_grants_raises_when_file_missing(tmp_path):
    import pytest
    with pytest.raises(macos_tcc.TccUnavailable):
        macos_tcc._query_tcc_grants(str(tmp_path / "does_not_exist.db"))


def test_check_flags_process_with_grant(make_process, tmp_path):
    db_path = tmp_path / "TCC.db"
    _make_fake_tcc_db(db_path, [("/Applications/Sketchy.app/Contents/MacOS/Sketchy", "kTCCServiceAccessibility", 2)])
    proc = make_process(exe="/Applications/Sketchy.app/Contents/MacOS/Sketchy")
    hit = macos_tcc.check(proc, tcc_path=str(db_path))
    assert hit is not None
    assert hit.indicator_id == "macos_tcc_input_permission"


def test_check_no_grant_returns_none(make_process, tmp_path):
    db_path = tmp_path / "TCC.db"
    _make_fake_tcc_db(db_path, [("/Applications/Other.app", "kTCCServiceAccessibility", 2)])
    proc = make_process(exe="/Applications/Sketchy.app/Contents/MacOS/Sketchy")
    hit = macos_tcc.check(proc, tcc_path=str(db_path))
    assert hit is None


def test_check_missing_db_returns_none_not_a_crash(make_process, tmp_path):
    proc = make_process(exe="/Applications/Sketchy.app/Contents/MacOS/Sketchy")
    hit = macos_tcc.check(proc, tcc_path=str(tmp_path / "nope.db"))
    assert hit is None


def test_check_no_exe_returns_none(make_process, tmp_path):
    proc = make_process(exe=None)
    assert macos_tcc.check(proc, tcc_path=str(tmp_path / "nope.db")) is None


# ---------------------------------------------------------------- macos_persistence

def test_flags_matching_launch_agent(make_process, tmp_path):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    plist_path = agents_dir / "com.example.thing.plist"
    import plistlib
    with open(plist_path, "wb") as f:
        plistlib.dump({"Label": "com.example.thing",
                        "ProgramArguments": ["/Applications/Thing.app/Contents/MacOS/Thing"]}, f)
    proc = make_process(exe="/Applications/Thing.app/Contents/MacOS/Thing")
    hit = macos_persistence.check(proc, search_dirs=[str(agents_dir)])
    assert hit is not None
    assert "com.example.thing.plist" in hit.evidence


def test_no_match_returns_none(make_process, tmp_path):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    import plistlib
    with open(agents_dir / "other.plist", "wb") as f:
        plistlib.dump({"ProgramArguments": ["/Applications/Other.app/Contents/MacOS/Other"]}, f)
    proc = make_process(exe="/Applications/Thing.app/Contents/MacOS/Thing")
    hit = macos_persistence.check(proc, search_dirs=[str(agents_dir)])
    assert hit is None


def test_missing_dir_returns_none(make_process, tmp_path):
    proc = make_process(exe="/Applications/Thing.app/Contents/MacOS/Thing")
    hit = macos_persistence.check(proc, search_dirs=[str(tmp_path / "does_not_exist")])
    assert hit is None


def test_malformed_plist_skipped_not_crashed(make_process, tmp_path):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    (agents_dir / "broken.plist").write_bytes(b"not a real plist")
    proc = make_process(exe="/Applications/Thing.app/Contents/MacOS/Thing")
    hit = macos_persistence.check(proc, search_dirs=[str(agents_dir)])
    assert hit is None


def test_no_exe_returns_none(make_process, tmp_path):
    proc = make_process(exe=None)
    assert macos_persistence.check(proc, search_dirs=[str(tmp_path)]) is None
