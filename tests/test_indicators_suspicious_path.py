from keylog_audit.indicators import suspicious_path


def test_flags_linux_tmp_path(make_process):
    proc = make_process(exe="/tmp/weird_thing")
    hit = suspicious_path.check(proc, "linux")
    assert hit is not None
    assert hit.indicator_id == "suspicious_path"


def test_flags_linux_cache_path(make_process):
    proc = make_process(exe="/home/alice/.cache/thing/run")
    hit = suspicious_path.check(proc, "linux")
    assert hit is not None


def test_does_not_flag_normal_linux_path(make_process):
    proc = make_process(exe="/usr/bin/firefox")
    hit = suspicious_path.check(proc, "linux")
    assert hit is None


def test_flags_windows_appdata_path(make_process):
    proc = make_process(exe=r"C:\Users\alice\AppData\Roaming\thing.exe")
    hit = suspicious_path.check(proc, "windows")
    assert hit is not None


def test_does_not_flag_windows_program_files(make_process):
    proc = make_process(exe=r"C:\Program Files\Vendor\App.exe")
    hit = suspicious_path.check(proc, "windows")
    assert hit is None


def test_no_exe_returns_none(make_process):
    proc = make_process(exe=None)
    assert suspicious_path.check(proc, "linux") is None


def test_unknown_os_returns_none_for_normal_path(make_process):
    proc = make_process(exe="/usr/bin/thing")
    assert suspicious_path.check(proc, "other") is None


def test_evidence_is_the_exe_path(make_process):
    proc = make_process(exe="/tmp/thing")
    hit = suspicious_path.check(proc, "linux")
    assert hit.evidence == "/tmp/thing"
