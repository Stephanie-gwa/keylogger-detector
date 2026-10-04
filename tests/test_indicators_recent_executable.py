import os
import time

from keylog_audit.indicators import recent_executable


def test_flags_recently_modified_file(make_process, tmp_path):
    exe = tmp_path / "thing"
    exe.write_text("x")
    proc = make_process(exe=str(exe))
    hit = recent_executable.check(proc, recency_days=7, now=time.time())
    assert hit is not None
    assert hit.indicator_id == "recent_executable"


def test_does_not_flag_old_file(make_process, tmp_path):
    exe = tmp_path / "thing"
    exe.write_text("x")
    old_time = time.time() - 30 * 86400
    os.utime(exe, (old_time, old_time))
    proc = make_process(exe=str(exe))
    hit = recent_executable.check(proc, recency_days=7, now=time.time())
    assert hit is None


def test_boundary_just_inside_window(make_process, tmp_path):
    exe = tmp_path / "thing"
    exe.write_text("x")
    now = time.time()
    os.utime(exe, (now - 6 * 86400, now - 6 * 86400))
    hit = recent_executable.check(make_process(exe=str(exe)), recency_days=7, now=now)
    assert hit is not None


def test_boundary_just_outside_window(make_process, tmp_path):
    exe = tmp_path / "thing"
    exe.write_text("x")
    now = time.time()
    os.utime(exe, (now - 8 * 86400, now - 8 * 86400))
    hit = recent_executable.check(make_process(exe=str(exe)), recency_days=7, now=now)
    assert hit is None


def test_missing_file_returns_none(make_process):
    proc = make_process(exe="/nonexistent/path/to/nothing")
    assert recent_executable.check(proc) is None


def test_no_exe_returns_none(make_process):
    proc = make_process(exe=None)
    assert recent_executable.check(proc) is None


def test_custom_recency_window(make_process, tmp_path):
    exe = tmp_path / "thing"
    exe.write_text("x")
    now = time.time()
    os.utime(exe, (now - 2 * 86400, now - 2 * 86400))
    assert recent_executable.check(make_process(exe=str(exe)), recency_days=1, now=now) is None
    assert recent_executable.check(make_process(exe=str(exe)), recency_days=3, now=now) is not None
