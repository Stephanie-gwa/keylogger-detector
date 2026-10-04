from keylog_audit.indicators import name_masquerade


def test_flags_mismatched_known_name_linux(make_process):
    proc = make_process(name="sshd", exe="/tmp/sshd")
    hit = name_masquerade.check(proc, "linux")
    assert hit is not None
    assert hit.indicator_id == "name_masquerade"


def test_does_not_flag_matching_known_name_linux(make_process):
    proc = make_process(name="sshd", exe="/usr/sbin/sshd")
    hit = name_masquerade.check(proc, "linux")
    assert hit is None


def test_unrelated_name_not_flagged(make_process):
    proc = make_process(name="my_custom_tool", exe="/tmp/my_custom_tool")
    hit = name_masquerade.check(proc, "linux")
    assert hit is None  # not a name we have a reference for at all


def test_flags_mismatched_svchost_windows(make_process):
    proc = make_process(name="svchost.exe", exe=r"C:\Users\alice\AppData\svchost.exe")
    hit = name_masquerade.check(proc, "windows")
    assert hit is not None


def test_does_not_flag_matching_svchost_windows(make_process):
    proc = make_process(name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")
    hit = name_masquerade.check(proc, "windows")
    assert hit is None


def test_case_insensitive_matching(make_process):
    proc = make_process(name="SSHD", exe="/usr/sbin/sshd")
    hit = name_masquerade.check(proc, "linux")
    assert hit is None  # still matches despite case difference


def test_no_exe_returns_none(make_process):
    proc = make_process(name="sshd", exe=None)
    assert name_masquerade.check(proc, "linux") is None


def test_no_name_returns_none(make_process):
    proc = make_process(name="", exe="/usr/sbin/sshd")
    assert name_masquerade.check(proc, "linux") is None
