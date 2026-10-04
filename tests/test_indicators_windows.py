import platform
import pytest

from keylog_audit.indicators import windows_persistence


# ---------------------------------------------------------------- pure matching logic (portable)

def test_matches_exact_path():
    assert windows_persistence._matches(r"C:\Program\thing.exe", r"C:\Program\thing.exe") is True


def test_matches_quoted_path_with_args():
    assert windows_persistence._matches(
        r"C:\Program\thing.exe", r'"C:\Program\thing.exe" --silent'
    ) is True


def test_matches_case_insensitive():
    assert windows_persistence._matches(r"C:\Program\Thing.EXE", r"c:\program\thing.exe") is True


def test_no_match_returns_false():
    assert windows_persistence._matches(r"C:\Program\thing.exe", r"C:\Other\other.exe") is False


def test_empty_values_return_false():
    assert windows_persistence._matches("", "something") is False
    assert windows_persistence._matches("something", "") is False
    assert windows_persistence._matches(None, "something") is False


# ---------------------------------------------------------------- check() gracefully no-ops off Windows

def test_check_returns_none_when_winreg_unavailable(make_process, monkeypatch):
    monkeypatch.setattr(windows_persistence, "HAVE_WINREG", False)
    proc = make_process(exe=r"C:\thing.exe")
    assert windows_persistence.check(proc) is None


def test_check_returns_none_without_exe(make_process):
    proc = make_process(exe=None)
    assert windows_persistence.check(proc) is None


# ---------------------------------------------------------------- live registry access (Windows only)

@pytest.mark.skipif(platform.system() != "Windows", reason="winreg only exists on Windows")
def test_read_run_keys_does_not_crash_on_windows():
    # We can't assert on contents (depends on the machine), just that the
    # real registry read path executes without error.
    results = windows_persistence._read_run_keys()
    assert isinstance(results, list)
