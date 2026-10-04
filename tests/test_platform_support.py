from unittest.mock import patch

from keylog_audit.platform_support import current_os, OS, macos_has_full_disk_access


def test_current_os_returns_enum():
    assert current_os() in (OS.LINUX, OS.MACOS, OS.WINDOWS, OS.OTHER)


def test_current_os_maps_linux():
    with patch("keylog_audit.platform_support.platform.system", return_value="Linux"):
        assert current_os() == OS.LINUX


def test_current_os_maps_darwin_to_macos():
    with patch("keylog_audit.platform_support.platform.system", return_value="Darwin"):
        assert current_os() == OS.MACOS


def test_current_os_maps_windows():
    with patch("keylog_audit.platform_support.platform.system", return_value="Windows"):
        assert current_os() == OS.WINDOWS


def test_current_os_unknown_is_other():
    with patch("keylog_audit.platform_support.platform.system", return_value="FreeBSD"):
        assert current_os() == OS.OTHER


def test_full_disk_access_false_when_file_missing():
    with patch("os.path.expanduser", return_value="/nonexistent/path/TCC.db"):
        assert macos_has_full_disk_access() is False
