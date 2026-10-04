import os
import pytest

from keylog_audit.indicators import linux_input_fd


def _make_fake_proc_fd(tmp_path, pid, fd_targets):
    """Builds tmp_path/<pid>/fd/0, 1, 2... as symlinks pointing at the
    given targets, mimicking /proc/<pid>/fd."""
    fd_dir = tmp_path / str(pid) / "fd"
    fd_dir.mkdir(parents=True)
    for i, target in enumerate(fd_targets):
        link = fd_dir / str(i)
        # symlink target doesn't need to exist for os.readlink to work
        os.symlink(target, link)
    return str(tmp_path)


def test_flags_process_with_input_device_fd(make_process, tmp_path):
    proc_root = _make_fake_proc_fd(tmp_path, 1234, ["/dev/input/event3", "/dev/pts/0"])
    proc = make_process(pid=1234)
    hit = linux_input_fd.check(proc, proc_root=proc_root)
    assert hit is not None
    assert hit.indicator_id == "linux_input_fd"
    assert "/dev/input/event3" in hit.evidence


def test_does_not_flag_process_without_input_device_fd(make_process, tmp_path):
    proc_root = _make_fake_proc_fd(tmp_path, 1234, ["/dev/pts/0", "/home/alice/file.txt"])
    proc = make_process(pid=1234)
    hit = linux_input_fd.check(proc, proc_root=proc_root)
    assert hit is None


def test_multiple_input_device_fds_all_reported(make_process, tmp_path):
    proc_root = _make_fake_proc_fd(tmp_path, 1234, ["/dev/input/event1", "/dev/input/event2"])
    hit = linux_input_fd.check(make_process(pid=1234), proc_root=proc_root)
    assert hit is not None
    assert "/dev/input/event1" in hit.evidence
    assert "/dev/input/event2" in hit.evidence


def test_process_with_no_fd_directory_returns_none(make_process, tmp_path):
    # pid directory exists but has no fd subdirectory at all
    (tmp_path / "9999").mkdir()
    hit = linux_input_fd.check(make_process(pid=9999), proc_root=str(tmp_path))
    assert hit is None


def test_nonexistent_pid_returns_none(make_process, tmp_path):
    hit = linux_input_fd.check(make_process(pid=99999), proc_root=str(tmp_path))
    assert hit is None


def test_permission_denied_returns_none_not_a_crash(make_process, tmp_path, monkeypatch):
    fd_dir = tmp_path / "1234" / "fd"
    fd_dir.mkdir(parents=True)

    def fake_listdir(path):
        if path.endswith("fd"):
            raise PermissionError("denied")
        return os.listdir(path)

    monkeypatch.setattr(linux_input_fd.os, "listdir", fake_listdir)
    hit = linux_input_fd.check(make_process(pid=1234), proc_root=str(tmp_path))
    assert hit is None  # unavailable, not a crash and not a false "confirmed clean" either


def test_list_input_fd_targets_raises_permission_unavailable_directly(tmp_path, monkeypatch):
    """The lower-level helper should surface the permission problem as a
    distinct exception type, even though check() swallows it into None —
    this is what lets a caller distinguish 'checked, clean' from
    'could not check' if they need to."""
    fd_dir = tmp_path / "1234" / "fd"
    fd_dir.mkdir(parents=True)

    def fake_listdir(path):
        raise PermissionError("denied")

    monkeypatch.setattr(linux_input_fd.os, "listdir", fake_listdir)
    with pytest.raises(linux_input_fd.PermissionUnavailable):
        linux_input_fd._list_input_fd_targets(1234, proc_root=str(tmp_path))
