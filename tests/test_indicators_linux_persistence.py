from keylog_audit.indicators import linux_persistence


def test_flags_matching_autostart_desktop_entry(make_process, tmp_path):
    autostart = tmp_path / "autostart"
    autostart.mkdir()
    (autostart / "thing.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/home/alice/.local/bin/thing --flag\n"
    )
    systemd_dir = tmp_path / "systemd_empty"
    proc = make_process(exe="/home/alice/.local/bin/thing")
    hit = linux_persistence.check(proc, autostart_dir=str(autostart), systemd_user_dir=str(systemd_dir))
    assert hit is not None
    assert hit.indicator_id == "linux_persistence"
    assert "thing.desktop" in hit.evidence


def test_flags_matching_systemd_user_unit(make_process, tmp_path):
    systemd_dir = tmp_path / "systemd" / "user"
    systemd_dir.mkdir(parents=True)
    (systemd_dir / "thing.service").write_text(
        "[Service]\nExecStart=/home/alice/.local/bin/thing\n"
    )
    autostart = tmp_path / "autostart_empty"
    proc = make_process(exe="/home/alice/.local/bin/thing")
    hit = linux_persistence.check(proc, autostart_dir=str(autostart), systemd_user_dir=str(systemd_dir))
    assert hit is not None


def test_no_match_returns_none(make_process, tmp_path):
    autostart = tmp_path / "autostart"
    autostart.mkdir()
    (autostart / "other.desktop").write_text("[Desktop Entry]\nExec=/usr/bin/other\n")
    proc = make_process(exe="/home/alice/.local/bin/thing")
    hit = linux_persistence.check(proc, autostart_dir=str(autostart), systemd_user_dir=str(tmp_path / "none"))
    assert hit is None


def test_missing_directories_return_none(make_process, tmp_path):
    proc = make_process(exe="/home/alice/.local/bin/thing")
    hit = linux_persistence.check(
        proc, autostart_dir=str(tmp_path / "does_not_exist"),
        systemd_user_dir=str(tmp_path / "also_missing"),
    )
    assert hit is None


def test_no_exe_returns_none(make_process, tmp_path):
    proc = make_process(exe=None)
    hit = linux_persistence.check(proc, autostart_dir=str(tmp_path), systemd_user_dir=str(tmp_path))
    assert hit is None


def test_multiple_matches_all_listed(make_process, tmp_path):
    autostart = tmp_path / "autostart"
    autostart.mkdir()
    (autostart / "a.desktop").write_text("Exec=/home/alice/thing\n")
    (autostart / "b.desktop").write_text("Exec=/home/alice/thing --other\n")
    proc = make_process(exe="/home/alice/thing")
    hit = linux_persistence.check(proc, autostart_dir=str(autostart), systemd_user_dir=str(tmp_path / "x"))
    assert "a.desktop" in hit.evidence and "b.desktop" in hit.evidence
