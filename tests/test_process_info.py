import os

from keylog_audit.process_info import collect_processes, ProcessRecord


def test_collect_processes_returns_list():
    procs = collect_processes()
    assert isinstance(procs, list)
    assert len(procs) > 0


def test_collect_processes_includes_self():
    procs = collect_processes()
    pids = {p.pid for p in procs}
    assert os.getpid() in pids


def test_process_record_has_expected_fields():
    procs = collect_processes()
    self_proc = next(p for p in procs if p.pid == os.getpid())
    assert self_proc.name  # current process definitely has a name
    assert isinstance(self_proc.cmdline, list)


def test_process_record_to_dict():
    record = ProcessRecord(pid=123, name="test", exe="/bin/test", cmdline=["test"],
                            ppid=1, username="alice", create_time=1700000000.0)
    d = record.to_dict()
    assert d["pid"] == 123
    assert d["name"] == "test"
    assert d["create_time"] is not None  # should be ISO formatted


def test_process_record_create_time_none_when_unset():
    record = ProcessRecord(pid=1, name="x", exe=None)
    assert record.create_time_iso is None


def test_process_record_defaults():
    record = ProcessRecord(pid=1, name="x", exe=None)
    assert record.cmdline == []
    assert record.ppid is None
    assert record.username is None
