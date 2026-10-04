import pytest

from keylog_audit.process_info import ProcessRecord


@pytest.fixture
def make_process():
    def _make(**kw):
        defaults = dict(pid=1234, name="test", exe="/usr/bin/test", cmdline=["test"],
                         ppid=1, username="alice", create_time=None)
        defaults.update(kw)
        return ProcessRecord(**defaults)
    return _make
