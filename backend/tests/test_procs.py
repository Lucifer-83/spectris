from app import procs


class FakeProc:
    def __init__(self, alive=True, pid=4242):
        self._alive = alive
        self.pid = pid

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        self._alive = False  # simulate the kill having worked
        return 0

    def kill(self):
        self._alive = False


def test_popen_puts_tool_in_its_own_session(monkeypatch):
    seen = {}
    monkeypatch.setattr(procs.subprocess, "Popen", lambda cmd, **k: seen.update(k) or "P")
    procs.popen(["echo", "hi"])
    assert seen.get("start_new_session") is True  # so the whole tree is one killable group


def test_terminate_kills_process_group_as_root(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    procs.terminate(FakeProc(alive=True, pid=4242))
    # tools run as root via sudo, so we kill the whole GROUP (negative pgid) as root
    assert ["sudo", "-n", "kill", "-TERM", "-4242"] in calls


def test_terminate_noop_when_already_exited(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    procs.terminate(FakeProc(alive=False))
    assert calls == []


def test_terminate_none_is_safe():
    procs.terminate(None)  # must not raise
