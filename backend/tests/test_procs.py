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
    assert seen.get("start_new_session") is True  # so its whole subtree is findable


def test_terminate_signals_the_exact_pid_by_positive_number(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    # no /proc entry for this fake pid, so no descendants are found
    procs.terminate(FakeProc(alive=True, pid=4242))
    assert ["sudo", "-n", "kill", "-TERM", "4242"] in calls


def test_terminate_NEVER_sends_a_process_group_signal(monkeypatch):
    """A negative target (`-<pgid>`) sent as root can wipe the whole login
    session — the Ubuntu 'Stop closed every app' bug. Guard against it ever
    coming back: no argument may be a negative number."""
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    procs.terminate(FakeProc(alive=True, pid=4242))
    for cmd in calls:
        for arg in cmd:
            assert not (arg.startswith("-") and arg[1:].isdigit()), f"group-kill leaked: {cmd}"


def test_kill_snapshot_never_signals_pid_0_or_1(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    procs._sudo_kill_snapshot([(1, None), (0, None), (4242, None)], "TERM")
    # init (1) and the invalid 0 are dropped; only the real pid is signalled
    assert calls == [["sudo", "-n", "kill", "-TERM", "4242"]]


def test_kill_snapshot_skips_reused_pids(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    # snapshot recorded start-time "111", but the PID now reports a different one
    monkeypatch.setattr(procs, "_proc_starttime", lambda pid: "999")
    procs._sudo_kill_snapshot([(4242, "111")], "TERM")
    assert calls == []  # PID was reused → do NOT signal it


def test_terminate_noop_when_already_exited(monkeypatch):
    calls = []
    monkeypatch.setattr(procs.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    procs.terminate(FakeProc(alive=False))
    assert calls == []


def test_terminate_none_is_safe():
    procs.terminate(None)  # must not raise
