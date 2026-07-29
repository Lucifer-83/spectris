"""Spawn and reliably — and SAFELY — STOP the elevated wireless tools.

The tools run as root (`sudo -n <tool>`) while this backend runs as the normal
user, so a plain `Popen.terminate()` fails with EPERM and the tool keeps running
(hcxdumptool/airodump that "won't stop", hostapd, reaver…).

Earlier this module stopped a tool by killing its whole PROCESS GROUP as root:
`sudo -n kill -<sig> -<pgid>`. That is dangerous. A *group* signal (negative
target) sent **as root** hits EVERY process in that group, and it relies on the
tool's group being perfectly isolated. On some distros that assumption broke and
root ended up SIGTERM-ing the user's entire login session — every open app
closed at once, as if the machine had rebooted. (Reported on Ubuntu: pressing
"Stop" on a scan closed the whole desktop.)

The safe design used here: signal ONLY the exact processes we spawned — the
`sudo` wrapper *and its descendants* (the real tool) — by explicit **positive**
PID. A positive-PID kill can never be a process-group / session-wide signal, so
it can never touch a process we did not start. We additionally guard against PID
reuse (match each PID's start-time) and never signal pid 0 or 1. We still launch
each tool in its own session (`start_new_session=True`) for tidy accounting, but
correctness no longer depends on a blanket group kill.
"""

import os
import subprocess


def popen(cmd: list[str], **kwargs) -> subprocess.Popen:
    """Popen that puts the (sudo-elevated) tool in its own session so its whole
    subtree is easy to find and stop later."""
    kwargs.setdefault("start_new_session", True)
    return subprocess.Popen(cmd, **kwargs)


def _proc_starttime(pid: int) -> str | None:
    """The process' start-time (field 22 of /proc/<pid>/stat). Unique per PID
    incarnation, so we use it to make sure a PID we're about to signal is still
    the same process we snapshotted — never a reused PID."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    # comm (field 2) can contain spaces/parens, so parse from AFTER the last ')'.
    try:
        rest = data[data.rindex(b")") + 2:].split()
        return rest[19].decode()  # field 22 overall = index 19 after (state, ppid, …)
    except (ValueError, IndexError):
        return None


def _snapshot_subtree(root_pid: int) -> list[tuple[int, str | None]]:
    """(pid, starttime) for root_pid and every live descendant, read from /proc.
    Snapshotted BEFORE we start killing so that when the `sudo` wrapper dies and
    the real tool re-parents away, we can still stop it by its original PID."""
    children: dict[int, list[int]] = {}
    starttimes: dict[int, str | None] = {}
    try:
        entries = os.listdir("/proc")
    except FileNotFoundError:
        return [(root_pid, _proc_starttime(root_pid))]
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                data = fh.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        try:
            rest = data[data.rindex(b")") + 2:].split()
            ppid = int(rest[1])          # field 4 overall (state, PPID, …)
            starttimes[pid] = rest[19].decode()
        except (ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(pid)

    out = [(root_pid, starttimes.get(root_pid, _proc_starttime(root_pid)))]
    stack = list(children.get(root_pid, []))
    while stack:
        pid = stack.pop()
        out.append((pid, starttimes.get(pid)))
        stack.extend(children.get(pid, []))
    return out


def _sudo_kill_snapshot(targets: list[tuple[int, str | None]], sig: str) -> None:
    """Signal ONLY these exact PIDs, as root (the tools are root-owned). Positive
    PIDs only — never a negative (process-group) target — so this can never fan
    out to the login session. pid 0/1 are never signalled, and a PID whose
    start-time no longer matches (i.e. it was reused) is skipped."""
    pids = [
        str(pid)
        for pid, st0 in targets
        if pid > 1 and (st0 is None or _proc_starttime(pid) == st0)
    ]
    if not pids:
        return
    # `kill` (positive PIDs) is granted passwordless in packaging/setup-sudo.sh.
    subprocess.run(["sudo", "-n", "kill", f"-{sig}", *pids], capture_output=True)


def terminate(proc: subprocess.Popen | None, timeout: int = 5) -> None:
    """Graceful-then-forceful stop of a process started with popen(). Signals the
    exact `sudo` wrapper and its descendants (the real tool) by positive PID —
    TERM, then KILL — as root. Never sends a process-group signal, so it can never
    disturb any process this backend did not spawn. Falls back to a plain
    terminate for a non-sudo child we own (e.g. the captive portal)."""
    if proc is None or proc.poll() is not None:
        return
    # snapshot the subtree BEFORE killing — once the wrapper dies its children
    # re-parent to init and would otherwise be unfindable.
    targets = _snapshot_subtree(proc.pid)
    _sudo_kill_snapshot(targets, "TERM")
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    _sudo_kill_snapshot(targets, "KILL")
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    # last resort for a child we actually own (no sudo): plain signals
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
