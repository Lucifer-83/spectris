"""Spawn and reliably STOP the elevated wireless tools.

The tools run as root (`sudo -n <tool>`), but this backend runs as the normal
user. A user process cannot signal a root process, so a plain
`Popen.terminate()` fails with EPERM and the tool keeps running forever (e.g.
hcxdumptool capture that "won't stop", hostapd, airodump). The fix:

  * launch each tool in its OWN process group (`start_new_session=True`), and
  * stop it by killing that whole group AS ROOT via `sudo -n kill -<sig> -<pgid>`
    (kill is granted in packaging/setup-sudo.sh).

This kills the sudo wrapper AND the tool it launched together, cleanly.
"""

import subprocess


def popen(cmd: list[str], **kwargs) -> subprocess.Popen:
    """Popen that puts the (sudo-elevated) tool in its own process group so the
    whole tree can be killed later."""
    kwargs.setdefault("start_new_session", True)
    return subprocess.Popen(cmd, **kwargs)


def _sudo_kill_group(pgid: int, sig: str) -> None:
    # negative pgid = the whole process group; run as root since the tools are root
    subprocess.run(["sudo", "-n", "kill", f"-{sig}", f"-{pgid}"], capture_output=True)


def terminate(proc: subprocess.Popen | None, timeout: int = 5) -> None:
    """Graceful-then-forceful stop of a process started with popen(). Kills the
    process GROUP as root (TERM, then KILL). Falls back to a plain terminate for a
    non-sudo child we own (e.g. the captive portal)."""
    if proc is None or proc.poll() is not None:
        return
    pgid = proc.pid  # start_new_session → the child is its own group leader
    _sudo_kill_group(pgid, "TERM")
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    _sudo_kill_group(pgid, "KILL")
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
