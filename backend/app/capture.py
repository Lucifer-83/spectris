"""Handshake/PMKID capture against a scope-authorized target.

Wraps hcxdumptool 7.x (passive EAPOL/PMKID capture). hcxdumptool 7 dropped the
old `-o`/`--filterlist`/`--filtermode` options and changed the channel syntax
(a band letter is now required, e.g. channel 6 -> "6a" for 2.4 GHz), so the
capture is locked to the target's channel with the new `-c`/`-w` flags. Output
is streamed to a log so the UI can show progress. The interface must be in
monitor mode; the target BSSID is scope-checked by the API before start().
"""

import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from app import procs


class CaptureCommandError(Exception):
    pass


def channel_arg(channel: str) -> str:
    """hcxdumptool 7 needs a band letter on the channel (a=2.4GHz, b=5GHz)."""
    ch = channel.strip().lower()
    if ch and ch[-1] in "abcde":
        return ch
    try:
        n = int(ch)
    except ValueError:
        return ch
    return f"{n}a" if n <= 14 else f"{n}b"


@dataclass
class CaptureState:
    running: bool
    interface: str | None
    bssid: str | None
    output_pcapng: str | None
    hash_file: str | None
    hashes: int = 0  # crackable EAPOL/PMKID hashes captured so far
    output: list[str] = field(default_factory=list)


class CaptureManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._process: subprocess.Popen | None = None
        self._log_fh = None
        self._log_file: Path | None = None
        self._interface: str | None = None
        self._bssid: str | None = None
        self._output_dir: Path | None = None
        self._last_probe: float = 0.0
        self._last_count: int = 0

    def start(self, interface: str, bssid: str, channel: str) -> Path:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("A capture is already running")
            self._output_dir = Path(tempfile.mkdtemp(prefix="wificapture_"))
            self._last_probe = 0.0
            self._last_count = 0
            output_pcapng = self._output_dir / "capture.pcapng"
            self._log_file = self._output_dir / "hcxdumptool.log"
            self._log_fh = open(self._log_file, "wb")
            cmd = [
                "sudo", "-n", "hcxdumptool",
                "-i", interface,
                "-w", str(output_pcapng),
                "-c", channel_arg(channel),
                "-t", "5",
            ]
            try:
                self._process = procs.popen(cmd, stdout=self._log_fh, stderr=subprocess.STDOUT)
            except FileNotFoundError as exc:
                self._log_fh.close()
                raise CaptureCommandError("Required tool not found: hcxdumptool") from exc
            self._interface = interface
            self._bssid = bssid
            return output_pcapng

    def stop(self) -> None:
        with self._lock:
            procs.terminate(self._process)  # root-owned (sudo) → killed as root
            self._process = None
            if self._log_fh:
                self._log_fh.close()
                self._log_fh = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def output_pcapng(self) -> Path | None:
        if not self._output_dir:
            return None
        return self._output_dir / "capture.pcapng"

    def hash_file(self) -> Path | None:
        """The .hc22000 produced by the last convert, if it exists. Lets the
        crack step auto-fill its input instead of making the operator paste a
        path."""
        pcapng = self.output_pcapng()
        if not pcapng:
            return None
        hf = pcapng.with_suffix(".hc22000")
        return hf if hf.exists() else None

    def _recent_output(self) -> list[str]:
        if not self._log_file or not self._log_file.exists():
            return []
        lines = [ln for ln in self._log_file.read_text(errors="replace").splitlines() if ln.strip()]
        return lines[-40:]

    def _count_hashes(self) -> int:
        """Peek at the live pcapng and count crackable hashes so the UI can show
        'handshake captured' without waiting for a manual convert. Throttled and
        best-effort — probes into a scratch file, never the convert output."""
        pcapng = self.output_pcapng()
        if not pcapng or not pcapng.exists() or pcapng.stat().st_size == 0:
            return self._last_count
        now = time.monotonic()
        if now - self._last_probe < 4:
            return self._last_count
        self._last_probe = now
        probe = pcapng.with_suffix(".probe.hc22000")
        try:
            subprocess.run(
                ["hcxpcapngtool", "-o", str(probe), str(pcapng)],
                capture_output=True, timeout=15,
            )
            if probe.exists():
                self._last_count = sum(1 for ln in probe.read_text(errors="replace").splitlines() if ln.strip())
        except (subprocess.TimeoutExpired, OSError):
            pass
        return self._last_count

    def convert_to_hashcat_format(self) -> Path:
        """Runs hcxpcapngtool to extract crackable hashes (EAPOL/PMKID) into
        hashcat's .hc22000 format from the captured pcapng."""
        pcapng = self.output_pcapng()
        if not pcapng or not pcapng.exists():
            raise CaptureCommandError("No capture output found; run a capture first")
        hash_file = pcapng.with_suffix(".hc22000")
        proc = subprocess.run(
            ["hcxpcapngtool", "-o", str(hash_file), str(pcapng)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise CaptureCommandError(f"hcxpcapngtool failed: {proc.stderr.strip()}")
        if not hash_file.exists() or hash_file.stat().st_size == 0:
            raise CaptureCommandError(
                "No crackable hashes in the capture yet — no handshake/PMKID captured. "
                "Keep the capture running (a deauth helps) and try again."
            )
        return hash_file

    def status(self) -> CaptureState:
        pcapng = self.output_pcapng()
        return CaptureState(
            running=self.is_running(),
            interface=self._interface,
            bssid=self._bssid,
            output_pcapng=str(pcapng) if pcapng and pcapng.exists() else None,
            hash_file=None,
            hashes=self._count_hashes(),
            output=self._recent_output(),
        )


capture_manager = CaptureManager()
