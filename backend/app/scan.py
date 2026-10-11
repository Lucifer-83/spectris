"""Runs airodump-ng in the background against a monitor-mode interface and
parses its CSV output into a list of discovered access points."""

import csv
import io
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from app import loot, procs


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: str
    signal_dbm: str
    encryption: str
    clients: int = 0


class ScanManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._process: subprocess.Popen | None = None
        self._output_prefix: Path | None = None
        self._tmp_dir: Path | None = None

    def start(self, interface: str) -> None:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("A scan is already running")
            loot.cleanup(self._tmp_dir)  # clear the PREVIOUS scan's CSV temp dir
            tmp_dir = Path(tempfile.mkdtemp(prefix="wifiscan_"))
            self._tmp_dir = tmp_dir
            self._output_prefix = tmp_dir / "scan"
            self._process = procs.popen(
                [
                    "sudo", "-n", "airodump-ng",
                    "--output-format", "csv",
                    "--write", str(self._output_prefix),
                    interface,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def stop(self) -> None:
        with self._lock:
            procs.terminate(self._process)  # root-owned (sudo) → killed as root
            self._process = None

    def cleanup_tmp(self) -> None:
        """Delete this scan's CSV temp dir. Called on shutdown; during a session the
        dir is kept so results() can still return the AP list after stop(), and is
        cleared on the next start()."""
        loot.cleanup(self._tmp_dir)
        self._tmp_dir = None

    def is_running(self) -> bool:
        p = self._process  # snapshot: stop() may null it between the check and poll()
        return p is not None and p.poll() is None

    def results(self) -> list[AccessPoint]:
        if not self._output_prefix:
            return []
        csv_path = self._output_prefix.with_name(self._output_prefix.name + "-01.csv")
        if not csv_path.exists():
            return []
        return parse_airodump_csv(csv_path.read_text(errors="replace"))


def _count_clients_per_bssid(station_section: str) -> dict[str, int]:
    """The station section lists each connected client and the BSSID it is
    associated with; count them per AP so the UI can show how busy a network is."""
    counts: dict[str, int] = {}
    reader = csv.reader(io.StringIO(station_section))
    rows = [row for row in reader if row]
    if not rows:
        return counts
    header = [h.strip() for h in rows[0]]
    try:
        bssid_i = header.index("BSSID")
    except ValueError:
        return counts
    for row in rows[1:]:
        if len(row) <= bssid_i:
            continue
        bssid = row[bssid_i].strip().upper()
        if bssid and bssid != "(NOT ASSOCIATED)":
            counts[bssid] = counts.get(bssid, 0) + 1
    return counts


def parse_airodump_csv(raw: str) -> list[AccessPoint]:
    """airodump-ng's CSV has an AP section, a blank line, then a client section.
    We parse the AP section for networks and the client section for how many
    devices are connected to each."""
    blocks = re.split(r"\r?\n\r?\n", raw)
    ap_section = blocks[0]
    client_counts = _count_clients_per_bssid(blocks[1]) if len(blocks) > 1 else {}

    reader = csv.reader(io.StringIO(ap_section))
    rows = [row for row in reader if row]
    if not rows:
        return []
    header = [h.strip() for h in rows[0]]
    try:
        bssid_i = header.index("BSSID")
        channel_i = header.index("channel")
        power_i = header.index("Power")
        enc_i = header.index("Privacy")
        essid_i = header.index("ESSID")
    except ValueError:
        return []

    access_points = []
    for row in rows[1:]:
        if len(row) <= max(bssid_i, channel_i, power_i, enc_i, essid_i):
            continue
        bssid = row[bssid_i].strip()
        access_points.append(
            AccessPoint(
                bssid=bssid,
                ssid=row[essid_i].strip(),
                channel=row[channel_i].strip(),
                signal_dbm=row[power_i].strip(),
                encryption=row[enc_i].strip(),
                clients=client_counts.get(bssid.upper(), 0),
            )
        )
    return access_points


scan_manager = ScanManager()
