"""Detect which nearby APs have WPS enabled (and whether it's locked) using
`wash`, so the operator can tell up front which targets are worth a WPS/Pixie
Dust attempt instead of wasting time.

Note: whether an AP is actually *Pixie Dust* vulnerable cannot be known without
attempting it (it depends on the AP's WPS implementation). What we CAN report is
the necessary precondition: WPS is enabled and not locked. A locked WPS is not
worth attacking; no WPS at all rules out reaver/bully entirely.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path


def parse_wash_json(raw: str) -> list[dict]:
    """wash -j emits WPS-capable APs as JSON. Parse defensively (array or
    per-line objects) and normalise to {bssid, locked}."""
    raw = raw.strip()
    if not raw:
        return []
    objs: list = []
    try:
        data = json.loads(raw)
        objs = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in "[]":
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    results: dict[str, bool] = {}
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        bssid = str(obj.get("bssid") or obj.get("BSSID") or "").upper()
        if not bssid:
            continue
        locked_raw = obj.get("wps_locked", obj.get("locked", 0))
        locked = str(locked_raw).strip().lower() in ("1", "true", "yes", "locked")
        # if seen twice, keep "locked" if any report said locked
        results[bssid] = results.get(bssid, False) or locked
    return [{"bssid": b, "locked": locked} for b, locked in results.items()]


def wps_scan(interface: str, duration: int = 15) -> list[dict]:
    """Run wash for a bounded window and return WPS-capable APs. Blocking —
    the API runs it in a threadpool. The caller must ensure no other tool is
    using the interface (airodump scan stopped) first."""
    duration = max(5, min(duration, 60))
    tmp = Path(tempfile.mkdtemp(prefix="washscan_"))
    outfile = tmp / "wash.json"
    with open(outfile, "wb") as fh:
        try:
            proc = subprocess.Popen(
                ["sudo", "-n", "wash", "-i", interface, "-j"],
                stdout=fh,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Required tool not found: wash") from exc
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return parse_wash_json(outfile.read_text(errors="replace"))
