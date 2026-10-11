"""Preserve captured loot and clean up throwaway temp dirs.

Attack tools write into per-run temp dirs under the system temp (wificapture_*,
wifiet_*, wifiscan_*, wifiwps_*, wificrack_*, washscan_*). Two things must happen
to those dirs:

  * LOOT — the captured handshake (.pcapng / .hc22000) and the evil-twin's
    captured credentials (captured.jsonl) — must NOT be lost. The session keeps
    using the originals in /tmp (convert → crack read them in place), so we COPY
    the loot into a private, persistent folder as it's produced, rather than
    moving it (which would break the in-session workflow).

  * JUNK — tool logs, hostapd/dnsmasq configs, scan CSVs, wash output — is
    throwaway. We delete a run's temp dir on the NEXT run of that tool (never on
    stop(), because status()/convert/crack still read it right after stop), and
    sweep whatever is left on shutdown.

The loot folder is ~/.spectris/loot/ (override with SPECTRIS_LOOT_DIR), created
private (0700) because it holds captured Wi-Fi passwords.
"""

import os
import shutil
from datetime import datetime
from pathlib import Path


def loot_dir() -> Path:
    base = os.environ.get("SPECTRIS_LOOT_DIR")
    return Path(base) if base else Path.home() / ".spectris" / "loot"


def preserve(files, category: str) -> Path | None:
    """Copy each existing, non-empty file into ~/.spectris/loot/<category>_<ts>/.
    Returns the destination dir, or None if there was nothing worth saving.
    Never raises — archiving loot must not break a stop()."""
    existing = [Path(f) for f in files if f and Path(f).exists() and Path(f).stat().st_size > 0]
    if not existing:
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = loot_dir() / f"{category}_{ts}"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(loot_dir(), 0o700)  # holds captured passwords — keep it private
        except OSError:
            pass
        for f in existing:
            shutil.copy2(f, dest / f.name)
    except OSError:
        return None
    return dest


def cleanup(path) -> None:
    """Best-effort recursive delete of a throwaway temp dir. Never raises."""
    if not path:
        return
    shutil.rmtree(Path(path), ignore_errors=True)
