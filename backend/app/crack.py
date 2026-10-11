"""Offline PSK recovery against a captured WPA/WPA2 handshake or PMKID.

This is the step AFTER capture+convert: the .hc22000 file holds the EAPOL MIC /
PMKID, NOT the password. Recovery is an offline dictionary attack — hash every
candidate word and compare the derived MIC. Nothing is decrypted and no packets
are sent, so this needs no root and no monitor mode. It is still gated on the
engagement scope by the API layer (you may only crack a target you're
authorized against) and every start/stop is written to the audit log.

Two engines, because a pentest team's laptops differ:

  * hashcat (mode 22000) -- fast, uses the GPU when one is present. Primary.
                            Supports three attack modes: straight wordlist,
                            wordlist+rules (mutations), and mask/brute-force.
  * aircrack-ng          -- pure CPU, reads the original .pcapng directly, runs
                            on any VM without OpenCL/GPU. Team-friendly fallback
                            (wordlist only).

Note: this method only works on WPA/WPA2 PSK. WPA3/SAE (Dragonfly) is NOT
crackable this way — the API/UI warns when the target looks like WPA3-only.
"""

import gzip
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from app import loot

ENGINES = ("hashcat", "aircrack")
ATTACK_MODES = ("wordlist", "rules", "mask")

# Where team members' wordlists / hashcat rules usually live on Kali. Scanned
# read-only so the UI can offer a pick-list instead of making everyone type a path.
WORDLIST_DIRS = ("/usr/share/wordlists", "/usr/share/seclists/Passwords")
RULES_DIRS = ("/usr/share/hashcat/rules",)


def _bundled_wordlist_dir() -> Path | None:
    """The wordlist(s) shipped inside the app so cracking works out of the box
    even on a host with no /usr/share/wordlists. Resolves in dev (next to this
    module) and when frozen by PyInstaller (bundled via --add-data under
    app/wordlists, extracted to sys._MEIPASS)."""
    for base in (Path(__file__).resolve().parent, Path(getattr(sys, "_MEIPASS", "")) / "app"):
        d = base / "wordlists"
        if d.is_dir():
            return d
    return None


class CrackCommandError(Exception):
    pass


# aircrack-ng prints "KEY FOUND! [ mypassword ]" on success.
_AIRCRACK_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
# hashcat status block (repeats; we take the LAST occurrence).
_HC_PROGRESS_RE = re.compile(r"Progress\.+:\s*\d+/\d+\s*\(([\d.]+)%\)")
_HC_SPEED_RE = re.compile(r"Speed\.#[*\d]+\.+:\s*([\d.]+\s*\w?H/s)")
_HC_ETA_RE = re.compile(r"Time\.Estimated\.+:.*?\(([^)]+)\)")
# aircrack progress: "[00:01:23] 45678/14344385 keys tested (1234.56 k/s)"
_AC_PROGRESS_RE = re.compile(r"(\d+)/(\d+)\s+keys tested\s*\(([\d.]+)\s*k/s\)")
# a mask is hashcat charset tokens (?l ?u ?d ?s ?a ?b) plus literals. Reject
# whitespace AND a leading '-' so a value like "--outfile=/path" can't smuggle an
# extra hashcat option in through the trailing mask positional (argument injection).
_MASK_RE = re.compile(r"^[^\s-][^\s]{0,63}$")


@dataclass
class CrackState:
    running: bool
    engine: str | None
    attack_mode: str | None
    bssid: str | None
    wordlist: str | None
    hash_file: str | None
    psk: str | None            # recovered password, or None until/unless found
    exhausted: bool            # wordlist finished with no match
    progress_pct: float | None
    speed: str | None
    eta: str | None
    output: list[str] = field(default_factory=list)


def _scan_dirs(dirs, suffixes) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()
    for d in dirs:
        base = Path(d)
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not (p.is_file() or p.is_symlink()):
                continue
            if not any(p.name.lower().endswith(s) for s in suffixes):
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            found.append({"path": str(p), "size": size})
    return found


def list_wordlists() -> list[dict]:
    """Discover candidate wordlists so the UI can show a pick-list. rockyou
    ships gzipped on Kali, so a .gz with no matching .txt is flagged with the
    exact decompress command (the UI runs it in the integrated terminal).

    The app's own bundled wordlist is always listed FIRST (marked bundled) so
    cracking works out of the box on a host with no system wordlists. The user
    can still pick any discovered list or type a custom path in the UI."""
    found = _scan_dirs(WORDLIST_DIRS, (".txt", ".lst", ".gz"))
    for e in found:
        p = Path(e["path"])
        e["needs_gunzip"] = p.name.lower().endswith(".gz")
        e["bundled"] = False
    found.sort(key=lambda e: (-e["size"], e["path"]))  # rockyou floats near the top

    bundled: list[dict] = []
    d = _bundled_wordlist_dir()
    if d:
        for p in sorted(d.glob("*.txt")):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            bundled.append({"path": str(p), "size": size, "needs_gunzip": False, "bundled": True})
    return bundled + found  # bundled default first — always a working choice


def list_rules() -> list[dict]:
    """hashcat rule files (mutations like best64, leetspeak) for the rules mode."""
    found = _scan_dirs(RULES_DIRS, (".rule",))
    found.sort(key=lambda e: e["path"])
    return found


def decompress_wordlist(gz_path: str) -> dict:
    """Decompress a .gz wordlist (e.g. Kali's rockyou.txt.gz) so hashcat/aircrack
    can read it. Uses Python's gzip and writes to a writable temp dir — the source
    .gz is world-readable, so this needs NO root (unlike writing back into
    /usr/share/wordlists). Returns the decompressed path for the UI to select."""
    src = Path(gz_path)
    if not src.is_file() or not src.name.lower().endswith(".gz"):
        raise CrackCommandError(f"Not a .gz wordlist: {gz_path}")
    out_dir = Path(tempfile.gettempdir()) / "wifi-pentest-wordlists"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / src.with_suffix("").name  # strip the .gz
    # reuse an existing decompressed copy instead of doing it again
    if not out.exists() or out.stat().st_size == 0:
        try:
            with gzip.open(src, "rb") as fin, open(out, "wb") as fout:
                shutil.copyfileobj(fin, fout)
        except OSError as exc:
            raise CrackCommandError(f"Could not decompress {gz_path}: {exc}") from exc
    return {"path": str(out), "size": out.stat().st_size}


def hashcat_benchmark(timeout: int = 180) -> dict:
    """Run hashcat's built-in benchmark for WPA (mode 22000) so the operator can
    see the expected crack rate on THIS machine before committing to a real run.
    Pure compute — no root, no hardware, no target — same as the offline crack, so
    the Setup page can offer it as a quick "how fast will cracking be here?" check.
    `--force` lets it benchmark on a CPU-only VM with no OpenCL GPU."""
    if not shutil.which("hashcat"):
        raise CrackCommandError("hashcat not found — install it (Setup → System tools).")
    try:
        proc = subprocess.run(
            ["hashcat", "-b", "-m", "22000", "--force"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CrackCommandError("hashcat not found — install it (Setup → System tools).") from exc
    except subprocess.TimeoutExpired as exc:
        raise CrackCommandError(f"hashcat benchmark timed out after {timeout}s") from exc
    raw = (proc.stdout or "") + (proc.stderr or "")
    speeds = [s.strip() for s in _HC_SPEED_RE.findall(raw)]
    return {
        "mode": "22000 — WPA-PBKDF2-PMKID+EAPOL",
        "speeds": speeds,
        "raw": "\n".join(raw.splitlines()[-40:]),
    }


def _build_command(
    engine: str, hash_file: str, wordlist: str, pcapng: str | None, bssid: str, tmp_dir: Path,
    attack_mode: str = "wordlist", rules: str | None = None, mask: str | None = None,
) -> tuple[list[str], Path | None]:
    """Returns (argv, outfile). hashcat writes the plain key to `outfile`;
    aircrack-ng's key is parsed from stdout so its outfile is None."""
    if attack_mode not in ATTACK_MODES:
        raise CrackCommandError(f"Unknown attack mode '{attack_mode}' (expected one of {ATTACK_MODES})")

    if engine == "hashcat":
        # -m 22000 = WPA-PBKDF2-PMKID+EAPOL. --potfile-path isolated to this run
        # so a stale global potfile can't make a repeat run silently skip.
        # --force lets it run on CPU-only VMs with no OpenCL GPU device.
        # --status streams a progress block every few seconds.
        outfile = tmp_dir / "cracked.txt"
        potfile = tmp_dir / "hashcat.pot"
        opts = [
            "hashcat", "-m", "22000", "--force",
            "--status", "--status-timer", "3",
            "--potfile-path", str(potfile),
            "--outfile", str(outfile), "--outfile-format", "2",
        ]
        if attack_mode == "mask":
            if not mask or not _MASK_RE.match(mask):
                raise CrackCommandError("Mask attack needs a valid hashcat mask, e.g. ?d?d?d?d?d?d?d?d")
            cmd = opts + ["-a", "3", hash_file, mask]
        elif attack_mode == "rules":
            if not rules or not Path(rules).is_file():
                raise CrackCommandError(f"Rules file not found: {rules}")
            cmd = opts + ["-a", "0", "-r", rules, hash_file, wordlist]
        else:  # wordlist
            cmd = opts + ["-a", "0", hash_file, wordlist]
        return cmd, outfile

    if engine == "aircrack":
        if attack_mode != "wordlist":
            raise CrackCommandError("aircrack-ng supports wordlist mode only — use hashcat for rules/mask")
        if not pcapng:
            raise CrackCommandError("aircrack-ng needs the original .pcapng capture, not the .hc22000")
        cmd = ["aircrack-ng", "-w", wordlist, "-b", bssid, pcapng]  # -b pins the target BSSID
        return cmd, None

    raise CrackCommandError(f"Unknown engine '{engine}' (expected one of {ENGINES})")


def _parse_progress(engine: str | None, raw: str) -> tuple[float | None, str | None, str | None]:
    """Extract (percent, speed, eta) from the live tool output for the UI's
    progress bar. Returns Nones when nothing is parseable yet."""
    if engine == "hashcat":
        pct = _HC_PROGRESS_RE.findall(raw)
        spd = _HC_SPEED_RE.findall(raw)
        eta = _HC_ETA_RE.findall(raw)
        return (
            float(pct[-1]) if pct else None,
            spd[-1].strip() if spd else None,
            eta[-1].strip() if eta else None,
        )
    if engine == "aircrack":
        m = list(_AC_PROGRESS_RE.finditer(raw))
        if not m:
            return None, None, None
        tested, total, rate = int(m[-1].group(1)), int(m[-1].group(2)), float(m[-1].group(3))
        pct = round(tested / total * 100, 2) if total else None
        eta = None
        if rate > 0 and total:
            secs = int((total - tested) / (rate * 1000))
            h, rem = divmod(secs, 3600)
            mnt, _ = divmod(rem, 60)
            eta = f"{h}h {mnt}m" if h else f"{mnt}m"
        return pct, f"{rate} kH/s", eta
    return None, None, None


class CrackManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._process: subprocess.Popen | None = None
        self._log_fh = None
        self._log_file: Path | None = None
        self._tmp_dir: Path | None = None
        self._outfile: Path | None = None
        self._engine: str | None = None
        self._attack_mode: str | None = None
        self._bssid: str | None = None
        self._wordlist: str | None = None
        self._hash_file: str | None = None

    def start(
        self, engine: str, bssid: str, wordlist: str, hash_file: str, pcapng: str | None = None,
        attack_mode: str = "wordlist", rules: str | None = None, mask: str | None = None,
    ) -> None:
        with self._lock:
            if self._process and self._process.poll() is None:
                raise RuntimeError("A crack is already running")
            if engine not in ENGINES:
                raise CrackCommandError(f"Unknown engine '{engine}' (expected one of {ENGINES})")
            # A mask attack needs no wordlist; every other mode does.
            if attack_mode != "mask" and not Path(wordlist).is_file():
                raise CrackCommandError(f"Wordlist not found: {wordlist}")
            if engine == "hashcat" and not Path(hash_file).is_file():
                raise CrackCommandError(f"Hash file not found: {hash_file} — run Capture → Convert first")
            if engine == "aircrack" and (not pcapng or not Path(pcapng).is_file()):
                raise CrackCommandError(f"Capture file not found: {pcapng} — run a capture first")

            loot.cleanup(self._tmp_dir)  # clear the PREVIOUS run's throwaway temp dir
            tmp_dir = Path(tempfile.mkdtemp(prefix="wificrack_"))
            self._tmp_dir = tmp_dir
            cmd, outfile = _build_command(
                engine, hash_file, wordlist, pcapng, bssid, tmp_dir, attack_mode, rules, mask
            )
            self._log_file = tmp_dir / "crack.log"
            self._log_fh = open(self._log_file, "wb")
            try:
                self._process = subprocess.Popen(cmd, stdout=self._log_fh, stderr=subprocess.STDOUT)
            except FileNotFoundError as exc:
                self._log_fh.close()
                self._log_fh = None
                raise CrackCommandError(f"Required tool not found: {cmd[0]}") from exc
            except Exception:  # any other spawn failure — don't leak the log handle
                self._log_fh.close()
                self._log_fh = None
                raise
            self._outfile = outfile
            self._engine = engine
            self._attack_mode = attack_mode
            self._bssid = bssid
            self._wordlist = wordlist if attack_mode != "mask" else (mask or "")
            self._hash_file = hash_file

    def stop(self) -> None:
        with self._lock:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
            self._process = None
            if self._log_fh:
                self._log_fh.close()
                self._log_fh = None

    def cleanup_tmp(self) -> None:
        """Delete this run's throwaway temp dir (crack.log + outfile). Called on
        shutdown; during a session the dir is kept so status() can read the result
        and is cleared on the next start()."""
        loot.cleanup(self._tmp_dir)
        self._tmp_dir = None

    def is_running(self) -> bool:
        p = self._process  # snapshot: stop() may null it between the check and poll()
        return p is not None and p.poll() is None

    def _read_output(self) -> str:
        if not self._log_file or not self._log_file.exists():
            return ""
        return self._log_file.read_text(errors="replace")

    def _recovered_psk(self, raw: str) -> str | None:
        # hashcat: plain key in the outfile. aircrack: parsed from stdout.
        if self._engine == "hashcat" and self._outfile and self._outfile.exists():
            lines = [ln for ln in self._outfile.read_text(errors="replace").splitlines() if ln.strip()]
            return lines[-1] if lines else None
        m = _AIRCRACK_KEY_RE.search(raw)
        return m.group(1) if m else None

    def status(self) -> CrackState:
        raw = self._read_output()
        psk = self._recovered_psk(raw)
        finished = not self.is_running() and self._process is not None
        # Only a genuine "ran through the whole keyspace" signal counts as
        # exhausted. The old code also matched any "not found" in the output, which
        # a tool/driver error ("OpenCL device not found", "file not found") would
        # trip — making a FAILED run look like "password definitely not in list".
        exhausted = bool(finished and psk is None and (
            "Exhausted" in raw or "Passphrase not in dictionary" in raw
        ))
        pct, speed, eta = _parse_progress(self._engine, raw)
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        return CrackState(
            running=self.is_running(),
            engine=self._engine,
            attack_mode=self._attack_mode,
            bssid=self._bssid,
            wordlist=self._wordlist,
            hash_file=self._hash_file,
            psk=psk,
            exhausted=exhausted,
            progress_pct=pct,
            speed=speed,
            eta=eta,
            output=lines[-40:],
        )


crack_manager = CrackManager()
