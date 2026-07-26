import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import adapter, logging_db, tools
from app.auto import auto_manager, looks_like_wpa3_only
from app.capture import CaptureCommandError, capture_manager
from app.crack import CrackCommandError, crack_manager, decompress_wordlist, hashcat_benchmark, list_rules, list_wordlists
from app.deauth import DeauthCommandError, deauth_manager
from app.eviltwin import EvilTwinCommandError, eviltwin_manager
from app.report import build_report, report_filename
from app.scan import AccessPoint, scan_manager
from app.scope import OutOfScopeError, ScopeNotSetError, current_scope
from app.wps import WpsCommandError, wps_manager
from app import wpsscan

app = FastAPI(title="WiFi Pentest Toolkit Backend")

# The Electron renderer (Vite dev server in dev, file:// when packaged) and the
# Docker/browser mode (UI served over HTTP) all call this API from a different
# origin than the backend's own localhost:8000, so the browser enforces CORS
# even though everything runs on the same machine. This is a localhost-only
# tool, so we allow any localhost/127.0.0.1 origin (dev-port drift, Docker
# host networking) plus the file:// origin of a packaged Electron build.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|file://.*|null)$",
    allow_methods=["*"],
    allow_headers=["*"],
)


class MonitorModeRequest(BaseModel):
    interface: str
    enable: bool


class KillInterferersRequest(BaseModel):
    interface: str


class ScopeRequest(BaseModel):
    bssids: list[str] = []
    ssids: list[str] = []


class ScanStartRequest(BaseModel):
    interface: str


class WpsScanRequest(BaseModel):
    interface: str


class CaptureStartRequest(BaseModel):
    interface: str
    bssid: str
    channel: str


class WpsStartRequest(BaseModel):
    interface: str
    bssid: str
    channel: str
    attack: str = "pixie"  # "pixie" (Pixie Dust) | "pin" (online PIN)
    engine: str = "reaver"  # "reaver" | "bully"


class CrackStartRequest(BaseModel):
    bssid: str                    # scope-gated target; also aircrack-ng's -b
    wordlist: str = ""            # path to the dictionary (not needed for mask mode)
    engine: str = "hashcat"       # "hashcat" | "aircrack"
    attack_mode: str = "wordlist"  # "wordlist" | "rules" | "mask" (rules/mask are hashcat-only)
    rules: str | None = None      # hashcat rules file (rules mode)
    mask: str | None = None       # hashcat mask, e.g. ?d?d?d?d?d?d?d?d (mask mode)
    hash_file: str | None = None  # defaults to the current capture's .hc22000
    pcapng: str | None = None     # defaults to the current capture's .pcapng (aircrack)


class DecompressRequest(BaseModel):
    path: str  # a .gz wordlist to decompress (e.g. rockyou.txt.gz)


class AutoStartRequest(BaseModel):
    interface: str
    bssid: str
    channel: str
    wordlist: str
    encryption: str | None = None  # from the scan, so we can reject WPA3-only up front
    deauth_count: int = 8
    capture_seconds: int = 60


class DeauthStartRequest(BaseModel):
    interface: str
    bssid: str
    count: int = 8
    client: str | None = None
    channel: str | None = None


class EvilTwinStartRequest(BaseModel):
    interface: str                       # AP adapter (becomes the fake AP)
    ssid: str
    channel: str = "6"
    deauth_interface: str | None = None  # monitor-mode adapter for sustained deauth
    target_bssid: str | None = None      # real AP whose clients get pushed to the twin
    handshake_file: str | None = None    # captured .pcapng to verify submitted passwords


def _assert_scope_or_raise(bssid: str) -> None:
    try:
        current_scope.assert_in_scope(bssid=bssid)
    except ScopeNotSetError as exc:
        logging_db.log_action("scope-check", bssid, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OutOfScopeError as exc:
        logging_db.log_action("scope-check", bssid, "rejected", detail=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _assert_ssid_scope_or_raise(ssid: str) -> None:
    """Evil-twin is authorized by SSID: you may only impersonate a network name
    that is inside the engagement scope."""
    try:
        current_scope.assert_in_scope(ssid=ssid)
    except ScopeNotSetError as exc:
        logging_db.log_action("scope-check", ssid, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OutOfScopeError as exc:
        logging_db.log_action("scope-check", ssid, "rejected", detail=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _assert_monitor_mode_or_raise(interface: str, action: str) -> None:
    """reaver/aireplay/airodump can only inject on a monitor-mode interface. On a
    managed one they run but never associate — the "can't associate with the AP"
    symptom. Catch it up front with a clear, actionable 400 instead of a silent
    failure the operator has to decode from the live output."""
    try:
        mode = adapter.interface_mode(interface)
    except adapter.AdapterCommandError:
        mode = None
    if mode is not None and mode != "monitor":
        detail = (
            f"{interface} is in '{mode}' mode — this needs monitor mode, or it can't associate "
            "with the AP. Enable monitor mode for it in Setup first (if it keeps reverting to "
            "managed, use 'Kill interfering processes')."
        )
        logging_db.log_action(action, interface, "rejected", detail=detail)
        raise HTTPException(status_code=400, detail=detail)


@app.get("/tools/status")
def get_tools_status():
    return tools.tools_status()


@app.get("/adapter/status")
def get_adapter_status():
    try:
        return adapter.adapter_status()
    except adapter.AdapterCommandError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/adapter/kill-interferers")
def post_kill_interferers(req: KillInterferersRequest):
    try:
        output = adapter.kill_interfering_processes(req.interface)
        logging_db.log_action("kill-interferers", req.interface, "success", detail=output[:500])
        return {"output": output}
    except adapter.AdapterCommandError as exc:
        logging_db.log_action("kill-interferers", req.interface, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/adapter/monitor-mode")
def post_monitor_mode(req: MonitorModeRequest):
    try:
        mode = adapter.set_monitor_mode(req.interface, req.enable)
        logging_db.log_action("monitor-mode", req.interface, "success", detail=mode)
        return {"interface": req.interface, "mode": mode}
    except adapter.AdapterCommandError as exc:
        logging_db.log_action("monitor-mode", req.interface, "error", detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _current_activity() -> dict:
    """Which long-running operations are active right now. Used to lock scope
    edits mid-run (changing scope while an attack targets an old BSSID is a
    footgun) and to surface a 'busy' state in the UI."""
    running = []
    if scan_manager.is_running():
        running.append("scan")
    if capture_manager.status().running:
        running.append("capture")
    if wps_manager.is_running():
        running.append("wps")
    if crack_manager.status().running:
        running.append("crack")
    if auto_manager.status().running:
        running.append("auto")
    if deauth_manager.status().running:
        running.append("deauth")
    if eviltwin_manager.is_running():
        running.append("eviltwin")
    return {"busy": bool(running), "running": running}


@app.get("/engagement/activity")
def get_activity():
    return _current_activity()


def _cleanup_all() -> dict:
    """Return the box to its pre-tool state: stop every running operation and
    revert any monitor-mode adapter back to managed (so normal Wi-Fi works) and
    undo the evil-twin network changes. Best-effort — used on shutdown and by the
    /engagement/shutdown endpoint so closing the tool leaves nothing behind to
    conflict on the next launch."""
    for stop in (
        scan_manager.stop, capture_manager.stop, wps_manager.stop,
        deauth_manager.stop, eviltwin_manager.stop, crack_manager.stop, auto_manager.stop,
    ):
        try:
            stop()
        except Exception:  # noqa: BLE001 - cleanup must never raise
            pass
    reverted = []
    try:
        reverted = adapter.reset_all_to_managed()
    except Exception:  # noqa: BLE001
        pass
    return {"reverted_interfaces": reverted}


@app.on_event("shutdown")
def _on_shutdown():
    # runs on graceful uvicorn shutdown (SIGTERM) — revert everything.
    _cleanup_all()


@app.post("/engagement/shutdown")
def post_shutdown():
    """Explicitly revert everything (attacks stopped, monitor→managed, iptables
    cleaned). Called by the app when it closes and by stop.sh, so the next launch
    starts clean."""
    result = _cleanup_all()
    logging_db.log_action("shutdown-cleanup", None, "success", detail=str(result))
    return {"status": "cleaned", **result}


@app.post("/engagement/scope")
def post_scope(req: ScopeRequest):
    activity = _current_activity()
    if activity["busy"]:
        detail = (
            f"An operation is running ({', '.join(activity['running'])}) — stop it before changing the "
            "scope. Changing scope mid-run can leave a live attack pointed at an out-of-scope target."
        )
        logging_db.log_action("set-scope", None, "rejected", detail=detail)
        raise HTTPException(status_code=409, detail=detail)
    current_scope.set_scope(bssids=req.bssids, ssids=req.ssids)
    logging_db.log_action("set-scope", None, "success", detail=str(req.model_dump()))
    return current_scope.as_dict()


@app.get("/engagement/scope")
def get_scope():
    return current_scope.as_dict()


@app.post("/scan/start")
def post_scan_start(req: ScanStartRequest):
    # airodump only sees beacons in monitor mode; on a managed interface it runs
    # but finds nothing, which used to look like "scan is broken". Fail loudly.
    _assert_monitor_mode_or_raise(req.interface, "scan-start")
    try:
        scan_manager.start(req.interface)
        logging_db.log_action("scan-start", req.interface, "success")
        return {"status": "started", "interface": req.interface}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/scan/stop")
def post_scan_stop():
    scan_manager.stop()
    logging_db.log_action("scan-stop", None, "success")
    return {"status": "stopped"}


@app.get("/scan/results")
def get_scan_results():
    results: list[AccessPoint] = scan_manager.results()
    return {"running": scan_manager.is_running(), "access_points": [ap.__dict__ for ap in results]}


@app.post("/scan/wps")
def post_scan_wps(req: WpsScanRequest):
    # wash and airodump can't share the interface, so free it first.
    scan_manager.stop()
    try:
        aps = wpsscan.wps_scan(req.interface)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    logging_db.log_action("wps-scan", req.interface, "success", detail=f"{len(aps)} WPS-capable AP(s)")
    return {"access_points": aps}


@app.post("/capture/start")
def post_capture_start(req: CaptureStartRequest):
    _assert_scope_or_raise(req.bssid)
    _assert_monitor_mode_or_raise(req.interface, "capture-start")
    try:
        output = capture_manager.start(req.interface, req.bssid, req.channel)
        logging_db.log_action("capture-start", req.bssid, "success", detail=str(output))
        return {"status": "started", "bssid": req.bssid, "output_pcapng": str(output)}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/capture/stop")
def post_capture_stop():
    state = capture_manager.status()
    capture_manager.stop()
    logging_db.log_action("capture-stop", state.bssid, "success")
    return {"status": "stopped"}


@app.get("/capture/status")
def get_capture_status():
    state = capture_manager.status()
    return state.__dict__


@app.post("/capture/convert")
def post_capture_convert():
    state = capture_manager.status()
    try:
        hash_file = capture_manager.convert_to_hashcat_format()
        logging_db.log_action("capture-convert", state.bssid, "success", detail=str(hash_file))
        return {"hash_file": str(hash_file)}
    except CaptureCommandError as exc:
        logging_db.log_action("capture-convert", state.bssid, "error", detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/crack/wordlists")
def get_crack_wordlists():
    return {"wordlists": list_wordlists(), "rules": list_rules()}


@app.post("/crack/benchmark")
def post_crack_benchmark():
    """Benchmark hashcat's WPA mode on this machine so Setup can show the crack
    speed before a real run. No target, no scope check — pure local compute."""
    try:
        result = hashcat_benchmark()
        logging_db.log_action(
            "hashcat-benchmark", None, "success", detail=", ".join(result["speeds"]) or "no speed parsed"
        )
        return result
    except CrackCommandError as exc:
        logging_db.log_action("hashcat-benchmark", None, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/crack/decompress")
def post_crack_decompress(req: DecompressRequest):
    """Decompress a .gz wordlist (Python gzip → writable temp dir, no root) so it
    can be used for cracking. Returns the decompressed path for the UI to select."""
    try:
        result = decompress_wordlist(req.path)
        logging_db.log_action("wordlist-decompress", None, "success", detail=result["path"])
        return result
    except CrackCommandError as exc:
        logging_db.log_action("wordlist-decompress", None, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/crack/start")
def post_crack_start(req: CrackStartRequest):
    _assert_scope_or_raise(req.bssid)
    # Auto-fill the capture outputs so the operator doesn't paste paths.
    hash_file = req.hash_file or (str(capture_manager.hash_file()) if capture_manager.hash_file() else None)
    pcapng = req.pcapng or (str(capture_manager.output_pcapng()) if capture_manager.output_pcapng() else None)
    if req.engine == "hashcat" and not hash_file:
        raise HTTPException(status_code=400, detail="No .hc22000 yet — run Capture → Convert to hashcat first.")
    try:
        crack_manager.start(
            req.engine, req.bssid, req.wordlist, hash_file or "", pcapng,
            attack_mode=req.attack_mode, rules=req.rules, mask=req.mask,
        )
        logging_db.log_action(
            "crack-start", req.bssid, "success",
            detail=f"engine={req.engine} mode={req.attack_mode} wordlist={req.wordlist}",
        )
        return {"status": "started", "bssid": req.bssid, "engine": req.engine}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CrackCommandError as exc:
        logging_db.log_action("crack-start", req.bssid, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/crack/stop")
def post_crack_stop():
    state = crack_manager.status()
    crack_manager.stop()
    logging_db.log_action("crack-stop", state.bssid, "success")
    return {"status": "stopped"}


@app.get("/crack/status")
def get_crack_status():
    state = crack_manager.status()
    # Persist the win the moment the key is recovered, so it lands in the audit
    # log even if the operator never clicks stop.
    if state.psk and not getattr(get_crack_status, "_logged_psk", None) == (state.bssid, state.psk):
        logging_db.log_action("crack-recovered", state.bssid, "success", detail="PSK recovered")
        get_crack_status._logged_psk = (state.bssid, state.psk)
    return state.__dict__


@app.post("/auto/start")
def post_auto_start(req: AutoStartRequest):
    _assert_scope_or_raise(req.bssid)
    if looks_like_wpa3_only(req.encryption):
        detail = (
            "Target looks like WPA3-only (SAE) — its handshake is not crackable by this dictionary "
            "method. Auto mode is for WPA/WPA2-PSK."
        )
        logging_db.log_action("auto-start", req.bssid, "rejected", detail=detail)
        raise HTTPException(status_code=400, detail=detail)
    try:
        auto_manager.start(
            req.interface, req.bssid, req.channel, req.wordlist,
            deauth_count=req.deauth_count, capture_seconds=req.capture_seconds,
        )
        return {"status": "started", "bssid": req.bssid}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CaptureCommandError as exc:
        logging_db.log_action("auto-start", req.bssid, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/auto/stop")
def post_auto_stop():
    state = auto_manager.status()
    auto_manager.stop()
    logging_db.log_action("auto-stop", state.bssid, "success")
    return {"status": "stopped"}


@app.get("/auto/status")
def get_auto_status():
    return auto_manager.status().__dict__


@app.post("/wps/start")
def post_wps_start(req: WpsStartRequest):
    _assert_scope_or_raise(req.bssid)
    _assert_monitor_mode_or_raise(req.interface, f"wps-{req.attack}")
    try:
        wps_manager.start(req.interface, req.bssid, req.channel, req.attack, req.engine)
        logging_db.log_action(
            f"wps-{req.attack}", req.bssid, "success", detail=f"engine={req.engine} channel={req.channel}"
        )
        return {"status": "started", "bssid": req.bssid, "attack": req.attack, "engine": req.engine}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except WpsCommandError as exc:
        logging_db.log_action(f"wps-{req.attack}", req.bssid, "error", detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/wps/stop")
def post_wps_stop():
    state = wps_manager.status()
    wps_manager.stop()
    logging_db.log_action("wps-stop", state.bssid, "success")
    return {"status": "stopped"}


@app.get("/wps/status")
def get_wps_status():
    return wps_manager.status().__dict__


@app.post("/deauth/start")
def post_deauth_start(req: DeauthStartRequest):
    _assert_scope_or_raise(req.bssid)
    _assert_monitor_mode_or_raise(req.interface, "deauth")
    try:
        deauth_manager.start(req.interface, req.bssid, req.count, req.client, req.channel)
        logging_db.log_action(
            "deauth", req.bssid, "success",
            detail=f"count={req.count} channel={req.channel} client={req.client or 'broadcast'}",
        )
        return {"status": "started", "bssid": req.bssid, "count": req.count}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DeauthCommandError as exc:
        logging_db.log_action("deauth", req.bssid, "error", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/deauth/stop")
def post_deauth_stop():
    state = deauth_manager.status()
    deauth_manager.stop()
    logging_db.log_action("deauth-stop", state.bssid, "success")
    return {"status": "stopped"}


@app.get("/deauth/status")
def get_deauth_status():
    return deauth_manager.status().__dict__


@app.post("/eviltwin/start")
def post_eviltwin_start(req: EvilTwinStartRequest):
    _assert_ssid_scope_or_raise(req.ssid)
    # Evil twin here always clones a specific real AP, so a target BSSID is required.
    if not req.target_bssid:
        detail = "Select the real target AP (BSSID) on Scan & Target first — evil twin clones a specific network."
        logging_db.log_action("eviltwin-start", req.ssid, "rejected", detail=detail)
        raise HTTPException(status_code=400, detail=detail)
    # The real AP's BSSID must ALSO be in scope (impersonation is SSID-authorized;
    # deauthing its clients is BSSID-authorized), and the deauth adapter must be in
    # monitor mode.
    _assert_scope_or_raise(req.target_bssid)
    if req.deauth_interface:
        _assert_monitor_mode_or_raise(req.deauth_interface, "eviltwin-deauth")
    # Auto-fill the handshake + PMKID hash from the current capture. pcapng feeds
    # aircrack-ng; the .hc22000 feeds the hashcat fallback for PMKID-only hcxdumptool
    # captures. If the capture hasn't been converted yet, convert it now so a
    # PMKID-only capture can still be verified (aircrack alone won't see a PMKID).
    handshake = req.handshake_file or (
        str(capture_manager.output_pcapng()) if capture_manager.output_pcapng() else None
    )
    hash_file = str(capture_manager.hash_file()) if capture_manager.hash_file() else None
    if not hash_file and capture_manager.output_pcapng() and capture_manager.output_pcapng().exists():
        try:
            hash_file = str(capture_manager.convert_to_hashcat_format())
        except CaptureCommandError:
            hash_file = None  # nothing crackable captured yet → the check below 400s
    # HARD REQUIREMENT: evil twin must NOT run without a usable handshake — without
    # it the portal can't tell the real Wi-Fi password from a wrong guess. This is
    # now an INSTANT check: convert_to_hashcat_format() above only yields a non-empty
    # .hc22000 when a crackable handshake/PMKID exists (it raises otherwise), so a
    # present hash_file means verification is possible. (No slow aircrack/hashcat
    # probe at start — that's what made the AP take so long to come up.)
    usable = bool(hash_file and Path(hash_file).exists() and Path(hash_file).stat().st_size > 0)
    if not usable:
        detail = (
            "No usable 4-way handshake / PMKID captured for this target — capture it first on the "
            "Handshake Capture tab (deauth a connected client so it re-handshakes), then start the "
            "evil twin. Without a handshake the portal can't verify the Wi-Fi password."
        )
        logging_db.log_action("eviltwin-start", req.ssid, "rejected", detail=detail)
        raise HTTPException(status_code=400, detail=detail)
    try:
        eviltwin_manager.start(
            req.interface, req.ssid, req.channel,
            deauth_interface=req.deauth_interface, target_bssid=req.target_bssid,
            handshake_file=handshake, hash_file=hash_file,
        )
        logging_db.log_action(
            "eviltwin-start", req.ssid, "success",
            detail=(
                f"interface={req.interface} channel={req.channel} "
                f"deauth={req.deauth_interface or 'off'} target={req.target_bssid or '-'} "
                f"verify={'yes' if (handshake or hash_file) else 'no'}"
            ),
        )
        return {"status": "started", "ssid": req.ssid}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except EvilTwinCommandError as exc:
        logging_db.log_action("eviltwin-start", req.ssid, "error", detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/eviltwin/stop")
def post_eviltwin_stop():
    state = eviltwin_manager.status()
    # persist how many credentials the portal captured before tearing down
    captured = len(state.captured)
    eviltwin_manager.stop()
    logging_db.log_action("eviltwin-stop", state.ssid, "success", detail=f"captured={captured}")
    return {"status": "stopped", "captured": captured}


@app.get("/eviltwin/status")
def get_eviltwin_status():
    return eviltwin_manager.status().__dict__


@app.get("/log")
def get_log():
    return logging_db.get_log()


@app.post("/log/clear")
def post_log_clear():
    removed = logging_db.clear_log()
    return {"status": "cleared", "removed": removed}


@app.get("/engagement/report")
def get_engagement_report():
    """Build the engagement report (Markdown) from the audit log + the session's
    recovered credentials. Returned as text for the UI to save — nothing is
    written or transmitted server-side. The export itself is logged after the
    report is built, so it never appears inside its own timeline."""
    content = build_report()
    logging_db.log_action("export-report", None, "success", detail=f"{len(content)} bytes")
    return {"filename": report_filename(), "content": content, "mimetype": "text/markdown"}


# Serve the built web UI from the backend so the Docker/browser mode needs no
# separate dev server or Electron shell — open http://localhost:8000. Mounted
# LAST so it never shadows the API routes above. Absent in local dev (Vite
# serves the UI then), so this is a no-op unless a build has been placed here.
_gui_dist = Path(os.environ.get("WIFI_GUI_DIST", Path(__file__).resolve().parent.parent / "static"))
if _gui_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_gui_dist), html=True), name="gui")
