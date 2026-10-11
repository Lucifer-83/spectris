import pytest
from fastapi.testclient import TestClient

from app.eviltwin import (
    EvilTwinCommandError,
    EvilTwinManager,
    _validate_ap_params,
    build_dnsmasq_conf,
    build_hostapd_conf,
)
from app.main import app
from app.portal import has_accepted, read_captured, record_submission, render_page, verify_password
from app.scope import current_scope


@pytest.fixture(autouse=True)
def reset_scope():
    current_scope.clear()
    yield
    current_scope.clear()


@pytest.fixture
def client():
    return TestClient(app)


# --- scope gating: evil twin is authorized by SSID ------------------------

def test_eviltwin_rejected_when_scope_never_set(client):
    resp = client.post("/eviltwin/start", json={"interface": "wlan0", "ssid": "CorpGuest", "channel": "6"})
    assert resp.status_code == 400


def test_eviltwin_rejected_for_out_of_scope_ssid(client):
    current_scope.set_scope(ssids=["CorpGuest"])
    resp = client.post("/eviltwin/start", json={"interface": "wlan0", "ssid": "SomeoneElse", "channel": "6"})
    assert resp.status_code == 403


def test_eviltwin_never_invokes_manager_when_out_of_scope(client, monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("eviltwin_manager.start must not run for an out-of-scope SSID")

    monkeypatch.setattr("app.main.eviltwin_manager.start", fail_if_called)
    current_scope.set_scope(ssids=["CorpGuest"])
    resp = client.post("/eviltwin/start", json={"interface": "wlan0", "ssid": "SomeoneElse", "channel": "6"})
    assert resp.status_code == 403
    assert called is False


# --- config generation ----------------------------------------------------

def test_hostapd_conf_has_ssid_and_channel():
    conf = build_hostapd_conf("wlan0", "CorpGuest", "11")
    assert "ssid=CorpGuest" in conf
    assert "channel=11" in conf
    assert "interface=wlan0" in conf


def test_dnsmasq_conf_hijacks_all_dns_to_gateway():
    conf = build_dnsmasq_conf("wlan0", "/tmp/x.leases", "10.0.0.1")
    assert "address=/#/10.0.0.1" in conf  # catch-all DNS -> captive portal
    assert "dhcp-range=" in conf
    assert "dhcp-leasefile=/tmp/x.leases" in conf  # so we can count connected clients


# --- hostapd AP-param validation (config-injection guard) -----------------

def test_validate_ap_params_rejects_newline_ssid():
    # a newline would let the SSID inject extra hostapd.conf directives
    with pytest.raises(EvilTwinCommandError):
        _validate_ap_params("evil\nwpa_passphrase=pwned", "6")


def test_validate_ap_params_rejects_control_char_ssid():
    with pytest.raises(EvilTwinCommandError):
        _validate_ap_params("evil\x00ssid", "6")


def test_validate_ap_params_rejects_oversize_ssid():
    with pytest.raises(EvilTwinCommandError):
        _validate_ap_params("A" * 33, "6")  # 802.11 SSID max is 32 bytes


def test_validate_ap_params_rejects_non_numeric_channel():
    with pytest.raises(EvilTwinCommandError):
        _validate_ap_params("CorpGuest", "6; reboot")


def test_validate_ap_params_accepts_normal():
    _validate_ap_params("CorpGuest", "6")  # must not raise


# --- client count ignores the dnsmasq IPv6 "duid" header line -------------

def test_connected_clients_ignores_duid_line(tmp_path):
    mgr = EvilTwinManager()
    leases = tmp_path / "dnsmasq.leases"
    leases.write_text(
        "duid 00:01:00:01:aa:bb:cc:dd:ee:ff\n"  # IPv6 header — NOT a device
        "1699999999 aa:bb:cc:dd:ee:01 10.0.0.11 phone 01:aa:bb:cc:dd:ee:01\n"
        "1699999999 aa:bb:cc:dd:ee:02 10.0.0.12 laptop *\n"
    )
    mgr._leases_file = leases
    assert mgr.connected_clients() == 2  # two real leases, duid line not counted


# --- captive portal capture -----------------------------------------------

def test_portal_records_and_reads_back_submissions(tmp_path):
    creds = tmp_path / "captured.jsonl"
    record_submission(creds, "10.0.0.23", {"password": "hunter2"})
    record_submission(creds, "10.0.0.24", {"password": "letmein"})
    rows = read_captured(creds)
    assert len(rows) == 2
    assert rows[0]["client"] == "10.0.0.23"
    assert rows[0]["fields"]["password"] == "hunter2"
    assert "timestamp" in rows[0]


def test_portal_page_is_generic_not_brand_clone():
    page = render_page("CorpGuest")
    # shows the (scope-authorized) network name but is a generic auth page
    assert "CorpGuest" in page
    for brand in ("google", "facebook", "microsoft", "apple", "instagram"):
        assert brand not in page.lower()


def test_portal_page_asks_only_for_wifi_password_with_mfa_pretext():
    page = render_page("CorpGuest").lower()
    assert 'name="password"' in page
    assert 'name="email"' not in page and 'name="username"' not in page
    assert "mfa" in page or "verification" in page  # security re-auth pretext


def test_portal_done_page_confirms_reconnect():
    assert "reconnected" in render_page("CorpGuest", done=True).lower()


def test_portal_page_escapes_ssid():
    # an SSID pasted from a scan can contain HTML metacharacters — they must be
    # escaped so they can't break (or inject into) the portal page.
    page = render_page('<script>alert(1)</script>')
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


# --- password verification / accept logic ---------------------------------

def test_verify_password_none_without_handshake():
    # no pcapng and no hc22000 -> cannot verify -> None
    assert verify_password("", "", "AA:BB:CC:DD:EE:FF", "whatever12") is None


def test_pmkid_python_verify_fast_path(tmp_path):
    # craft a valid PMKID line and confirm the instant pure-Python check works
    import hashlib
    import hmac

    from app.portal import _verify_pmkid_python

    pw, essid = "Kunal@21", b"vaikun"
    ap, sta = bytes.fromhex("403306e1d031"), bytes.fromhex("aabbccddeeff")
    pmk = hashlib.pbkdf2_hmac("sha1", pw.encode(), essid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16].hex()
    hc = tmp_path / "h.hc22000"
    hc.write_text(f"WPA*01*{pmkid}*403306e1d031*aabbccddeeff*{essid.hex()}****\n")
    assert _verify_pmkid_python(str(hc), "Kunal@21") is True    # correct
    assert _verify_pmkid_python(str(hc), "WrongPass9") is False  # wrong
    empty = tmp_path / "e.hc22000"
    empty.write_text("")
    assert _verify_pmkid_python(str(empty), "x2345678") is None  # no PMKID line → fall back


def test_verify_password_rejects_impossible_length(tmp_path):
    cap = tmp_path / "hs.pcapng"
    cap.write_bytes(b"\x00")  # exists so we reach the length gate
    assert verify_password(str(cap), "", "AA:BB:CC:DD:EE:FF", "short") is False  # <8 chars


def test_has_accepted_only_on_verified_correct(tmp_path):
    creds = tmp_path / "c.jsonl"
    record_submission(creds, "10.0.0.5", {"password": "nope1234"}, verified=False)
    assert has_accepted(creds) is False  # wrong guess -> keep the attack running
    record_submission(creds, "10.0.0.6", {"password": "unknown12"}, verified=None)
    assert has_accepted(creds) is False  # unverifiable (no handshake) -> still running
    record_submission(creds, "10.0.0.7", {"password": "correct1"}, verified=True)
    assert has_accepted(creds) is True   # only a VERIFIED correct password stops it


# --- scope gating for the sustained deauth (BSSID-authorized) --------------

def test_eviltwin_deauth_target_bssid_must_be_in_scope(client):
    # SSID authorized, but deauthing a BSSID that isn't in scope must be rejected
    current_scope.set_scope(ssids=["CorpGuest"])
    resp = client.post("/eviltwin/start", json={
        "interface": "wlan0", "ssid": "CorpGuest", "channel": "6",
        "deauth_interface": "wlan1", "target_bssid": "11:22:33:44:55:66",
    })
    assert resp.status_code == 403


def test_eviltwin_deauth_requires_monitor_mode(client, monkeypatch):
    current_scope.set_scope(ssids=["CorpGuest"], bssids=["11:22:33:44:55:66"])
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "managed")
    resp = client.post("/eviltwin/start", json={
        "interface": "wlan0", "ssid": "CorpGuest", "channel": "6",
        "deauth_interface": "wlan1", "target_bssid": "11:22:33:44:55:66",
    })
    assert resp.status_code == 400
    assert "monitor" in resp.json()["detail"].lower()


def test_scope_change_blocked_while_operation_running(client, monkeypatch):
    monkeypatch.setattr("app.main.scan_manager.is_running", lambda: True)
    resp = client.post("/engagement/scope", json={"bssids": ["AA:BB:CC:DD:EE:FF"], "ssids": []})
    assert resp.status_code == 409
    assert "running" in resp.json()["detail"].lower()


def test_activity_endpoint_reports_running_ops(client, monkeypatch):
    monkeypatch.setattr("app.main.wps_manager.is_running", lambda: True)
    data = client.get("/engagement/activity").json()
    assert data["busy"] is True and "wps" in data["running"]


def test_eviltwin_requires_target_bssid(client):
    current_scope.set_scope(ssids=["CorpGuest"])
    resp = client.post("/eviltwin/start", json={"interface": "wlan1", "ssid": "CorpGuest", "channel": "6"})
    assert resp.status_code == 400
    assert "target" in resp.json()["detail"].lower()


def test_eviltwin_blocked_without_usable_handshake(client, monkeypatch):
    # scope + monitor OK, but no captured handshake -> must be rejected, and the
    # manager must never be started.
    current_scope.set_scope(ssids=["CorpGuest"], bssids=["11:22:33:44:55:66"])
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "monitor")
    monkeypatch.setattr("app.main.capture_manager.output_pcapng", lambda: None)
    monkeypatch.setattr("app.main.capture_manager.hash_file", lambda: None)
    started = {"called": False}
    monkeypatch.setattr("app.main.eviltwin_manager.start", lambda *a, **k: started.update(called=True))
    resp = client.post("/eviltwin/start", json={
        "interface": "wlan2", "ssid": "CorpGuest", "channel": "6",
        "deauth_interface": "wlan1", "target_bssid": "11:22:33:44:55:66",
    })
    assert resp.status_code == 400
    assert "handshake" in resp.json()["detail"].lower()
    assert started["called"] is False
