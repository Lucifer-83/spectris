import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scope import current_scope
from app.wps import WpsCommandError, WpsManager, _build_command, _channel_is_5ghz, _diagnose


@pytest.fixture(autouse=True)
def reset_scope():
    current_scope.clear()
    yield
    current_scope.clear()


@pytest.fixture
def client():
    return TestClient(app)


# --- scope gating (the safety guardrail) ---------------------------------

def test_wps_start_rejected_when_scope_never_set(client):
    resp = client.post(
        "/wps/start",
        json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"},
    )
    assert resp.status_code == 400


def test_wps_start_rejected_for_out_of_scope_bssid(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/wps/start",
        json={"interface": "wlan1", "bssid": "11:22:33:44:55:66", "channel": "6"},
    )
    assert resp.status_code == 403


def test_wps_start_never_invokes_manager_when_out_of_scope(client, monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("wps_manager.start must not run for an out-of-scope target")

    monkeypatch.setattr("app.main.wps_manager.start", fail_if_called)
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/wps/start",
        json={"interface": "wlan1", "bssid": "11:22:33:44:55:66", "channel": "6"},
    )
    assert resp.status_code == 403
    assert called is False


def test_wps_start_rejected_when_interface_not_in_monitor_mode(client, monkeypatch):
    # in scope, but the interface is managed → reaver could never associate, so
    # fail up front with a clear message instead of a silent "can't associate".
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "managed")
    resp = client.post(
        "/wps/start",
        json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"},
    )
    assert resp.status_code == 400
    assert "monitor" in resp.json()["detail"].lower()


def test_wps_start_proceeds_when_in_monitor_mode(client, monkeypatch):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "monitor")
    started = {}
    monkeypatch.setattr("app.main.wps_manager.start", lambda *a, **k: started.update(ok=True))
    resp = client.post(
        "/wps/start",
        json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"},
    )
    assert resp.status_code == 200
    assert started.get("ok") is True


# --- command construction -------------------------------------------------

def test_reaver_pixie_command_uses_bare_K_flag():
    # reaver 1.6.6's -K/--pixie-dust is boolean — the old fork's "-K 1" left a
    # stray "1" positional. Ensure we pass a bare -K with no trailing "1".
    cmd = _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "pixie", "reaver")
    assert "reaver" in cmd and "-K" in cmd
    assert cmd[cmd.index("-K") + 1 :] == []  # -K is the last token, no "1" after it
    assert "-b" in cmd and "AA:BB:CC:DD:EE:FF" in cmd


def test_reaver_pin_command_omits_pixie_flag():
    cmd = _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "pin", "reaver")
    assert "-K" not in cmd


def test_bully_pixie_command_forces_and_uses_pixiewps():
    cmd = _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "pixie", "bully")
    assert "bully" in cmd and "-d" in cmd and "-F" in cmd


def test_5ghz_channel_adds_band_flag():
    # channel 36 is 5 GHz — reaver/bully must be told, or they only tune 2.4 GHz.
    assert _channel_is_5ghz("36") is True
    assert _channel_is_5ghz("6") is False
    assert _channel_is_5ghz("") is False
    reaver = _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "36", "pixie", "reaver")
    assert "-5" in reaver
    bully = _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "149", "pixie", "bully")
    assert "-5" in bully
    # 2.4 GHz target must NOT get the 5 GHz flag
    assert "-5" not in _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "pixie", "reaver")


def test_unknown_attack_or_engine_raises():
    with pytest.raises(WpsCommandError):
        _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "nope", "reaver")
    with pytest.raises(WpsCommandError):
        _build_command("wlan1", "AA:BB:CC:DD:EE:FF", "6", "pixie", "nope")


# --- failure diagnostics ("pixie kam nahi kar raha") ----------------------

def test_diagnose_none_when_key_recovered():
    assert _diagnose("[+] WPS PIN: '12345670'", running=False, has_result=True) is None


def test_diagnose_flags_association_failure_as_radio_problem():
    raw = "\n".join(["[!] Failed to associate with AA:BB:CC:DD:EE:FF"] * 4)
    msg = _diagnose(raw, running=True, has_result=False)
    assert msg and "injection" in msg.lower()


def test_diagnose_flags_locked_wps():
    msg = _diagnose("[!] WARNING: Detected AP rate limiting", running=True, has_result=False)
    assert msg and ("lock" in msg.lower() or "rate" in msg.lower())


def test_diagnose_flags_not_vulnerable():
    msg = _diagnose("[-] WPS pin not found!", running=False, has_result=False)
    assert msg and "vulnerable" in msg.lower()


# --- output parsing -------------------------------------------------------

def test_status_parses_reaver_pin_and_psk(tmp_path):
    mgr = WpsManager()
    log = tmp_path / "wps.log"
    log.write_text(
        "[+] Associated with AA:BB:CC:DD:EE:FF\n"
        "[+] WPS PIN: '12345670'\n"
        "[+] WPA PSK: 'hunter2secret'\n"
    )
    mgr._log_file = log
    state = mgr.status()
    assert state.pin == "12345670"
    assert state.psk == "hunter2secret"
    assert state.running is False


def test_status_parses_bully_style_output(tmp_path):
    mgr = WpsManager()
    log = tmp_path / "wps.log"
    log.write_text("[+] PIN : '00005678'\n[+] KEY : 'passphrase!'\n")
    mgr._log_file = log
    state = mgr.status()
    assert state.pin == "00005678"
    assert state.psk == "passphrase!"
