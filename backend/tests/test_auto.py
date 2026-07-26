import time

import pytest
from fastapi.testclient import TestClient

from app.auto import AutoManager, looks_like_wpa3_only
from app.main import app
from app.scope import current_scope


@pytest.fixture(autouse=True)
def reset_scope():
    current_scope.clear()
    yield
    current_scope.clear()


@pytest.fixture
def client():
    return TestClient(app)


# --- WPA3 detection -------------------------------------------------------

def test_looks_like_wpa3_only():
    assert looks_like_wpa3_only("WPA3") is True
    assert looks_like_wpa3_only("SAE") is True
    assert looks_like_wpa3_only("WPA2 WPA3") is False        # transition -> WPA2 still crackable
    assert looks_like_wpa3_only("WPA2") is False
    assert looks_like_wpa3_only("") is False
    assert looks_like_wpa3_only(None) is False


# --- scope + WPA3 gating on the endpoint ----------------------------------

def test_auto_start_rejected_when_scope_never_set(client):
    resp = client.post("/auto/start", json={
        "interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6",
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    })
    assert resp.status_code == 400


def test_auto_start_rejected_for_out_of_scope_bssid(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post("/auto/start", json={
        "interface": "wlan1", "bssid": "11:22:33:44:55:66", "channel": "6",
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    })
    assert resp.status_code == 403


def test_auto_start_rejects_wpa3_only_target(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post("/auto/start", json={
        "interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6",
        "wordlist": "/usr/share/wordlists/rockyou.txt", "encryption": "WPA3",
    })
    assert resp.status_code == 400
    assert "WPA3" in resp.json()["detail"]


# --- orchestration happy path (managers faked, sleep neutralised) ---------

class _FakeCapture:
    def __init__(self, hashes):
        self._hashes = hashes
    def start(self, *a, **k):
        pass
    def stop(self):
        pass
    def status(self):
        return type("S", (), {"hashes": self._hashes})()
    def convert_to_hashcat_format(self):
        return "/tmp/x.hc22000"


class _FakeDeauth:
    def start(self, *a, **k):
        pass
    def stop(self):
        pass


class _FakeCrack:
    def __init__(self, psk):
        self._psk = psk
    def start(self, *a, **k):
        pass
    def stop(self):
        pass
    def is_running(self):
        return False
    def status(self):
        return type("S", (), {"psk": self._psk, "progress_pct": 100, "speed": "1 H/s"})()


def _wait_done(mgr, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = mgr.status()
        if not st.running:
            return st
        time.sleep(0.02)
    raise AssertionError("auto run did not finish in time")


def test_auto_run_reaches_done_when_handshake_and_key_found(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("hunter2secret\n")
    monkeypatch.setattr("app.auto.time.sleep", lambda s: None)
    monkeypatch.setattr("app.auto.capture_manager", _FakeCapture(hashes=1))
    monkeypatch.setattr("app.auto.deauth_manager", _FakeDeauth())
    monkeypatch.setattr("app.auto.crack_manager", _FakeCrack(psk="hunter2secret"))
    mgr = AutoManager()
    mgr.start("wlan1", "AA:BB:CC:DD:EE:FF", "6", str(wl))
    st = _wait_done(mgr)
    assert st.phase == "done"
    assert st.psk == "hunter2secret"


def test_auto_run_fails_when_no_handshake(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n")
    monkeypatch.setattr("app.auto.time.sleep", lambda s: None)
    monkeypatch.setattr("app.auto.capture_manager", _FakeCapture(hashes=0))
    monkeypatch.setattr("app.auto.deauth_manager", _FakeDeauth())
    monkeypatch.setattr("app.auto.crack_manager", _FakeCrack(psk=None))
    mgr = AutoManager()
    mgr.start("wlan1", "AA:BB:CC:DD:EE:FF", "6", str(wl), capture_seconds=0)
    st = _wait_done(mgr)
    assert st.phase == "failed"
    assert "handshake" in (st.error or "").lower()
