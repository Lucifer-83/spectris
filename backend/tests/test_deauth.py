import pytest
from fastapi.testclient import TestClient

from app.deauth import DeauthCommandError, DeauthManager
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


# --- scope gating ---------------------------------------------------------

def test_deauth_rejected_when_scope_never_set(client):
    resp = client.post("/deauth/start", json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF"})
    assert resp.status_code == 400


def test_deauth_rejected_for_out_of_scope_bssid(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post("/deauth/start", json={"interface": "wlan1", "bssid": "11:22:33:44:55:66"})
    assert resp.status_code == 403


def test_deauth_never_invokes_manager_when_out_of_scope(client, monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("deauth_manager.start must not run for an out-of-scope target")

    monkeypatch.setattr("app.main.deauth_manager.start", fail_if_called)
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post("/deauth/start", json={"interface": "wlan1", "bssid": "11:22:33:44:55:66"})
    assert resp.status_code == 403
    assert called is False


# --- count: operator-controlled, no hard cap ------------------------------

def test_negative_count_is_rejected():
    mgr = DeauthManager()
    with pytest.raises(DeauthCommandError):
        mgr.start("wlan1", "AA:BB:CC:DD:EE:FF", count=-1)


def test_large_count_now_allowed(client, monkeypatch):
    # no 64 cap anymore — the operator picks the count; don't actually spawn aireplay
    started = {}
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "monitor")
    monkeypatch.setattr("app.main.deauth_manager.start", lambda *a, **k: started.update(ok=True))
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/deauth/start",
        json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "count": 9999},
    )
    assert resp.status_code == 200
    assert started.get("ok") is True


def test_continuous_count_zero_allowed(client, monkeypatch):
    started = {}
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "monitor")
    monkeypatch.setattr("app.main.deauth_manager.start", lambda *a, **k: started.update(ok=True))
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/deauth/start",
        json={"interface": "wlan1", "bssid": "AA:BB:CC:DD:EE:FF", "count": 0},
    )
    assert resp.status_code == 200
