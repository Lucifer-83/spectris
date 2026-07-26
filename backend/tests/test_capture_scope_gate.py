import pytest
from fastapi.testclient import TestClient

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


def test_capture_start_rejected_when_scope_never_set(client):
    resp = client.post(
        "/capture/start",
        json={"interface": "wlan1mon", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"},
    )
    assert resp.status_code == 400


def test_capture_start_rejected_for_out_of_scope_bssid(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/capture/start",
        json={"interface": "wlan1mon", "bssid": "11:22:33:44:55:66", "channel": "6"},
    )
    assert resp.status_code == 403


def test_capture_start_never_invokes_manager_when_out_of_scope(client, monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("capture_manager.start must not run for an out-of-scope target")

    monkeypatch.setattr("app.main.capture_manager.start", fail_if_called)
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/capture/start",
        json={"interface": "wlan1mon", "bssid": "11:22:33:44:55:66", "channel": "6"},
    )
    assert resp.status_code == 403
    assert called is False
