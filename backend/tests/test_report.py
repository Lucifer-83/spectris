import pytest

from app import report
from app.crack import CrackState
from app.scope import current_scope


@pytest.fixture(autouse=True)
def reset_scope():
    current_scope.clear()
    yield
    current_scope.clear()


def _crack_state(**overrides) -> CrackState:
    base = dict(
        running=False, engine=None, attack_mode=None, bssid=None, wordlist=None,
        hash_file=None, psk=None, exhausted=False, progress_pct=None, speed=None, eta=None,
    )
    base.update(overrides)
    return CrackState(**base)


def test_report_includes_scope_and_recovered_psk(monkeypatch):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"], ssids=["CorpWiFi"])
    monkeypatch.setattr(
        report.crack_manager, "status",
        lambda: _crack_state(engine="hashcat", attack_mode="wordlist",
                             bssid="AA:BB:CC:DD:EE:FF", psk="hunter2secret"),
    )

    md = report.build_report()
    assert md.startswith("# WiFi Penetration Test")
    assert "AA:BB:CC:DD:EE:FF" in md   # scope + recovered target
    assert "CorpWiFi" in md            # scope ssid
    assert "hunter2secret" in md       # the recovered PSK
    assert "## 3. Action timeline" in md


def test_report_notes_when_nothing_recovered(monkeypatch):
    # no crack/wps/eviltwin findings in this session
    monkeypatch.setattr(report, "_recovered_rows", lambda: [])
    monkeypatch.setattr(report.crack_manager, "status", lambda: _crack_state())
    md = report.build_report()
    assert "No PSK/PIN was recovered" in md


def test_report_filename_shape():
    name = report.report_filename()
    assert name.startswith("engagement-report-") and name.endswith(".md")
