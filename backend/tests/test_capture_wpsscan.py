from pathlib import Path

import app.wpsscan as wpsscan
from app.capture import channel_arg
from app.wpsscan import parse_wash_json


def test_channel_arg_adds_band_letter():
    assert channel_arg("6") == "6a"       # 2.4GHz
    assert channel_arg("11") == "11a"
    assert channel_arg("36") == "36b"     # 5GHz
    assert channel_arg("6a") == "6a"      # already banded -> unchanged
    assert channel_arg("auto") == "auto"  # non-numeric passes through


def test_parse_wash_json_array():
    raw = '[{"bssid":"AA:BB:CC:DD:EE:FF","wps_locked":0},{"bssid":"11:22:33:44:55:66","wps_locked":1}]'
    out = {a["bssid"]: a["locked"] for a in parse_wash_json(raw)}
    assert out["AA:BB:CC:DD:EE:FF"] is False
    assert out["11:22:33:44:55:66"] is True


def test_parse_wash_json_ndjson_and_case():
    raw = '{"bssid":"aa:bb:cc:dd:ee:ff","locked":"Yes"}\n{"BSSID":"11:22:33:44:55:66"}'
    out = {a["bssid"]: a["locked"] for a in parse_wash_json(raw)}
    assert out["AA:BB:CC:DD:EE:FF"] is True    # uppercased + locked parsed
    assert out["11:22:33:44:55:66"] is False   # missing lock -> not locked


def test_parse_wash_json_empty():
    assert parse_wash_json("") == []
    assert parse_wash_json("garbage not json") == []


def test_wps_scan_stops_via_procs_and_cleans_tmp(monkeypatch):
    # HIGH-fix: wash runs as root, so it must be spawned/stopped via app.procs
    # (positive-PID root kill), NOT a raw Popen.terminate (which EPERMs and leaks a
    # root process). Also the throwaway wash.json temp dir must be cleaned up.
    terminated = {"called": False}
    created = []

    real_mkdtemp = wpsscan.tempfile.mkdtemp

    def tracking_mkdtemp(*a, **k):
        d = real_mkdtemp(*a, **k)
        created.append(d)
        return d

    def fake_popen(cmd, **kw):
        assert cmd[:3] == ["sudo", "-n", "wash"]  # spawned via procs.popen as root
        return object()  # a dummy proc; we never poll it

    monkeypatch.setattr(wpsscan.tempfile, "mkdtemp", tracking_mkdtemp)
    monkeypatch.setattr(wpsscan.procs, "popen", fake_popen)
    monkeypatch.setattr(wpsscan.procs, "terminate", lambda proc, **k: terminated.update(called=True))
    monkeypatch.setattr(wpsscan.time, "sleep", lambda s: None)

    out = wpsscan.wps_scan("wlan1", duration=5)
    assert out == []                                   # empty wash.json -> nothing
    assert terminated["called"] is True                # stopped via procs.terminate
    assert created and not Path(created[0]).exists()   # temp dir cleaned up
